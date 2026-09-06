"""The on-demand scanner — the core sweep engine behind every scan type.

A scan is a three-stage pipeline per file: **hash** (SHA-256), **match** (signature
lookup), **classify** (heuristics). Every detection is written to the timeline as the
full narrative chain (FILE_DETECTED → HASH_GENERATED → SIGNATURE_CHECK →
MATCH_FOUND/NO_MATCH → HEURISTIC_FLAG… → THREAT_CLASSIFIED → QUARANTINE_ACTION), while
clean files stay off the timeline entirely — a narrative per file would drown the
incident log in "looked at it, it was fine" entries and push real incidents out of the
dashboard's activity window.

``run()`` is deliberately **blocking**; the GUI runs it on a worker thread and feeds it
``on_progress``/``should_cancel`` callbacks. That keeps the engine free of Tk (so tests
and ``--no-gui`` can run it) while the UI keeps its responsiveness contract.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.antivirus.hashing import sha256_file
from core.antivirus.heuristics import Finding, HeuristicEngine
from core.antivirus.quarantine import QuarantineError, QuarantineManager
from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["Detection", "ScanResult", "Scanner"]

ProgressCallback = Callable[[int, int, str], None]
CancelCallback = Callable[[], bool]

#: How many files between SCAN_PROGRESS timeline entries (keeps the activity feed useful).
PROGRESS_EVENT_EVERY = 500


@dataclass
class Detection:
    """One file judged malicious or suspicious by the pipeline."""

    path: str
    threat_name: str
    severity: str
    kind: str  # "signature" (known malware) | "heuristic" (suspicious behaviour)
    sha256: str | None = None
    heuristic_rules: list[str] = field(default_factory=list)
    quarantined: bool = False
    quarantine_id: int | None = None
    quarantine_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "threat_name": self.threat_name,
            "severity": self.severity,
            "kind": self.kind,
            "sha256": self.sha256,
            "heuristic_rules": list(self.heuristic_rules),
            "quarantined": self.quarantined,
            "quarantine_id": self.quarantine_id,
            "quarantine_error": self.quarantine_error,
        }


@dataclass
class ScanResult:
    """Everything one ``run()`` learned, for the history table and the summary UI."""

    scan_id: int
    scan_type: str
    target: str
    status: str = "RUNNING"  # COMPLETED | CANCELLED | FAILED, set by run()
    files_scanned: int = 0
    files_skipped: int = 0
    threats_found: int = 0
    detections: list[Detection] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None

    @property
    def severity_summary(self) -> dict[str, int]:
        """Detections counted by severity — the shape ``finish_scan`` persists."""
        summary: dict[str, int] = {}
        for detection in self.detections:
            summary[detection.severity] = summary.get(detection.severity, 0) + 1
        return summary


class Scanner:
    """Runs quick/full/custom scans and single-file analyses."""

    def __init__(
        self, config: Config, db: Database, timeline: TimelineLogger, quarantine: QuarantineManager
    ) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.quarantine = quarantine
        self.heuristics = HeuristicEngine(config)

    # ================================================================== public API
    def run(
        self,
        scan_type: str,
        target: str | Path | None = None,
        on_progress: ProgressCallback | None = None,
        should_cancel: CancelCallback | None = None,
    ) -> ScanResult:
        """Execute one scan. Blocking; see the module docstring for the threading model.

        ``scan_type`` is ``quick`` (the usual infection sites), ``full`` (all fixed
        disks), ``custom`` (``target`` — a file or directory) or ``single`` (``target``
        file only, no scan_history row; used by the real-time monitor).
        """
        started = time.monotonic()
        scan_id = -1
        result = ScanResult(scan_id=-1, scan_type=scan_type, target=str(target or ""))
        try:
            targets = self._resolve_targets(scan_type, target)
            label = ", ".join(str(item) for item in targets) if targets else str(target or "")
            result.target = label
            if scan_type != "single":
                scan_id = self.db.start_scan(scan_type, label or scan_type)
                result.scan_id = scan_id
                self.timeline.log_antivirus(
                    EventType.SCAN_STARTED,
                    f"{scan_type.title()} scan started on {label or 'system locations'}",
                    Severity.INFO,
                )

            for root in targets:
                if self._cancelled(should_cancel):
                    break
                if root.is_file():
                    self._scan_file(root, result, scan_id, origin=scan_type)
                else:
                    self._walk(root, result, scan_id, scan_type, on_progress, should_cancel)
            if self._cancelled(should_cancel):
                result.status = "CANCELLED"
            else:
                result.status = "COMPLETED"
        except Exception as exc:  # a bad target or dead walk must still close the history row
            result.status = "FAILED"
            result.error = str(exc)
            logger.exception("Scan of %s failed", target)

        result.duration_seconds = time.monotonic() - started
        result.threats_found = len(result.detections)

        if scan_type != "single" and scan_id > 0:
            self.db.finish_scan(
                scan_id,
                files_scanned=result.files_scanned,
                threats_found=result.threats_found,
                severity_summary=result.severity_summary,
                status=result.status,
            )
            event = {
                "COMPLETED": EventType.SCAN_COMPLETED,
                "CANCELLED": EventType.SCAN_COMPLETED,
                "FAILED": EventType.SCAN_FAILED,
            }[result.status]
            detail = (
                f"{scan_type.title()} scan {result.status.lower()}: "
                f"{result.files_scanned} file(s), {result.threats_found} threat(s)"
                f" in {result.duration_seconds:.1f}s"
            )
            if result.status == "FAILED":
                detail += f" — {result.error}"
            self.timeline.log_antivirus(event, detail, Severity.INFO)
        elif scan_type != "single" and result.status == "FAILED":
            # The target never resolved (missing path, unreadable disk): no history row
            # exists to close, but the failure must still reach the timeline.
            self.timeline.log_antivirus(
                EventType.SCAN_FAILED,
                f"{scan_type.title()} scan failed — {result.error}",
                Severity.MEDIUM,
            )

        return result

    def scan_single(self, path: Path, origin: str = "realtime") -> Detection | None:
        """Analyse one file for the real-time monitor. No scan row; returns a Detection.

        Auto-quarantine applies here too: a real-time detection that is left on disk
        while a notification waits for the user is exactly the window malware wants.
        """
        holder = ScanResult(scan_id=-1, scan_type="single", target=str(path))
        self._scan_file(Path(path), holder, None, origin=origin)
        return holder.detections[0] if holder.detections else None

    # ================================================================== targeting
    def _resolve_targets(self, scan_type: str, target: str | Path | None) -> list[Path]:
        """Turn a scan type into the list of roots to sweep."""
        if scan_type == "quick":
            return self.cfg.resolve_paths("antivirus.quick_scan_paths", directories_only=True)
        if scan_type == "full":
            import psutil

            roots: list[Path] = []
            for partition in psutil.disk_partitions(all=False):
                if "cdrom" in partition.opts or not partition.mountpoint:
                    continue
                try:
                    if not Path(partition.mountpoint).exists():
                        continue
                except OSError:
                    continue
                roots.append(Path(partition.mountpoint))
            return roots
        if scan_type in ("custom", "single"):
            if not target:
                raise ValueError(f"{scan_type} scan requires a target path")
            chosen = Path(target)
            if not chosen.exists():
                raise FileNotFoundError(f"Scan target does not exist: {chosen}")
            return [chosen]
        raise ValueError(f"Unknown scan type {scan_type!r}")

    def _walk(
        self,
        root: Path,
        result: ScanResult,
        scan_id: int | None,
        scan_type: str,
        on_progress: ProgressCallback | None,
        should_cancel: CancelCallback | None,
    ) -> None:
        """Iterate one directory tree, pruning exclusions and reparse points."""
        max_bytes = int(self.cfg.get("antivirus.max_file_size_mb", 512)) * 1024 * 1024

        for dirpath, dirnames, filenames in os.walk(
            root, followlinks=bool(self.cfg.get("antivirus.follow_symlinks", False))
        ):
            if self._cancelled(should_cancel):
                return
            current = Path(dirpath)

            # Prune excluded/unsafe directories in place so os.walk never descends
            # into them: quarantined malware inside the vault must not be re-swept.
            kept: list[str] = []
            for name in dirnames:
                candidate = current / name
                if self.cfg.is_excluded(candidate):
                    continue
                if not bool(self.cfg.get("antivirus.follow_symlinks", False)):
                    try:
                        if candidate.is_symlink():
                            continue
                    except OSError:
                        continue
                kept.append(name)
            dirnames[:] = kept

            for name in filenames:
                if self._cancelled(should_cancel):
                    return
                path = current / name
                try:
                    stat = path.stat()
                except (OSError, ValueError):
                    result.files_skipped += 1
                    continue
                if stat.st_size > max_bytes:
                    result.files_skipped += 1
                    continue
                self._scan_file(path, result, scan_id, origin=scan_type, stat=stat)

                if result.files_scanned % 25 == 0 and on_progress is not None:
                    on_progress(result.files_scanned, result.threats_found, str(path))
                if result.files_scanned % PROGRESS_EVENT_EVERY == 0:
                    self.timeline.log_antivirus(
                        EventType.SCAN_PROGRESS,
                        f"Scanned {result.files_scanned} file(s), "
                        f"{result.threats_found} threat(s) so far",
                        Severity.INFO,
                    )

    # ================================================================== the pipeline
    def _scan_file(
        self,
        path: Path,
        result: ScanResult,
        scan_id: int | None,
        origin: str,
        stat: os.stat_result | None = None,
    ) -> None:
        """Hash → match → classify one file, recording only real detections."""
        result.files_scanned += 1

        try:
            stat = stat or path.stat()
        except (OSError, ValueError):
            result.files_skipped += 1
            result.files_scanned -= 1
            return

        file_hash = sha256_file(path, int(self.cfg.get("antivirus.hash_chunk_size", 65_536)))
        if file_hash is None:
            result.files_skipped += 1
            result.files_scanned -= 1
            return

        signature = self.db.lookup_hash(file_hash)
        findings: list[Finding] = []
        if signature is None:
            findings = self.heuristics.examine(path, stat)

        if signature is None and not findings:
            return  # clean file: no timeline entry by design

        self._log_narrative(path, file_hash, signature, findings, origin)
        detection = self._classify(path, file_hash, signature, findings)
        self.timeline.threat_classified(path, detection.severity)

        if (
            signature is not None
            and bool(self.cfg.get("antivirus.auto_quarantine_on_signature_match", True))
        ):
            self._auto_quarantine(detection, scan_id)

        result.detections.append(detection)
        logger.info(
            "Detection: %s (%s, %s)", path, detection.threat_name, detection.severity
        )

    def _log_narrative(
        self,
        path: Path,
        file_hash: str,
        signature: dict[str, Any] | None,
        findings: list[Finding],
        origin: str,
    ) -> None:
        """Emit the detection narrative — the sequence the timeline UI is built to show."""
        timeline = self.timeline
        timeline.file_detected(path, origin=origin)
        timeline.hash_generated(path, file_hash)
        timeline.signature_check(path, self.db.signature_count())
        if signature is not None:
            timeline.match_found(path, str(signature.get("name", "Unknown")), str(signature.get("severity", Severity.HIGH)))
        else:
            timeline.no_match(path)
        for finding in findings:
            timeline.heuristic_flag(path, finding.rule, finding.severity)

    def _classify(
        self,
        path: Path,
        file_hash: str,
        signature: dict[str, Any] | None,
        findings: list[Finding],
    ) -> Detection:
        """Decide threat name and severity from the evidence collected."""
        if signature is not None:
            return Detection(
                path=str(path),
                threat_name=str(signature.get("name", "Unknown")),
                severity=Severity.normalize(str(signature.get("severity", Severity.HIGH)), Severity.HIGH),
                kind="signature",
                sha256=file_hash,
            )

        worst = max(
            (finding.severity for finding in findings),
            key=lambda level: Severity.rank(level),
        )
        return Detection(
            path=str(path),
            threat_name=f"Suspicious ({', '.join(finding.rule for finding in findings)})",
            severity=worst,
            kind="heuristic",
            sha256=file_hash,
            heuristic_rules=[finding.rule for finding in findings],
        )

    def _auto_quarantine(self, detection: Detection, scan_id: int | None) -> None:
        """Move a signature-matched file into the vault, recording failures honestly."""
        try:
            detection.quarantine_id = self.quarantine.quarantine(
                Path(detection.path),
                threat_name=detection.threat_name,
                severity=detection.severity,
                file_hash=detection.sha256,
                scan_id=scan_id,
            )
            detection.quarantined = True
        except QuarantineError as exc:
            detection.quarantine_error = str(exc)
            self.timeline.log_antivirus(
                EventType.ENGINE_ERROR,
                f"Could not quarantine {Path(detection.path).name}: {exc}",
                Severity.MEDIUM,
                detection.path,
            )
            logger.error("Auto-quarantine failed for %s: %s", detection.path, exc)

    # ================================================================== helpers
    @staticmethod
    def _cancelled(should_cancel: CancelCallback | None) -> bool:
        if should_cancel is None:
            return False
        try:
            return bool(should_cancel())
        except Exception:  # a broken cancel callback must not kill the scan
            logger.exception("should_cancel callback raised; ignoring")
            return False
