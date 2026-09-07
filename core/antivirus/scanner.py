"""The on-demand scanner — the core sweep engine behind every scan type.

A scan is a three-stage pipeline per file: **hash** (SHA-256), **match** (signature
lookup), **classify** (heuristics). Every detection is written to the timeline as the
full narrative chain (FILE_DETECTED → HASH_GENERATED → SIGNATURE_CHECK →
MATCH_FOUND/NO_MATCH → HEURISTIC_FLAG… → THREAT_CLASSIFIED → QUARANTINE_ACTION), while
clean files stay off the timeline entirely — a narrative per file would drown the
incident log in "looked at it, it was fine" entries and push real incidents out of the
dashboard's activity window.

Hashing dominates the runtime and :mod:`hashlib` releases the GIL while digesting, so
files are hashed on a small thread pool (``antivirus.scan_threads``) in batches while
everything that touches shared state — signature lookups, heuristics, the timeline,
quarantine — stays on the scan thread. That keeps verdict order deterministic and the
databases' write lock uncontended while still using every core.

``run()`` is deliberately **blocking**; the GUI runs it on a worker thread and feeds it
``on_progress``/``should_cancel`` callbacks. That keeps the engine free of Tk (so tests
and ``--no-gui`` can run it) while the UI keeps its responsiveness contract.
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.antivirus.hashing import sha256_file
from core.antivirus.heuristics import Finding, HeuristicEngine, score_to_severity
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

#: Files hashed per pool batch — small enough that cancellation lands quickly,
#: large enough that thread hand-off overhead stays negligible.
_BATCH_SIZE = 128


def _default_threads() -> int:
    """Sensible pool size: leave one core for the UI and the OS."""
    try:
        import os as _os

        cpus = _os.cpu_count() or 2
    except Exception:
        cpus = 2
    return max(2, cpus - 1)


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

    @property
    def live_threat_count(self) -> int:
        """Detections *so far*. 

        ``threats_found`` stays 0 until the whole walk finishes, so reporting it in
        progress callbacks showed "0 threats" all scan long while detections were
        already being logged — the GUI stat and the SCAN_PROGRESS timeline rows
        disagreed with the Detection lines appearing right beside them.
        """
        return len(self.detections)


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
        #: Hashes already *reported* in the current scan. Installers and dev tools leave
        #: many byte-identical copies around (the same vs_installer.exe in five temp
        #: folders); each is counted as scanned, but a detection is reported once and the
        #: duplicates are folded into a single "also seen at N other locations" note.
        self._reported_hashes: dict[str, list[str]] = {}

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
        self._reported_hashes = {}
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
        """Iterate one directory tree, hashing batches of files on a thread pool.

        Quick scans are depth-limited (``antivirus.quick_scan_max_depth``): real
        droppers land in the *top* of %TEMP% or a Startup folder, while the bulk of a
        quick scan's runtime went into recursively hashing browser caches and
        application state directories tens of levels deep — turning a "quick" scan
        into a de-facto full scan.

        Only the *hashing* runs on the pool: SHA-256 releases the GIL, so a pool of
        ``antivirus.scan_threads`` workers digests files on every core, while the
        verdicts (signature lookup, heuristics, timeline, quarantine) stay on this
        thread in discovery order — determinism where state is shared, parallelism
        where the CPU work actually is.
        """
        max_bytes = int(self.cfg.get("antivirus.max_file_size_mb", 512)) * 1024 * 1024
        if scan_type == "quick":
            max_depth = int(self.cfg.get("antivirus.quick_scan_max_depth", 2))
        else:
            max_depth = 0  # unlimited

        workers = max(1, int(self.cfg.get("antivirus.scan_threads", 0)) or _default_threads())
        chunk_size = int(self.cfg.get("antivirus.hash_chunk_size", 65_536))
        pending: list[tuple[Path, os.stat_result]] = []

        def hash_batch(
            paths: list[tuple[Path, os.stat_result]],
        ) -> list[str | None]:
            """Hash every file in ``paths`` on the pool (None per unreadable file)."""
            if pool is None or len(paths) == 1:
                return [sha256_file(path, chunk_size) for path, _stat in paths]
            return list(pool.map(lambda item: sha256_file(item[0], chunk_size), paths))

        from contextlib import ExitStack

        with ExitStack() as stack:
            pool = (
                stack.enter_context(ThreadPoolExecutor(max_workers=workers))
                if workers > 1
                else None
            )
            self._walk_tree(
                root, result, scan_id, scan_type, on_progress, should_cancel,
                max_bytes, max_depth, pending, hash_batch,
            )

    def _walk_tree(
        self,
        root: Path,
        result: ScanResult,
        scan_id: int | None,
        scan_type: str,
        on_progress: ProgressCallback | None,
        should_cancel: CancelCallback | None,
        max_bytes: int,
        max_depth: int,
        pending: list[tuple[Path, os.stat_result]],
        hash_batch: Callable[[list[tuple[Path, os.stat_result]]], list[str | None]],
    ) -> None:
        """The os.walk loop; ``pending`` is flushed in batches through ``hash_batch``."""
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(
            root, followlinks=bool(self.cfg.get("antivirus.follow_symlinks", False))
        ):
            if self._cancelled(should_cancel):
                return
            current = Path(dirpath)
            if max_depth and len(current.parts) - root_depth >= max_depth:
                dirnames[:] = []  # at the depth ceiling: scan this level, go no deeper

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
                pending.append((path, stat))
                if len(pending) >= _BATCH_SIZE:
                    batch_hashes = hash_batch(pending)
                    self._process_batch(
                        pending, batch_hashes, result, scan_id, scan_type,
                        on_progress, should_cancel,
                    )
                    pending.clear()
                    if self._cancelled(should_cancel):
                        return

        if pending and not self._cancelled(should_cancel):
            batch_hashes = hash_batch(pending)
            self._process_batch(
                pending, batch_hashes, result, scan_id, scan_type,
                on_progress, should_cancel,
            )

    def _process_batch(
        self,
        batch: list[tuple[Path, os.stat_result]],
        hashes: list[str | None],
        result: ScanResult,
        scan_id: int | None,
        scan_type: str,
        on_progress: ProgressCallback | None,
        should_cancel: CancelCallback | None,
    ) -> None:
        """Verdict a hashed batch in discovery order: match → classify → quarantine."""
        for (path, stat), file_hash in zip(batch, hashes):
            if self._cancelled(should_cancel):
                return
            threats_before = len(result.detections)
            self._finish_file(path, result, scan_id, origin=scan_type, stat=stat, file_hash=file_hash)

            if on_progress is not None and (
                result.files_scanned % 25 == 0 or len(result.detections) != threats_before
            ):
                on_progress(result.files_scanned, result.live_threat_count, str(path))
            if result.files_scanned % PROGRESS_EVENT_EVERY == 0:
                self.timeline.log_antivirus(
                    EventType.SCAN_PROGRESS,
                    f"Scanned {result.files_scanned} file(s), "
                    f"{result.live_threat_count} threat(s) so far",
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
        """Hash → match → classify one file synchronously (real-time monitor path).

        Counting is :meth:`_finish_file`'s job: this used to increment as well, so
        single-file targets were reported as two scanned files.
        """
        try:
            stat = stat or path.stat()
        except (OSError, ValueError):
            result.files_skipped += 1
            return
        file_hash = sha256_file(path, int(self.cfg.get("antivirus.hash_chunk_size", 65_536)))
        self._finish_file(path, result, scan_id, origin=origin, stat=stat, file_hash=file_hash)

    def _finish_file(
        self,
        path: Path,
        result: ScanResult,
        scan_id: int | None,
        origin: str,
        stat: os.stat_result | None,
        file_hash: str | None,
    ) -> None:
        """Match → classify one *already-hashed* file, recording real detections."""
        result.files_scanned += 1

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
        if signature is None and self.heuristics.total_score(findings) < 20:
            # Below LOW is "noteworthy at most": a single weak indicator (a .js in
            # %TEMP%, entropy in a signed installer) is not a detection. Logging these
            # as threats turned a 11k-file quick scan into 115 false positives.
            return

        prior_locations = self._reported_hashes.get(file_hash)
        if prior_locations is not None:
            prior_locations.append(str(path))
            if signature is None:
                # Byte-identical heuristic duplicate: count it, never re-narrate it.
                # A five-copy installer would otherwise produce five full detection
                # stories and five verdict popups.
                return
            # A signature match is different: every byte-identical copy is live malware
            # on disk, so quarantine this one too — but without the narrative repeat.
            detection = self._classify(path, file_hash, signature, findings)
            if bool(self.cfg.get("antivirus.auto_quarantine_on_signature_match", True)):
                self._auto_quarantine(detection, scan_id)
            result.detections.append(detection)
            return
        self._reported_hashes[file_hash] = [str(path)]

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
        """Decide threat name and severity from the evidence collected.

        Heuristic verdicts come from the summed rule weights (see the scoring table in
        :mod:`core.antivirus.heuristics`), never from any single rule: two weak leads
        can be a pattern, one weak lead is background noise.
        """
        if signature is not None:
            return Detection(
                path=str(path),
                threat_name=str(signature.get("name", "Unknown")),
                severity=Severity.normalize(str(signature.get("severity", Severity.HIGH)), Severity.HIGH),
                kind="signature",
                sha256=file_hash,
            )

        score = self.heuristics.total_score(findings)
        severity = score_to_severity(score)
        return Detection(
            path=str(path),
            threat_name=f"Suspicious ({', '.join(finding.rule for finding in findings)}) — score {score}",
            severity=severity,
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
