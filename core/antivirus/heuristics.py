"""Static heuristic rules — the signature-free half of the antivirus engine.

Each rule takes a file and its stat info and returns a :class:`Finding` when it fires.
Rules are driven entirely by ``antivirus.heuristics`` in config.json, so they can be
tuned or switched off without touching code.

Heuristics deliberately *over*-report — that is what a heuristic is for. A flag is a
lead, not a verdict: the scanner counts flags per file and escalates severity when
several fire together (``escalate_to_medium_after_flags``).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.config import Config
from core.timeline import Severity

logger = logging.getLogger(__name__)

__all__ = ["Finding", "HeuristicEngine"]


@dataclass
class Finding:
    """One heuristic that fired for one file."""

    rule: str
    detail: str
    severity: str = Severity.LOW
    #: Free-form context for the timeline detail panel.
    extra: dict[str, Any] = field(default_factory=dict)


def _ext(path: Path) -> str:
    return path.suffix.lower()


class HeuristicEngine:
    """Evaluates the configured static heuristics against single files."""

    def __init__(self, config: Config) -> None:
        self.cfg = config

    # ------------------------------------------------------------------ public API
    def examine(self, path: Path, stat: os.stat_result | None = None) -> list[Finding]:
        """Run every enabled heuristic against ``path``. Never raises."""
        findings: list[Finding] = []
        if not bool(self.cfg.get("antivirus.heuristics.enabled", True)):
            return findings

        try:
            stat = stat or path.stat()
        except (OSError, ValueError):
            return findings  # vanished or unreadable; the scanner already logged it

        for rule in (
            self._double_extension,
            self._script_in_user_dirs,
            self._no_extension_in_system_dir,
            self._large_file_in_startup,
            self._recently_modified_in_protected_dir,
            self._high_entropy,
        ):
            try:
                findings.extend(rule(path, stat) or [])
            except Exception as exc:  # a broken rule must never abort a scan
                logger.error("Heuristic rule %s failed on %s: %s", rule.__name__, path, exc)

        return self._escalate(path, findings)

    # ------------------------------------------------------------------ rules
    def _double_extension(self, path: Path, stat: os.stat_result) -> list[Finding]:
        """``invoice.pdf.exe`` — a document extension hiding an executable one."""
        if not bool(self.cfg.get("antivirus.heuristics.double_extension.enabled", True)):
            return []
        outer = _ext(path)
        outer_list = [
            ext.lower() for ext in self.cfg.get("antivirus.heuristics.double_extension.outer_extensions", [])
        ]
        inner_list = [
            ext.lower() for ext in self.cfg.get("antivirus.heuristics.double_extension.inner_extensions", [])
        ]
        if outer not in outer_list:
            return []
        # The extension before the (executable) one must look like a document.
        stem = path.stem
        if not stem or "." not in stem:
            return []
        inner = "." + stem.rsplit(".", 1)[-1]
        if inner.lower() not in inner_list:
            return []
        severity = str(self.cfg.get("antivirus.heuristics.double_extension.severity", Severity.MEDIUM))
        return [
            Finding(
                rule="double_extension",
                detail=f"Double extension: {path.name} poses as a {inner} document",
                severity=Severity.normalize(severity, Severity.MEDIUM),
                extra={"outer": outer, "inner": inner},
            )
        ]

    def _script_in_user_dirs(self, path: Path, stat: os.stat_result) -> list[Finding]:
        """Script files loose in user-writable locations are a classic persistence drop."""
        if not bool(self.cfg.get("antivirus.heuristics.script_in_user_dirs.enabled", True)):
            return []
        watched = self.cfg.resolve_paths(
            "antivirus.realtime_monitor.watched_paths", existing_only=False
        )
        if not watched or not self._under_any(path, watched):
            return []
        extensions = [
            ext.lower()
            for ext in self.cfg.get("antivirus.heuristics.script_in_user_dirs.extensions", [])
        ]
        if _ext(path) not in extensions:
            return []
        severity = str(self.cfg.get("antivirus.heuristics.script_in_user_dirs.severity", Severity.MEDIUM))
        return [
            Finding(
                rule="script_in_user_dir",
                detail=f"Script file ({_ext(path)}) in a user-writable location",
                severity=Severity.normalize(severity, Severity.MEDIUM),
            )
        ]

    def _no_extension_in_system_dir(self, path: Path, stat: os.stat_result) -> list[Finding]:
        """Extension-less executables hiding in System32-style directories."""
        if not bool(self.cfg.get("antivirus.heuristics.no_extension_in_system_dir.enabled", True)):
            return []
        system_dirs = self.cfg.resolve_paths(["%SYSTEM32%"], existing_only=True)
        if not self._under_any(path, system_dirs) or path.suffix:
            return []
        # PE files start with "MZ"; anything else in System32 without an extension is
        # more likely a data file and not worth alarming the user over.
        try:
            with open(path, "rb") as handle:
                if handle.read(2) != b"MZ":
                    return []
        except OSError:
            return []
        severity = str(self.cfg.get("antivirus.heuristics.no_extension_in_system_dir.severity", Severity.LOW))
        return [
            Finding(
                rule="no_extension_in_system_dir",
                detail="Extension-less executable in a protected system directory",
                severity=Severity.normalize(severity, Severity.LOW),
            )
        ]

    def _large_file_in_startup(self, path: Path, stat: os.stat_result) -> list[Finding]:
        """A big blob sitting in a startup folder is usually a dropper."""
        if not bool(self.cfg.get("antivirus.heuristics.large_file_in_startup.enabled", True)):
            return []
        startup = self.cfg.resolve_paths(["%STARTUP%"], existing_only=True)
        if not self._under_any(path, startup):
            return []
        threshold_mb = float(self.cfg.get("antivirus.heuristics.large_file_in_startup.threshold_mb", 50))
        if stat.st_size < threshold_mb * 1024 * 1024:
            return []
        severity = str(self.cfg.get("antivirus.heuristics.large_file_in_startup.severity", Severity.MEDIUM))
        return [
            Finding(
                rule="large_file_in_startup",
                detail=f"Large file ({stat.st_size / (1024 * 1024):.0f} MB) in a startup folder",
                severity=Severity.normalize(severity, Severity.MEDIUM),
            )
        ]

    def _recently_modified_in_protected_dir(self, path: Path, stat: os.stat_result) -> list[Finding]:
        """Something changed inside a protected directory recently."""
        if not bool(
            self.cfg.get("antivirus.heuristics.recently_modified_in_protected_dir.enabled", True)
        ):
            return []
        protected = self.cfg.resolve_paths("antivirus.protected_paths", existing_only=True)
        if not self._under_any(path, protected):
            return []
        window_hours = float(self.cfg.get("antivirus.heuristics.recently_modified_in_protected_dir.window_hours", 24))
        age = max(0.0, time.time() - stat.st_mtime)
        if age > window_hours * 3600:
            return []
        severity = str(
            self.cfg.get("antivirus.heuristics.recently_modified_in_protected_dir.severity", Severity.LOW)
        )
        return [
            Finding(
                rule="recently_modified_in_protected_dir",
                detail=f"Modified {age / 3600:.1f}h ago in a protected directory",
                severity=Severity.normalize(severity, Severity.LOW),
            )
        ]

    def _high_entropy(self, path: Path, stat: os.stat_result) -> list[Finding]:
        """Packed/encrypted payload hiding inside an otherwise ordinary file."""
        if not bool(self.cfg.get("antivirus.heuristics.entropy.enabled", True)):
            return []
        min_kb = float(self.cfg.get("antivirus.heuristics.entropy.min_file_size_kb", 16))
        if stat.st_size < min_kb * 1024:
            return []
        from core.antivirus.hashing import file_entropy_stats

        stats = file_entropy_stats(
            path, int(self.cfg.get("antivirus.heuristics.entropy.sample_bytes", 262_144))
        )
        if stats is None:
            return []
        threshold = float(self.cfg.get("antivirus.heuristics.entropy.threshold", 7.2))
        if stats["entropy"] < threshold:
            return []
        severity = str(self.cfg.get("antivirus.heuristics.entropy.severity", Severity.MEDIUM))
        return [
            Finding(
                rule="high_entropy",
                detail=f"High entropy {stats['entropy']:.2f} bits/byte — packed or encrypted content",
                severity=Severity.normalize(severity, Severity.MEDIUM),
                extra=stats,
            )
        ]

    # ------------------------------------------------------------------ escalation
    def _escalate(self, path: Path, findings: list[Finding]) -> list[Finding]:
        """Several Low flags on one file add up to real suspicion.

        A single Low heuristic is noise (a script in %TEMP% might be a setup helper);
        three of them on the same file is a pattern worth Medium attention.
        """
        threshold = int(self.cfg.get("antivirus.heuristics.escalate_to_medium_after_flags", 2))
        if threshold <= 0 or len(findings) < threshold:
            return findings
        # Only escalate when nothing already reached Medium — never downgrade an existing
        # finding, or a double_extension High would be softened by company.
        if any(Severity.at_least(finding.severity, Severity.MEDIUM) for finding in findings):
            return findings
        findings.append(
            Finding(
                rule="multi_flag_escalation",
                detail=f"{len(findings)} heuristic flags fired together on {path.name}",
                severity=Severity.MEDIUM,
            )
        )
        return findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _under_any(path: Path, roots: list[Path]) -> bool:
        """True when ``path`` sits beneath one of ``roots`` (case-insensitive on Windows)."""
        try:
            resolved = path.resolve()
        except (OSError, ValueError):
            resolved = path
        for root in roots:
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False
