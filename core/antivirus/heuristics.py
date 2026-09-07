"""Static heuristic rules — the signature-free half of the antivirus engine.

Each rule takes a file and its stat info and returns a :class:`Finding` when it fires.
Rules are driven entirely by ``antivirus.heuristics`` in config.json, so they can be
tuned or switched off without touching code.

**Scoring model.** A single heuristic is a *lead*, not a verdict: "a .js file lives in
%TEMP%" describes half the dev ecosystem and must never be a Medium threat on its own.
Findings therefore carry **weights** (``score`` in config) and one file gets exactly one
verdict derived from the *sum* of the weights of everything that fired:

========  ========  ==================================================
Score     Verdict   Meaning
========  ========  ==================================================
0–19      CLEAN    nothing (or nothing worth mentioning) fired
20–39     LOW      mildly unusual — worth a log line, not attention
40–69     MEDIUM   a real pattern; warrants user-visible reporting
70–99     HIGH     strongly malicious behaviour
100+      (n/a)    signature territory — handled before heuristics
========  ========  ==================================================

Rule weights ship deliberately *low* so one indicator alone stays CLEAN/LOW and only
combinations escalate (e.g. script_in_user_dir 5 + double_extension 40 + high_entropy
10 = 55 → Medium). This replaces the earlier design where any single rule could report
Medium on its own, which flagged every Node helper script in %TEMP% and every packed
installer as "threats".
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

__all__ = ["Finding", "HeuristicEngine", "score_to_severity", "SCORE_THRESHOLDS"]

#: (minimum score, severity) pairs, ascending. The first threshold the sum *reaches*
#: becomes the file's verdict. Mirrors the ShieldEX detection-design table.
SCORE_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (40, Severity.MEDIUM),
    (70, Severity.HIGH),
)


def score_to_severity(score: int) -> str:
    """Map a summed rule score onto a severity verdict (below 40 → below Medium).

    Checked from the top down: the *highest* band the sum reaches is the verdict, so
    a score of 75 is High, not the Medium it would first match at 40.
    """
    for threshold, severity in reversed(SCORE_THRESHOLDS):
        if score >= threshold:
            return severity
    return Severity.LOW if score >= 20 else Severity.INFO


@dataclass
class Finding:
    """One heuristic that fired for one file."""

    rule: str
    detail: str
    score: int = 5
    #: Free-form context for the timeline detail panel.
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        """Convenience view of this single indicator's weight, for the timeline chip."""
        return score_to_severity(self.score)


def _ext(path: Path) -> str:
    return path.suffix.lower()


#: Suffixes whose content we treat as *executable*: packed/encrypted payload inside
#: these is suspicious. Everything else (documents, archives, media) legitimately has
#: high entropy, so scanning %APPDATA% would flag every installer and image it meets.
_EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".sys", ".com", ".scr", ".pif", ".cpl", ".msi", ".jar",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
}


def _is_executable_like(path: Path) -> bool:
    return path.suffix.lower() in _EXECUTABLE_SUFFIXES


class HeuristicEngine:
    """Evaluates the configured static heuristics against single files."""

    def __init__(self, config: Config) -> None:
        self.cfg = config
        #: Resolved watched/protected/system path sets, cached for the engine's
        #: lifetime. ``Config.resolve_paths`` hits the filesystem (token expansion,
        #: existence checks) and used to run *per scanned file*, costing ~0.6 ms
        #: each — several seconds across a quick scan.
        self._watched_cache: list[Path] | None = None
        self._protected_cache: list[Path] | None = None
        self._system_cache: list[Path] | None = None
        self._startup_cache: list[Path] | None = None

    def _cached_paths(self, key: str, cache_attr: str) -> list[Path]:
        """Resolve (once) and cache a configured path list."""
        cached = getattr(self, cache_attr)
        if cached is None:
            cached = self.cfg.resolve_paths(key, existing_only=True)
            setattr(self, cache_attr, cached)
        return cached

    # ------------------------------------------------------------------ public API
    def examine(self, path: Path, stat: os.stat_result | None = None) -> list[Finding]:
        """Run every enabled heuristic against ``path``. Never raises.

        Returns the individual findings — the *verdict* is the caller's, derived from
        :meth:`total_score` (or simply by summing the findings' scores).
        """
        findings: list[Finding] = []
        if not bool(self.cfg.get("antivirus.heuristics.enabled", True)):
            return findings

        try:
            stat = stat or path.stat()
        except (OSError, ValueError):
            return findings  # vanished or unreadable; the scanner already logged it

        # Resolved once here because several rules need it and Path.resolve() is a
        # realpath syscall — resolving per rule cost three syscalls per scanned file.
        try:
            resolved = path.resolve()
        except (OSError, ValueError):
            resolved = path

        for rule in (
            self._double_extension,
            self._script_in_user_dirs,
            self._no_extension_in_system_dir,
            self._large_file_in_startup,
            self._recently_modified_in_protected_dir,
            self._high_entropy,
        ):
            try:
                findings.extend(rule(path, stat, resolved) or [])
            except Exception as exc:  # a broken rule must never abort a scan
                logger.error("Heuristic rule %s failed on %s: %s", rule.__name__, path, exc)

        return findings

    @staticmethod
    def total_score(findings: list[Finding]) -> int:
        """The one number a file's verdict comes from."""
        return sum(finding.score for finding in findings)

    # ------------------------------------------------------------------ rules
    def _rule_score(self, rule_key: str, default: int) -> int:
        """A rule's configured weight, clamped to 0–100."""
        try:
            score = int(self.cfg.get(f"antivirus.heuristics.{rule_key}.score", default))
        except (TypeError, ValueError):
            return default
        return max(0, min(100, score))

    def _double_extension(self, path: Path, stat: os.stat_result, resolved: Path) -> list[Finding]:
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
        return [
            Finding(
                rule="double_extension",
                detail=f"Double extension: {path.name} poses as a {inner} document",
                score=self._rule_score("double_extension", 40),
                extra={"outer": outer, "inner": inner},
            )
        ]

    def _script_in_user_dirs(self, path: Path, stat: os.stat_result, resolved: Path) -> list[Finding]:
        """Script files loose in user-writable locations.

        Worth 5 points on its own — the classic persistence *lead*, but half of %TEMP%'s
        population on a developer machine, so never a verdict by itself.
        """
        if not bool(self.cfg.get("antivirus.heuristics.script_in_user_dirs.enabled", True)):
            return []
        watched = self._cached_paths(
            "antivirus.realtime_monitor.watched_paths", "_watched_cache"
        )
        if not watched or not self._under_any(resolved, watched):
            return []
        extensions = [
            ext.lower()
            for ext in self.cfg.get("antivirus.heuristics.script_in_user_dirs.extensions", [])
        ]
        if _ext(path) not in extensions:
            return []
        return [
            Finding(
                rule="script_in_user_dir",
                detail=f"Script file ({_ext(path)}) in a user-writable location",
                score=self._rule_score("script_in_user_dirs", 5),
            )
        ]

    def _no_extension_in_system_dir(self, path: Path, stat: os.stat_result, resolved: Path) -> list[Finding]:
        """Extension-less executables hiding in System32-style directories."""
        if not bool(self.cfg.get("antivirus.heuristics.no_extension_in_system_dir.enabled", True)):
            return []
        system_dirs = self._cached_paths(["%SYSTEM32%"], "_system_cache")
        if not self._under_any(resolved, system_dirs) or path.suffix:
            return []
        # PE files start with "MZ"; anything else in System32 without an extension is
        # more likely a data file and not worth alarming the user over.
        try:
            with open(path, "rb") as handle:
                if handle.read(2) != b"MZ":
                    return []
        except OSError:
            return []
        return [
            Finding(
                rule="no_extension_in_system_dir",
                detail="Extension-less executable in a protected system directory",
                score=self._rule_score("no_extension_in_system_dir", 20),
            )
        ]

    def _large_file_in_startup(self, path: Path, stat: os.stat_result, resolved: Path) -> list[Finding]:
        """A big blob sitting in a startup folder is usually a dropper."""
        if not bool(self.cfg.get("antivirus.heuristics.large_file_in_startup.enabled", True)):
            return []
        startup = self._cached_paths(["%STARTUP%"], "_startup_cache")
        if not self._under_any(resolved, startup):
            return []
        threshold_mb = float(self.cfg.get("antivirus.heuristics.large_file_in_startup.threshold_mb", 50))
        if stat.st_size < threshold_mb * 1024 * 1024:
            return []
        return [
            Finding(
                rule="large_file_in_startup",
                detail=f"Large file ({stat.st_size / (1024 * 1024):.0f} MB) in a startup folder",
                score=self._rule_score("large_file_in_startup", 35),
            )
        ]

    def _recently_modified_in_protected_dir(self, path: Path, stat: os.stat_result, resolved: Path) -> list[Finding]:
        """Something changed inside a protected directory recently.

        Restricted to executable/script-suffixed files: %APPDATA% and %STARTUP% are
        written to constantly by ordinary applications (caches, profiles, state files),
        so without the gate the rule fires on every one of them and loses all meaning.
        """
        if not bool(
            self.cfg.get("antivirus.heuristics.recently_modified_in_protected_dir.enabled", True)
        ):
            return []
        if not _is_executable_like(path):
            return []
        protected = self._cached_paths("antivirus.protected_paths", "_protected_cache")
        if not self._under_any(resolved, protected):
            return []
        window_hours = float(self.cfg.get("antivirus.heuristics.recently_modified_in_protected_dir.window_hours", 24))
        age = max(0.0, time.time() - stat.st_mtime)
        if age > window_hours * 3600:
            return []
        return [
            Finding(
                rule="recently_modified_in_protected_dir",
                detail=f"Modified {age / 3600:.1f}h ago in a protected directory",
                score=self._rule_score("recently_modified_in_protected_dir", 10),
            )
        ]

    def _high_entropy(self, path: Path, stat: os.stat_result, resolved: Path) -> list[Finding]:
        """Packed/encrypted payload hiding inside an otherwise ordinary executable.

        Only applies to executable/script-suffixed files (see :data:`_EXECUTABLE_SUFFIXES`):
        archives, images and installers are legitimately high-entropy, so without that
        gate every downloaded .zip in %DOWNLOADS% would be flagged. Even then it is only
        worth 10 points — most signed installers compress their payload, so entropy
        alone must not condemn them.
        """
        if not bool(self.cfg.get("antivirus.heuristics.entropy.enabled", True)):
            return []
        if not _is_executable_like(path):
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
        return [
            Finding(
                rule="high_entropy",
                detail=f"High entropy {stats['entropy']:.2f} bits/byte — packed or encrypted content",
                score=self._rule_score("entropy", 10),
                extra=stats,
            )
        ]

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _under_any(resolved: Path, roots: list[Path]) -> bool:
        """True when ``resolved`` (already canonical) sits beneath one of ``roots``.

        ``Path.resolve()`` is a realpath syscall; it is the *caller's* job to resolve
        once per file (``examine`` does) — this used to resolve per rule, three
        syscalls per scanned file.
        """
        for root in roots:
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False
