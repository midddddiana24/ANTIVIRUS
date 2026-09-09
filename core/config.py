"""Configuration loading, validation and cross-platform path resolution for ShieldEX.

This module owns three concerns:

1. Loading ``config.json`` and deep-merging it over :data:`DEFAULT_CONFIG` so that a
   partial or older config file still yields a complete, valid configuration.
2. Dotted-key access (``config.get("firewall.ids.port_scan.distinct_ports")``) so no
   other module needs to know the nesting layout.
3. Resolving symbolic path tokens (``%TEMP%``, ``%STARTUP%``, ``%BROWSER_CACHE%`` ...)
   into real :class:`pathlib.Path` objects for the current operating system.

Nothing here touches the database or the GUI.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import platform
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterable, Sequence

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "config.json"


def _path_key(path: Path | str) -> str:
    """Return a comparison key for de-duplicating paths on the current platform.

    ``os.path.normpath`` collapses redundant separators and drops a trailing one (while
    preserving the root), and ``os.path.normcase`` case-folds *only* on Windows. Doing
    this by hand — ``str(path).rstrip("\\\\/").lower()`` — is wrong twice on POSIX, where
    ``/srv/Data`` and ``/srv/data`` are different directories and a backslash is a legal
    character in a filename, so ``/tmp/back\\\\slash`` would silently lose its last
    character and stop matching the real path.
    """
    return os.path.normcase(os.path.normpath(str(path)))

# --------------------------------------------------------------------------------------
# Defaults. config.json is regenerated from this structure when missing, and any key
# absent from an existing config.json is filled in from here on load.
# --------------------------------------------------------------------------------------
DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "name": "ShieldEX",
        "version": "0.1.0",
        "require_admin": True,
        "theme": "dark",
        "accent_color": "#2f6fb0",
        "start_view": "dashboard",
        "window": {"width": 1320, "height": 840, "min_width": 1080, "min_height": 680},
    },
    "logging": {
        "level": "INFO",
        "file": "logs/shieldex.log",
        "max_bytes": 2_097_152,
        "backup_count": 5,
        "console": True,
    },
    "database": {"path": "shieldex.db", "busy_timeout_ms": 10_000},
    "antivirus": {
        "quick_scan_paths": [
            "%TEMP%",
            "%APPDATA%",
            "%LOCALAPPDATA%",
            "%DOWNLOADS%",
            "%STARTUP%",
            "%BROWSER_CACHE%",
        ],
        "protected_paths": ["%STARTUP%", "%SYSTEM32%", "%APPDATA%"],
        "excluded_paths": ["%QUARANTINE%"],
        "max_file_size_mb": 512,
        "quick_scan_max_depth": 2,
        "hash_chunk_size": 65_536,
        "follow_symlinks": False,
        "auto_quarantine_on_signature_match": True,
        "heuristics": {
            "enabled": True,
            "double_extension": {
                "enabled": True,
                "score": 40,
                "inner_extensions": [
                    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".jpg", ".jpeg",
                    ".png", ".gif", ".txt", ".zip", ".rar", ".mp3", ".mp4",
                ],
                "outer_extensions": [
                    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
                    ".js", ".jse", ".jar", ".ps1", ".msi", ".lnk", ".hta",
                ],
            },
            "script_in_user_dirs": {
                "enabled": True,
                "score": 5,
                "extensions": [
                    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
                ],
            },
            "no_extension_in_system_dir": {"enabled": True, "score": 20},
            "large_file_in_startup": {"enabled": True, "score": 35, "threshold_mb": 50},
            "recently_modified_in_protected_dir": {
                "enabled": True,
                "score": 10,
                "window_hours": 24,
            },
            "entropy": {
                "enabled": True,
                "score": 10,
                "threshold": 7.2,
                "sample_bytes": 262_144,
                "min_file_size_kb": 16,
            },
        },
        "realtime_monitor": {
            "enabled": False,
            "watched_paths": ["%TEMP%", "%APPDATA%", "%DOWNLOADS%", "%STARTUP%"],
            "recursive": True,
            "debounce_seconds": 1.5,
            "ignore_patterns": ["*.tmp", "*.part", "*.crdownload", "~$*", "*.quar"],
        },
        "scheduled_scans": {
            "enabled": False,
            "scan_type": "quick",
            "time": "02:00",
        },
        "quarantine": {
            "path": ".quarantine",
            "extension": ".quar",
            "confirm_before_delete": True,
        },
    },
    "updater": {
        "enabled": True,
        "check_on_startup": True,
        "feed_url": "",
        "extra_feeds": ["https://bazaar.abuse.ch/export/csv/recent/"],
        "timeout_seconds": 30,
        "check_interval_hours": 24,
        "verify_tls": True,
    },
    "firewall": {
        "enforce_rules": False,
        "backend": "auto",
        "profiles": {"domain": True, "private": True, "public": True},
        "connection_monitor": {
            "enabled": True,
            "poll_interval_seconds": 2,
            "log_allowed_connections": False,
            "resolve_country": False,
            "geolocation_url": "http://ip-api.com/json/{ip}?fields=countryCode,country",
        },
        "packet_inspector": {"enabled": False, "interface": None, "bpf_filter": "ip"},
        "ids": {
            "enabled": True,
            "auto_block_source": False,
            "port_scan": {
                "enabled": True,
                "distinct_ports": 15,
                "window_seconds": 10,
                "severity": "High",
            },
            "syn_flood": {
                "enabled": True,
                "syn_packets": 200,
                "window_seconds": 5,
                "severity": "High",
            },
            "auth_failures": {
                "enabled": True,
                "watch_ports": [22, 3389],
                "attempts": 5,
                "window_seconds": 60,
                "severity": "High",
            },
            "icmp_flood": {
                "enabled": True,
                "packets": 100,
                "window_seconds": 5,
                "severity": "Medium",
            },
        },
        "blocklist_feeds": {"enabled": False, "urls": []},
        "reconnect_alert_threshold": 3,
    },
    "notifications": {
        "enabled": True,
        "app_name": "ShieldEX",
        "timeout_seconds": 8,
        "min_severity": "Medium",
        "first_time_app_prompt": True,
    },
    "ui": {
        "timeline_page_size": 200,
        "recent_activity_count": 10,
        "dashboard_refresh_seconds": 5,
    },
    "retention": {
        "timeline_days": 90,
        "connection_log_days": 30,
        "purge_on_startup": True,
    },
    "policies": {
        "threat_response": {
            "Critical": True,
            "High": True,
            "Medium": False,
            "Low": False,
        },
        "ids_auto_block": False,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Recursively merge ``override`` onto a copy of ``base``.

    Returns the merged mapping and a flag that is ``True`` when ``base`` contributed a
    key that ``override`` did not have (meaning the on-disk config is missing defaults
    and should be rewritten).
    """
    merged = copy.deepcopy(base)
    added_from_base = False

    for key, base_value in base.items():
        if key not in override:
            added_from_base = True

    for key, value in override.items():
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(value, dict):
            merged[key], child_added = _deep_merge(base_value, value)
            added_from_base = added_from_base or child_added
        else:
            merged[key] = value

    return merged, added_from_base


def _home() -> Path:
    return Path.home()


def _windows_token_paths(token: str, app_root: Path) -> list[Path]:
    """Resolve a token on Windows."""
    appdata = os.environ.get("APPDATA", str(_home() / "AppData" / "Roaming"))
    local = os.environ.get("LOCALAPPDATA", str(_home() / "AppData" / "Local"))
    system_root = os.environ.get("SystemRoot", "C:\\Windows")

    mapping: dict[str, list[Path]] = {
        "%TEMP%": [Path(tempfile.gettempdir())],
        "%APPDATA%": [Path(appdata)],
        "%LOCALAPPDATA%": [Path(local)],
        "%USERPROFILE%": [_home()],
        "%DOWNLOADS%": [_home() / "Downloads"],
        "%DESKTOP%": [_home() / "Desktop"],
        "%DOCUMENTS%": [_home() / "Documents"],
        "%STARTUP%": [
            Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("ProgramData", "C:\\ProgramData"))
            / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
        ],
        "%SYSTEM32%": [Path(system_root) / "System32"],
        "%BROWSER_CACHE%": [
            Path(local) / "Google" / "Chrome" / "User Data" / "Default" / "Cache",
            Path(local) / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache",
            Path(local) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cache",
            Path(local) / "Mozilla" / "Firefox" / "Profiles",
        ],
        "%QUARANTINE%": [app_root / ".quarantine"],
        "%APP_ROOT%": [app_root],
    }
    return mapping.get(token.upper(), [])


def _posix_token_paths(token: str, app_root: Path) -> list[Path]:
    """Resolve a token on Linux/macOS, keeping the same symbolic names as Windows."""
    home = _home()
    mapping: dict[str, list[Path]] = {
        "%TEMP%": [Path(tempfile.gettempdir())],
        "%APPDATA%": [Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))],
        "%LOCALAPPDATA%": [Path(os.environ.get("XDG_DATA_HOME", str(home / ".local" / "share")))],
        "%USERPROFILE%": [home],
        "%DOWNLOADS%": [home / "Downloads"],
        "%DESKTOP%": [home / "Desktop"],
        "%DOCUMENTS%": [home / "Documents"],
        "%STARTUP%": [home / ".config" / "autostart"],
        "%SYSTEM32%": [Path("/usr/bin"), Path("/usr/local/bin")],
        "%BROWSER_CACHE%": [
            home / ".cache" / "google-chrome" / "Default" / "Cache",
            home / ".cache" / "chromium" / "Default" / "Cache",
            home / ".cache" / "mozilla" / "firefox",
        ],
        "%QUARANTINE%": [app_root / ".quarantine"],
        "%APP_ROOT%": [app_root],
    }
    return mapping.get(token.upper(), [])


def resolve_token(token: str, app_root: Path) -> list[Path]:
    """Expand a single path token or literal path into zero or more concrete paths.

    A token is any ``%NAME%`` string listed in the platform maps above. Anything else is
    treated as a literal path and passed through ``expandvars``/``expanduser``, so
    ``"D:/Projects"`` or ``"~/scan-me"`` work as-is.
    """
    token = token.strip()
    if not token:
        return []

    if token.startswith("%") and token.endswith("%") and len(token) > 2:
        if platform.system() == "Windows":
            paths = _windows_token_paths(token, app_root)
        else:
            paths = _posix_token_paths(token, app_root)
        if not paths:
            logger.warning("Unknown path token in configuration: %s", token)
        return paths

    expanded = os.path.expandvars(os.path.expanduser(token))
    return [Path(expanded)]


class Config:
    """In-memory view of ``config.json`` with dotted access and path resolution."""

    def __init__(self, path: Path, data: dict[str, Any], app_root: Path) -> None:
        self.path = path
        self.app_root = app_root
        self._data = data
        # CHANGED: is_excluded() is on the scan hot path — once per file — and used to
        # re-resolve every exclusion root on every call. The resolved roots are cached
        # against the config values they were derived from, so editing
        # antivirus.excluded_paths (or the quarantine path) still takes effect immediately
        # without any explicit invalidation call.
        self._exclusion_lock = threading.Lock()
        self._exclusion_cache_key: tuple[tuple[str, ...], str] | None = None
        self._exclusion_roots: tuple[Path, ...] = ()

    # ---------------------------------------------------------------- construction
    @classmethod
    def load(cls, path: Path | str | None = None, app_root: Path | str | None = None) -> "Config":
        """Load configuration, creating or topping-up ``config.json`` as needed."""
        root = Path(app_root).resolve() if app_root else Path(__file__).resolve().parent.parent
        cfg_path = Path(path) if path else root / CONFIG_FILENAME

        if cfg_path.exists():
            try:
                raw = json.loads(cfg_path.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    raise ValueError("config root must be a JSON object")
                data, needs_rewrite = _deep_merge(DEFAULT_CONFIG, raw)
                if needs_rewrite:
                    logger.info("Config file was missing keys; filling in defaults")
            except (OSError, ValueError) as exc:
                logger.error("Could not read %s (%s); falling back to defaults", cfg_path, exc)
                data, needs_rewrite = copy.deepcopy(DEFAULT_CONFIG), False
        else:
            logger.info("No config file at %s; writing defaults", cfg_path)
            data, needs_rewrite = copy.deepcopy(DEFAULT_CONFIG), True

        config = cls(cfg_path, data, root)
        if needs_rewrite:
            config.save()
        return config

    # ---------------------------------------------------------------- dotted access
    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Return ``config["a"]["b"]`` for ``get("a.b")``, or ``default`` if absent."""
        node: Any = self._data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted_key: str, value: Any) -> None:
        """Assign a value at a dotted key, creating intermediate dicts as required."""
        parts = dotted_key.split(".")
        node = self._data
        for part in parts[:-1]:
            existing = node.get(part)
            if not isinstance(existing, dict):
                existing = {}
                node[part] = existing
            node = existing
        node[parts[-1]] = value

    def as_dict(self) -> dict[str, Any]:
        """Return a deep copy of the whole configuration."""
        return copy.deepcopy(self._data)

    def save(self) -> bool:
        """Write the configuration back to disk atomically. Returns success."""
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(self._data, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.path)
            logger.debug("Configuration saved to %s", self.path)
            return True
        except OSError as exc:
            logger.error("Failed to save configuration to %s: %s", self.path, exc)
            try:
                tmp.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                # CHANGED: logged rather than swallowed. A leftover config.json.tmp is
                # harmless on its own, but it is evidence of *why* the save failed (a
                # read-only directory, a lock held by a sync client), and silently
                # discarding that turns a diagnosable problem into a mystery.
                logger.debug("Could not remove temporary file %s: %s", tmp, cleanup_exc)
            return False

    def reset_to_defaults(self) -> None:
        """Replace the in-memory config with the shipped defaults (does not save)."""
        self._data = copy.deepcopy(DEFAULT_CONFIG)

    # ---------------------------------------------------------------- paths
    def app_path(self, relative: str) -> Path:
        """Resolve a config value that names a file relative to the project root."""
        candidate = Path(os.path.expandvars(os.path.expanduser(relative)))
        return candidate if candidate.is_absolute() else self.app_root / candidate

    @property
    def database_path(self) -> Path:
        """Absolute path of the unified SQLite database."""
        return self.app_path(str(self.get("database.path", "shieldex.db")))

    @property
    def log_path(self) -> Path:
        """Absolute path of the rotating application log."""
        return self.app_path(str(self.get("logging.file", "logs/shieldex.log")))

    @property
    def quarantine_path(self) -> Path:
        """Absolute path of the quarantine vault."""
        return self.app_path(str(self.get("antivirus.quarantine.path", ".quarantine")))

    def resolve_paths(
        self,
        tokens: str | Sequence[str],
        existing_only: bool = True,
        directories_only: bool = False,
    ) -> list[Path]:
        """Resolve a dotted config key (or an explicit token list) to real paths.

        ``tokens`` may be a dotted config key whose value is a list of tokens, or the
        list of tokens itself. Results are de-duplicated while preserving order.
        """
        raw: Iterable[str]
        if isinstance(tokens, str):
            value = self.get(tokens, [])
            raw = value if isinstance(value, (list, tuple)) else [str(value)]
        else:
            raw = tokens

        resolved: list[Path] = []
        seen: set[str] = set()
        for token in raw:
            if not isinstance(token, str):
                logger.warning("Ignoring non-string path entry: %r", token)
                continue
            for candidate in resolve_token(token, self.app_root):
                # CHANGED: platform-aware key, see _path_key.
                key = _path_key(candidate)
                if key in seen:
                    continue
                seen.add(key)
                if existing_only and not candidate.exists():
                    continue
                if directories_only and not candidate.is_dir():
                    continue
                resolved.append(candidate)
        return resolved

    def exclusion_roots(self) -> tuple[Path, ...]:
        """Resolved, de-duplicated exclusion roots — including the quarantine vault.

        Cached against the raw config values it was built from, because :meth:`is_excluded`
        runs once per scanned file and ``Path.resolve()`` is several syscalls each. The
        cache key is the token list plus the quarantine path, so an edit through
        :meth:`set` or a :meth:`reset_to_defaults` is picked up on the next call with no
        explicit invalidation.

        Two details are load-bearing:

        * the key is read *inside* the lock. Reading it outside and recomputing inside
          leaves a window where one thread stores another thread's freshly-resolved roots
          under its own stale key — after which the roots and the key disagree until the
          config changes again, which is a silent hole in the scan (and the cache is
          exactly what the lock was supposed to make safe);
        * the result is only cached when every root existed and resolved cleanly. A root
          resolved while it was missing gets its tail appended verbatim, so if it is later
          created as a symlink, a junction or under an 8.3 short name the canonical path of
          a file inside it no longer starts with the cached root, and the exclusion quietly
          stops matching. A transient ``OSError`` (offline share, revoked permission) would
          likewise be frozen in. Both cases simply skip the cache and re-resolve next call.
        """
        with self._exclusion_lock:
            raw = self.get("antivirus.excluded_paths", [])
            tokens = (
                tuple(str(token) for token in raw)
                if isinstance(raw, (list, tuple))
                else (str(raw),)
            )
            quarantine = self.quarantine_path
            cache_key = (tokens, str(quarantine))
            if self._exclusion_cache_key == cache_key:
                return self._exclusion_roots

            roots: list[Path] = []
            seen: set[str] = set()
            cacheable = True
            candidates = self.resolve_paths("antivirus.excluded_paths", existing_only=False)
            candidates.append(quarantine)  # non-negotiable, see is_excluded
            for candidate in candidates:
                try:
                    resolved = candidate.resolve()
                    if not resolved.exists():
                        cacheable = False  # canonical form may change once it is created
                except (OSError, ValueError) as exc:
                    # ValueError covers an embedded NUL; OSError a dead share or denied ACL.
                    logger.debug("Could not resolve exclusion path %s: %s", candidate, exc)
                    resolved = candidate
                    cacheable = False
                key = _path_key(resolved)
                if key in seen:
                    continue
                seen.add(key)
                roots.append(resolved)

            result = tuple(roots)
            if cacheable:
                self._exclusion_roots = result
                self._exclusion_cache_key = cache_key
            else:
                self._exclusion_roots = ()
                self._exclusion_cache_key = None
            return result

    def is_excluded(self, target: Path) -> bool:
        """True when ``target`` sits inside any exclusion path.

        The quarantine vault is always excluded, whatever ``antivirus.excluded_paths``
        says. Without that guarantee a user who overwrites the exclusion list turns the
        vault into a scan target: quarantined ``.quar`` files get re-detected, re-hashed
        and re-quarantined inside themselves, and a restore is immediately undone by the
        real-time monitor. Config should not be able to express that state.
        """
        try:
            target_resolved = target.resolve()
        except (OSError, ValueError):  # ValueError: embedded NUL in the path
            target_resolved = target
        for root in self.exclusion_roots():  # CHANGED: cached, was re-resolved per call
            try:
                target_resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Config path={self.path} root={self.app_root}>"
