"""Real-time protection — a watchdog observer over the configured watched paths.

The monitor deliberately reacts to created and modified events only. Deletions are
logged by the timeline only via scan narratives; there is nothing to analyse in a file
that no longer exists, and reacting to them would make the monitor (and the IDS, which
it feeds with ``observe_connection``) chatty without evidence value.

Every filesystem event is debounced (``debounce_seconds``) and then handed to
:meth:`Scanner.scan_single`, which runs the full hash → match → classify pipeline on
it. A single worker thread drains the debounce queue, so analysis is serialised
against the database's write lock and a burst of downloads cannot outrun it.
"""

from __future__ import annotations

import logging
import threading
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from core.antivirus.quarantine import QuarantineManager
from core.antivirus.scanner import Scanner
from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

try:  # optional dependency: the monitor is one of the few modules that needs it
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # keep the module importable for tests and --no-gui fallbacks
    FileSystemEventHandler = object
    Observer = None

__all__ = ["RealTimeMonitor"]


class RealTimeMonitor:
    """Starts and stops the watchdog-based real-time protection."""

    def __init__(
        self,
        config: Config,
        db: Database,
        timeline: TimelineLogger,
        scanner: Scanner,
        quarantine: QuarantineManager,
    ) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.scanner = scanner
        self.quarantine = quarantine

        self._observer: Any | None = None
        self._lock = threading.Lock()
        self._running = False
        self._pending: dict[str, float] = {}  # path → last-seen timestamp
        self._pending_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()

        self._watched = config.resolve_paths(
            "antivirus.realtime_monitor.watched_paths", existing_only=True, directories_only=True
        )
        self._recursive = bool(config.get("antivirus.realtime_monitor.recursive", True))
        self._debounce = float(config.get("antivirus.realtime_monitor.debounce_seconds", 1.5))
        self._ignore_patterns = [
            str(pattern)
            for pattern in config.get("antivirus.realtime_monitor.ignore_patterns", [])
        ]

    # ------------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> bool:
        """Start observing. Returns True when the monitor is now running."""
        if self._running:
            return True
        if not self._watched:
            logger.warning("Real-time monitor: no existing watched paths; not starting")
            return False

        if Observer is None:
            logger.warning("Real-time monitor unavailable: watchdog is not installed")
            return False

        handler = _MonitorHandler(self)
        observer = Observer(timeout=1)
        for watch_root in self._watched:
            observer.schedule(handler, str(watch_root), recursive=self._recursive)
        try:
            observer.start()
        except Exception as exc:
            logger.error("Could not start the real-time observer: %s", exc)
            self.timeline.log_antivirus(
                EventType.MONITOR_STOPPED, f"Real-time observer failed to start: {exc}", Severity.MEDIUM
            )
            return False

        with self._lock:
            self._observer = observer
            self._running = True
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._process_loop, name="shieldex-rt-monitor", daemon=True
        )
        self._worker.start()

        self.db.set_bool_setting("realtime_monitoring_enabled", True)
        self.timeline.log_antivirus(
            EventType.MONITOR_STARTED,
            f"Real-time protection active over {len(self._watched)} location(s)",
            Severity.INFO,
        )
        return True

    def stop(self) -> None:
        """Stop observing and record the state change."""
        with self._lock:
            observer = self._observer
            self._observer = None
            self._running = False
        self._stop_event.set()
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception as exc:
                logger.debug("Observer shutdown noise: %s", exc)
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=5)
        self._worker = None

        self.db.set_bool_setting("realtime_monitoring_enabled", False)
        self.timeline.log_antivirus(
            EventType.MONITOR_STOPPED, "Real-time protection stopped", Severity.INFO
        )

    # ------------------------------------------------------------------ event intake
    def on_fs_event(self, path_str: str) -> None:
        """Record a filesystem event's timestamp for debouncing (called from watchdog threads)."""
        with self._pending_lock:
            self._pending[path_str] = time.monotonic()

    def _process_loop(self) -> None:
        """Debounce loop: wait, then hand matured paths to the scanner."""
        while not self._stop_event.is_set():
            with self._pending_lock:
                matured = [
                    path
                    for path, seen_at in self._pending.items()
                    if time.monotonic() - seen_at >= self._debounce
                ]
                for path in matured:
                    self._pending.pop(path, None)
            for path_str in matured:
                if self._stop_event.is_set():
                    break
                self._analyze(Path(path_str))
            self._stop_event.wait(0.25)

    def _analyze(self, path: Path) -> None:
        """Run the pipeline on one file; guarded because watchdog threads rely on it."""
        try:
            if self.cfg.is_excluded(path):
                return
            if not path.exists() or path.is_dir():
                return
            if any(fnmatch(path.name, pattern) for pattern in self._ignore_patterns):
                return
            self.scanner.scan_single(path, origin="realtime")
        except Exception:
            logger.exception("Real-time analysis of %s failed", path)

    # ------------------------------------------------------------------ info
    def watched_paths(self) -> list[Path]:
        """The locations under real-time protection, for the settings view."""
        return list(self._watched)

    def status(self) -> dict[str, Any]:
        """Runtime snapshot for the dashboard/settings."""
        with self._pending_lock:
            pending = len(self._pending)
        return {
            "running": self._running,
            "watched": [str(path) for path in self._watched],
            "pending": pending,
            "recursive": self._recursive,
            "debounce_seconds": self._debounce,
        }


class _MonitorHandler(FileSystemEventHandler):
    """Watchdog handler that funnels created/modified files into the monitor."""

    def __init__(self, monitor: "RealTimeMonitor") -> None:
        self.monitor = monitor

    def on_any_event(self, event: Any) -> None:
        if event.is_directory:
            return
        if event.event_type not in ("created", "modified"):
            return
        path_str = getattr(event, "src_path", None)
        if not path_str:
            return
        self.monitor.on_fs_event(str(path_str))
