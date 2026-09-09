"""Scheduled scans — the antivirus runs itself on a timetable.

Real protection cannot depend on the user remembering to click "Scan": the scheduler
runs a configured scan type once a day at a configured local time, in a background
thread, logging the result to the timeline like any other scan (the scanner already
writes SCAN_STARTED/COMPLETED rows, so scheduled runs show up in Scan History with
no special casing).

Design notes:

* Uses the ``schedule`` library's daily jobs rather than a hand-rolled clock loop —
  one less place for off-by-one and DST bugs to hide.
* The job runs on the scheduler thread itself (the scanner is blocking by design),
  guarded by a run lock so a still-running scan is never overlapped by the next
  day's trigger — it is skipped with a timeline note instead.
* A missed window (app was closed at scan time) is simply skipped, never
  back-filled: waking up to ten queued catch-up scans is how schedulers annoy
  people into disabling them.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["ScanScheduler"]


class ScanScheduler:
    """Runs a configured scan type daily at a configured local time."""

    def __init__(
        self,
        config: Config,
        db: Database,
        timeline: TimelineLogger,
        scanner: Any,
    ) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.scanner = scanner

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()
        self._running_scan = False

    # ------------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Start the scheduler thread. True when running now."""
        if self.running:
            return True
        if not bool(self.cfg.get("antivirus.scheduled_scans.enabled", False)):
            logger.info("Scheduled scans disabled by configuration")
            return False
        if self.scanner is None:
            logger.warning("Scheduled scans unavailable: no scanner engine")
            return False
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._schedule_loop, name="shieldex-scheduler", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop the scheduler thread (immediate — sleeps on the Event)."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        self._thread = None

    # ------------------------------------------------------------------ schedule
    def _schedule_loop(self) -> None:
        """Register the daily job and tick the schedule library until stopped."""
        try:
            import schedule
        except ImportError:
            logger.warning("Scheduled scans unavailable: 'schedule' package not installed")
            return

        scan_time = str(self.cfg.get("antivirus.scheduled_scans.time", "02:00"))
        if not self._valid_time(scan_time):
            logger.warning("Invalid scheduled scan time %r; using 02:00", scan_time)
            scan_time = "02:00"

        schedule.clear("shieldex-scan")
        schedule.every().day.at(scan_time).do(self._run_job).tag("shieldex-scan")
        logger.info("Scheduled %s scan daily at %s", self._scan_type(), scan_time)

        while not self._stop_event.wait(30):
            try:
                schedule.run_pending()
            except Exception:
                logger.exception("Scheduled scan tick failed")

    @staticmethod
    def _valid_time(value: str) -> bool:
        try:
            hours, minutes = value.split(":")
            return 0 <= int(hours) <= 23 and 0 <= int(minutes) <= 59
        except (ValueError, AttributeError):
            return False

    def _scan_type(self) -> str:
        scan_type = str(self.cfg.get("antivirus.scheduled_scans.scan_type", "quick"))
        return scan_type if scan_type in ("quick", "full") else "quick"

    def next_run_info(self) -> str:
        """Human-readable next-run description for the Settings view."""
        if not bool(self.cfg.get("antivirus.scheduled_scans.enabled", False)):
            return "disabled"
        scan_time = str(self.cfg.get("antivirus.scheduled_scans.time", "02:00"))
        state = "armed" if self.running else "configured (starts on launch)"
        return f"{self._scan_type()} scan daily at {scan_time} — {state}"

    # ------------------------------------------------------------------ the job
    def run_now(self) -> bool:
        """Trigger the configured scan immediately (Settings "Run now" + tests).

        Returns False when a scan is already running — overlapping two full sweeps
        would double disk I/O and interleave two scan_history rows' narratives.
        """
        if not self._run_lock.acquire(blocking=False):
            logger.info("Scheduled scan skipped: another scan is already running")
            return False
        try:
            return self._run_job()
        finally:
            self._run_lock.release()

    def _run_job(self) -> bool:
        """Execute one scheduled scan. True when it ran (not skipped)."""
        if self._running_scan:
            self.timeline.log_antivirus(
                EventType.SCAN_FAILED,
                "Scheduled scan skipped: previous scheduled scan still running",
                Severity.LOW,
            )
            return False
        self._running_scan = True
        try:
            scan_type = self._scan_type()
            self.timeline.log_antivirus(
                EventType.SCAN_STARTED,
                f"Scheduled {scan_type} scan started",
                Severity.INFO,
            )
            result = self.scanner.run(scan_type)
            self.db.set_setting("scheduled_scan_last_run", result.status)
            return result.status == "COMPLETED"
        except Exception as exc:
            logger.exception("Scheduled scan failed")
            self.timeline.log_antivirus(
                EventType.SCAN_FAILED, f"Scheduled scan failed: {exc}", Severity.MEDIUM
            )
            return False
        finally:
            self._running_scan = False
