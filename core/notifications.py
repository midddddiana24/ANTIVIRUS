"""Desktop notifications — the user-facing end of the timeline.

Subscribes to the timeline and turns qualifying events into desktop toasts via
``plyer``. Two details keep it safe:

* **Recursion guard**: the notifier writes NOTIFICATION_SENT events to the timeline
  (so "we told the user" is auditable). It must never react to its own events — with a
  ``min_severity`` of Info that would be an infinite notification loop, because every
  "notification sent" event meets the bar for sending the next one.
* **No blocking**: ``plyer`` is guarded and every send is best-effort; a notification
  backend that hangs must not hold up the thread that logged the event (usually the
  scanner or the connection monitor mid-scan).
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["Notifier"]

try:  # optional dependency: notifications degrade to log lines without plyer
    import plyer
except ImportError:
    plyer = None


class Notifier:
    """Timeline subscriber that raises desktop notifications for severe events."""

    def __init__(self, config: Config, db: Database, timeline: TimelineLogger) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline

        self._enabled = bool(config.get("notifications.enabled", True))
        self._min_severity = str(config.get("notifications.min_severity", Severity.MEDIUM))
        self._app_name = str(config.get("notifications.app_name", "ShieldEX"))
        self._timeout = int(config.get("notifications.timeout_seconds", 8))
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ wiring
    def attach(self) -> None:
        """Subscribe to the timeline (idempotent)."""
        self.timeline.subscribe(self.on_event)

    def detach(self) -> None:
        self.timeline.unsubscribe(self.on_event)

    def stop(self) -> None:
        """Engine-registry symmetry: detach and disable."""
        self._enabled = False
        self.detach()

    # ------------------------------------------------------------------ events
    def on_event(self, event: dict[str, Any]) -> None:
        """Timeline subscriber: notify when the event is severe enough."""
        if not self._enabled:
            return
        if event.get("event_type") == EventType.NOTIFICATION_SENT:
            return  # recursion guard: never react to our own audit entries
        severity = str(event.get("severity", Severity.INFO))
        if not Severity.at_least(severity, self._min_severity):
            return

        title, message = self._compose(event)
        if message is None:
            return
        self._send(title, message)

    def _compose(self, event: dict[str, Any]) -> tuple[str, str | None]:
        """Human-readable (title, message) for one timeline event."""
        source = str(event.get("source", "SYSTEM"))
        event_type = str(event.get("event_type", ""))
        detail = str(event.get("event_detail", "")) or event_type
        subject = event.get("file_path") or event.get("remote_ip") or ""

        title = f"{self._app_name}: {self._label(source, event_type)}"
        message = detail
        if subject:
            message = f"{detail}\n{subject}"
        return title, message

    @staticmethod
    def _label(source: str, event_type: str) -> str:
        if source == "ANTIVIRUS" and event_type.startswith("IDS_"):
            return "Intrusion detected"
        if event_type == EventType.MATCH_FOUND:
            return "Threat detected"
        if event_type == EventType.QUARANTINE_ACTION:
            return "Threat quarantined"
        if event_type == EventType.IDS_PORT_SCAN:
            return "Port scan detected"
        if event_type == EventType.SIGNATURE_DB_UPDATED:
            return "Signature database"
        return "Security event"

    # ------------------------------------------------------------------ delivery
    def _send(self, title: str, message: str) -> None:
        """Deliver one toast; never raises and never blocks the emitting thread."""
        if plyer is None:
            logger.info("[notification] %s — %s", title, message.splitlines()[0])
            return
        try:
            plyer.notification.notify(
                title=title,
                message=message,
                app_name=self._app_name,
                timeout=self._timeout,
            )
            self.timeline.notification_sent("SYSTEM", f"{title}: {message.splitlines()[0]}")
        except Exception as exc:
            logger.debug("Notification delivery failed: %s", exc)
