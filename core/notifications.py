"""Desktop notifications — plyer-based alerts for high-severity events.

Subscribes to the timeline and turns qualifying events into desktop notifications
(Windows toast / POSIX notify), honouring ``notifications.*`` from config.json. The
engine is deliberately tolerant: plyer can be missing or the desktop bus absent
(headless CI, services session), in which case notifications degrade to log lines —
never exceptions into the timeline's emit path.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from core.config import Config
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["NotificationEngine"]

try:  # optional dependency, like watchdog and scapy
    from plyer import notification as _plyer_notification
except ImportError:  # pragma: no cover - depends on the environment
    _plyer_notification = None


class NotificationEngine:
    """Sends a desktop notification for timeline events at or above the threshold."""

    def __init__(self, config: Config, timeline: TimelineLogger) -> None:
        self.cfg = config
        self.timeline = timeline
        self.enabled = bool(config.get("notifications.enabled", True))
        self.app_name = str(config.get("notifications.app_name", "ShieldEX"))
        self.timeout = int(config.get("notifications.timeout_seconds", 8))
        self.min_severity = Severity.normalize(
            str(config.get("notifications.min_severity", Severity.MEDIUM))
        )
        self._lock = threading.Lock()
        self._recent: list[str] = []  # de-dup guard for bursts
        self._recent_max = 50

        if _plyer_notification is None:
            logger.info("Desktop notifications unavailable: plyer is not installed")
        timeline.subscribe(self._on_event)

    # ------------------------------------------------------------------ lifecycle
    @property
    def available(self) -> bool:
        """True when notifications can actually be delivered."""
        return _plyer_notification is not None

    def stop(self) -> None:
        """Engine-registry symmetry: drop the subscription."""
        try:
            self.timeline.unsubscribe(self._on_event)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Unsubscribe failed: %s", exc)

    # ------------------------------------------------------------------ events
    def _on_event(self, event: dict[str, Any]) -> None:
        """Timeline subscriber (runs on the emitting thread)."""
        if not self.enabled or _plyer_notification is None:
            return
        if not Severity.at_least(str(event.get("severity") or Severity.INFO), self.min_severity):
            return

        event_type = str(event.get("event_type") or "")
        if event_type in (EventType.NOTIFICATION_SENT, EventType.SCAN_PROGRESS):
            return  # procedural noise must not notify

        # One notification per subject+type per burst: a scan hitting 20 packed
        # detections would otherwise fire 20 toasts within a second.
        dedup_key = f"{event_type}:{event.get('file_path') or event.get('remote_ip') or ''}"
        with self._lock:
            if dedup_key in self._recent:
                return
            self._recent.append(dedup_key)
            if len(self._recent) > self._recent_max:
                self._recent = self._recent[-self._recent_max // 2 :]

        title = f"{self.app_name}: {event_type.replace('_', ' ').title()}"
        detail = str(event.get("event_detail") or "")
        subject = str(event.get("file_path") or event.get("remote_ip") or "")
        message = f"{detail} — {subject}" if subject and subject not in detail else detail

        # plyer's notify can block on the desktop bus; the timeline's emit path must
        # never wait on it, so delivery happens on a short-lived daemon thread.
        threading.Thread(
            target=self._deliver, args=(title, message), daemon=True,
            name="shieldex-notify",
        ).start()

    def _deliver(self, title: str, message: str) -> None:
        """Deliver one notification; any failure is logged, never raised."""
        try:
            _plyer_notification.notify(  # type: ignore[misc]
                title=title[:60],
                message=message[:220],
                app_name=self.app_name,
                timeout=self.timeout,
            )
            # Best-effort audit line: a closed database (shutdown racing the notify
            # thread) is logged, not raised into the timeline's emit path.
            try:
                self.timeline.notification_sent(self.app_name, f"{title}: {message}")
            except Exception:
                logger.debug("Could not record notification in the timeline (shutting down?)")
        except Exception as exc:
            logger.warning("Desktop notification failed: %s", exc)
