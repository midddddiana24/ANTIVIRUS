"""Threat Behavior Timeline — the shared incident log for both ShieldEX engines.

Every meaningful step taken by the antivirus and the firewall is written here as a
timestamped event, so an incident reads as a narrative ("file appeared → hashed →
matched → quarantined → user notified") instead of a single "threat found" line.

Design notes
------------
* :class:`Severity`, :class:`Source` and :class:`EventType` are the single source of
  truth for those strings. Using the constants (not literals) keeps filters, dashboard
  counters and exports consistent — a typo'd ``"Critcal"`` would silently vanish from
  every severity filter.
* Event types prefixed ``IDS_`` are what the dashboard counts as intrusion alerts.
* GUI views subscribe with :meth:`TimelineLogger.subscribe`. Subscribers are invoked on
  the **emitting** thread, which is usually a background worker, so a Tk subscriber must
  hand the event to the UI thread (ShieldEX does this with a queue drained by ``after``).
"""

from __future__ import annotations

import csv
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from core.database import Database, TIMESTAMP_FORMAT, now_str

logger = logging.getLogger(__name__)

TimelineSubscriber = Callable[[dict[str, Any]], None]


class Severity:
    """Threat severity levels and ordering helpers."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    INFO = "Info"  # procedural steps that are not themselves a threat

    ORDER: tuple[str, ...] = (INFO, LOW, MEDIUM, HIGH, CRITICAL)

    @classmethod
    def normalize(cls, value: str | None, default: str = "Info") -> str:
        """Map any casing/whitespace variant onto a canonical level."""
        if not value:
            return default
        candidate = str(value).strip().lower()
        for level in cls.ORDER:
            if level.lower() == candidate:
                return level
        logger.warning("Unknown severity %r; treating as %s", value, default)
        return default

    @classmethod
    def rank(cls, value: str | None) -> int:
        """Numeric rank of a severity (higher is worse)."""
        return cls.ORDER.index(cls.normalize(value))

    @classmethod
    def at_least(cls, value: str | None, minimum: str) -> bool:
        """True when ``value`` is as severe as ``minimum`` or worse."""
        return cls.rank(value) >= cls.rank(minimum)

    @classmethod
    def levels_at_least(cls, minimum: str) -> tuple[str, ...]:
        """All levels from ``minimum`` upwards — handy for SQL ``IN`` filters."""
        return cls.ORDER[cls.rank(minimum):]


class Source:
    """Which engine produced an event."""

    ANTIVIRUS = "ANTIVIRUS"
    FIREWALL = "FIREWALL"
    SYSTEM = "SYSTEM"


class EventType:
    """Canonical event type strings."""

    # ---- antivirus ----
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_PROGRESS = "SCAN_PROGRESS"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    FILE_DETECTED = "FILE_DETECTED"
    HASH_GENERATED = "HASH_GENERATED"
    SIGNATURE_CHECK = "SIGNATURE_CHECK"
    MATCH_FOUND = "MATCH_FOUND"
    NO_MATCH = "NO_MATCH"
    HEURISTIC_FLAG = "HEURISTIC_FLAG"
    THREAT_CLASSIFIED = "THREAT_CLASSIFIED"
    QUARANTINE_ACTION = "QUARANTINE_ACTION"
    QUARANTINE_RESTORED = "QUARANTINE_RESTORED"
    THREAT_REMOVED = "THREAT_REMOVED"
    MONITOR_STARTED = "MONITOR_STARTED"
    MONITOR_STOPPED = "MONITOR_STOPPED"
    SIGNATURE_DB_UPDATED = "SIGNATURE_DB_UPDATED"

    # ---- firewall ----
    CONNECTION_ATTEMPT = "CONNECTION_ATTEMPT"
    RULE_CHECK = "RULE_CHECK"
    IP_REPUTATION = "IP_REPUTATION"
    RULE_MATCHED = "RULE_MATCHED"
    CONNECTION_BLOCKED = "CONNECTION_BLOCKED"
    CONNECTION_ALLOWED = "CONNECTION_ALLOWED"
    RULE_CREATED = "RULE_CREATED"
    RULE_MODIFIED = "RULE_MODIFIED"
    RULE_DELETED = "RULE_DELETED"
    RULE_APPLIED = "RULE_APPLIED"
    RULE_DRY_RUN = "RULE_DRY_RUN"
    PROFILE_CHANGED = "PROFILE_CHANGED"
    FIREWALL_ENABLED = "FIREWALL_ENABLED"
    FIREWALL_DISABLED = "FIREWALL_DISABLED"
    IP_BLOCKED = "IP_BLOCKED"
    IP_UNBLOCKED = "IP_UNBLOCKED"
    APP_PROMPT = "APP_PROMPT"

    # ---- intrusion detection (the IDS_ prefix drives the dashboard alert counter) ----
    IDS_PORT_SCAN = "IDS_PORT_SCAN"
    IDS_SYN_FLOOD = "IDS_SYN_FLOOD"
    IDS_AUTH_FAILURES = "IDS_AUTH_FAILURES"
    IDS_ICMP_FLOOD = "IDS_ICMP_FLOOD"
    IDS_PREFIX = "IDS_"

    # ---- shared ----
    NOTIFICATION_SENT = "NOTIFICATION_SENT"
    ENGINE_ERROR = "ENGINE_ERROR"
    APP_STARTED = "APP_STARTED"
    APP_STOPPED = "APP_STOPPED"
    PRIVILEGE_STATE = "PRIVILEGE_STATE"


#: Column order used by both CSV and TXT exports.
EXPORT_COLUMNS: tuple[str, ...] = (
    "timestamp", "source", "event_type", "severity", "file_path", "remote_ip", "event_detail",
)


class TimelineLogger:
    """Writes and reads Threat Behavior Timeline events."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._subscribers: list[TimelineSubscriber] = []
        self._subscriber_lock = threading.Lock()

    # ------------------------------------------------------------------ subscribers
    def subscribe(self, callback: TimelineSubscriber) -> None:
        """Register a callback invoked with each new event (on the emitting thread)."""
        with self._subscriber_lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: TimelineSubscriber) -> None:
        """Remove a previously registered callback."""
        with self._subscriber_lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _notify_subscribers(self, event: dict[str, Any]) -> None:
        with self._subscriber_lock:
            listeners = list(self._subscribers)
        for callback in listeners:
            try:
                callback(event)
            except Exception as exc:  # never let a listener break event logging
                logger.error("Timeline subscriber %r failed: %s", callback, exc, exc_info=True)

    # ------------------------------------------------------------------ writing
    def log(
        self,
        source: str,
        event_type: str,
        detail: str = "",
        severity: str | None = None,
        file_path: str | Path | None = None,
        remote_ip: str | None = None,
    ) -> dict[str, Any]:
        """Persist one event and return it as a dict (including its new ``id``).

        Never raises: a failed timeline write is logged and reported through the returned
        event's ``id`` being ``-1``, because losing an audit line must not abort a scan or
        a firewall action mid-flight.
        """
        normalized_severity = Severity.normalize(severity)
        path_text = str(file_path) if file_path is not None else None
        timestamp = now_str()

        event_id = self.db.add_timeline_event(
            source=source,
            event_type=event_type,
            event_detail=detail,
            severity=normalized_severity,
            file_path=path_text,
            remote_ip=remote_ip,
            timestamp=timestamp,
        )

        event: dict[str, Any] = {
            "id": event_id,
            "source": source.upper(),
            "event_type": event_type,
            "event_detail": detail,
            "severity": normalized_severity,
            "file_path": path_text,
            "remote_ip": remote_ip,
            "timestamp": timestamp,
        }

        if Severity.at_least(normalized_severity, Severity.HIGH):
            logger.warning("[%s] %s — %s", source.upper(), event_type, detail)
        else:
            logger.info("[%s] %s — %s", source.upper(), event_type, detail)

        self._notify_subscribers(event)
        return event

    def log_antivirus(
        self,
        event_type: str,
        detail: str = "",
        severity: str | None = None,
        file_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Log an antivirus event."""
        return self.log(Source.ANTIVIRUS, event_type, detail, severity, file_path=file_path)

    def log_firewall(
        self,
        event_type: str,
        detail: str = "",
        severity: str | None = None,
        remote_ip: str | None = None,
    ) -> dict[str, Any]:
        """Log a firewall event."""
        return self.log(Source.FIREWALL, event_type, detail, severity, remote_ip=remote_ip)

    def log_system(
        self, event_type: str, detail: str = "", severity: str | None = None
    ) -> dict[str, Any]:
        """Log an application-level event (startup, shutdown, privilege state)."""
        return self.log(Source.SYSTEM, event_type, detail, severity)

    def log_sequence(
        self,
        source: str,
        steps: Iterable[tuple[str, str]],
        severity: str | None = None,
        file_path: str | Path | None = None,
        remote_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """Log an ordered ``(event_type, detail)`` sequence sharing one subject.

        Used by the scanner and the packet inspector to emit a whole detection narrative
        in one call while keeping every step its own queryable row.
        """
        return [
            self.log(source, event_type, detail, severity, file_path=file_path, remote_ip=remote_ip)
            for event_type, detail in steps
        ]

    # ------------------- named antivirus steps (the AV narrative) -------------------
    def file_detected(self, path: str | Path, origin: str = "scan") -> dict[str, Any]:
        """A file entered the pipeline (from a scan or the real-time monitor)."""
        return self.log_antivirus(
            EventType.FILE_DETECTED,
            f"File queued for analysis via {origin}: {Path(path).name}",
            Severity.INFO,
            path,
        )

    def hash_generated(self, path: str | Path, sha256: str) -> dict[str, Any]:
        """SHA-256 computed for a file."""
        return self.log_antivirus(
            EventType.HASH_GENERATED, f"SHA-256: {sha256}", Severity.INFO, path
        )

    def signature_check(self, path: str | Path, signature_count: int) -> dict[str, Any]:
        """Signature comparison started."""
        return self.log_antivirus(
            EventType.SIGNATURE_CHECK,
            f"Checking against malware database ({signature_count} signatures)...",
            Severity.INFO,
            path,
        )

    def match_found(self, path: str | Path, threat_name: str, severity: str) -> dict[str, Any]:
        """A known malware hash matched."""
        return self.log_antivirus(
            EventType.MATCH_FOUND, f'Known malware: "{threat_name}"', severity, path
        )

    def no_match(self, path: str | Path) -> dict[str, Any]:
        """No signature matched."""
        return self.log_antivirus(
            EventType.NO_MATCH, "No signature match", Severity.INFO, path
        )

    def heuristic_flag(self, path: str | Path, rule: str, severity: str) -> dict[str, Any]:
        """A heuristic rule fired."""
        return self.log_antivirus(
            EventType.HEURISTIC_FLAG, f"Heuristic triggered: {rule}", severity, path
        )

    def threat_classified(self, path: str | Path, severity: str) -> dict[str, Any]:
        """Final severity decided for a detection."""
        return self.log_antivirus(
            EventType.THREAT_CLASSIFIED, f"Severity: {severity.upper()}", severity, path
        )

    def quarantine_action(
        self, path: str | Path, quarantine_path: str | Path, severity: str
    ) -> dict[str, Any]:
        """A file was moved into the quarantine vault."""
        return self.log_antivirus(
            EventType.QUARANTINE_ACTION,
            f"File moved to {Path(quarantine_path).parent.name}/",
            severity,
            path,
        )

    # ------------------- named firewall steps (the FW narrative) -------------------
    def connection_attempt(
        self, process: str, remote_ip: str, remote_port: int | str, protocol: str = "TCP"
    ) -> dict[str, Any]:
        """An outbound/inbound connection was observed."""
        return self.log_firewall(
            EventType.CONNECTION_ATTEMPT,
            f"{process} → {remote_ip}:{remote_port} ({protocol})",
            Severity.INFO,
            remote_ip,
        )

    def rule_check(self, remote_ip: str, rule_count: int) -> dict[str, Any]:
        """Rule evaluation started for a connection."""
        return self.log_firewall(
            EventType.RULE_CHECK,
            f"Checking against {rule_count} firewall rule(s)...",
            Severity.INFO,
            remote_ip,
        )

    def ip_reputation(self, remote_ip: str, verdict: str, severity: str) -> dict[str, Any]:
        """Reputation verdict for a remote address."""
        return self.log_firewall(EventType.IP_REPUTATION, verdict, severity, remote_ip)

    def rule_matched(self, remote_ip: str, rule_name: str, action: str) -> dict[str, Any]:
        """A stored rule matched a connection."""
        return self.log_firewall(
            EventType.RULE_MATCHED,
            f'{action.title()} rule: "{rule_name}"',
            Severity.INFO,
            remote_ip,
        )

    def connection_blocked(
        self, remote_ip: str, direction: str, severity: str = Severity.MEDIUM
    ) -> dict[str, Any]:
        """A connection was denied."""
        return self.log_firewall(
            EventType.CONNECTION_BLOCKED,
            f"{direction.title()} connection denied",
            severity,
            remote_ip,
        )

    def ids_alert(
        self, event_type: str, remote_ip: str, detail: str, severity: str = Severity.HIGH
    ) -> dict[str, Any]:
        """An intrusion-detection rule fired.

        ``event_type`` must be one of the ``IDS_*`` constants so the dashboard counts it.
        """
        if not event_type.startswith(EventType.IDS_PREFIX):
            logger.warning(
                "IDS event type %r lacks the %s prefix and will not be counted as an alert",
                event_type, EventType.IDS_PREFIX,
            )
        return self.log_firewall(event_type, detail, severity, remote_ip)

    def notification_sent(self, source: str, detail: str) -> dict[str, Any]:
        """A desktop notification was delivered to the user."""
        return self.log(source, EventType.NOTIFICATION_SENT, detail, Severity.INFO)

    # ------------------------------------------------------------------ reading
    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """Newest events, for the dashboard activity feed."""
        return self.db.get_recent_timeline(limit)

    def query(
        self,
        source: str | None = None,
        min_severity: str | None = None,
        severities: Sequence[str] | str | None = None,  # CHANGED: a bare level is accepted
        event_type: str | None = None,
        event_type_prefix: str | None = None,
        search: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Filtered event query.

        ``min_severity`` is expanded into the explicit list of levels at or above it, so
        severity ordering lives here rather than being duplicated in SQL.
        ``event_type_prefix`` filters on an escaped LIKE prefix (e.g. ``"IDS_"``) and is
        what the IDS Alerts view uses, mirroring the dashboard's alert counter.
        """
        if severities is None and min_severity:
            severities = Severity.levels_at_least(min_severity)
        return self.db.get_timeline_events(
            source=source,
            severities=severities,
            event_type=event_type,
            event_type_prefix=event_type_prefix,
            search=search,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            offset=offset,
        )

    def counts_today(self) -> dict[str, int]:
        """Today's event counts, split by engine and by alert class."""
        return {
            "total": self.db.count_timeline_events(today=True),
            "antivirus": self.db.count_timeline_events(source=Source.ANTIVIRUS, today=True),
            "firewall": self.db.count_timeline_events(source=Source.FIREWALL, today=True),
            "ids_alerts": self.db.count_timeline_events(
                source=Source.FIREWALL, event_type_prefix=EventType.IDS_PREFIX, today=True
            ),
            "high_or_worse": self.db.count_timeline_events(
                severities=Severity.levels_at_least(Severity.HIGH), today=True
            ),
        }

    @staticmethod
    def date_range(days: int) -> tuple[str, str]:
        """``(from, to)`` timestamps covering the last ``days`` days, inclusive of today."""
        end = datetime.now()
        start = (end - timedelta(days=max(0, days - 1))).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return start.strftime(TIMESTAMP_FORMAT), end.strftime(TIMESTAMP_FORMAT)

    # ------------------------------------------------------------------ export
    def export(
        self,
        destination: str | Path,
        events: Sequence[dict[str, Any]] | None = None,
        fmt: str = "csv",
        **filters: Any,
    ) -> int:
        """Write events to ``destination`` as ``csv`` or ``txt``; returns rows written.

        Pass ``events`` to export exactly what the user is looking at, or pass query
        filters to re-run the query. Raises :class:`OSError` on write failure so the GUI
        can surface a real error dialog.
        """
        rows = list(events) if events is not None else self.query(limit=100_000, **filters)
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "csv":
            with target.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=EXPORT_COLUMNS, extrasaction="ignore"
                )
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: row.get(key, "") for key in EXPORT_COLUMNS})
        else:
            with target.open("w", encoding="utf-8") as handle:
                handle.write(f"ShieldEX Threat Behavior Timeline — exported {now_str()}\n")
                handle.write("=" * 96 + "\n")
                for row in rows:
                    subject = row.get("file_path") or row.get("remote_ip") or "-"
                    handle.write(
                        f"{row.get('timestamp','')}  "
                        f"[{str(row.get('source','')):9}] "
                        f"{str(row.get('event_type','')):22} "
                        f"{str(row.get('severity','')):8} "
                        f"{row.get('event_detail','')}\n"
                        f"{'':22}subject: {subject}\n"
                    )
                handle.write(f"\n{len(rows)} event(s)\n")

        logger.info("Exported %d timeline event(s) to %s", len(rows), target)
        return len(rows)
