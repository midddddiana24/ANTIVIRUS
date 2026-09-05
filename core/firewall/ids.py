"""Intrusion detection — pattern detectors over the observed connection stream.

The detectors are intentionally simple statistical rules over short time windows:

* **port scan**: one remote host probing ≥ N distinct local ports within the window;
* **auth failures**: repeated connections to SSH (22) or RDP (3389);
* **syn flood / icmp flood**: packet-rate thresholds fed by the optional
  :class:`~core.firewall.packet_inspector.PacketInspector`.

Each detector has its own cooldown per (ip, type), so a scanning host that trips the
alert every window does not flood the timeline with one alert per packet — the
dashboard would then count a single scan as hundreds of intrusions.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable

from core.config import Config
from core.database import Database
from core.firewall.ip_blocklist import IPBlocklist
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["IDSDetector"]


class IDSDetector:
    """Stateful detectors over the connection/packet stream."""

    def __init__(
        self,
        config: Config,
        db: Database,
        timeline: TimelineLogger,
        blocklist: IPBlocklist | None = None,
        rule_engine: Any | None = None,
    ) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.blocklist = blocklist
        self.rule_engine = rule_engine

        self._lock = threading.Lock()
        self._ports_by_ip: dict[str, set[int]] = defaultdict(set)
        self._port_seen_at: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._auth_failures: dict[str, deque[float]] = defaultdict(deque)
        self._syn_counts: dict[str, deque[float]] = defaultdict(deque)
        self._icmp_counts: dict[str, deque[float]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], float] = {}
        self.alert_handlers: list[Callable[[str, str, str], None]] = []

    # ------------------------------------------------------------------ public API
    def observe_connection(
        self, remote_ip: str, local_port: int | None = None, remote_port: int | None = None
    ) -> list[str]:
        """Feed one observed connection through the detectors. Returns alert type(s)."""
        if not bool(self.cfg.get("firewall.ids.enabled", True)):
            return []
        alerts: list[str] = []
        now = time.monotonic()

        watched_port = remote_port if remote_port is not None else local_port
        if watched_port is not None:
            with self._lock:
                self._ports_by_ip[remote_ip].add(int(watched_port))
                self._port_seen_at[remote_ip].append((now, int(watched_port)))
                self._prune(self._port_seen_at[remote_ip], now)

                if self._port_scan_alert_ready(remote_ip, now):
                    alerts.append(EventType.IDS_PORT_SCAN)

                auth_ports = [int(p) for p in self.cfg.get("firewall.ids.auth_failures.watch_ports", [22, 3389])]
                if watched_port in auth_ports:
                    self._auth_failures[remote_ip].append(now)
                    self._prune(self._auth_failures[remote_ip], now)
                    if self._auth_failure_alert_ready(remote_ip):
                        alerts.append(EventType.IDS_AUTH_FAILURES)
                else:
                    self._auth_failures[remote_ip].clear()

        for alert in alerts:
            self._raise(alert, remote_ip)
        self._maybe_auto_block(remote_ip, alerts)
        return alerts

    def observe_syn(self, remote_ip: str) -> list[str]:
        """Feed one SYN packet (from the packet inspector)."""
        if not bool(self.cfg.get("firewall.ids.enabled", True)):
            return []
        alerts: list[str] = []
        now = time.monotonic()
        with self._lock:
            self._syn_counts[remote_ip].append(now)
            self._prune(self._syn_counts[remote_ip], now)
            if self._syn_flood_alert_ready(remote_ip, now):
                alerts.append(EventType.IDS_SYN_FLOOD)
        for alert in alerts:
            self._raise(alert, remote_ip)
        self._maybe_auto_block(remote_ip, alerts)
        return alerts

    def observe_icmp(self, remote_ip: str) -> list[str]:
        """Feed one ICMP echo request (from the packet inspector)."""
        if not bool(self.cfg.get("firewall.ids.enabled", True)):
            return []
        alerts: list[str] = []
        now = time.monotonic()
        with self._lock:
            self._icmp_counts[remote_ip].append(now)
            self._prune(self._icmp_counts[remote_ip], now)
            if self._icmp_flood_alert_ready(remote_ip, now):
                alerts.append(EventType.IDS_ICMP_FLOOD)
        for alert in alerts:
            self._raise(alert, remote_ip)
        self._maybe_auto_block(remote_ip, alerts)
        return alerts

    def stop(self) -> None:
        """Engine-registry symmetry: no thread of its own, just drop handlers."""
        self.alert_handlers.clear()

    # ------------------------------------------------------------------ detectors
    def _port_scan_alert_ready(self, remote_ip: str, now: float) -> bool:
        if not bool(self.cfg.get("firewall.ids.port_scan.enabled", True)):
            return False
        window = float(self.cfg.get("firewall.ids.port_scan.window_seconds", 10))
        distinct = len({
            port for seen_at, port in self._port_seen_at[remote_ip] if now - seen_at <= window
        })
        threshold = int(self.cfg.get("firewall.ids.port_scan.distinct_ports", 15))
        return distinct >= threshold

    def _auth_failure_alert_ready(self, remote_ip: str) -> bool:
        if not bool(self.cfg.get("firewall.ids.auth_failures.enabled", True)):
            return False
        attempts = int(self.cfg.get("firewall.ids.auth_failures.attempts", 5))
        return len(self._auth_failures[remote_ip]) >= attempts

    def _syn_flood_alert_ready(self, remote_ip: str, now: float) -> bool:
        if not bool(self.cfg.get("firewall.ids.syn_flood.enabled", True)):
            return False
        window = float(self.cfg.get("firewall.ids.syn_flood.window_seconds", 5))
        packets = int(self.cfg.get("firewall.ids.syn_flood.syn_packets", 200))
        recent = sum(1 for seen_at in self._syn_counts[remote_ip] if now - seen_at <= window)
        return recent >= packets

    def _icmp_flood_alert_ready(self, remote_ip: str, now: float) -> bool:
        if not bool(self.cfg.get("firewall.ids.icmp_flood.enabled", True)):
            return False
        window = float(self.cfg.get("firewall.ids.icmp_flood.window_seconds", 5))
        packets = int(self.cfg.get("firewall.ids.icmp_flood.packets", 100))
        recent = sum(1 for seen_at in self._icmp_counts[remote_ip] if now - seen_at <= window)
        return recent >= packets

    # ------------------------------------------------------------------ alerting
    def _raise(self, alert_type: str, remote_ip: str) -> None:
        """Log an IDS alert (after cooldown) and notify the GUI handlers."""
        now = time.monotonic()
        with self._lock:
            last = self._last_alert.get((remote_ip, alert_type), 0.0)
            if now - last < 60.0:  # cooldown keeps one incident from becoming hundreds
                return
            self._last_alert[(remote_ip, alert_type)] = now

        severity = self._severity_for(alert_type)
        detail = {
            EventType.IDS_PORT_SCAN: f"Port scan detected from {remote_ip}",
            EventType.IDS_SYN_FLOOD: f"SYN flood pattern from {remote_ip}",
            EventType.IDS_AUTH_FAILURES: f"Repeated auth failures from {remote_ip}",
            EventType.IDS_ICMP_FLOOD: f"ICMP flood from {remote_ip}",
        }.get(alert_type, f"Intrusion pattern ({alert_type}) from {remote_ip}")
        self.timeline.ids_alert(alert_type, remote_ip, detail, severity)

        for handler in list(self.alert_handlers):
            try:
                handler(alert_type, remote_ip, severity)
            except Exception:
                logger.exception("IDS alert handler failed")

    def _maybe_auto_block(self, remote_ip: str, alerts: list[str]) -> None:
        """Add the source to the blocklist (and OS rule) when configured to."""
        if not alerts:
            return
        if not bool(self.cfg.get("firewall.ids.auto_block_source", False)):
            return
        if self.blocklist is not None:
            self.blocklist.block(remote_ip, label="IDS auto-block", source="ids")
        if self.rule_engine is not None:
            try:
                self.rule_engine.block_ip(remote_ip, label="IDS auto-block")
            except Exception:
                logger.exception("Auto-block OS rule failed for %s", remote_ip)

    def _severity_for(self, alert_type: str) -> str:
        mapping = {
            EventType.IDS_PORT_SCAN: "firewall.ids.port_scan.severity",
            EventType.IDS_SYN_FLOOD: "firewall.ids.syn_flood.severity",
            EventType.IDS_AUTH_FAILURES: "firewall.ids.auth_failures.severity",
            EventType.IDS_ICMP_FLOOD: "firewall.ids.icmp_flood.severity",
        }
        key = mapping.get(alert_type)
        if key is None:
            return Severity.HIGH
        return Severity.normalize(str(self.cfg.get(key, Severity.HIGH)), Severity.HIGH)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _prune(queue: deque, now: float, keep_seconds: float = 120.0) -> None:
        """Drop entries older than the longest configured window (state stays bounded)."""
        while queue and now - (queue[0][0] if isinstance(queue[0], tuple) else queue[0]) > keep_seconds:
            queue.popleft()
