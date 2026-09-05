"""Connection monitor — polls live sockets and feeds the rule engine and IDS.

psutil's ``net_connections`` is the transport, which shapes the design:

* the process name behind a socket is often unavailable (gone already, or the poller
  lacks rights), so every field is optional and the monitor never assumes it;
* polling returns the *whole* socket table, so dedup happens here — a long-lived TLS
  connection would otherwise be re-logged (and re-fed to the IDS) every two seconds,
  and any counter downstream would be meaningless. Identity is the
  (pid, laddr, raddr, state) tuple; NEWLY_SEEN sockets are the interesting ones;
* the dedup cache grows with traffic, so it is pruned of dead sockets each cycle and
  fully rebuilt when it exceeds a safety cap.

The verdict for each new connection goes to the timeline; the row's ``action`` column
records what the engine decided (allow/block/monitor) so the connections view can show
intent, not just existence.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from core.config import Config
from core.database import Database
from core.firewall.ids import IDSDetector
from core.firewall.rule_engine import RuleEngine
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["ConnectionMonitor"]

#: Hard cap on the dedup cache; a leaky cache would eventually pin real memory.
MAX_CACHE = 20_000


class ConnectionMonitor:
    """Background poller producing logged, deduplicated connection events."""

    def __init__(
        self,
        config: Config,
        db: Database,
        timeline: TimelineLogger,
        rule_engine: RuleEngine,
        ids: IDSDetector,
    ) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.rule_engine = rule_engine
        self.ids = ids

        self._seen: set[tuple[Any, ...]] = set()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._interval = max(0.5, float(config.get("firewall.connection_monitor.poll_interval_seconds", 2)))
        self._log_allowed = bool(config.get("firewall.connection_monitor.log_allowed_connections", False))

    # ------------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Start the poller thread. True when running now."""
        if self.running:
            return True
        if not bool(self.cfg.get("firewall.connection_monitor.enabled", True)):
            logger.info("Connection monitor disabled by configuration")
            return False
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name="shieldex-conn-monitor", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop the poller thread (immediate — the loop sleeps on the Event)."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        self._thread = None

    # ------------------------------------------------------------------ polling
    def _poll_loop(self) -> None:
        """Poll forever; each iteration must survive on its own."""
        while not self._stop_event.wait(self._interval):
            try:
                self.poll_once()
            except Exception:
                logger.exception("Connection poll cycle failed")

    def poll_once(self) -> int:
        """One poll cycle. Returns the number of newly-seen connections processed.

        Public because the IDS test drives it directly with a stable socket table.
        """
        import psutil

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            logger.debug("Could not enumerate connections: %s", exc)
            return 0

        fresh = 0
        alive: set[tuple[Any, ...]] = set()
        for conn in connections:
            if conn.type not in (1, 2):  # SOCK_STREAM, SOCK_DGRAM
                continue
            identity = (
                conn.pid,
                str(conn.laddr),
                str(conn.raddr),
                conn.status,
            )
            alive.add(identity)
            with self._lock:
                if identity in self._seen:
                    continue
                self._seen.add(identity)
            if len(self._seen) > MAX_CACHE:
                with self._lock:
                    self._seen.clear()  # rebuild from this cycle; duplicates re-log once
            fresh += 1
            self._handle(conn)

        with self._lock:
            self._seen &= alive  # forget sockets that disappeared
        return fresh

    # ------------------------------------------------------------------ per-connection
    def _handle(self, conn: Any) -> None:
        """Evaluate, log and IDS-feed one new connection."""
        raddr = getattr(conn, "raddr", None)
        if not raddr or not getattr(raddr, "ip", None):
            return  # listening sockets and connectionless entries carry no remote side

        remote_ip = str(raddr.ip)
        remote_port = int(getattr(raddr, "port", 0) or 0)
        laddr = getattr(conn, "laddr", None)
        local_port = int(getattr(laddr, "port", 0) or 0) if laddr else None
        direction = "inbound" if conn.status == "NONE" and conn.type == 2 else "outbound"
        pid = getattr(conn, "pid", None)
        process_name = self._process_name(pid)

        verdict = self.rule_engine.evaluate(
            remote_ip,
            process_name=process_name,
            remote_port=remote_port or None,
            protocol="TCP" if conn.type == 1 else "UDP",
            direction=direction,
        )

        action = verdict.action
        self.db.log_connection(
            process=process_name or "",
            pid=pid or 0,
            protocol="TCP" if conn.type == 1 else "UDP",
            local_ip=str(getattr(laddr, "ip", "") or "") if laddr else "",
            local_port=local_port or 0,
            remote_ip=remote_ip,
            remote_port=remote_port or 0,
            direction=direction,
            action=action,
            rule_matched=verdict.rule_name,
        )

        if verdict.blocked:
            self.timeline.connection_blocked(remote_ip, direction)
        elif self._log_allowed:
            self.timeline.connection_attempt(
                process_name or f"pid {pid}", remote_ip, remote_port, "TCP" if conn.type == 1 else "UDP"
            )

        self.ids.observe_connection(remote_ip, local_port=local_port, remote_port=remote_port)

    @staticmethod
    def _process_name(pid: int | None) -> str:
        """Best-effort process name for a pid; empty when unavailable."""
        if not pid:
            return ""
        try:
            import psutil

            return (psutil.Process(pid).name() or "").lower()
        except Exception:
            return ""
