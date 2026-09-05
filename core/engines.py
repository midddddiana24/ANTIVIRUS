"""Engine bootstrap — constructs and wires every ShieldEX engine, once per process.

The GUI shell drives long-running engines through its registry
(:meth:`gui.app.ShieldEXApp.register_engine`), and views reach them with
:meth:`gui.app.ShieldEXApp.get_engine`. Nothing constructed them, though: main.py
opened the database and handed it straight to the shell, so the registry stayed
empty — every toggle fell back to "state saved (engine not loaded yet)" and no scan
or firewall engine ever ran.

This module owns the construction order, which is fixed by the engines' own
dependencies:

1. quarantine (needs scanner? no — scanner needs quarantine);
2. scanner (needs quarantine);
3. real-time monitor (needs scanner + quarantine);
4. IP blocklist;
5. rule engine (needs blocklist);
6. IDS detector (needs blocklist, optionally the rule engine);
7. connection monitor (needs rule engine + IDS);
8. packet inspector (optional, needs IDS);
9. signature updater.

Everything is built defensively: an engine whose import fails (scapy without Npcap,
watchdog missing) is skipped rather than fatal, and :class:`EngineRegistry` exposes
``None`` for it so the views can show an honest "unavailable" state.
"""

from __future__ import annotations

import logging
from typing import Any

from core.config import Config
from core.database import Database
from core.timeline import TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["EngineRegistry", "build_engines"]


class EngineRegistry:
    """Named home for every long-running engine the shell and the views can reach."""

    def __init__(self) -> None:
        self._engines: dict[str, Any] = {}

    def register(self, name: str, engine: Any) -> None:
        """Store an engine under ``name``; the shell's toggles look these up."""
        self._engines[name] = engine
        logger.info("Engine registered: %s (%s)", name, type(engine).__name__)

    def get(self, name: str) -> Any | None:
        """Return the engine, or ``None`` when it could not be built."""
        return self._engines.get(name)

    def names(self) -> list[str]:
        return sorted(self._engines)

    def stop_all(self) -> None:
        """Stop every engine that has a ``stop()``; never raises."""
        for name, engine in self._engines.items():
            stop = getattr(engine, "stop", None)
            if callable(stop):
                try:
                    stop()
                    logger.info("Engine stopped: %s", name)
                except Exception as exc:
                    logger.error("Engine %s failed to stop: %s", name, exc, exc_info=True)


def build_engines(config: Config, db: Database, timeline: TimelineLogger) -> EngineRegistry:
    """Construct and register every engine the configuration allows.

    Individual engine failures are logged and skipped, because a machine without
    Npcap must still get the antivirus side of the suite. Returns the filled registry;
    the caller hands it to the shell, which re-registers each engine under the same
    names (registry and shell share the naming contract documented on
    :meth:`gui.app.ShieldEXApp.register_engine`).
    """
    registry = EngineRegistry()

    # ---- antivirus ------------------------------------------------------------
    try:
        from core.antivirus.quarantine import QuarantineManager

        registry.register("quarantine", QuarantineManager(config, db, timeline))
    except Exception as exc:
        logger.error("Quarantine engine unavailable: %s", exc, exc_info=True)

    try:
        from core.antivirus.scanner import Scanner

        quarantine = registry.get("quarantine")
        if quarantine is not None:
            registry.register("scanner", Scanner(config, db, timeline, quarantine))
    except Exception as exc:
        logger.error("Scanner engine unavailable: %s", exc, exc_info=True)

    try:
        from core.antivirus.monitor import RealTimeMonitor

        scanner = registry.get("scanner")
        quarantine = registry.get("quarantine")
        if scanner is not None and quarantine is not None:
            registry.register("realtime_monitor", RealTimeMonitor(config, db, timeline, scanner, quarantine))
    except Exception as exc:
        logger.error("Real-time monitor engine unavailable: %s", exc, exc_info=True)

    try:
        from core.antivirus.updater import SignatureUpdater

        registry.register("updater", SignatureUpdater(config, db, timeline))
    except Exception as exc:
        logger.error("Signature updater unavailable: %s", exc, exc_info=True)

    # ---- firewall ---------------------------------------------------------------
    try:
        from core.firewall.ip_blocklist import IPBlocklist

        registry.register("blocklist", IPBlocklist(config, db, timeline))
    except Exception as exc:
        logger.error("IP blocklist unavailable: %s", exc, exc_info=True)

    try:
        from core.firewall.rule_engine import RuleEngine

        blocklist = registry.get("blocklist")
        if blocklist is not None:
            registry.register("firewall", RuleEngine(config, db, timeline, blocklist))
    except Exception as exc:
        logger.error("Firewall rule engine unavailable: %s", exc, exc_info=True)

    try:
        from core.firewall.ids import IDSDetector

        blocklist = registry.get("blocklist")
        if blocklist is not None:
            registry.register("ids", IDSDetector(
                config, db, timeline,
                blocklist=blocklist,
                rule_engine=registry.get("firewall"),
            ))
    except Exception as exc:
        logger.error("IDS detector unavailable: %s", exc, exc_info=True)

    try:
        from core.firewall.connection_monitor import ConnectionMonitor

        rule_engine = registry.get("firewall")
        ids = registry.get("ids")
        if rule_engine is not None and ids is not None:
            registry.register("connection_monitor", ConnectionMonitor(config, db, timeline, rule_engine, ids))
    except Exception as exc:
        logger.error("Connection monitor unavailable: %s", exc, exc_info=True)

    try:
        from core.firewall.packet_inspector import PacketInspector

        ids = registry.get("ids")
        if ids is not None:
            registry.register("packet_inspector", PacketInspector(config, db, timeline, ids))
    except Exception as exc:
        logger.info("Packet inspector unavailable: %s", exc)

    # ---- shared -----------------------------------------------------------------
    try:
        from core.notifications import NotificationEngine

        registry.register("notifications", NotificationEngine(config, timeline))
    except Exception as exc:
        logger.error("Notification engine unavailable: %s", exc, exc_info=True)

    return registry
