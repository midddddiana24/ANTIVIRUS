"""Engine factory — constructs and wires every long-running ShieldEX engine.

Centralised so ``main.py`` stays a thin entry point and the GUI's engine registry gets
one consistent set of objects: the scanner needs the quarantine manager, the IDS needs
the blocklist, the connection monitor needs the rule engine *and* the IDS, and the
notifier needs the timeline. Building them in one place is the only way that dependency
graph stays visible.

Every engine class import is guarded: the app must start and keep its working engines
even when an optional dependency (watchdog, scapy, plyer, psutil) is missing.
"""

from __future__ import annotations

import logging
from typing import Any

from core.config import Config
from core.database import Database
from core.timeline import TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["EngineBundle"]


class EngineBundle:
    """Owns the engine instances and their startup/shutdown order."""

    def __init__(self, config: Config, db: Database, timeline: TimelineLogger) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self._engines: dict[str, Any] = {}
        self._build()

    # ------------------------------------------------------------------ construction
    def _build(self) -> None:
        """Construct every engine, degrading individually when dependencies are missing."""
        quarantine = self._try(
            "quarantine",
            "core.antivirus.quarantine", "QuarantineManager",
            dict(config=self.cfg, db=self.db, timeline=self.timeline),
        )

        scanner = None
        if quarantine is not None:
            scanner = self._try(
                "scanner",
                "core.antivirus.scanner", "Scanner",
                dict(config=self.cfg, db=self.db, timeline=self.timeline, quarantine=quarantine),
            )
            if scanner is not None:
                self._try(
                    "realtime_monitor",
                    "core.antivirus.monitor", "RealTimeMonitor",
                    dict(
                        config=self.cfg, db=self.db, timeline=self.timeline,
                        scanner=scanner, quarantine=quarantine,
                    ),
                )

        self._try(
            "updater",
            "core.antivirus.updater", "SignatureUpdater",
            dict(config=self.cfg, db=self.db, timeline=self.timeline),
        )

        blocklist = self._try(
            "blocklist",
            "core.firewall.ip_blocklist", "IPBlocklist",
            dict(config=self.cfg, db=self.db, timeline=self.timeline),
        )

        if blocklist is not None:
            rule_engine = self._try(
                "firewall",
                "core.firewall.rule_engine", "RuleEngine",
                dict(config=self.cfg, db=self.db, timeline=self.timeline, blocklist=blocklist),
            )
            ids = self._try(
                "ids",
                "core.firewall.ids", "IDSDetector",
                dict(
                    config=self.cfg, db=self.db, timeline=self.timeline,
                    blocklist=blocklist, rule_engine=rule_engine,
                ),
            )
            if rule_engine is not None and ids is not None:
                self._try(
                    "connection_monitor",
                    "core.firewall.connection_monitor", "ConnectionMonitor",
                    dict(
                        config=self.cfg, db=self.db, timeline=self.timeline,
                        rule_engine=rule_engine, ids=ids,
                    ),
                )
            if ids is not None:
                self._try(
                    "packet_inspector",
                    "core.firewall.packet_inspector", "PacketInspector",
                    dict(config=self.cfg, db=self.db, timeline=self.timeline, ids=ids),
                )

        notifier = self._try(
            "notifications",
            "core.notifications", "Notifier",
            dict(config=self.cfg, db=self.db, timeline=self.timeline),
        )
        if notifier is not None:
            try:
                notifier.attach()
            except Exception as exc:
                logger.error("Could not attach the notifier: %s", exc)

    def _try(self, name: str, module_path: str, class_name: str, kwargs: dict[str, Any]) -> Any | None:
        """Import and build one engine; log and skip it when anything fails."""
        try:
            import importlib

            module = importlib.import_module(module_path)
            engine_class = getattr(module, class_name)
            engine = engine_class(**kwargs)
            self._engines[name] = engine
            logger.debug("Engine built: %s (%s)", name, class_name)
            return engine
        except Exception as exc:
            logger.warning("Engine %s unavailable: %s", name, exc, exc_info=True)
            return None

    # ------------------------------------------------------------------ registry interface
    def names(self) -> list[str]:
        """Engine names in registration order (stable for tests and startup logs)."""
        return list(self._engines.keys())

    def get(self, name: str) -> Any | None:
        return self._engines.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._engines

    # ------------------------------------------------------------------ lifecycle
    def stop_all(self) -> None:
        """Stop every engine, in reverse registration order."""
        for name in reversed(self.names()):
            engine = self._engines.get(name)
            stop = getattr(engine, "stop", None)
            if not callable(stop):
                continue
            try:
                stop()
                logger.info("Engine stopped: %s", name)
            except Exception as exc:
                logger.error("Engine %s failed to stop: %s", name, exc, exc_info=True)


def build_engines(config: Config, db: Database, timeline: TimelineLogger) -> EngineBundle:
    """Construct the full engine bundle (the function ``main.py`` calls)."""
    return EngineBundle(config, db, timeline)
