"""Packet inspector — optional scapy-based raw packet feed for the IDS.

The connection monitor can only see *sockets*, not *packets*: a SYN flood that never
completes a connection, or an ICMP flood, is invisible to it. This module bridges that
gap by sniffing with scapy and feeding :meth:`IDSDetector.observe_syn` /
:meth:`IDSDetector.observe_icmp`.

Scapy on Windows requires Npcap, which is exactly why this whole module is optional
and disabled by default: a missing driver would otherwise make the firewall panel
unusable. Every failure mode (missing library, missing driver, bad interface) degrades
to "inspector off", never to an exception.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["PacketInspector"]


class PacketInspector:
    """Optional raw-packet feed for the IDS (scapy + Npcap on Windows)."""

    def __init__(
        self,
        config: Config,
        db: Database,
        timeline: TimelineLogger,
        ids: Any,
    ) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.ids = ids

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._available: bool | None = None

        interface = config.get("firewall.packet_inspector.interface")
        self._interface = str(interface) if interface else None
        self._bpf = str(config.get("firewall.packet_inspector.bpf_filter", "ip"))

    # ------------------------------------------------------------------ availability
    def check_available(self) -> bool:
        """True when scapy imports and a capture interface exists. Cached."""
        if self._available is not None:
            return self._available
        try:
            from scapy.arch import get_if_list  # noqa: F401  (probes the driver)
            from scapy.all import conf  # noqa: F401

            interfaces = get_if_list()
            self._available = bool(interfaces)
            if not self._available:
                logger.info("Packet inspector: no capture interfaces (Npcap missing?)")
        except Exception as exc:
            logger.info("Packet inspector unavailable: %s", exc)
            self._available = False
        return self._available

    # ------------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Start sniffing. True when the inspector is now running."""
        if self.running:
            return True
        if not bool(self.cfg.get("firewall.packet_inspector.enabled", False)):
            return False
        if not self.check_available():
            self.timeline.log_firewall(
                EventType.ENGINE_ERROR,
                "Packet inspector enabled but unavailable (scapy/Npcap missing)",
                Severity.LOW,
            )
            return False

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sniff_loop, name="shieldex-packet-inspector", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop sniffing (scapy's stop flag ends the capture thread)."""
        self._stop_event.set()
        try:
            from scapy.all import stop_sniff_if_running  # type: ignore[attr-defined]
        except Exception:
            pass
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=3)
        self._thread = None

    # ------------------------------------------------------------------ sniffing
    def _sniff_loop(self) -> None:
        """Run scapy's sniff until stopped (retrying after transient errors)."""
        try:
            from scapy.all import ICMP, IP, TCP  # noqa: F401

            from scapy.all import AsyncSniffer
        except Exception as exc:
            logger.info("Packet inspector unavailable: %s", exc)
            return

        while not self._stop_event.is_set():
            sniffer = None
            try:
                sniffer = AsyncSniffer(
                    iface=self._interface,
                    filter=self._bpf,
                    prn=self._on_packet,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
                sniffer.start()
                while not self._stop_event.is_set():
                    self._stop_event.wait(1.0)
                if sniffer.running:
                    sniffer.stop()
                break
            except Exception as exc:
                logger.warning("Packet capture error: %s", exc)
                if sniffer is not None and sniffer.running:
                    try:
                        sniffer.stop()
                    except Exception:
                        pass
                self._stop_event.wait(5)  # back off, then retry while enabled

    def _on_packet(self, packet: Any) -> None:
        """Classify one packet and feed the IDS. Must never raise inside scapy."""
        try:
            if self._stop_event.is_set():
                return
            if packet.haslayer(TCP):
                flags = int(packet[TCP].flags)
                SYN_ONLY = 0x02
                if flags == SYN_ONLY:
                    src_ip = packet[IP].src
                    self.ids.observe_syn(src_ip)
            elif packet.haslayer(ICMP):
                src_ip = packet[IP].src
                if packet[ICMP].type in (8, 0):  # echo request/reply
                    self.ids.observe_icmp(src_ip)
        except Exception:
            logger.exception("Packet classification failed")
