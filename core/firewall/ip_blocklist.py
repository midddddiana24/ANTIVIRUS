"""IP blocklist — CIDR-aware blocked/trusted address management.

A single IP can be expressed as ``1.2.3.4`` or ``10.0.0.0/8``; both the blocklist and
the trustlist accept either form. Matching is done with :mod:`ipaddress` (not string
prefixes — ``192.168.1.5`` does **not** live inside ``192.168.1.50/24``), and the
standard library handles IPv6 transparently.

Feeds merge the same way the signature feed does: remote or local JSON lines/CSV, best
-effort, never fatal.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["IPBlocklist", "normalize_ip"]


def normalize_ip(ip_or_cidr: str) -> str:
    """Canonical form of an address or network (``"10.0.0.1/32"`` → ``"10.0.0.1"``).

    Raises ``ValueError`` for garbage so the caller can reject the edit before it
    reaches the database.
    """
    text = (ip_or_cidr or "").strip()
    if not text:
        raise ValueError("empty address")
    if "/" in text:
        network = ipaddress.ip_network(text, strict=False)
        return str(network)
    return str(ipaddress.ip_address(text))


class IPBlocklist:
    """Blocked and trusted addresses, with CIDR matching and optional feed sync."""

    def __init__(self, config: Config, db: Database, timeline: TimelineLogger) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline

    # ------------------------------------------------------------------ checks
    def is_blocked(self, ip: str) -> bool:
        """True when ``ip`` falls inside any blocked network (trusted entries win)."""
        try:
            address = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        if self._covers(self.db.get_trusted_ips(), address):
            return False  # a trust entry must override a broader block
        return self._covers(self.db.get_blocked_ips(), address)

    def is_trusted(self, ip: str) -> bool:
        """True when ``ip`` falls inside any trusted network."""
        try:
            address = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        return self._covers(self.db.get_trusted_ips(), address)

    @staticmethod
    def _covers(entries: list[dict[str, Any]], address: ipaddress._BaseAddress) -> bool:
        for entry in entries:
            value = entry.get("ip_or_cidr", "") if "ip_or_cidr" in entry else entry.get("ip", "")
            try:
                if "/" in str(value):
                    if address in ipaddress.ip_network(str(value), strict=False):
                        return True
                elif str(value) and ipaddress.ip_address(str(value)) == address:
                    return True
            except ValueError:
                continue  # a malformed stored row must not break the lookup
        return False

    # ------------------------------------------------------------------ blocklist
    def block(self, ip_or_cidr: str, label: str = "", source: str = "manual") -> bool:
        """Add an address/network to the blocklist. True when a new row was created."""
        try:
            normalized = normalize_ip(ip_or_cidr)
        except ValueError as exc:
            logger.warning("Refusing to block invalid address %r: %s", ip_or_cidr, exc)
            return False
        reason = f"{label} ({source})" if label and source != "manual" else (label or source)
        added = self.db.add_blocked_ip(normalized, reason=reason, auto_added=source != "manual")
        if added:
            self.timeline.log_firewall(
                EventType.IP_BLOCKED,
                f"Blocked {normalized}" + (f" ({label})" if label else ""),
                Severity.MEDIUM,
                normalized,
            )
        return added

    def unblock(self, ip_or_cidr: str) -> bool:
        """Remove a blocklist row. True when one existed and was deleted."""
        removed = self.db.remove_blocked_ip(ip_or_cidr)
        if removed:
            self.timeline.log_firewall(
                EventType.IP_UNBLOCKED, f"Unblocked {ip_or_cidr}", Severity.INFO, ip_or_cidr
            )
        return removed

    def blocked_entries(self) -> list[dict[str, Any]]:
        return self.db.get_blocked_ips()

    def trusted_entries(self) -> list[dict[str, Any]]:
        return self.db.get_trusted_ips()

    def trust(self, ip_or_cidr: str, label: str = "") -> bool:
        """Add an address/network to the trustlist (overrides blocks)."""
        try:
            normalized = normalize_ip(ip_or_cidr)
        except ValueError as exc:
            logger.warning("Refusing to trust invalid address %r: %s", ip_or_cidr, exc)
            return False
        return self.db.add_trusted_ip(normalized, label=label)

    def untrust(self, ip_or_cidr: str) -> bool:
        return self.db.remove_trusted_ip(ip_or_cidr)

    # ------------------------------------------------------------------ feeds
    def sync_feeds(self, urls: list[str] | None = None) -> int:
        """Merge blocklist feeds (JSON list, JSON-lines or one IP/CIDR per line).

        Returns the number of new blocked entries; never raises.
        """
        targets = urls
        if targets is None:
            raw = self.cfg.get("firewall.blocklist_feeds.urls", [])
            targets = [str(item) for item in raw] if isinstance(raw, list) else []
        if not bool(self.cfg.get("firewall.blocklist_feeds.enabled", False)) and urls is None:
            return 0

        added = 0
        for url in targets:
            try:
                added += self._sync_one_feed(url)
            except Exception as exc:
                logger.warning("Blocklist feed %s failed: %s", url, exc)
        if added:
            self.timeline.log_firewall(
                EventType.IP_BLOCKED,
                f"Merged {added} address(es) from blocklist feed(s)",
                Severity.MEDIUM,
            )
        return added

    def _sync_one_feed(self, url: str) -> int:
        """Fetch and merge one feed (http(s) or local path)."""
        if url.lower().startswith(("http://", "https://")):
            import requests

            response = requests.get(url, timeout=10)
            response.raise_for_status()
            text = response.text
        else:
            from urllib.parse import unquote, urlparse

            parsed = urlparse(url)
            path = Path(unquote(parsed.path) if parsed.scheme == "file" else url)
            if not path.is_file():
                return 0
            text = path.read_text(encoding="utf-8")

        entries: list[str] = []
        stripped = text.strip()
        if stripped.startswith("["):
            import json

            payload = json.loads(stripped)
            if isinstance(payload, list):
                entries = [str(item) for item in payload]
        elif stripped.startswith("{"):
            import json

            payload = json.loads(stripped)
            for value in payload.get("addresses", payload.get("ips", [])):
                entries.append(str(value))
        else:
            entries = [line.strip() for line in stripped.splitlines() if line.strip()]

        added = 0
        for entry in entries:
            try:
                normalized = normalize_ip(entry)
            except ValueError:
                continue
            if self.db.add_blocked_ip(normalized, reason="blocklist feed", auto_added=True):
                added += 1
        return added

    # ------------------------------------------------------------------ helpers
    def counts(self) -> dict[str, int]:
        return {
            "blocked": self.db.blocked_ip_count(),
            "trusted": self.db.trusted_ip_count(),
        }
