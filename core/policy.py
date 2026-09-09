"""Response policy — what ShieldEX *does* about each severity level.

A policy is the product's documented promise: "a Critical signature match is
quarantined immediately; a Medium heuristic finding is logged and shown but left on
disk". Without it, response behavior hides inside scattered booleans
(``auto_quarantine_on_signature_match``) that no user — and no auditor — can review
in one place.

The table lives in config under ``policies.threat_response`` so it is tunable without
code changes and visible in Settings:

===========  ===========  ================================================
Severity     Quarantine   Rationale
===========  ===========  ================================================
Critical     always       known-bad payload; leaving it on disk helps nobody
High         always       known-bad or strongly malicious behaviour
Medium       never        suspicious pattern, but false positives are real —
                          the user decides per file from the Quarantine view
Low/Info     never        advisory only; logged to the timeline
===========  ===========  ================================================

``policies.ids_auto_block`` keeps the firewall's IDS response next to the same
document instead of buried in ``firewall.ids``.
"""

from __future__ import annotations

import logging
from typing import Any

from core.config import Config
from core.timeline import Severity

logger = logging.getLogger(__name__)

__all__ = ["ResponsePolicy", "DEFAULT_THREAT_RESPONSE"]

#: Severity → quarantine decision shipped out of the box. Mirrors the table above.
DEFAULT_THREAT_RESPONSE: dict[str, bool] = {
    Severity.CRITICAL: True,
    Severity.HIGH: True,
    Severity.MEDIUM: False,
    Severity.LOW: False,
    Severity.INFO: False,
}


class ResponsePolicy:
    """Answers "what do we do with a detection of severity X?" from config."""

    def __init__(self, config: Config) -> None:
        self.cfg = config

    # ------------------------------------------------------------------ antivirus
    def should_quarantine(self, severity: str | None, kind: str = "signature") -> bool:
        """True when a detection of this severity is auto-quarantined.

        ``kind`` is ``"signature"`` (known malware) or ``"heuristic"`` (suspicious
        behaviour). Heuristic detections are never auto-quarantined regardless of
        severity — a heuristic is a lead, and deleting user files on a lead is how
        antivirus products destroy trust. The per-severity table then decides the
        signature-match cases.
        """
        if kind != "signature":
            return False
        level = Severity.normalize(severity, Severity.HIGH)
        table = self.cfg.get("policies.threat_response", None)
        if isinstance(table, dict) and level in table:
            return bool(table[level])
        # Legacy fallback: the single boolean this table replaces. Honoured so an
        # upgrade never silently changes behaviour on an existing config.json.
        if self.cfg.get("antivirus.auto_quarantine_on_signature_match", None) is not None:
            return bool(self.cfg.get("antivirus.auto_quarantine_on_signature_match", True))
        return DEFAULT_THREAT_RESPONSE.get(level, False)

    def describe(self) -> list[tuple[str, bool]]:
        """The effective (severity, quarantine?) table for display in Settings."""
        return [
            (level, self.should_quarantine(level, kind="signature"))
            for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        ]

    # ------------------------------------------------------------------ firewall
    @property
    def ids_auto_block(self) -> bool:
        """Whether IDS alerts automatically block the offending source."""
        value = self.cfg.get("policies.ids_auto_block", None)
        if value is not None:
            return bool(value)
        return bool(self.cfg.get("firewall.ids.auto_block_source", False))

    def set_ids_auto_block(self, enabled: bool) -> None:
        self.cfg.set("policies.ids_auto_block", bool(enabled))

    # ------------------------------------------------------------------ editing
    def set_quarantine(self, severity: str, enabled: bool) -> bool:
        """Set one row of the threat-response table. Returns False for bad input."""
        level = Severity.normalize(severity, "")
        if level not in DEFAULT_THREAT_RESPONSE:
            logger.warning("Refusing to set policy for unknown severity %r", severity)
            return False
        table = self.cfg.get("policies.threat_response", None)
        merged: dict[str, Any] = (
            dict(table) if isinstance(table, dict) else dict(DEFAULT_THREAT_RESPONSE)
        )
        merged[level] = bool(enabled)
        self.cfg.set("policies.threat_response", merged)
        return True
