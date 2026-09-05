"""Visual language for the ShieldEX interface.

Colours are expressed as customtkinter ``(light, dark)`` tuples where a single hex value
would look wrong in the other appearance mode; accents and severity colours are single
values because they are chosen to read correctly on both.

Fonts are created by functions rather than module constants: ``CTkFont`` needs a live Tk
root, which does not exist at import time.
"""

from __future__ import annotations

import logging
import platform
from typing import Any

import customtkinter as ctk

from core.timeline import Severity, Source

logger = logging.getLogger(__name__)


def _pick_families() -> tuple[str, str]:
    """Return ``(ui_family, mono_family)`` appropriate for this platform.

    Hardcoding "Segoe UI"/"Consolas" would leave POSIX users on Tk's silent substitute,
    which is usually wider than the metrics the fixed column widths in the timeline and
    dashboard were laid out against, so headers stop lining up with row content.
    """
    system = platform.system()
    if system == "Windows":
        return "Segoe UI", "Consolas"
    if system == "Darwin":
        return "SF Pro Text", "SF Mono"
    return "DejaVu Sans", "DejaVu Sans Mono"


FONT_FAMILY, MONO_FAMILY = _pick_families()

#: Structural surfaces — (light mode, dark mode).
PALETTE: dict[str, Any] = {
    "window": ("#eef1f6", "#0f1420"),
    "sidebar": ("#e2e7ef", "#141a26"),
    "surface": ("#ffffff", "#171d2b"),
    "surface_alt": ("#f4f6fa", "#1e2636"),
    "surface_hover": ("#e8ecf3", "#243044"),
    "border": ("#d3dae5", "#2a3446"),
    "text": ("#1b2231", "#e6ebf5"),
    "text_muted": ("#5d6779", "#8f9bb3"),
    "accent": "#2f6fb0",
    "accent_hover": "#3b86d1",
    "success": "#2f9e44",
    "warning": "#c98a15",
    "danger": "#d94a44",
    "critical": "#a4161a",
    "neutral": "#6b7a90",
}

#: Severity → colour. Matches the severity table in the ShieldEX spec.
SEVERITY_COLORS: dict[str, str] = {
    Severity.INFO: PALETTE["neutral"],
    Severity.LOW: PALETTE["success"],
    Severity.MEDIUM: PALETTE["warning"],
    Severity.HIGH: PALETTE["danger"],
    Severity.CRITICAL: PALETTE["critical"],
}

#: Engine → colour. Red for antivirus, blue for firewall, grey for app-level events.
SOURCE_COLORS: dict[str, str] = {
    Source.ANTIVIRUS: "#d94a44",
    Source.FIREWALL: "#3b86d1",
    Source.SYSTEM: PALETTE["neutral"],
}

#: Overall protection state → colour.
STATUS_COLORS: dict[str, str] = {
    "PROTECTED": PALETTE["success"],
    "PARTIAL": PALETTE["warning"],
    "AT RISK": PALETTE["danger"],
}

PAD = 12
PAD_SM = 6
PAD_LG = 20
CORNER = 10


def apply_appearance(theme: str = "dark", accent: str | None = None) -> None:
    """Set the global customtkinter appearance mode and colour theme."""
    mode = theme.strip().lower()
    if mode not in {"dark", "light", "system"}:
        logger.warning("Unknown theme %r; using dark", theme)
        mode = "dark"
    ctk.set_appearance_mode(mode)
    ctk.set_default_color_theme("dark-blue")
    if accent:
        PALETTE["accent"] = accent


def font(size: int = 13, weight: str = "normal", family: str | None = None) -> ctk.CTkFont:
    """Return a UI font. Call only after the Tk root exists."""
    return ctk.CTkFont(family=family or FONT_FAMILY, size=size, weight=weight)


def mono_font(size: int = 12, weight: str = "normal") -> ctk.CTkFont:
    """Return a monospaced font for hashes, IPs and log lines."""
    return ctk.CTkFont(family=MONO_FAMILY, size=size, weight=weight)


def severity_color(severity: str | None) -> str:
    """Colour for a severity value, tolerant of unknown input."""
    return SEVERITY_COLORS.get(Severity.normalize(severity), PALETTE["neutral"])


def source_color(source: str | None) -> str:
    """Colour for an event source, tolerant of unknown input."""
    return SOURCE_COLORS.get(str(source or "").upper(), PALETTE["neutral"])


def status_color(status: str) -> str:
    """Colour for an overall protection status label."""
    return STATUS_COLORS.get(status.upper(), PALETTE["neutral"])
