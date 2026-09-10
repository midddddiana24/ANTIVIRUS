"""Visual language for the ShieldEX interface — Console v2.

Layout runs on a 4px base grid: XS=4, SM=8, MD=16, LG=24, XL=32. View padding is LG
(24px) on the sides, cards breathe with MD (16px) internal padding, rows sit 8px
(SM) apart. The legacy ``PAD``/``PAD_SM``/``PAD_LG`` names remain as aliases so
existing views keep working untouched.

Colours are expressed as customtkinter ``(light, dark)`` tuples where a single hex value
would look wrong in the other appearance mode; accents and severity colours are single
values because they are chosen to read correctly on both. The dark ramp is stepped so
window → sidebar → surface → hover are each visibly distinct layers.

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
    "window": ("#e9edf4", "#0b0f19"),
    "sidebar": ("#dde3ee", "#111725"),
    "surface": ("#ffffff", "#151c2d"),
    "surface_alt": ("#f1f4f9", "#1c2438"),
    "surface_hover": ("#e3e9f4", "#242e46"),
    "border": ("#cfd7e4", "#2b3549"),
    "text": ("#1b2231", "#e8edf6"),
    "text_muted": ("#5d6779", "#93a0b8"),
    "accent": "#2f6fb0",
    "accent_hover": "#3b86d1",
    "accent_soft": ("#d7e7f7", "#1d3350"),
    "accent_text": ("#1f5b96", "#7db6e8"),
    "success": "#2f9e44",
    "success_soft": ("#d9f0df", "#123a22"),
    "warning": "#c98a15",
    "warning_soft": ("#f9ecd4", "#43320c"),
    "danger": "#d94a44",
    "danger_soft": ("#f9dede", "#471917"),
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

#: 4px-base spacing scale. New code should use these; the PAD_* aliases above map
#: onto the scale so the eleven existing views keep their current look until they
#: are individually migrated.
SP_XS = 4
SP_SM = 8
SP_MD = 16
SP_LG = 24
SP_XL = 32

#: Corner radii: cards/inputs 12, pills/chips 8, rows 8.
RADIUS_CARD = 12
RADIUS_PILL = 8
RADIUS_ROW = 8

#: Shell metrics.
SIDEBAR_WIDTH = 248
NAV_ROW_HEIGHT = 40
STATUS_BAR_HEIGHT = 34
BUTTON_H_PRIMARY = 32
BUTTON_H_SECONDARY = 30

#: Type scale (sizes; weights chosen at call sites).
TYPE_DISPLAY = 24  # view titles
TYPE_TITLE = 15  # card titles, sentence case
TYPE_BODY = 13  # default UI text
TYPE_CAPTION = 12  # subtitles, secondary text
TYPE_MICRO = 11  # section labels, chips, table headers
TYPE_MONO = 12  # hashes, paths, log lines


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
