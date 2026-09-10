"""Base class for every ShieldEX view.

Views are plain frames that the application shell swaps in and out of the content area.
The shell drives four lifecycle hooks:

``build``
    Called once during construction. Subclasses create their widgets inside
    :attr:`BaseView.content` here.
``on_show`` / ``on_hide``
    Called each time the view becomes visible or is navigated away from.
``refresh``
    Called on the shell's polling interval while the view is visible, and by ``on_show``.
``on_timeline_events``
    Called on the **UI thread** with a batch of new Threat Behavior Timeline events that
    background engines produced, so live views can update without polling the database.

Note the attribute name :attr:`BaseView.cfg` for the configuration object: ``self.config``
would shadow Tk's own ``config()`` method on the widget.
"""

from __future__ import annotations

import importlib.util
from typing import TYPE_CHECKING, Any

import customtkinter as ctk

from gui.theme import SP_LG, SP_MD, SP_SM, PALETTE, font
from gui.widgets import SectionHeading

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids a circular import at runtime
    from gui.app import ShieldEXApp


def module_available(module_path: str) -> bool:
    """True when a module can be imported, checked without importing it.

    This is how the shell and the dashboard decide whether a feature has landed yet: a
    nav entry or button for a module that does not exist is shown disabled, and enables
    itself automatically once the module is added.
    """
    try:
        return importlib.util.find_spec(module_path) is not None
    except (ImportError, ValueError, AttributeError):
        return False


class BaseView(ctk.CTkFrame):
    """Common scaffolding (heading, action bar, content area) for all views."""

    #: Heading shown at the top of the view.
    title: str = "ShieldEX"
    #: Optional one-line explanation under the heading.
    subtitle: str = ""

    def __init__(self, master: Any, app: "ShieldEXApp") -> None:
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.db = app.db
        self.timeline = app.timeline
        self.cfg = app.cfg  # not ``self.config``: that name belongs to Tk

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ---- heading + per-view action bar -------------------------------------
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=SP_LG, pady=(SP_LG, SP_MD))
        header.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")
        SectionHeading(title_box, self.title).grid(row=0, column=0, sticky="w")
        if self.subtitle:
            ctk.CTkLabel(
                title_box,
                text=self.subtitle,
                font=font(12),
                text_color=PALETTE["text_muted"],
                anchor="w",
            ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        #: Right-aligned frame for view-specific buttons.
        self.actions = ctk.CTkFrame(header, fg_color="transparent")
        self.actions.grid(row=0, column=1, sticky="e", padx=(SP_MD, 0))

        #: Frame subclasses fill with their own widgets.
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=1, column=0, sticky="nsew", padx=SP_LG, pady=(0, SP_LG))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.build()

    # ------------------------------------------------------------------ lifecycle
    def build(self) -> None:
        """Create this view's widgets inside :attr:`content`. Overridden by subclasses."""

    def on_show(self) -> None:
        """Called when the view becomes visible. Refreshes data by default."""
        self.refresh()

    def on_hide(self) -> None:
        """Called when the view is navigated away from. Override to pause work."""

    def refresh(self) -> None:
        """Re-read data and update widgets. Overridden by data-driven views."""

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        """Handle newly logged timeline events on the UI thread. Override to react."""
