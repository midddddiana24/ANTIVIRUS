"""Reusable customtkinter widgets shared by the ShieldEX views.

Keeping cards, chips, badges and hoverable rows here means the dashboard, the timeline
and every view added later look identical without copy-pasted styling.
"""

from __future__ import annotations

from typing import Any, Callable

import customtkinter as ctk

from gui.theme import (
    CORNER,
    PAD,
    PAD_SM,
    PALETTE,
    font,
    mono_font,
    severity_color,
    source_color,
)


#: Attribute name a widget can carry to opt its whole subtree out of :func:`bind_recursive`.
#: Used for interactive panels nested inside a clickable row — buttons and entries there
#: must handle their own clicks without also triggering the row's click action.
NO_ROW_BINDING = "_shieldex_no_row_binding"


def exclude_from_row_bindings(widget: Any) -> Any:
    """Mark ``widget`` (and its descendants) as off-limits to :func:`bind_recursive`.

    Returns the widget so it can be used inline at construction.
    """
    setattr(widget, NO_ROW_BINDING, True)
    return widget


def bind_recursive(widget: Any, sequence: str, handler: Callable[[Any], None]) -> None:
    """Bind an event on a widget and all of its descendants.

    Child widgets otherwise swallow ``<Enter>``/``<Button-1>`` before the parent row sees
    them, which would make hover highlighting and row clicks unreliable.

    Subtrees marked by :func:`exclude_from_row_bindings` are skipped. Without that, a
    button inside a clickable row fires its own command *and* the row's click handler —
    and when the row handler re-renders the list, the button is destroyed while Tk is
    still dispatching its event, which raises ``invalid command name``.
    """
    if getattr(widget, NO_ROW_BINDING, False):
        return
    widget.bind(sequence, handler, add="+")
    for child in widget.winfo_children():
        bind_recursive(child, sequence, handler)


class Card(ctk.CTkFrame):
    """A titled panel with a ``body`` frame for callers to fill."""

    def __init__(
        self,
        master: Any,
        title: str = "",
        subtitle: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            master,
            fg_color=PALETTE["surface"],
            corner_radius=CORNER,
            border_width=1,
            border_color=PALETTE["border"],
            **kwargs,
        )
        self.grid_columnconfigure(0, weight=1)
        row = 0

        if title:
            self.title_label = ctk.CTkLabel(
                self,
                text=title.upper(),
                font=font(11, "bold"),
                text_color=PALETTE["text_muted"],
                anchor="w",
            )
            self.title_label.grid(row=row, column=0, sticky="ew", padx=PAD, pady=(PAD, 0))
            row += 1

        if subtitle:
            self.subtitle_label = ctk.CTkLabel(
                self, text=subtitle, font=font(12), text_color=PALETTE["text_muted"], anchor="w"
            )
            self.subtitle_label.grid(row=row, column=0, sticky="ew", padx=PAD, pady=(2, 0))
            row += 1

        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.grid(row=row, column=0, sticky="nsew", padx=PAD, pady=PAD)
        self.body.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(row, weight=1)


class Chip(ctk.CTkLabel):
    """Small rounded label used for severities, statuses and counts."""

    def __init__(self, master: Any, text: str, color: str, **kwargs: Any) -> None:
        super().__init__(
            master,
            text=f" {text} ",
            fg_color=color,
            text_color="#ffffff",
            corner_radius=8,
            font=font(11, "bold"),
            **kwargs,
        )

    def update_chip(self, text: str, color: str) -> None:
        """Change both the label and the colour in one call."""
        self.configure(text=f" {text} ", fg_color=color)


class SeverityChip(Chip):
    """Chip coloured by threat severity."""

    def __init__(self, master: Any, severity: str, **kwargs: Any) -> None:
        super().__init__(master, str(severity or "Info"), severity_color(severity), **kwargs)


class SourceBadge(Chip):
    """Chip coloured by originating engine (antivirus / firewall / system)."""

    def __init__(self, master: Any, source: str, **kwargs: Any) -> None:
        super().__init__(master, str(source or "SYSTEM").upper(), source_color(source), **kwargs)


class StatLine(ctk.CTkFrame):
    """A label on the left and a value on the right, for summary cards."""

    def __init__(
        self,
        master: Any,
        label: str,
        value: str = "—",
        value_color: str | None = None,
        monospace: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.label = ctk.CTkLabel(
            self, text=label, font=font(12), text_color=PALETTE["text_muted"], anchor="w"
        )
        self.label.grid(row=0, column=0, sticky="w")

        self.value = ctk.CTkLabel(
            self,
            text=value,
            font=mono_font(12, "bold") if monospace else font(12, "bold"),
            text_color=value_color or PALETTE["text"],
            anchor="e",
        )
        self.value.grid(row=0, column=1, sticky="e", padx=(PAD, 0))

    def set_value(self, value: str, color: str | None = None) -> None:
        """Update the right-hand value (and optionally its colour)."""
        self.value.configure(text=value, text_color=color or PALETTE["text"])


class HoverRow(ctk.CTkFrame):
    """A clickable table row that highlights on hover."""

    def __init__(self, master: Any, on_click: Callable[[], None] | None = None, **kwargs: Any):
        super().__init__(
            master, fg_color=PALETTE["surface_alt"], corner_radius=6, **kwargs
        )
        self._on_click = on_click
        self._base_color = PALETTE["surface_alt"]

    def activate_bindings(self) -> None:
        """Attach hover/click handlers. Call once after the row's children exist.

        Call this *before* adding any interactive panel to the row, or mark that panel
        with :func:`exclude_from_row_bindings`; otherwise its buttons inherit the row's
        click handler.
        """
        bind_recursive(self, "<Enter>", lambda _event: self._tint(PALETTE["surface_hover"]))
        bind_recursive(self, "<Leave>", lambda _event: self._tint(self._base_color))
        if self._on_click is not None:
            bind_recursive(self, "<Button-1>", lambda _event: self._invoke())

    def _tint(self, color: Any) -> None:
        """Recolour, tolerating a row that has already been destroyed.

        A click that rebuilds the list destroys this row, and Tk still delivers the
        matching ``<Leave>`` afterwards — which would hit a dead widget.
        """
        if self.winfo_exists():
            self.configure(fg_color=color)

    def _invoke(self) -> None:
        """Run the click handler once the current event dispatch has finished.

        Deferring to an idle callback matters because handlers here typically rebuild the
        whole list, destroying this very row. Doing that synchronously tears the widget
        down while Tk is still walking its binding chain. The callback is scheduled on the
        toplevel, which outlives the row.
        """
        if self._on_click is None:
            return
        handler = self._on_click
        try:
            self.winfo_toplevel().after_idle(handler)
        except Exception:  # pragma: no cover - no toplevel (widget already gone)
            handler()

    def set_base_color(self, color: Any) -> None:
        """Change the resting background colour (used to mark selection)."""
        self._base_color = color
        self._tint(color)


class EmptyState(ctk.CTkLabel):
    """Muted centred message shown when a list has nothing in it."""

    def __init__(self, master: Any, text: str, **kwargs: Any) -> None:
        super().__init__(
            master,
            text=text,
            font=font(12),
            text_color=PALETTE["text_muted"],
            justify="center",
            **kwargs,
        )


class SectionHeading(ctk.CTkLabel):
    """Large heading used at the top of a view."""

    def __init__(self, master: Any, text: str, **kwargs: Any) -> None:
        super().__init__(
            master,
            text=text,
            font=font(22, "bold"),
            text_color=PALETTE["text"],
            anchor="w",
            **kwargs,
        )


class Banner(ctk.CTkFrame):
    """Full-width coloured notice strip with optional action button."""

    def __init__(
        self,
        master: Any,
        text: str,
        color: str,
        action_text: str | None = None,
        action: Callable[[], None] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=color, corner_radius=0, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.message = ctk.CTkLabel(
            self, text=text, font=font(12, "bold"), text_color="#ffffff", anchor="w"
        )
        self.message.grid(row=0, column=0, sticky="ew", padx=PAD, pady=PAD_SM)

        if action_text and action is not None:
            self.action_button = ctk.CTkButton(
                self,
                text=action_text,
                command=action,
                width=200,
                height=26,
                font=font(11, "bold"),
                fg_color="#ffffff",
                text_color=color,
                hover_color="#e6ebf5",
            )
            self.action_button.grid(row=0, column=1, sticky="e", padx=PAD, pady=PAD_SM)
