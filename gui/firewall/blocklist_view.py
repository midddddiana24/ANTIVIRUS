"""IP Lists view — the blocklist and the trustlist, with CIDR support.

All writes go through the ``blocklist`` engine so CIDR normalisation, timeline
narrative and (in IDS auto-block cases) OS enforcement stay consistent. The two
lists sit side by side because the mental model is one screen: "who is banned, who is
vouched for".
"""

from __future__ import annotations

import logging
from tkinter import messagebox
from typing import Any

import customtkinter as ctk

from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, StatLine

logger = logging.getLogger(__name__)


class BlocklistView(BaseView):
    """Manage blocked and trusted IP addresses / networks."""

    title = "IP Lists"
    subtitle = "Blocked addresses are denied; trusted ones override blocks"

    def build(self) -> None:
        self._blocked_rows: list[ctk.CTkFrame] = []
        self._trusted_rows: list[ctk.CTkFrame] = []

        self.content.grid_columnconfigure(0, weight=1, uniform="ips")
        self.content.grid_columnconfigure(1, weight=1, uniform="ips")
        self.content.grid_rowconfigure(1, weight=1)

        self._build_block_pane()
        self._build_trust_pane()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build_block_pane(self) -> None:
        card = Card(self.content, title="Blocked")
        card.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, PAD_SM))
        card.grid_rowconfigure(2, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        self._blocked_count = StatLine(body, "Entries blocked")
        self._blocked_count.grid(row=0, column=0, sticky="ew")

        entry_row = ctk.CTkFrame(body, fg_color="transparent")
        entry_row.grid(row=1, column=0, sticky="ew", pady=(PAD_SM, 0))
        entry_row.grid_columnconfigure(0, weight=1)
        self._block_entry = ctk.CTkEntry(
            entry_row, height=28, font=mono_font(12), placeholder_text="IP or CIDR, e.g. 10.0.0.0/8"
        )
        self._block_entry.grid(row=0, column=0, sticky="ew", padx=(0, PAD_SM))
        self._block_entry.bind("<Return>", lambda _event: self._block_add())
        self._block_reason = ctk.CTkEntry(
            entry_row, width=140, height=28, font=font(12), placeholder_text="reason"
        )
        self._block_reason.grid(row=0, column=1, padx=(0, PAD_SM))
        ctk.CTkButton(
            entry_row, text="Block", width=80, height=28, font=font(11, "bold"),
            fg_color=PALETTE["danger"], hover_color="#b03a35", command=self._block_add,
        ).grid(row=0, column=2)

        self._blocked_scroll = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._blocked_scroll.grid(row=2, column=0, sticky="nsew", pady=(PAD_SM, 0))
        self._blocked_scroll.grid_columnconfigure(0, weight=1)
        self._blocked_empty = EmptyState(self._blocked_scroll, "Nothing is blocked yet.")

    def _build_trust_pane(self) -> None:
        card = Card(self.content, title="Trusted")
        card.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(PAD_SM, 0))
        card.grid_rowconfigure(2, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)

        self._trusted_count = StatLine(body, "Entries trusted")
        self._trusted_count.grid(row=0, column=0, sticky="ew")

        entry_row = ctk.CTkFrame(body, fg_color="transparent")
        entry_row.grid(row=1, column=0, sticky="ew", pady=(PAD_SM, 0))
        entry_row.grid_columnconfigure(0, weight=1)
        self._trust_entry = ctk.CTkEntry(
            entry_row, height=28, font=mono_font(12), placeholder_text="IP or CIDR"
        )
        self._trust_entry.grid(row=0, column=0, sticky="ew", padx=(0, PAD_SM))
        self._trust_entry.bind("<Return>", lambda _event: self._trust_add())
        self._trust_label_entry = ctk.CTkEntry(
            entry_row, width=140, height=28, font=font(12), placeholder_text="label"
        )
        self._trust_label_entry.grid(row=0, column=1, padx=(0, PAD_SM))
        ctk.CTkButton(
            entry_row, text="Trust", width=80, height=28, font=font(11, "bold"),
            fg_color=PALETTE["success"], hover_color="#25823a", command=self._trust_add,
        ).grid(row=0, column=2)

        self._trusted_scroll = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._trusted_scroll.grid(row=2, column=0, sticky="nsew", pady=(PAD_SM, 0))
        self._trusted_scroll.grid_columnconfigure(0, weight=1)
        self._trusted_empty = EmptyState(self._trusted_scroll, "Nothing is trusted yet.")

    # ==================================================================
    # Data
    # ==================================================================
    def _engine(self) -> Any | None:
        return self.app.get_engine("blocklist")

    def refresh(self) -> None:
        blocked = self.db.get_blocked_ips()
        trusted = self.db.get_trusted_ips()
        self._blocked_count.set_value(f"{len(blocked):,}")
        self._trusted_count.set_value(f"{len(trusted):,}")
        self._render_blocked(blocked)
        self._render_trusted(trusted)

    def _render_blocked(self, entries: list[dict[str, Any]]) -> None:
        for row in self._blocked_rows:
            row.destroy()
        self._blocked_rows.clear()
        if not entries:
            self._blocked_empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._blocked_empty.grid_remove()
        for index, entry in enumerate(entries):
            row = HoverRow(self._blocked_scroll)
            row.grid(row=index, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(2, weight=1)

            ctk.CTkLabel(
                row, text=str(entry.get("ip_or_cidr") or "?"), font=mono_font(12, "bold"),
                text_color=PALETTE["text"], anchor="w", width=160,
            ).grid(row=0, column=0, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)
            auto = bool(entry.get("auto_added"))
            Chip(
                row, "auto" if auto else "manual",
                PALETTE["warning"] if auto else PALETTE["neutral"],
            ).grid(row=0, column=1, padx=(0, PAD_SM), pady=PAD_SM)
            ctk.CTkLabel(
                row, text=str(entry.get("reason") or "—"), font=font(11),
                text_color=PALETTE["text_muted"], anchor="w", justify="left",
            ).grid(row=0, column=2, sticky="ew", pady=PAD_SM)
            ctk.CTkLabel(
                row, text=str(entry.get("date_added") or "")[:10], font=mono_font(11),
                text_color=PALETTE["text_muted"],
            ).grid(row=0, column=3, sticky="w", padx=(0, PAD_SM), pady=PAD_SM)

            ip = str(entry.get("ip_or_cidr") or "")
            ctk.CTkButton(
                row, text="Unblock", width=90, height=26, font=font(10, "bold"),
                fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
                hover_color=PALETTE["surface_hover"],
                command=lambda value=ip: self._block_remove(value),
            ).grid(row=0, column=4, padx=PAD_SM, pady=PAD_SM)

    def _render_trusted(self, entries: list[dict[str, Any]]) -> None:
        for row in self._trusted_rows:
            row.destroy()
        self._trusted_rows.clear()
        if not entries:
            self._trusted_empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._trusted_empty.grid_remove()
        for index, entry in enumerate(entries):
            row = HoverRow(self._trusted_scroll)
            row.grid(row=index, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(2, weight=1)

            ctk.CTkLabel(
                row, text=str(entry.get("ip_or_cidr") or "?"), font=mono_font(12, "bold"),
                text_color=PALETTE["text"], anchor="w", width=160,
            ).grid(row=0, column=0, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)
            ctk.CTkLabel(
                row, text=str(entry.get("label") or "—"), font=font(11),
                text_color=PALETTE["text_muted"], anchor="w", justify="left",
            ).grid(row=0, column=2, sticky="ew", pady=PAD_SM)
            ctk.CTkLabel(
                row, text=str(entry.get("date_added") or "")[:10], font=mono_font(11),
                text_color=PALETTE["text_muted"],
            ).grid(row=0, column=3, sticky="w", padx=(0, PAD_SM), pady=PAD_SM)

            ip = str(entry.get("ip_or_cidr") or "")
            ctk.CTkButton(
                row, text="Untrust", width=90, height=26, font=font(10, "bold"),
                fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
                hover_color=PALETTE["surface_hover"],
                command=lambda value=ip: self._trust_remove(value),
            ).grid(row=0, column=4, padx=PAD_SM, pady=PAD_SM)

    # ==================================================================
    # Mutations (engine-backed; validation errors never raise past the dialog)
    # ==================================================================
    def _block_add(self) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("IP Lists", "The IP blocklist engine is not loaded.")
            return
        value = self._block_entry.get().strip()
        if not value:
            return
        added = engine.block(value, label=self._block_reason.get().strip() or "")
        if added:
            self._block_entry.delete(0, "end")
            self._block_reason.delete(0, "end")
            self.app.set_status_message(f"Blocked {value}")
        else:
            # normalize_ip rejected the input, or the entry already existed.
            self.app.set_status_message(
                f"Could not block '{value}' — invalid address, or already listed"
            )
        self.refresh()

    def _block_remove(self, ip: str) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("IP Lists", "The IP blocklist engine is not loaded.")
            return
        if engine.unblock(ip):
            self.app.set_status_message(f"Unblocked {ip}")
        self.refresh()

    def _trust_add(self) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("IP Lists", "The IP blocklist engine is not loaded.")
            return
        value = self._trust_entry.get().strip()
        if not value:
            return
        added = engine.trust(value, label=self._trust_label_entry.get().strip() or "")
        if added:
            self._trust_entry.delete(0, "end")
            self._trust_label_entry.delete(0, "end")
            self.app.set_status_message(f"Trusted {value}")
        else:
            self.app.set_status_message(
                f"Could not trust '{value}' — invalid address, or already listed"
            )
        self.refresh()

    def _trust_remove(self, ip: str) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("IP Lists", "The IP blocklist engine is not loaded.")
            return
        if engine.untrust(ip):
            self.app.set_status_message(f"Removed trust for {ip}")
        self.refresh()

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        if any(event.get("event_type") in ("IP_BLOCKED", "IP_UNBLOCKED") for event in events):
            self.refresh()
