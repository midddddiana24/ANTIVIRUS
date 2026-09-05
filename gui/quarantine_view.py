"""Quarantine view — the vault: restore, delete, and inspect quarantined files.

Every action goes through the ``quarantine`` engine (never the database directly),
because the engine owns the file moves and the timeline narrative. Destructive
actions confirm first, honouring ``antivirus.quarantine.confirm_before_delete``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from tkinter import messagebox
from typing import Any

import customtkinter as ctk

from gui.base_view import BaseView
from gui.theme import PAD, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, SeverityChip, StatLine, exclude_from_row_bindings

logger = logging.getLogger(__name__)

_STATUS_FILTERS: tuple[str, ...] = ("QUARANTINED", "RESTORED", "DELETED", "ALL")


class QuarantineView(BaseView):
    """List and manage quarantined files."""

    title = "Quarantine"
    subtitle = "Neutralised threats — restore a mistaken detection or delete forever"

    def build(self) -> None:
        self._rows: list[ctk.CTkFrame] = []
        self._filter = "QUARANTINED"
        self._expanded_id: int | None = None

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(2, weight=1)

        self._build_summary()
        self._build_filters()
        self._build_list()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build_summary(self) -> None:
        card = Card(self.content, title="Vault summary")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        for column in range(4):
            body.grid_columnconfigure(column, weight=1, uniform="quar")

        self._summary_lines: dict[str, StatLine] = {}
        for column, (key, label) in enumerate((
            ("quarantined", "Quarantined now"),
            ("restored", "Restored"),
            ("deleted", "Deleted forever"),
            ("missing", "Vault files missing"),
        )):
            line = StatLine(body, label)
            line.grid(row=0, column=column, sticky="ew", padx=PAD_SM)
            self._summary_lines[key] = line

        ctk.CTkButton(
            body, text="Drop entries whose vault file is gone", height=28, font=font(11),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._cleanup_missing,
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(PAD_SM, 0))

    def _build_filters(self) -> None:
        card = Card(self.content)
        card.grid(row=1, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        ctk.CTkLabel(
            body, text="SHOW", font=font(10, "bold"), text_color=PALETTE["text_muted"],
        ).grid(row=0, column=0, padx=(0, PAD_SM))
        self._filter_menu = ctk.CTkOptionMenu(
            body, values=list(_STATUS_FILTERS), width=160, height=28, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda value: self._on_filter(value),
        )
        self._filter_menu.grid(row=0, column=1, sticky="w")
        self._count_label = ctk.CTkLabel(
            body, text="", font=font(11), text_color=PALETTE["text_muted"], anchor="e"
        )
        self._count_label.grid(row=0, column=2, sticky="e")

    def _build_list(self) -> None:
        card = Card(self.content, title="Entries", subtitle="Click a row to expand actions")
        card.grid(row=2, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        for column, (text, width) in enumerate((
            ("SEVERITY", 90), ("THREAT", 190), ("ORIGINAL PATH", 0), ("DATE", 150), ("STATUS", 110)
        )):
            header.grid_columnconfigure(column, weight=1 if width == 0 else 0)
            ctk.CTkLabel(
                header, text=text, font=font(10, "bold"), text_color=PALETTE["text_muted"],
                anchor="w", width=width,
            ).grid(row=0, column=column, sticky="w", padx=(PAD_SM, PAD_SM))

        self._scroll = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._scroll.grid(row=1, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        self._empty = EmptyState(
            self._scroll, "Quarantine is empty.\nDetections land here automatically."
        )

    # ==================================================================
    # Data
    # ==================================================================
    def _engine(self) -> Any | None:
        return self.app.get_engine("quarantine")

    def _on_filter(self, value: str) -> None:
        self._filter = value
        self.refresh()

    def refresh(self) -> None:
        """Reload summary counters and the filtered entry list."""
        engine = self._engine()
        entries = self.db.get_quarantine_entries(
            status=None if self._filter == "ALL" else self._filter
        )
        self._summary_lines["quarantined"].set_value(
            f"{self.db.quarantine_count('QUARANTINED'):,}"
        )
        self._summary_lines["restored"].set_value(f"{self.db.quarantine_count('RESTORED'):,}")
        self._summary_lines["deleted"].set_value(f"{self.db.quarantine_count('DELETED'):,}")
        missing = sum(
            1 for entry in self.db.get_quarantine_entries(status="QUARANTINED", limit=100_000)
            if not Path(str(entry.get("quarantine_path") or "")).exists()
        )
        self._summary_lines["missing"].set_value(f"{missing:,}", PALETTE["warning"] if missing else PALETTE["text"])
        self._count_label.configure(text=f"{len(entries)} entrie(s) shown · filter: {self._filter}")
        self._render(entries)

    def _render(self, entries: list[dict[str, Any]]) -> None:
        for row in self._rows:
            row.destroy()
        self._rows.clear()

        if not entries:
            self._empty.grid(row=0, column=0, pady=PAD_SM * 4)
            return
        self._empty.grid_remove()

        for index, entry in enumerate(entries):
            self._rows.append(self._build_row(index, entry))

    def _build_row(self, index: int, entry: dict[str, Any]) -> ctk.CTkFrame:
        entry_id = int(entry.get("id") or 0)
        row = HoverRow(self._scroll, on_click=lambda eid=entry_id: self._toggle(eid))
        row.grid(row=index, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(2, weight=1)

        SeverityChip(row, str(entry.get("severity") or "Info")).grid(
            row=0, column=0, padx=(PAD_SM, PAD_SM), pady=PAD_SM
        )
        ctk.CTkLabel(
            row, text=str(entry.get("threat_name") or "Unknown"), font=font(12, "bold"),
            text_color=PALETTE["text"], anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(0, PAD_SM), pady=PAD_SM)
        ctk.CTkLabel(
            row, text=str(entry.get("original_path") or "—"), font=mono_font(11),
            text_color=PALETTE["text_muted"], anchor="w", justify="left",
        ).grid(row=0, column=2, sticky="ew", pady=PAD_SM)
        ctk.CTkLabel(
            row, text=str(entry.get("date_quarantined") or "")[:16], font=mono_font(11),
            text_color=PALETTE["text_muted"], anchor="w",
        ).grid(row=0, column=3, sticky="w", padx=(0, PAD_SM), pady=PAD_SM)
        status = str(entry.get("status") or "")
        status_color = {
            "QUARANTINED": PALETTE["warning"],
            "RESTORED": PALETTE["success"],
            "DELETED": PALETTE["neutral"],
        }.get(status, PALETTE["neutral"])
        Chip(row, status.title(), status_color).grid(row=0, column=4, padx=PAD_SM, pady=PAD_SM)

        # Bindings first, then the expanded panel: bind_recursive would otherwise give
        # the panel's buttons the row's click handler too (see gui/widgets.py).
        row.activate_bindings()
        if entry_id and entry_id == self._expanded_id:
            self._build_action_panel(row, entry)
        return row

    def _toggle(self, entry_id: int) -> None:
        self._expanded_id = None if self._expanded_id == entry_id else entry_id
        self.refresh()

    def _build_action_panel(self, row: ctk.CTkFrame, entry: dict[str, Any]) -> None:
        """Detail + Restore/Delete buttons under the expanded row."""
        panel = exclude_from_row_bindings(
            ctk.CTkFrame(row, fg_color=PALETTE["surface"], corner_radius=6)
        )
        panel.grid(row=1, column=0, columnspan=5, sticky="ew", padx=PAD_SM, pady=(0, PAD_SM))
        panel.grid_columnconfigure(1, weight=1)

        fields = (
            ("Vault file", str(entry.get("quarantine_path") or "—")),
            ("SHA-256", str(entry.get("file_hash") or "—")),
            ("Scan id", str(entry.get("scan_id") or "—")),
        )
        for index, (name, value) in enumerate(fields):
            ctk.CTkLabel(
                panel, text=name, font=font(11, "bold"), text_color=PALETTE["text_muted"],
                anchor="nw", width=80,
            ).grid(row=index, column=0, sticky="nw", padx=(PAD_SM, PAD_SM), pady=2)
            ctk.CTkLabel(
                panel, text=value, font=mono_font(11), text_color=PALETTE["text"],
                anchor="w", justify="left", wraplength=640,
            ).grid(row=index, column=1, sticky="ew", padx=(0, PAD_SM), pady=2)

        if str(entry.get("status")) == "QUARANTINED":
            buttons = ctk.CTkFrame(panel, fg_color="transparent")
            buttons.grid(row=len(fields), column=0, columnspan=2, sticky="w", pady=(PAD_SM, PAD_SM))
            ctk.CTkButton(
                buttons, text="Restore to original location", width=200, height=28,
                font=font(11, "bold"), fg_color=PALETTE["success"], hover_color="#25823a",
                command=lambda eid=int(entry.get("id") or 0): self._restore(eid),
            ).grid(row=0, column=0, padx=(0, PAD_SM))
            ctk.CTkButton(
                buttons, text="Delete forever", width=140, height=28, font=font(11, "bold"),
                fg_color=PALETTE["danger"], hover_color="#b03a35",
                command=lambda eid=int(entry.get("id") or 0): self._delete(eid),
            ).grid(row=0, column=1)

    def _restore(self, entry_id: int) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("Quarantine", "The quarantine engine is not loaded.")
            return
        entry = self.db.get_quarantine_entry(entry_id)
        original = str(entry.get("original_path")) if entry else ""
        if self.app.ask_yes_no(
            "Restore file",
            f"Put the file back at:\n{original}\n\n"
            "Anything currently at that path will be overwritten. Continue?",
        ):
            try:
                restored = engine.restore(entry_id)
                self.app.set_status_message(f"Restored {restored}")
            except Exception as exc:
                logger.error("Restore failed: %s", exc, exc_info=True)
                self.app.show_error("Restore failed", str(exc))
                return
            self._expanded_id = None
            self.refresh()

    def _delete(self, entry_id: int) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("Quarantine", "The quarantine engine is not loaded.")
            return
        confirm_needed = bool(self.cfg.get("antivirus.quarantine.confirm_before_delete", True))
        if confirm_needed and not self.app.ask_yes_no(
            "Delete forever",
            "The vault copy and its record will be permanently deleted.\n"
            "This cannot be undone. Continue?",
        ):
            return
        try:
            engine.delete_forever(entry_id)
        except Exception as exc:
            logger.error("Delete failed: %s", exc, exc_info=True)
            self.app.show_error("Delete failed", str(exc))
            return
        self._expanded_id = None
        self.refresh()

    # ==================================================================
    # Actions
    # ==================================================================
    def _cleanup_missing(self) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("Quarantine", "The quarantine engine is not loaded.")
            return
        removed = engine.delete_missing_files()
        self.app.set_status_message(
            f"Dropped {removed} missing vault entrie(s)" if removed else "No missing vault files"
        )
        self.refresh()

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        """A new quarantine/restore/removal event lands — refresh immediately."""
        if any(
            event.get("event_type") in ("QUARANTINE_ACTION", "QUARANTINE_RESTORED", "THREAT_REMOVED")
            for event in events
        ):
            self.refresh()
