"""Quarantine view — browse, inspect, restore or permanently delete vaulted files.

The vault holds files moved there by the scanner (auto-quarantine) or the real-time
monitor. Restoring is the escape hatch for false positives, so it asks before
overwriting whatever now sits at the original location; deleting is permanent and asks
too. Both confirmations route through the shell's dialogs so they stay modal to the app.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import customtkinter as ctk

from core.antivirus.quarantine import QuarantineError, QuarantineManager
from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, SeverityChip, StatLine

logger = logging.getLogger(__name__)

_STATUS_FILTERS: tuple[str, ...] = ("QUARANTINED", "RESTORED", "DELETED", "ALL")


class QuarantineView(BaseView):
    """The quarantine vault management view."""

    title = "Quarantine"
    subtitle = "Files moved out of harm's way — restore them or delete them for good"

    def build(self) -> None:
        self._status_filter = ctk.StringVar(value="QUARANTINED")
        self._entries: list[dict[str, Any]] = []
        self._selected_id: int | None = None

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_columnconfigure(1, weight=0)
        self.content.grid_rowconfigure(2, weight=1)

        self._build_actions()
        self._build_summary()
        self._build_list()
        self._build_detail()

    # ================================================================== header
    def _build_actions(self) -> None:
        self._refresh_button = ctk.CTkButton(
            self.actions, text="Refresh", width=90, height=30, font=font(12, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self.refresh,
        )
        self._refresh_button.grid(row=0, column=0)

    def _build_summary(self) -> None:
        card = Card(self.content, title="Vault")
        card.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, PAD))
        body = card.body
        body.grid_columnconfigure((0, 1, 2, 3), weight=1)

        for column, (label, variable) in enumerate((
            ("Quarantined", "QUARANTINED"), ("Restored", "RESTORED"),
            ("Deleted", "DELETED"), ("Showing", None),
        )):
            stat = StatLine(body, label)
            stat.grid(row=0, column=column, sticky="ew", padx=(0, PAD))
            if variable is None:
                self._stat_showing = stat
            else:
                setattr(self, f"_stat_{variable.lower()}", stat)

        filters = ctk.CTkFrame(body, fg_color="transparent")
        filters.grid(row=1, column=0, columnspan=4, sticky="w", pady=(PAD_SM, 0))
        ctk.CTkLabel(
            filters, text="Show:", font=font(12), text_color=PALETTE["text_muted"]
        ).grid(row=0, column=0, padx=(0, PAD_SM))
        for index, value in enumerate(_STATUS_FILTERS):
            ctk.CTkRadioButton(
                filters, text=value.title(), value=value, variable=self._status_filter,
                font=font(11), command=self.refresh,
            ).grid(row=0, column=index + 1, padx=(0, PAD))

    # ================================================================== list
    def _build_list(self) -> None:
        card = Card(self.content, title="Files")
        card.grid(row=2, column=0, sticky="nsew", padx=(0, PAD))
        body = card.body
        body.grid_rowconfigure(0, weight=1)

        self._list_frame = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._list_frame.grid(row=0, column=0, sticky="nsew")
        self._list_frame.grid_columnconfigure(0, weight=1)
        self._list_empty = EmptyState(self._list_frame, "Nothing in the quarantine vault")
        self._list_empty.grid(row=0, column=0, pady=PAD_LG)

    def _build_detail(self) -> None:
        card = Card(self.content, title="Selected file")
        card.grid(row=2, column=1, sticky="ns", padx=(0, 0))
        card.grid_columnconfigure(0, weight=1, minsize=380)

        self._detail_frame = card.body
        self._detail_frame.grid_columnconfigure(0, weight=1)
        self._detail_empty = EmptyState(
            self._detail_frame, "Select a file to see its details"
        )
        self._detail_empty.grid(row=0, column=0, pady=PAD_LG)

    # ================================================================== manager
    def _manager(self) -> QuarantineManager:
        engine = self.app.get_engine("quarantine")
        if engine is not None:
            return engine
        return QuarantineManager(self.cfg, self.db, self.timeline)

    # ================================================================== data
    def refresh(self) -> None:
        status = self._status_filter.get()
        wanted = None if status == "ALL" else status
        try:
            self._entries = self._manager().entries(status=wanted)
        except Exception as exc:
            logger.exception("Could not list quarantine entries")
            self.app.set_status_message(f"Quarantine read failed: {exc}")
            self._entries = []
        self._render_list()
        self._update_stats()

    def _update_stats(self) -> None:
        manager = self._manager()
        self._stat_quarantined.set_value(f"{manager.count('QUARANTINED'):,}")
        self._stat_restored.set_value(f"{manager.count('RESTORED'):,}")
        self._stat_deleted.set_value(f"{manager.count('DELETED'):,}")
        self._stat_showing.set_value(f"{len(self._entries):,}")

    def _render_list(self) -> None:
        for child in self._list_frame.winfo_children():
            child.destroy()
        if not self._entries:
            EmptyState(self._list_frame, "No entries for this filter").grid(
                row=0, column=0, pady=PAD_LG
            )
            self._selected_id = None
            self._render_detail(None)
            return

        for entry in self._entries:
            self._render_entry_row(entry)

    def _render_entry_row(self, entry: dict[str, Any]) -> None:
        row = HoverRow(self._list_frame, on_click=lambda e=entry: self._select(e))
        row.grid(sticky="ew", pady=(0, PAD_SM))
        row.grid_columnconfigure(1, weight=1)
        SeverityChip(row, str(entry.get("severity", "Low"))).grid(
            row=0, column=0, padx=(0, PAD), pady=PAD_SM
        )

        text = ctk.CTkFrame(row, fg_color="transparent")
        text.grid(row=0, column=1, sticky="ew", padx=(0, PAD))
        text.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            text, text=Path(str(entry.get("original_path", "?"))).name,
            font=font(12, "bold"), anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            text, text=str(entry.get("threat_name", "")), font=font(11),
            text_color=PALETTE["text_muted"], anchor="w",
        ).grid(row=1, column=0, sticky="ew")
        row.activate_bindings()

        if self._selected_id == int(entry.get("id", 0)):
            row.set_base_color(PALETTE["surface_hover"])

    def _select(self, entry: dict[str, Any]) -> None:
        self._selected_id = int(entry.get("id", 0))
        self._render_detail(entry)
        for child in self._list_frame.winfo_children():
            try:
                child.set_base_color(PALETTE["surface_alt"])
            except AttributeError:
                pass
        self._render_list()

    # ================================================================== detail
    def _render_detail(self, entry: dict[str, Any] | None) -> None:
        for child in self._detail_frame.winfo_children():
            child.destroy()
        if entry is None:
            EmptyState(self._detail_frame, "Select a file to see its details").grid(
                row=0, column=0, pady=PAD_LG
            )
            return

        frame = ctk.CTkFrame(self._detail_frame, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)

        def line(label: str, value: str, row: int, mono: bool = False) -> None:
            stat = StatLine(frame, label, value or "—", monospace=mono)
            stat.grid(row=row, column=0, sticky="ew", pady=(0, PAD_SM))

        line("Threat", str(entry.get("threat_name", "—")), 0)
        line("Severity", str(entry.get("severity", "—")), 1)
        line("Status", str(entry.get("status", "—")), 2)
        line("Original path", str(entry.get("original_path", "—")), 3, mono=True)
        line("Vault location", str(entry.get("quarantine_path", "—")), 4, mono=True)
        line("SHA-256", str(entry.get("file_hash") or "—"), 5, mono=True)
        line("Quarantined at", str(entry.get("date_quarantined", "—")), 6)

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.grid(row=7, column=0, sticky="ew", pady=(PAD, 0))
        buttons.grid_columnconfigure((0, 1), weight=1)

        can_act = str(entry.get("status")) == "QUARANTINED"
        state = "normal" if can_act else "disabled"
        self._restore_button = ctk.CTkButton(
            buttons, text="Restore File", height=32, font=font(12, "bold"),
            fg_color=PALETTE["success"], hover_color="#24824a",
            state=state, command=lambda: self._restore(entry),
        )
        self._restore_button.grid(row=0, column=0, sticky="ew", padx=(0, PAD_SM))
        self._delete_button = ctk.CTkButton(
            buttons, text="Delete Forever", height=32, font=font(12, "bold"),
            fg_color=PALETTE["danger"], hover_color="#b83833",
            state=state, command=lambda: self._delete(entry),
        )
        self._delete_button.grid(row=0, column=1, sticky="ew")

    # ================================================================== actions
    def _restore(self, entry: dict[str, Any]) -> None:
        entry_id = int(entry.get("id", 0))
        original = str(entry.get("original_path", "the original location"))
        if Path(original).exists() and not self.app.ask_yes_no(
            "Overwrite existing file",
            f"{original} already exists.\n\nRestoring will overwrite it. Continue?",
        ):
            return
        try:
            restored = self._manager().restore(entry_id)
            self.app.show_info("Restored", f"The file was restored to:\n{restored}")
        except QuarantineError as exc:
            self.app.show_error("Restore failed", str(exc))
        self.refresh()

    def _delete(self, entry: dict[str, Any]) -> None:
        entry_id = int(entry.get("id", 0))
        name = Path(str(entry.get("original_path", "?"))).name
        if not self.app.ask_yes_no(
            "Delete permanently",
            f"Delete {name} from the quarantine vault for good?\n\nThis cannot be undone.",
        ):
            return
        try:
            self._manager().delete_forever(entry_id)
            self.app.set_status_message(f"Deleted {name} permanently")
        except QuarantineError as exc:
            self.app.show_error("Delete failed", str(exc))
        self._selected_id = None
        self.refresh()
