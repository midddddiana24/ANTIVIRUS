"""Scan history view — the audit log of every scan ever run.

Each row is one ``scan_history`` record: type, target, duration, files, threats and the
severity breakdown. Clicking a row expands the per-severity detail. Data is paged the
same way the timeline view pages, so a year of scans stays navigable.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import customtkinter as ctk

from core.timeline import Severity
from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, EmptyState, HoverRow, SeverityChip, StatLine

logger = logging.getLogger(__name__)

_PAGE_SIZE = 25


class HistoryView(BaseView):
    """Browsable, paged list of past scans."""

    title = "Scan History"
    subtitle = "Every scan ShieldEX has run, with results and severity breakdown"

    def build(self) -> None:
        self._offset = 0
        self._rows: list[ctk.CTkFrame] = []
        self._expanded_id: int | None = None

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(2, weight=1)

        self._build_actions()
        self._build_summary()
        self._build_table()
        self._build_pager()

    # ================================================================== header
    def _build_actions(self) -> None:
        ctk.CTkButton(
            self.actions, text="Refresh", width=90, height=30, font=font(12, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self.refresh,
        ).grid(row=0, column=0)

    def _build_summary(self) -> None:
        card = Card(self.content, title="Lifetime totals")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD))
        body = card.body
        body.grid_columnconfigure((0, 1, 2, 3), weight=1)

        totals = self.db.get_dashboard_stats()
        antivirus = totals.get("antivirus", {})

        self._stat_scans = StatLine(body, "Total scans")
        self._stat_scans.grid(row=0, column=0, sticky="ew", padx=(0, PAD))
        self._stat_files = StatLine(body, "Files examined")
        self._stat_files.grid(row=0, column=1, sticky="ew", padx=(0, PAD))
        self._stat_threats = StatLine(body, "Threats found")
        self._stat_threats.grid(row=0, column=2, sticky="ew", padx=(0, PAD))
        self._stat_last = StatLine(body, "Last scan")
        self._stat_last.grid(row=0, column=3, sticky="ew")

    # ================================================================== table
    def _build_table(self) -> None:
        card = Card(self.content, title="Scans")
        card.grid(row=2, column=0, sticky="nsew", pady=(0, PAD))
        body = card.body
        body.grid_rowconfigure(0, weight=1)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew")
        widths = (2, 3, 1, 1, 1, 1)
        for column, text in enumerate(("Type", "Target", "Started", "Files", "Threats", "Status")):
            header.grid_columnconfigure(column, weight=widths[column])
            ctk.CTkLabel(
                header, text=text.upper(), font=font(10, "bold"),
                text_color=PALETTE["text_muted"], anchor="w",
            ).grid(row=0, column=column, sticky="w", padx=(0, PAD_SM))

        self._table_frame = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._table_frame.grid(row=1, column=0, sticky="nsew", pady=(PAD_SM, 0))
        self._table_frame.grid_columnconfigure(0, weight=1)
        EmptyState(self._table_frame, "No scans have been run yet").grid(
            row=0, column=0, pady=PAD_LG
        )

    def _build_pager(self) -> None:
        bar = ctk.CTkFrame(self.content, fg_color="transparent")
        bar.grid(row=3, column=0, sticky="ew")
        bar.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._prev_button = ctk.CTkButton(
            bar, text="← Newer", width=100, height=28, font=font(12),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._prev_page,
        )
        self._prev_button.grid(row=0, column=0, sticky="w")
        self._page_label = ctk.CTkLabel(
            bar, text="—", font=font(12), text_color=PALETTE["text_muted"]
        )
        self._page_label.grid(row=0, column=2, sticky="ew")
        self._next_button = ctk.CTkButton(
            bar, text="Older →", width=100, height=28, font=font(12),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._next_page,
        )
        self._next_button.grid(row=0, column=3, sticky="e")

    # ================================================================== data
    def refresh(self) -> None:
        try:
            history = self.db.get_scan_history(limit=_PAGE_SIZE, offset=self._offset)
            last = self.db.get_last_scan()
        except Exception as exc:
            logger.exception("Could not read scan history")
            self.app.set_status_message(f"History read failed: {exc}")
            return

        totals = self.db.get_dashboard_stats()
        antivirus = totals.get("antivirus", {})
        self._stat_scans.set_value(str(antivirus.get("total_scans", 0) or len(history)))
        self._stat_files.set_value(f"{int(antivirus.get('files_scanned', 0) or 0):,}")
        threats = int(antivirus.get("threats_found", 0) or 0)
        self._stat_threats.set_value(
            f"{threats:,}", PALETTE["danger"] if threats else PALETTE["success"]
        )
        if last:
            started = str(last.get("start_time") or "")
            self._stat_last.set_value(f"{last.get('scan_type', '?')} · {started[:16]}")
        else:
            self._stat_last.set_value("never")

        self._render(history)
        self._update_pager()

    def _render(self, history: list[dict[str, Any]]) -> None:
        for child in self._table_frame.winfo_children():
            child.destroy()
        if not history:
            EmptyState(self._table_frame, "No more scans").grid(row=0, column=0, pady=PAD_LG)
            return

        for scan in history:
            row = self._render_scan_row(scan)
            row.grid(sticky="ew", pady=(0, PAD_SM))
        if self._expanded_id is not None:
            for scan in history:
                if int(scan.get("id", 0)) == self._expanded_id:
                    self._render_expanded(scan)

    def _render_scan_row(self, scan: dict[str, Any]) -> ctk.CTkFrame:
        scan_id = int(scan.get("id", 0))
        row = HoverRow(self._table_frame, on_click=lambda i=scan_id: self._toggle(i))
        row.grid_columnconfigure(1, weight=3)
        row.activate_bindings()

        cells: list[tuple[str, str]] = [
            (str(scan.get("scan_type", "?")).title(), "normal"),
            (str(scan.get("target") or "—"), "mono"),
            (str(scan.get("start_time") or "—")[:16], "normal"),
            (f"{int(scan.get('files_scanned') or 0):,}", "normal"),
            (str(int(scan.get("threats_found") or 0)), "normal"),
            (str(scan.get("status", "?")), "normal"),
        ]
        threats = int(scan.get("threats_found") or 0)
        for column, (text, style) in enumerate(cells):
            if column == 4 and threats:
                chip = SeverityChip(row, Severity.HIGH if threats else Severity.INFO)
                chip.configure(text=f" {text} ")
                chip.grid(row=0, column=column, sticky="w", padx=(0, PAD_SM))
                continue
            ctk.CTkLabel(
                row, text=text, font=font(11) if style == "normal" else mono_font(11),
                text_color=PALETTE["text_muted"] if column == 5 else PALETTE["text"],
                anchor="w", justify="left",
            ).grid(row=0, column=column, sticky="w", padx=(0, PAD_SM))

        if self._expanded_id == scan_id:
            row.set_base_color(PALETTE["surface_hover"])
        return row

    def _toggle(self, scan_id: int) -> None:
        self._expanded_id = None if self._expanded_id == scan_id else scan_id
        self.refresh()

    def _render_expanded(self, scan: dict[str, Any]) -> None:
        panel = ctk.CTkFrame(self._table_frame, fg_color=PALETTE["surface_alt"], corner_radius=6)
        panel.grid(sticky="ew", pady=(0, PAD_SM))
        panel.grid_columnconfigure(0, weight=1)

        summary = _fmt_severity_summary(scan.get("severity_summary"))
        lines = [
            f"Scan #{scan.get('id')} · status {scan.get('status')} · "
            f"ended {str(scan.get('end_time') or '—')[:19]}",
            f"Files: {int(scan.get('files_scanned') or 0):,} · "
            f"Threats: {int(scan.get('threats_found') or 0)} · Severities: {summary}",
        ]
        for index, text in enumerate(lines):
            ctk.CTkLabel(
                panel, text=text, font=mono_font(11), text_color=PALETTE["text_muted"],
                anchor="w", justify="left",
            ).grid(row=index, column=0, sticky="ew", padx=PAD, pady=2)

    # ================================================================== paging
    def _update_pager(self) -> None:
        has_rows = bool(self._table_frame.winfo_children())
        self._page_label.configure(
            text=f"Showing newest {self._offset + 1}–{self._offset + _PAGE_SIZE}"
            if has_rows else "—"
        )
        self._prev_button.configure(state="disabled" if self._offset == 0 else "normal")
        self._next_button.configure(
            state="disabled" if not has_rows else "normal"
        )

    def _prev_page(self) -> None:
        self._offset = max(0, self._offset - _PAGE_SIZE)
        self.refresh()

    def _next_page(self) -> None:
        self._offset += _PAGE_SIZE
        self.refresh()


def _fmt_severity_summary(raw: str | None) -> str:
    """Render the stored JSON severity summary as ``'High 1 · Low 2'``."""
    if not raw:
        return "none"
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return str(raw)
    if not isinstance(data, dict) or not data:
        return "none"
    ordered = [
        f"{level} {data[level]}"
        for level in reversed(Severity.ORDER)
        if data.get(level)
    ]
    return " · ".join(ordered) if ordered else "none"
