"""Scan History view — the record of every scan this installation has run.

Read-only over ``scan_history``; each row drills into the timeline narrative via the
dashboard's drill-in contract. The severity summary JSON is rendered with the same
formatting the dashboard uses, so the two views never disagree.
"""

from __future__ import annotations

import logging
from typing import Any

import customtkinter as ctk

from core.timeline import Severity
from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, StatLine

logger = logging.getLogger(__name__)

_PAGE_SIZE = 25


class HistoryView(BaseView):
    """Browse past scans and their outcomes."""

    title = "Scan History"
    subtitle = "Every scan ever run, with results and severity breakdown"

    def build(self) -> None:
        self._rows: list[ctk.CTkFrame] = []
        self._offset = 0
        self._has_next = False

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(2, weight=1)

        self._build_summary()
        self._build_table()
        self._build_pager()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build_summary(self) -> None:
        card = Card(self.content, title="Lifetime totals")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        for column in range(4):
            body.grid_columnconfigure(column, weight=1, uniform="hist")

        self._summary: dict[str, StatLine] = {}
        for column, (key, label) in enumerate((
            ("scans", "Total scans"),
            ("files", "Files scanned"),
            ("threats", "Threats found"),
            ("failures", "Failed / cancelled"),
        )):
            line = StatLine(body, label)
            line.grid(row=0, column=column, sticky="ew", padx=PAD_SM)
            self._summary[key] = line

    def _build_table(self) -> None:
        card = Card(self.content, title="Past scans")
        card.grid(row=1, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        for column, (text, width) in enumerate((
            ("ID", 44), ("TYPE", 90), ("TARGET", 0), ("WHEN", 150),
            ("FILES", 80), ("THREATS", 80), ("SEVERITIES", 150), ("STATUS", 110),
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
            self._scroll, "No scans recorded yet.\nStart one from the Scan view."
        )

    def _build_pager(self) -> None:
        pager = ctk.CTkFrame(self.content, fg_color="transparent")
        pager.grid(row=2, column=0, sticky="ew", pady=(PAD_SM, 0))
        pager.grid_columnconfigure(0, weight=1)

        self._page_label = ctk.CTkLabel(
            pager, text="", font=font(11), text_color=PALETTE["text_muted"], anchor="w"
        )
        self._page_label.grid(row=0, column=0, sticky="w")

        self._prev_button = ctk.CTkButton(
            pager, text="◀ Newer", width=100, height=28, font=font(11, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._page_prev,
        )
        self._prev_button.grid(row=0, column=1, padx=(0, PAD_SM))
        self._next_button = ctk.CTkButton(
            pager, text="Older ▶", width=100, height=28, font=font(11, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._page_next,
        )
        self._next_button.grid(row=0, column=2)

    def _page_prev(self) -> None:
        if self._offset:
            self._offset = max(0, self._offset - _PAGE_SIZE)
            self.refresh()

    def _page_next(self) -> None:
        if self._has_next:
            self._offset += _PAGE_SIZE
            self.refresh()

    # ==================================================================
    # Data
    # ==================================================================
    def refresh(self) -> None:
        """Re-read the totals and the current page of scans."""
        totals = self.db.scan_history_totals()
        self._summary["scans"].set_value(f"{totals['scans']:,}")
        self._summary["files"].set_value(f"{totals['files']:,}")
        self._summary["threats"].set_value(
            f"{totals['threats']:,}", PALETTE["danger"] if totals["threats"] else PALETTE["text"]
        )
        self._summary["failures"].set_value(
            f"{totals['failures']:,}", PALETTE["warning"] if totals["failures"] else PALETTE["text"]
        )

        # One extra row detects a next page without a COUNT query (same trick as the
        # timeline view).
        scans = self.db.get_scan_history(limit=_PAGE_SIZE + 1, offset=self._offset)
        self._has_next = len(scans) > _PAGE_SIZE
        self._render(scans[:_PAGE_SIZE])

        first = self._offset + 1 if scans else 0
        last = self._offset + min(len(scans), _PAGE_SIZE)
        self._page_label.configure(
            text=f"Showing scans {first}–{last}" + ("  (more available)" if self._has_next else "")
        )
        self._prev_button.configure(state="normal" if self._offset else "disabled")
        self._next_button.configure(state="normal" if self._has_next else "disabled")

    def _render(self, scans: list[dict[str, Any]]) -> None:
        for row in self._rows:
            row.destroy()
        self._rows.clear()

        if not scans:
            self._empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._empty.grid_remove()

        for index, scan in enumerate(scans):
            self._rows.append(self._build_scan_row(index, scan))

    def _build_scan_row(self, index: int, scan: dict[str, Any]) -> HoverRow:
        row = HoverRow(
            self._scroll, on_click=lambda sid=int(scan.get("id") or 0): self._open(sid)
        )
        row.grid(row=index, column=0, sticky="ew", pady=2)

        def cell(text: str, column: int, width: int, mono: bool = False, color: str | None = None) -> None:
            ctk.CTkLabel(
                row, text=text, font=mono_font(11) if mono else font(12),
                text_color=color or PALETTE["text"], anchor="w", width=width,
                justify="left",
            ).grid(row=0, column=column, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)

        cell(str(scan.get("id") or ""), 0, 36, mono=True)
        cell(str(scan.get("scan_type") or "?").title(), 1, 80)
        cell(str(scan.get("target") or "—"), 2, 0)
        cell(str(scan.get("start_time") or "")[:16], 3, 140, mono=True)
        cell(f"{int(scan.get('files_scanned') or 0):,}", 4, 70, mono=True)
        threats = int(scan.get("threats_found") or 0)
        cell(str(threats), 5, 70, color=PALETTE["danger"] if threats else PALETTE["text"])
        cell(_severity_summary(scan.get("severity_summary")), 6, 140)
        status = str(scan.get("status") or "?")
        status_color = {
            "COMPLETED": PALETTE["success"], "RUNNING": PALETTE["accent"],
            "CANCELLED": PALETTE["warning"], "FAILED": PALETTE["danger"],
        }.get(status, PALETTE["neutral"])
        Chip(row, status.title(), status_color).grid(row=0, column=7, padx=PAD_SM, pady=PAD_SM)

        row.activate_bindings()
        return row

    def _open(self, scan_id: int) -> None:
        """Drill into the timeline for this scan's narrative."""
        self.app.open_timeline(source="ANTIVIRUS", search=str(scan_id))


def _severity_summary(raw: str | None) -> str:
    """Render a scan row's severity JSON as ``'High 1 · Low 2'`` (dashboard format)."""
    import json

    if not raw:
        return "—"
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return str(raw)
    if not isinstance(data, dict) or not data:
        return "none"
    ordered = [
        f"{level} {data[level]}" for level in reversed(Severity.ORDER) if data.get(level)
    ]
    return " · ".join(ordered) if ordered else "none"
