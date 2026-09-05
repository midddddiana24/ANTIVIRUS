"""IDS Alerts view — intrusion-detection alerts over the shared timeline.

The IDS writes its alerts as ``IDS_*`` timeline events (the prefix is what the
dashboard's alert counter keys on), so this view is a focused lens over the same
table: filter by alert type, drill into the offending IP, and hand the address to the
blocklist in one click.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from typing import Any

import customtkinter as ctk

from core.timeline import EventType
from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import (
    Card,
    Chip,
    EmptyState,
    HoverRow,
    SeverityChip,
    StatLine,
    exclude_from_row_bindings,
)

logger = logging.getLogger(__name__)

_ALERT_TYPES: tuple[str, ...] = (
    EventType.IDS_PORT_SCAN,
    EventType.IDS_SYN_FLOOD,
    EventType.IDS_AUTH_FAILURES,
    EventType.IDS_ICMP_FLOOD,
)

_RANGES: tuple[str, ...] = ("Today", "Last 7 days", "Last 30 days", "All time")


class AlertsView(BaseView):
    """Browse and act on intrusion-detection alerts."""

    title = "IDS Alerts"
    subtitle = "Port scans, SYN floods, auth failures and ICMP floods detected on this host"

    def build(self) -> None:
        self._rows: list[ctk.CTkFrame] = []
        self._expanded_id: int | None = None

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(3, weight=1)

        self._build_summary()
        self._build_filters()
        self._build_table()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build_summary(self) -> None:
        card = Card(self.content, title="Alert summary")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        for column in range(4):
            body.grid_columnconfigure(column, weight=1, uniform="ids")

        self._summary: dict[str, StatLine] = {}
        for column, (key, label) in enumerate((
            ("today", "Alerts today"),
            ("week", "Last 7 days"),
            ("scans", "Port scans"),
            ("state", "Detector state"),
        )):
            line = StatLine(body, label)
            line.grid(row=0, column=column, sticky="ew", padx=PAD_SM)
            self._summary[key] = line

    def _build_filters(self) -> None:
        card = Card(self.content)
        card.grid(row=1, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        body.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(
            body, text="ALERT TYPE", font=font(10, "bold"), text_color=PALETTE["text_muted"],
        ).grid(row=0, column=0, padx=(0, PAD_SM))
        self._type_menu = ctk.CTkOptionMenu(
            body, values=["All", *_ALERT_TYPES], width=180, height=28, font=mono_font(11),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda _value: self.refresh(),
        )
        self._type_menu.grid(row=0, column=1, padx=(0, PAD_SM))

        ctk.CTkLabel(
            body, text="RANGE", font=font(10, "bold"), text_color=PALETTE["text_muted"],
        ).grid(row=0, column=2, padx=(0, PAD_SM))
        self._range_menu = ctk.CTkOptionMenu(
            body, values=list(_RANGES), width=120, height=28, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda _value: self.refresh(),
        )
        self._range_menu.grid(row=0, column=3, sticky="w")

        self._count_label = ctk.CTkLabel(
            body, text="", font=font(11), text_color=PALETTE["text_muted"], anchor="e"
        )
        self._count_label.grid(row=0, column=4, sticky="e")

    def _build_table(self) -> None:
        card = Card(self.content, title="Alerts", subtitle="Click a row to expand actions")
        card.grid(row=2, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        for column, (text, width) in enumerate((
            ("TIME", 150), ("TYPE", 170), ("SEVERITY", 100), ("SOURCE IP", 0), ("DETAIL", 0),
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
            self._scroll,
            "No intrusion alerts.\nEither nothing hostile has been seen, or the IDS is idle.",
        )

    # ==================================================================
    # Data
    # ==================================================================
    def _range_bounds(self) -> tuple[str | None, str | None]:
        value = self._range_menu.get()
        if value == "All time":
            return None, None
        today = date.today()
        if value == "Today":
            start = today
        elif value == "Last 7 days":
            start = today - timedelta(days=6)
        else:
            start = today - timedelta(days=29)
        fmt = "%Y-%m-%d"
        return (
            datetime.combine(start, datetime.min.time()).strftime(fmt + " 00:00:00"),
            datetime.combine(today, datetime.max.time()).strftime(fmt + " 23:59:59"),
        )

    def refresh(self) -> None:
        date_from, date_to = self._range_bounds()
        selected_type = self._type_menu.get()

        events = self.timeline.query(
            source="FIREWALL",
            event_type_prefix=EventType.IDS_PREFIX,
            event_type=None if selected_type == "All" else selected_type,
            date_from=date_from,
            date_to=date_to,
            limit=200,
        )

        self._summary["today"].set_value(
            f"{self.db.count_timeline_events(source='FIREWALL', event_type_prefix=EventType.IDS_PREFIX, today=True):,}"
        )
        week_start = (date.today() - timedelta(days=6)).strftime("%Y-%m-%d 00:00:00")
        week_events = self.timeline.query(
            source="FIREWALL", event_type_prefix=EventType.IDS_PREFIX,
            date_from=week_start, limit=100_000,
        )
        self._summary["week"].set_value(f"{len(week_events):,}")
        self._summary["scans"].set_value(
            f"{sum(1 for event in week_events if event.get('event_type') == EventType.IDS_PORT_SCAN):,}"
        )

        ids_enabled = bool(self.cfg.get("firewall.ids.enabled", True))
        self._summary["state"].set_value(
            "ACTIVE" if ids_enabled else "DISABLED",
            PALETTE["success"] if ids_enabled else PALETTE["warning"],
        )

        self._count_label.configure(
            text=f"{len(events)} alert(s) shown · range: {self._range_menu.get()}"
        )
        self._render(events)

    def _render(self, events: list[dict[str, Any]]) -> None:
        for row in self._rows:
            row.destroy()
        self._rows.clear()

        if not events:
            self._empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._empty.grid_remove()

        for index, event in enumerate(events):
            self._rows.append(self._build_row(index, event))

    def _build_row(self, index: int, event: dict[str, Any]) -> HoverRow:
        event_id = int(event.get("id") or 0)
        row = HoverRow(self._scroll, on_click=lambda eid=event_id: self._toggle(eid))
        row.grid(row=index, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(4, weight=1)

        def cell(text: str, column: int, width: int, mono: bool = False, color: str | None = None) -> None:
            ctk.CTkLabel(
                row, text=text or "—", font=mono_font(11) if mono else font(12),
                text_color=color or PALETTE["text"], anchor="w", width=width, justify="left",
            ).grid(row=0, column=column, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)

        cell(str(event.get("timestamp") or "")[:19], 0, 140, mono=True)
        cell(str(event.get("event_type") or "?"), 1, 160, mono=True)
        SeverityChip(row, str(event.get("severity") or "High")).grid(
            row=0, column=2, padx=PAD_SM, pady=PAD_SM
        )
        cell(str(event.get("remote_ip") or "?"), 3, 0, mono=True)
        cell(str(event.get("event_detail") or ""), 4, 0)

        row.activate_bindings()
        if event_id and event_id == self._expanded_id:
            self._build_action_panel(row, event)
        return row

    def _toggle(self, event_id: int) -> None:
        self._expanded_id = None if self._expanded_id == event_id else event_id
        self.refresh()

    def _build_action_panel(self, row: ctk.CTkFrame, event: dict[str, Any]) -> None:
        panel = exclude_from_row_bindings(
            ctk.CTkFrame(row, fg_color=PALETTE["surface"], corner_radius=6)
        )
        panel.grid(row=1, column=0, columnspan=5, sticky="ew", padx=PAD_SM, pady=(0, PAD_SM))

        buttons = ctk.CTkFrame(panel, fg_color="transparent")
        buttons.grid(row=0, column=0, sticky="w", padx=PAD_SM, pady=PAD_SM)
        remote_ip = str(event.get("remote_ip") or "")

        if remote_ip:
            ctk.CTkButton(
                buttons, text=f"Block {remote_ip}", width=170, height=28, font=font(11, "bold"),
                fg_color=PALETTE["danger"], hover_color="#b03a35",
                command=lambda ip=remote_ip: self._block_ip(ip),
            ).grid(row=0, column=0, padx=(0, PAD_SM))
            ctk.CTkButton(
                buttons, text="View in timeline", width=150, height=28, font=font(11, "bold"),
                fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
                hover_color=PALETTE["surface_hover"],
                command=lambda ip=remote_ip: self.app.open_timeline(source="FIREWALL", search=ip),
            ).grid(row=0, column=1)

    def _block_ip(self, ip: str) -> None:
        engine = self.app.get_engine("blocklist")
        if engine is None:
            self.app.show_error("IDS Alerts", "The IP blocklist engine is not loaded.")
            return
        if not self.app.ask_yes_no(
            "Block address", f"Add {ip} to the blocked list?"
        ):
            return
        if engine.block(ip, label="manual block from IDS Alerts"):
            self.app.set_status_message(f"Blocked {ip}")
        else:
            self.app.set_status_message(f"Could not block '{ip}' — invalid or already listed")
        self.refresh()

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        if any(str(event.get("event_type") or "").startswith(EventType.IDS_PREFIX) for event in events):
            self.refresh()
