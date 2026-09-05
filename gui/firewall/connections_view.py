"""Live Connections view — the observed socket table with rule verdicts.

Shows what the connection monitor logged: process, remote endpoint, direction, the
rule that matched and the verdict. The monitor itself runs in the background; when
its engine is not running this view says so and offers to start it, because an empty
table otherwise looks like "no traffic" when it actually means "no observer".
"""

from __future__ import annotations

import logging
from typing import Any

import customtkinter as ctk

from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, StatLine

logger = logging.getLogger(__name__)


class ConnectionsView(BaseView):
    """Browse the live/recent connection log."""

    title = "Live Connections"
    subtitle = "Sockets observed by the connection monitor, with rule verdicts"

    def build(self) -> None:
        self._rows: list[ctk.CTkFrame] = []
        self._offset = 0
        self._page_size = 50
        self._has_next = False

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(3, weight=1)

        self._build_summary()
        self._build_filters()
        self._build_table()
        self._build_pager()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build_summary(self) -> None:
        card = Card(self.content, title="Monitor status")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        for column in range(4):
            body.grid_columnconfigure(column, weight=1, uniform="conns")

        self._summary: dict[str, StatLine] = {}
        for column, (key, label) in enumerate((
            ("today", "Logged today"),
            ("blocked_today", "Blocked today"),
            ("monitored", "Monitor state"),
            ("interval", "Poll interval"),
        )):
            line = StatLine(body, label)
            line.grid(row=0, column=column, sticky="ew", padx=PAD_SM)
            self._summary[key] = line

        self._monitor_button = ctk.CTkButton(
            body, text="Start monitor", width=130, height=28, font=font(11, "bold"),
            fg_color=PALETTE["success"], hover_color="#25823a", command=self._toggle_monitor,
        )
        self._monitor_button.grid(row=1, column=0, sticky="w", pady=(PAD_SM, 0))

    def _build_filters(self) -> None:
        card = Card(self.content)
        card.grid(row=1, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        body.grid_columnconfigure(5, weight=1)

        def label(text: str, column: int) -> None:
            ctk.CTkLabel(
                body, text=text, font=font(10, "bold"), text_color=PALETTE["text_muted"],
            ).grid(row=0, column=column, padx=(0, PAD_SM))

        label("ACTION", 0)
        self._action_menu = ctk.CTkOptionMenu(
            body, values=["All", "Allow", "Block", "Monitor"], width=110, height=28,
            font=font(12), fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda _value: self._reset_and_refresh(),
        )
        self._action_menu.grid(row=0, column=1, padx=(0, PAD_SM))

        label("SEARCH", 2)
        self._search_entry = ctk.CTkEntry(
            body, height=28, width=220, font=mono_font(12),
            placeholder_text="process or IP",
        )
        self._search_entry.grid(row=0, column=3, padx=(0, PAD_SM))
        self._search_entry.bind("<Return>", lambda _event: self._reset_and_refresh())

        ctk.CTkButton(
            body, text="Apply", width=80, height=28, font=font(11, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=self._reset_and_refresh,
        ).grid(row=0, column=4, padx=(0, PAD_SM))
        ctk.CTkButton(
            body, text="Clear", width=80, height=28, font=font(11, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._clear,
        ).grid(row=0, column=5, sticky="w")

    def _build_table(self) -> None:
        card = Card(self.content, title="Connections")
        card.grid(row=2, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        for column, (text, width) in enumerate((
            ("TIME", 140), ("PROCESS", 150), ("PID", 60), ("REMOTE", 0),
            ("PORT", 70), ("DIR", 90), ("ACTION", 100), ("RULE", 160),
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
            "No connections logged.\nStart the connection monitor to begin observation.",
        )

    def _build_pager(self) -> None:
        pager = ctk.CTkFrame(self.content, fg_color="transparent")
        pager.grid(row=3, column=0, sticky="ew", pady=(PAD_SM, 0))
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

    # ==================================================================
    # Data
    # ==================================================================
    def _engine(self) -> Any | None:
        return self.app.get_engine("connection_monitor")

    def _toggle_monitor(self) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error(
                "Connection monitor", "The connection monitor engine is not loaded."
            )
            return
        try:
            if engine.running:
                engine.stop()
                self.app.set_status_message("Connection monitor stopped")
            else:
                started = engine.start()
                self.app.set_status_message(
                    "Connection monitor started" if started
                    else "Connection monitor is disabled in config.json"
                )
        except Exception as exc:
            logger.error("Monitor toggle failed: %s", exc, exc_info=True)
            self.app.show_error("Connection monitor", str(exc))
        self.refresh()

    def _page_prev(self) -> None:
        if self._offset:
            self._offset = max(0, self._offset - self._page_size)
            self.refresh()

    def _page_next(self) -> None:
        if self._has_next:
            self._offset += self._page_size
            self.refresh()

    def _reset_and_refresh(self) -> None:
        self._offset = 0
        self.refresh()

    def _clear(self) -> None:
        self._action_menu.set("All")
        self._search_entry.delete(0, "end")
        self._reset_and_refresh()

    def refresh(self) -> None:
        engine = self._engine()
        running = bool(engine is not None and engine.running)
        self._summary["today"].set_value(f"{self.db.count_connections(today=True):,}")
        blocked_today = self.db.count_connections(action="BLOCKED", today=True)
        self._summary["blocked_today"].set_value(
            f"{blocked_today:,}", PALETTE["danger"] if blocked_today else PALETTE["text"]
        )
        self._summary["monitored"].set_value(
            "RUNNING" if running else "STOPPED",
            PALETTE["success"] if running else PALETTE["warning"],
        )
        interval = float(self.cfg.get("firewall.connection_monitor.poll_interval_seconds", 2))
        self._summary["interval"].set_value(f"{interval:g}s")
        self._monitor_button.configure(
            text="Stop monitor" if running else "Start monitor",
            fg_color=PALETTE["danger"] if running else PALETTE["success"],
            hover_color="#b03a35" if running else "#25823a",
        )

        action = self._action_menu.get()
        search = self._search_entry.get().strip()
        rows = self.db.get_connection_log(
            action=None if action == "All" else action,
            process=search or None,
            remote_ip=None,  # process search already covers the visible field
            limit=self._page_size + 1,
            offset=self._offset,
        )
        # The API's process filter is a LIKE; apply the same term to remote_ip by
        # post-filtering the page so an IP search works without a second query shape.
        if search:
            rows = [row for row in rows if search.lower() in str(row.get("remote_ip") or "").lower()] or rows

        self._has_next = len(rows) > self._page_size
        page = rows[: self._page_size]
        self._render(page)

        first = self._offset + 1 if page else 0
        last = self._offset + len(page)
        self._page_label.configure(
            text=f"Showing connections {first}–{last}"
            + ("  (more available)" if self._has_next else "")
        )
        self._prev_button.configure(state="normal" if self._offset else "disabled")
        self._next_button.configure(state="normal" if self._has_next else "disabled")

    def _render(self, rows: list[dict[str, Any]]) -> None:
        for row in self._rows:
            row.destroy()
        self._rows.clear()

        if not rows:
            self._empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._empty.grid_remove()

        for index, conn in enumerate(rows):
            self._rows.append(self._build_row(index, conn))

    def _build_row(self, index: int, conn: dict[str, Any]) -> HoverRow:
        row = HoverRow(
            self._scroll,
            on_click=lambda ip=str(conn.get("remote_ip") or ""): self._open_ip(ip) if ip else None,
        )
        row.grid(row=index, column=0, sticky="ew", pady=2)

        def cell(text: str, column: int, width: int, mono: bool = False, color: str | None = None) -> None:
            ctk.CTkLabel(
                row, text=text or "—", font=mono_font(11) if mono else font(12),
                text_color=color or PALETTE["text"], anchor="w", width=width, justify="left",
            ).grid(row=0, column=column, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)

        cell(str(conn.get("timestamp") or "")[:19], 0, 130, mono=True)
        cell(str(conn.get("process") or "unknown"), 1, 140)
        cell(str(conn.get("pid") or ""), 2, 50, mono=True)
        cell(str(conn.get("remote_ip") or "?"), 3, 0, mono=True)
        cell(str(conn.get("remote_port") or ""), 4, 60, mono=True)
        cell(str(conn.get("direction") or "").title(), 5, 80)
        action = str(conn.get("action") or "monitor").title()
        action_color = {
            "Allow": PALETTE["success"], "Block": PALETTE["danger"],
            "Monitor": PALETTE["neutral"],
        }.get(action, PALETTE["neutral"])
        Chip(row, action, action_color).grid(row=0, column=6, padx=PAD_SM, pady=PAD_SM)
        cell(str(conn.get("rule_matched") or "no rule"), 7, 150)

        row.activate_bindings()
        return row

    def _open_ip(self, ip: str) -> None:
        """Drill into the timeline for this remote address."""
        self.app.open_timeline(source="FIREWALL", search=ip)

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        """New connection events — refresh on the first page only."""
        if self._offset == 0 and any(
            event.get("event_type") in ("CONNECTION_BLOCKED", "CONNECTION_ATTEMPT")
            for event in events
        ):
            self.refresh()
