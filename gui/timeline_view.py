"""Threat Behavior Timeline view — the signature feature of ShieldEX.

One chronological log of both engines. Antivirus rows are tinted red, firewall rows blue,
system rows neutral, so a mixed incident reads as a single story: a file lands in %TEMP%,
gets hashed, matches a signature, is quarantined — or an IP hits closed ports, trips the
port-scan detector, and gets blocked.

Filtering, paging and export all run against the same
:meth:`core.timeline.TimelineLogger.query`, so what you export is exactly what the filters
describe.
"""

from __future__ import annotations

import logging
import os
from datetime import date, datetime, timedelta
from pathlib import Path
from tkinter import filedialog
from typing import Any

import customtkinter as ctk

from core.timeline import EventType, Severity, Source
from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font, source_color
from gui.widgets import (
    Card,
    EmptyState,
    HoverRow,
    SeverityChip,
    SourceBadge,
    exclude_from_row_bindings,
)

logger = logging.getLogger(__name__)

_ALL = "All"
_ANY = "Any"
_DATE_FORMAT = "%Y-%m-%d"

#: Quick date ranges offered in the filter bar.
_RANGES: tuple[str, ...] = ("Today", "Last 7 days", "Last 30 days", "All time", "Custom")

#: Row tint per source, so a mixed incident is readable at a glance (spec: blue = firewall,
#: red = antivirus). Kept subtle enough that the severity chip still carries the alarm.
_ROW_TINT: dict[str, tuple[str, str]] = {
    Source.ANTIVIRUS: ("#fbeceb", "#3a2422"),
    Source.FIREWALL: ("#eaf1fa", "#1e2c3c"),
    Source.SYSTEM: ("#f1f2f4", "#26282c"),
}


def _event_type_choices() -> list[str]:
    """Every event type constant declared on :class:`core.timeline.EventType`."""
    values = {
        value
        for name, value in vars(EventType).items()
        if name.isupper() and isinstance(value, str) and name != "IDS_PREFIX"
    }
    return [_ALL, *sorted(values)]


class TimelineView(BaseView):
    """Filterable, colour-coded, exportable view over the ``threat_timeline`` table."""

    title = "Threat Behavior Timeline"
    subtitle = "Every antivirus and firewall event in one chronological incident log"

    def build(self) -> None:
        # CHANGED: 100, not 200. Each row is a canvas-backed customtkinter frame with
        # ~7 children; 200 of them take seconds to build and re-layout, which froze the
        # UI on every refresh tick while this view was visible. 100 keeps roughly two
        # screens of scroll context at a quarter of the construction cost.
        self._page_size = max(20, min(100, int(self.cfg.get("ui.timeline_page_size", 100))))
        self._offset = 0
        self._has_next = False
        self._rows: list[ctk.CTkFrame] = []
        self._expanded_id: int | None = None
        self._events: list[dict[str, Any]] = []
        #: Identity of what is currently on screen, so refresh() can skip rebuilding
        #: an identical page (see refresh).
        self._rendered_signature: tuple[Any, ...] | None = None
        #: Debounce timer id for live-event-driven refreshes; None when idle.
        self._live_refresh_after: str | None = None
        #: Last date text this view wrote or acted on, so ``<FocusOut>`` can tell a real
        #: edit from merely tabbing out of an untouched box.
        self._last_date_text: tuple[str, str] = ("", "")

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

        self._build_actions()
        self._build_filters()
        self._build_results()
        self._build_pager()
        self._apply_range("Last 7 days")

    # ==================================================================
    # Header actions
    # ==================================================================
    def _build_actions(self) -> None:
        ctk.CTkButton(
            self.actions, text="Refresh", width=90, height=30, font=font(12, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self.refresh,
        ).grid(row=0, column=0, padx=(0, PAD_SM))
        ctk.CTkButton(
            self.actions, text="Export CSV", width=110, height=30, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=lambda: self._export("csv"),
        ).grid(row=0, column=1, padx=(0, PAD_SM))
        ctk.CTkButton(
            self.actions, text="Export TXT", width=110, height=30, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=lambda: self._export("txt"),
        ).grid(row=0, column=2)

    # ==================================================================
    # Filter bar
    # ==================================================================
    def _build_filters(self) -> None:
        card = Card(self.content, title="Filters")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD))
        body = card.body
        body.grid_columnconfigure(6, weight=1)

        def label(text: str, column: int) -> None:
            ctk.CTkLabel(
                body, text=text, font=font(10, "bold"), text_color=PALETTE["text_muted"], anchor="w"
            ).grid(row=0, column=column, sticky="w", padx=(0, PAD_SM))

        label("SOURCE", 0)
        self._source_menu = ctk.CTkOptionMenu(
            body,
            values=[_ALL, Source.ANTIVIRUS, Source.FIREWALL, Source.SYSTEM],
            width=130, height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda _value: self._reset_and_refresh(),
        )
        self._source_menu.grid(row=1, column=0, sticky="w", padx=(0, PAD_SM))

        label("MIN SEVERITY", 1)
        self._severity_menu = ctk.CTkOptionMenu(
            body,
            values=[_ANY, *Severity.ORDER],
            width=120, height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda _value: self._reset_and_refresh(),
        )
        self._severity_menu.grid(row=1, column=1, sticky="w", padx=(0, PAD_SM))

        label("EVENT TYPE", 2)
        self._type_menu = ctk.CTkOptionMenu(
            body,
            values=_event_type_choices(),
            width=200, height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda _value: self._reset_and_refresh(),
        )
        self._type_menu.grid(row=1, column=2, sticky="w", padx=(0, PAD_SM))

        label("RANGE", 3)
        self._range_menu = ctk.CTkOptionMenu(
            body,
            values=list(_RANGES),
            width=120, height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=self._on_range_selected,
        )
        self._range_menu.grid(row=1, column=3, sticky="w", padx=(0, PAD_SM))

        label("FROM / TO", 4)
        dates = ctk.CTkFrame(body, fg_color="transparent")
        dates.grid(row=1, column=4, columnspan=2, sticky="w", padx=(0, PAD_SM))
        self._from_entry = ctk.CTkEntry(
            dates, width=110, height=30, font=mono_font(12), placeholder_text="YYYY-MM-DD"
        )
        self._from_entry.grid(row=0, column=0)
        ctk.CTkLabel(dates, text="→", font=font(12), text_color=PALETTE["text_muted"]).grid(
            row=0, column=1, padx=4
        )
        self._to_entry = ctk.CTkEntry(
            dates, width=110, height=30, font=mono_font(12), placeholder_text="YYYY-MM-DD"
        )
        self._to_entry.grid(row=0, column=2)
        for entry in (self._from_entry, self._to_entry):
            entry.bind("<Return>", lambda _event: self._on_dates_edited())
            entry.bind("<FocusOut>", lambda _event: self._on_dates_edited())

        label("SEARCH (PATH, IP, TEXT)", 6)
        search_box = ctk.CTkFrame(body, fg_color="transparent")
        search_box.grid(row=1, column=6, sticky="ew")
        search_box.grid_columnconfigure(0, weight=1)
        self._search_entry = ctk.CTkEntry(
            search_box, height=30, font=font(12),
            # os.sep so the hint reads naturally on Windows and POSIX alike.
            placeholder_text=(
                f"e.g. 185.220.101.4  ·  {os.sep}Temp{os.sep}  ·  invoice.pdf.exe"
            ),
        )
        self._search_entry.grid(row=0, column=0, sticky="ew", padx=(0, PAD_SM))
        self._search_entry.bind("<Return>", lambda _event: self._reset_and_refresh())
        ctk.CTkButton(
            search_box, text="Apply", width=76, height=30, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=self._reset_and_refresh,
        ).grid(row=0, column=1, padx=(0, PAD_SM))
        ctk.CTkButton(
            search_box, text="Clear", width=76, height=30, font=font(12, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._clear_filters,
        ).grid(row=0, column=2)

    def _on_range_selected(self, value: str) -> None:
        """Quick range chosen: fill the date entries, then requery."""
        self._apply_range(value)
        self._reset_and_refresh()

    def _apply_range(self, value: str) -> None:
        """Write the concrete dates implied by ``value`` into the from/to entries."""
        today = date.today()
        if value == "Today":
            start, end = today, today
        elif value == "Last 7 days":
            start, end = today - timedelta(days=6), today
        elif value == "Last 30 days":
            start, end = today - timedelta(days=29), today
        elif value == "All time":
            start = end = None  # type: ignore[assignment]
        else:  # Custom — leave whatever the user typed alone
            return

        self._range_menu.set(value)
        for entry, moment in ((self._from_entry, start), (self._to_entry, end)):
            entry.delete(0, "end")
            if moment is not None:
                entry.insert(0, moment.strftime(_DATE_FORMAT))
        self._last_date_text = self._date_text()

    def _date_text(self) -> tuple[str, str]:
        """Current contents of the from/to date entries."""
        return (self._from_entry.get().strip(), self._to_entry.get().strip())

    def _on_dates_edited(self) -> None:
        """A date box changed: switch the range menu to Custom and requery.

        Guarded against no-op edits because this is also bound to ``<FocusOut>``, which
        fires on plain tabbing. Without the guard, moving focus out of an untouched date
        box silently relabelled the range "Custom" and threw away the page offset — so
        clicking "Older" right after touching a date box jumped back to page one.
        """
        current = self._date_text()
        if current == self._last_date_text:
            return
        self._last_date_text = current
        if self._range_menu.get() != "Custom":
            self._range_menu.set("Custom")
        self._reset_and_refresh()

    def _clear_filters(self) -> None:
        """Reset every filter to its default and reload."""
        self._source_menu.set(_ALL)
        self._severity_menu.set(_ANY)
        self._type_menu.set(_ALL)
        self._search_entry.delete(0, "end")
        self._apply_range("Last 7 days")
        self._reset_and_refresh()

    # ==================================================================
    # Results table
    # ==================================================================
    def _build_results(self) -> None:
        card = Card(self.content, title="Events")
        card.grid(row=1, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        for index, (text, width) in enumerate(
            (("TIME", 150), ("SOURCE", 96), ("EVENT TYPE", 190), ("SEVERITY", 86), ("DETAIL", 0))
        ):
            header.grid_columnconfigure(index, weight=1 if width == 0 else 0)
            ctk.CTkLabel(
                header, text=text, font=font(10, "bold"), text_color=PALETTE["text_muted"],
                anchor="w", width=width,  # 0 lets the DETAIL column size itself
            ).grid(row=0, column=index, sticky="w", padx=(PAD_SM, PAD_SM))

        self._scroll = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._scroll.grid(row=1, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        self._empty = EmptyState(
            self._scroll, "No events match these filters.\nWiden the date range or clear the search."
        )

    def _build_pager(self) -> None:
        pager = ctk.CTkFrame(self.content, fg_color="transparent")
        pager.grid(row=2, column=0, sticky="ew", pady=(PAD, 0))
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
            self._offset = max(0, self._offset - self._page_size)
            self.refresh()

    def _page_next(self) -> None:
        if self._has_next:
            self._offset += self._page_size
            self.refresh()

    # ==================================================================
    # Query + render
    # ==================================================================
    def _parse_date(self, raw: str, end_of_day: bool) -> str | None:
        """``'2026-09-04'`` → a full timestamp, or None when blank/invalid."""
        text = raw.strip()
        if not text:
            return None
        try:
            parsed = datetime.strptime(text, _DATE_FORMAT)
        except ValueError:
            self.app.set_status_message(f"Ignoring invalid date '{text}' — use YYYY-MM-DD")
            return None
        suffix = "23:59:59" if end_of_day else "00:00:00"
        return f"{parsed.strftime(_DATE_FORMAT)} {suffix}"

    def _current_filters(self) -> dict[str, Any]:
        """The filter bar translated into keyword arguments for ``TimelineLogger.query``."""
        source = self._source_menu.get()
        severity = self._severity_menu.get()
        event_type = self._type_menu.get()
        return {
            "source": None if source == _ALL else source,
            "min_severity": None if severity == _ANY else severity,
            "event_type": None if event_type == _ALL else event_type,
            "search": self._search_entry.get().strip() or None,
            "date_from": self._parse_date(self._from_entry.get(), end_of_day=False),
            "date_to": self._parse_date(self._to_entry.get(), end_of_day=True),
        }

    def _reset_and_refresh(self) -> None:
        """Filters changed: go back to the first page before reloading."""
        self._offset = 0
        self._expanded_id = None
        self.refresh()

    def refresh(self) -> None:
        """Run the current query and redraw the table — skipping the redraw when the
        page is unchanged.

        This view re-renders on the shell's 5-second polling tick and on every live
        event batch. Rebuilding 200 canvas-backed rows (≈1,400 widget constructions)
        freezes the UI for around a second each time, which made the whole app feel
        laggy whenever the timeline was visible — so identical data now short-circuits
        the redraw entirely.
        """
        filters = self._current_filters()
        try:
            # One extra row tells us whether an "Older" page exists without a COUNT query.
            fetched = self.timeline.query(
                limit=self._page_size + 1, offset=self._offset, **filters
            )
        except Exception as exc:
            logger.error("Timeline query failed: %s", exc, exc_info=True)
            self.app.show_error("Timeline", f"Could not read the timeline:\n{exc}")
            return

        self._has_next = len(fetched) > self._page_size
        self._events = fetched[: self._page_size]

        signature = (self._offset, self._expanded_id, tuple(
            int(event.get("id") or 0) for event in self._events
        ))
        if signature == self._rendered_signature:
            self._update_pager()  # counts can change even when ids did not
            return
        self._rendered_signature = signature

        self._render_rows()
        self._update_pager()

    def _update_pager(self) -> None:
        """Refresh the 'Showing events X–Y' line and the pager button states."""
        first = self._offset + 1 if self._events else 0
        last = self._offset + len(self._events)
        self._page_label.configure(
            text=f"Showing events {first}–{last}"
            + ("  (more available)" if self._has_next else "")
            + f"   ·   page size {self._page_size}"
        )
        self._prev_button.configure(state="normal" if self._offset else "disabled")
        self._next_button.configure(state="normal" if self._has_next else "disabled")

    def _render_rows(self) -> None:
        """Rebuild the visible rows, re-opening whichever row was expanded."""
        for row in self._rows:
            row.destroy()
        self._rows.clear()

        if not self._events:
            self._empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._empty.grid_remove()

        for index, event in enumerate(self._events):
            self._rows.append(self._build_row(index, event))

    def _build_row(self, index: int, event: dict[str, Any]) -> ctk.CTkFrame:
        """Create one timeline row (plus its detail panel when expanded)."""
        source = str(event.get("source") or Source.SYSTEM).upper()
        tint = _ROW_TINT.get(source, _ROW_TINT[Source.SYSTEM])
        event_id = int(event.get("id") or 0)

        row = HoverRow(self._scroll, on_click=lambda eid=event_id: self._toggle_expand(eid))
        row.set_base_color(tint)
        row.grid(row=index, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(5, weight=1)

        # Left edge stripe: the fastest visual cue for which engine spoke.
        stripe = ctk.CTkFrame(row, fg_color=source_color(source), width=4, corner_radius=2)
        stripe.grid(row=0, column=0, sticky="ns", padx=(4, PAD_SM), pady=4)

        ctk.CTkLabel(
            row, text=str(event.get("timestamp") or ""), font=mono_font(11),
            text_color=PALETTE["text_muted"], width=140, anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(0, PAD_SM), pady=PAD_SM)

        SourceBadge(row, source).grid(row=0, column=2, padx=(0, PAD_SM), pady=PAD_SM)

        ctk.CTkLabel(
            row, text=str(event.get("event_type") or ""), font=mono_font(11),
            text_color=PALETTE["text"], width=180, anchor="w",
        ).grid(row=0, column=3, sticky="w", padx=(0, PAD_SM), pady=PAD_SM)

        SeverityChip(row, str(event.get("severity") or Severity.INFO)).grid(
            row=0, column=4, padx=(0, PAD_SM), pady=PAD_SM
        )

        subject = event.get("file_path") or event.get("remote_ip") or ""
        detail = str(event.get("event_detail") or "")
        if subject:
            detail = f"{detail}  ·  {subject}" if detail else str(subject)
        ctk.CTkLabel(
            row, text=detail, font=font(12), text_color=PALETTE["text"], anchor="w", justify="left",
        ).grid(row=0, column=5, sticky="ew", padx=(0, PAD_SM), pady=PAD_SM)

        # CHANGED: bindings are attached to the summary row *before* the detail panel is
        # built. bind_recursive walks every descendant, so building the panel first gave its
        # three buttons the row's click handler too — each press ran its own command and
        # then collapsed (and destroyed) the row it was sitting in. The panel is also
        # explicitly excluded, so this stays correct if the order is ever changed back.
        row.activate_bindings()

        if event_id and event_id == self._expanded_id:
            self._build_detail_panel(row, event)
        return row

    def _build_detail_panel(self, row: ctk.CTkFrame, event: dict[str, Any]) -> None:
        """Expanded detail block shown under a clicked row."""
        panel = exclude_from_row_bindings(
            ctk.CTkFrame(row, fg_color=PALETTE["surface"], corner_radius=6)
        )
        panel.grid(row=1, column=1, columnspan=5, sticky="ew", padx=(0, PAD_SM), pady=(0, PAD_SM))
        panel.grid_columnconfigure(1, weight=1)

        fields = (
            ("Event ID", str(event.get("id", ""))),
            ("Timestamp", str(event.get("timestamp") or "")),
            ("Source", str(event.get("source") or "")),
            ("Event type", str(event.get("event_type") or "")),
            ("Severity", str(event.get("severity") or "")),
            ("File path", str(event.get("file_path") or "—")),
            ("Remote IP", str(event.get("remote_ip") or "—")),
            ("Detail", str(event.get("event_detail") or "—")),
        )
        for index, (name, value) in enumerate(fields):
            ctk.CTkLabel(
                panel, text=name, font=font(11, "bold"), text_color=PALETTE["text_muted"],
                anchor="nw", width=90,
            ).grid(row=index, column=0, sticky="nw", padx=(PAD_SM, PAD_SM), pady=2)
            ctk.CTkLabel(
                panel, text=value, font=mono_font(11), text_color=PALETTE["text"],
                anchor="w", justify="left", wraplength=760,
            ).grid(row=index, column=1, sticky="ew", padx=(0, PAD_SM), pady=2)

        buttons = ctk.CTkFrame(panel, fg_color="transparent")
        buttons.grid(row=len(fields), column=1, sticky="w", pady=(PAD_SM, PAD_SM))

        column = 0
        subject = event.get("file_path") or event.get("remote_ip")
        if subject:
            ctk.CTkButton(
                buttons, text=f"Filter by {subject}"[:44], width=200, height=26,
                font=font(11, "bold"), fg_color=PALETTE["accent"],
                hover_color=PALETTE["accent_hover"],
                command=lambda text=str(subject): self._filter_by(text),
            ).grid(row=0, column=column, padx=(0, PAD_SM))
            column += 1

        ctk.CTkButton(
            buttons, text="Copy detail", width=110, height=26, font=font(11, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"],
            command=lambda: self._copy_to_clipboard(event),
        ).grid(row=0, column=column, padx=(0, PAD_SM))
        column += 1

        ctk.CTkButton(
            buttons, text="Export this event", width=150, height=26, font=font(11, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"],
            command=lambda: self._export("txt", single=event),
        ).grid(row=0, column=column)

    def _toggle_expand(self, event_id: int) -> None:
        """Open the clicked row's detail panel, or close it if already open."""
        self._expanded_id = None if self._expanded_id == event_id else event_id
        self._render_rows()

    def _filter_by(self, text: str) -> None:
        """Put a path or IP into the search box and requery."""
        self._search_entry.delete(0, "end")
        self._search_entry.insert(0, text)
        self._apply_range("All time")
        self._reset_and_refresh()

    def _copy_to_clipboard(self, event: dict[str, Any]) -> None:
        """Copy a one-line summary of the event to the system clipboard."""
        line = (
            f"{event.get('timestamp','')} [{event.get('source','')}] "
            f"{event.get('event_type','')} ({event.get('severity','')}) "
            f"{event.get('event_detail','')} "
            f"{event.get('file_path') or event.get('remote_ip') or ''}".strip()
        )
        try:
            self.clipboard_clear()
            self.clipboard_append(line)
            self.app.set_status_message("Event copied to clipboard")
        except Exception as exc:  # clipboard access can fail on bare X11 sessions
            logger.warning("Clipboard copy failed: %s", exc)
            self.app.set_status_message(f"Could not access the clipboard: {exc}")

    # ==================================================================
    # Export
    # ==================================================================
    def _export(self, fmt: str, single: dict[str, Any] | None = None) -> None:
        """Export one event, or every event matching the current filters, to CSV/TXT."""
        default_name = (
            f"shieldex_event_{single.get('id')}.{fmt}"
            if single
            else f"shieldex_timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        )
        try:
            chosen = filedialog.asksaveasfilename(
                parent=self,
                title=f"Export timeline as {fmt.upper()}",
                defaultextension=f".{fmt}",
                initialfile=default_name,
                initialdir=str(Path.home()),
                filetypes=[("CSV file", "*.csv"), ("Text file", "*.txt"), ("All files", "*.*")],
            )
        except Exception as exc:
            # The native save dialog can fail outright on a headless or broken display.
            logger.error("Could not open the save dialog: %s", exc, exc_info=True)
            self.app.show_error("Export failed", f"Could not open the save dialog:\n{exc}")
            return
        if not chosen:
            return

        try:
            if single is not None:
                written = self.timeline.export(chosen, events=[single], fmt=fmt)
            else:
                # Export the whole filtered set, not just the visible page.
                written = self.timeline.export(chosen, fmt=fmt, **self._current_filters())
        except OSError as exc:
            logger.error("Timeline export failed: %s", exc, exc_info=True)
            self.app.show_error("Export failed", f"Could not write {chosen}:\n{exc}")
            return
        except Exception as exc:
            logger.error("Timeline export failed: %s", exc, exc_info=True)
            self.app.show_error("Export failed", str(exc))
            return

        self.app.set_status_message(f"Exported {written} event(s) to {chosen}")
        self.app.show_info("Export complete", f"Wrote {written} event(s) to:\n{chosen}")

    # ==================================================================
    # Lifecycle
    # ==================================================================
    def on_show(self) -> None:
        """Apply any filter handed over by another view (e.g. a dashboard drill-in)."""
        pending = self.app.take_pending_timeline_filter()
        if pending:
            source = str(pending.get("source") or "").upper()
            self._source_menu.set(source if source in {Source.ANTIVIRUS, Source.FIREWALL, Source.SYSTEM} else _ALL)
            self._severity_menu.set(_ANY)
            event_type = str(pending.get("event_type") or "")
            self._type_menu.set(event_type if event_type in _event_type_choices() else _ALL)
            self._search_entry.delete(0, "end")
            if pending.get("search"):
                self._search_entry.insert(0, str(pending["search"]))
            self._apply_range("All time")
            self._offset = 0
            self._expanded_id = None
        self.refresh()

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        """New engine events arrived while this view is visible.

        During a scan the event pump delivers batches several times a second, and each
        one used to trigger a full page rebuild. The refresh is now debounced to one
        per second at most — coalescing a burst into a single redraw — and the change
        check inside :meth:`refresh` skips it entirely when the page is identical.
        """
        if self._offset != 0:
            self.app.set_status_message(
                f"{len(events)} new event(s) logged — go to the first page to see them"
            )
            return
        if self._live_refresh_after is None:
            self._live_refresh_after = self.after(1000, self._run_live_refresh)

    def _run_live_refresh(self) -> None:
        """Timer body for the live-event debounce."""
        self._live_refresh_after = None
        self.refresh()

    def on_hide(self) -> None:
        """Cancel any pending live refresh; the shell re-arms it on the next show."""
        if self._live_refresh_after is not None:
            try:
                self.after_cancel(self._live_refresh_after)
            except Exception:  # the timer may already have fired
                pass
            self._live_refresh_after = None
