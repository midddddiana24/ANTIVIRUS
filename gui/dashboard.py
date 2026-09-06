"""Unified Security Dashboard — the ShieldEX home screen.

Shows the combined health of both engines in one pane: protection status with live
toggles, an antivirus summary, a firewall summary, quick actions, and the newest events
from the shared Threat Behavior Timeline.

Every number here comes from a single :meth:`core.database.Database.get_dashboard_stats`
call plus one timeline query, so a view refresh has exactly two entry points into the data
layer. (``get_dashboard_stats`` itself runs a number of small counting queries internally —
the point is that this module never fans out into ad-hoc reads of its own.)
"""

from __future__ import annotations

import json
import logging
from typing import Any

import customtkinter as ctk

from core.timeline import Severity
from gui.base_view import BaseView, module_available
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font, severity_color
from gui.widgets import Card, Chip, EmptyState, HoverRow, SeverityChip, SourceBadge, StatLine

logger = logging.getLogger(__name__)

#: Quick action buttons: (label, target view key, scan type or ``None``).
#: The scan type is what distinguishes "Quick Scan" from "Full Scan" — both land on the
#: same view, so without it the two buttons would be identical.
QUICK_ACTIONS: tuple[tuple[str, str, str | None], ...] = (
    ("Quick Scan", "scan", "Quick"),
    ("Full Scan", "scan", "Full"),
    ("Open Quarantine", "quarantine", None),
    ("Firewall Rules", "fw_rules", None),
    ("Live Connections", "fw_connections", None),
    ("View Timeline", "timeline", None),
)

#: View key → module, used to grey out actions whose module has not been built yet.
_VIEW_MODULES: dict[str, str] = {
    "scan": "gui.scan_view",
    "quarantine": "gui.quarantine_view",
    "history": "gui.history_view",
    "timeline": "gui.timeline_view",
    "fw_rules": "gui.firewall.rules_view",
    "fw_connections": "gui.firewall.connections_view",
}


def _fmt_datetime(value: str | None) -> str:
    """``'2026-09-04 10:31:02'`` → ``'2026-09-04 10:31'``; empty input → ``'—'``."""
    text = (value or "").strip()
    if not text:
        return "—"
    return text[:16] if len(text) >= 16 else text


def _fmt_time(value: str | None) -> str:
    """Extract ``HH:MM:SS`` from a stored timestamp."""
    text = (value or "").strip()
    return text[11:19] if len(text) >= 19 else text or "--:--:--"


def _fmt_severity_summary(raw: str | None) -> str:
    """Render the JSON severity summary stored on a scan row as ``'High 1 · Low 2'``."""
    if not raw:
        return "—"
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


class DashboardView(BaseView):
    """Protection status, engine summaries, quick actions and recent activity."""

    title = "Security Dashboard"
    subtitle = "Antivirus and firewall health at a glance"

    def build(self) -> None:
        self.content.grid_columnconfigure(0, weight=1, uniform="dash")
        self.content.grid_columnconfigure(1, weight=1, uniform="dash")
        self.content.grid_rowconfigure(3, weight=1)

        self._newest_event_id: int | None = None
        self._activity_rows: list[HoverRow] = []
        #: Debounce timer id for live-event-driven refreshes; None when idle.
        self._live_refresh_after: str | None = None

        self._build_status_card()
        self._build_antivirus_card()
        self._build_firewall_card()
        self._build_quick_actions()
        self._build_activity_card()

    # ==================================================================
    # Protection status
    # ==================================================================
    def _build_status_card(self) -> None:
        card = Card(self.content, title="Protection status")
        card.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, PAD))
        body = card.body
        body.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsw")

        self._status_label = ctk.CTkLabel(
            left, text="CHECKING…", font=font(30, "bold"), text_color=PALETTE["text"], anchor="w"
        )
        self._status_label.grid(row=0, column=0, sticky="w")

        self._status_detail = ctk.CTkLabel(
            left, text="", font=font(12), text_color=PALETTE["text_muted"], anchor="w",
            justify="left",
        )
        self._status_detail.grid(row=1, column=0, sticky="w", pady=(PAD_SM, 0))

        self._profile_chip = Chip(left, "PROFILE: UNKNOWN", PALETTE["neutral"])
        self._profile_chip.grid(row=2, column=0, sticky="w", pady=(PAD, 0))

        # ---- toggles -----------------------------------------------------------
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nse", padx=(PAD_LG, 0))

        ctk.CTkLabel(
            right, text="ANTIVIRUS", font=font(10, "bold"), text_color=PALETTE["text_muted"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self._realtime_switch = ctk.CTkSwitch(
            right,
            text="Real-time file monitoring",
            font=font(12),
            command=self._on_realtime_toggled,
            progress_color=PALETTE["success"],
        )
        self._realtime_switch.grid(row=1, column=0, sticky="w", pady=(2, PAD))

        ctk.CTkLabel(
            right, text="FIREWALL PROFILES", font=font(10, "bold"),
            text_color=PALETTE["text_muted"], anchor="w",
        ).grid(row=2, column=0, sticky="w")

        self._profile_switches: dict[str, ctk.CTkSwitch] = {}
        for index, profile in enumerate(("domain", "private", "public")):
            switch = ctk.CTkSwitch(
                right,
                text=f"{profile.title()} network",
                font=font(12),
                progress_color=PALETTE["success"],
                command=lambda name=profile: self._on_profile_toggled(name),
            )
            switch.grid(row=3 + index, column=0, sticky="w", pady=2)
            self._profile_switches[profile] = switch

        self._master_button = ctk.CTkButton(
            right,
            text="Disable all firewall protection",
            font=font(11, "bold"),
            height=28,
            fg_color=PALETTE["danger"],
            hover_color="#b03a35",
            command=self._on_master_toggle,
        )
        self._master_button.grid(row=6, column=0, sticky="ew", pady=(PAD, 0))

    def _on_realtime_toggled(self) -> None:
        """User flipped the real-time monitoring switch."""
        enabled = bool(self._realtime_switch.get())
        if not self.app.set_realtime_monitoring(enabled):
            self._sync_switch(self._realtime_switch, not enabled)
        self.refresh()

    def _on_profile_toggled(self, profile: str) -> None:
        """User flipped one firewall profile switch."""
        switch = self._profile_switches[profile]
        enabled = bool(switch.get())
        if not enabled and not self.app.ask_yes_no(
            "Turn off firewall protection",
            f"Turning off the {profile} profile firewall leaves this computer exposed on "
            f"{profile} networks.\n\nAre you sure?",
        ):
            self._sync_switch(switch, True)
            return
        if not self.app.set_firewall_profile(profile, enabled):
            self._sync_switch(switch, not enabled)
        self.refresh()

    def _on_master_toggle(self) -> None:
        """Global firewall on/off, mirroring Windows Defender Firewall's master switch."""
        currently_any_on = any(bool(s.get()) for s in self._profile_switches.values())
        if currently_any_on:
            if not self.app.ask_yes_no(
                "Disable all firewall protection",
                "This turns the firewall OFF for the Domain, Private and Public profiles.\n\n"
                "Your computer will accept all inbound connections until you turn it back on.\n\n"
                "Are you absolutely sure?",
            ):
                return
            target = False
        else:
            target = True

        for profile in self._profile_switches:
            self.app.set_firewall_profile(profile, target)
        self.refresh()

    @staticmethod
    def _sync_switch(switch: ctk.CTkSwitch, on: bool) -> None:
        """Set a switch's position without triggering its command callback."""
        if on:
            switch.select()
        else:
            switch.deselect()

    # ==================================================================
    # Engine summary cards
    # ==================================================================
    def _build_antivirus_card(self) -> None:
        card = Card(self.content, title="Antivirus")
        card.grid(row=1, column=0, sticky="nsew", padx=(0, PAD_SM), pady=(0, PAD))
        body = card.body

        self._av_lines: dict[str, StatLine] = {}
        rows = (
            ("last_scan", "Last scan"),
            ("last_result", "Last scan result"),
            ("severity", "Severity breakdown"),
            ("threats", "Threats found (lifetime)"),
            ("quarantine", "Files in quarantine"),
            ("signatures", "Signature database"),
            ("updated", "Database last updated"),
        )
        for index, (key, label) in enumerate(rows):
            line = StatLine(body, label)
            line.grid(row=index, column=0, sticky="ew", pady=3)
            self._av_lines[key] = line

        self._update_button = ctk.CTkButton(
            body,
            text="Update Now",
            font=font(12, "bold"),
            height=30,
            fg_color=PALETTE["accent"],
            hover_color=PALETTE["accent_hover"],
            command=self.app.request_signature_update,
        )
        self._update_button.grid(row=len(rows), column=0, sticky="ew", pady=(PAD, 0))

    def _build_firewall_card(self) -> None:
        card = Card(self.content, title="Firewall")
        card.grid(row=1, column=1, sticky="nsew", padx=(PAD_SM, 0), pady=(0, PAD))
        body = card.body

        self._fw_lines: dict[str, StatLine] = {}
        rows = (
            ("inbound", "Inbound rules"),
            ("outbound", "Outbound rules"),
            ("enabled", "Rules enabled"),
            ("blocked_today", "Connections blocked today"),
            ("ids_today", "IDS alerts today"),
            ("profile", "Current network profile"),
            ("blocked_ips", "Blocked IPs / domains"),
            ("trusted_ips", "Trusted IPs"),
        )
        for index, (key, label) in enumerate(rows):
            line = StatLine(body, label)
            line.grid(row=index, column=0, sticky="ew", pady=3)
            self._fw_lines[key] = line

        self._enforcement_label = ctk.CTkLabel(
            body,
            text="",
            font=font(11),
            text_color=PALETTE["text_muted"],
            anchor="w",
            justify="left",
            wraplength=360,
        )
        self._enforcement_label.grid(row=len(rows), column=0, sticky="ew", pady=(PAD, 0))

    # ==================================================================
    # Quick actions
    # ==================================================================
    def _build_quick_actions(self) -> None:
        card = Card(self.content, title="Quick actions")
        card.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, PAD))
        body = card.body

        for column in range(len(QUICK_ACTIONS)):
            body.grid_columnconfigure(column, weight=1, uniform="actions")

        for column, (label, view_key, scan_type) in enumerate(QUICK_ACTIONS):
            module = _VIEW_MODULES.get(view_key, "")
            available = bool(module) and module_available(module)
            if not available:
                command = None
            elif scan_type is not None:
                command = lambda kind=scan_type: self.app.open_scan(kind)
            else:
                command = lambda key=view_key: self.app.navigate(key)
            button = ctk.CTkButton(
                body,
                text=label if available else f"{label}\n(soon)",
                font=font(12, "bold"),
                height=44,
                corner_radius=8,
                fg_color=PALETTE["surface_alt"] if not available else PALETTE["accent"],
                hover_color=PALETTE["accent_hover"],
                text_color="#ffffff" if available else PALETTE["text_muted"],
                state="normal" if available else "disabled",
                command=command,
            )
            button.grid(row=0, column=column, sticky="ew", padx=PAD_SM // 2)

    # ==================================================================
    # Recent activity feed
    # ==================================================================
    def _build_activity_card(self) -> None:
        limit = int(self.cfg.get("ui.recent_activity_count", 10))
        card = Card(
            self.content,
            title="Recent activity",
            subtitle=f"Newest {limit} events from the Threat Behavior Timeline — click to drill in",
        )
        card.grid(row=3, column=0, columnspan=2, sticky="nsew")
        self._activity_body = card.body
        self._activity_body.grid_columnconfigure(0, weight=1)

        self._activity_empty = EmptyState(
            self._activity_body,
            "No events recorded yet.\nRun a scan or enable real-time monitoring to populate "
            "the timeline.",
        )
        self._activity_empty.grid(row=0, column=0, pady=PAD_LG)

    def _rebuild_activity(self, events: list[dict[str, Any]]) -> None:
        """Replace the feed rows with ``events`` (newest first)."""
        for row in self._activity_rows:
            row.destroy()
        self._activity_rows.clear()

        if not events:
            self._activity_empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._activity_empty.grid_remove()

        for index, event in enumerate(events):
            subject = event.get("file_path") or event.get("remote_ip") or ""
            row = HoverRow(
                self._activity_body,
                on_click=lambda evt=event: self._open_event(evt),
            )
            row.grid(row=index, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(2, weight=1)

            ctk.CTkLabel(
                row,
                text=_fmt_time(event.get("timestamp")),
                font=mono_font(11),
                text_color=PALETTE["text_muted"],
                width=64,
                anchor="w",
            ).grid(row=0, column=0, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)

            SourceBadge(row, str(event.get("source", ""))).grid(
                row=0, column=1, padx=(0, PAD_SM), pady=PAD_SM
            )

            detail = str(event.get("event_detail") or event.get("event_type") or "")
            if subject:
                detail = f"{detail}  ·  {subject}"
            ctk.CTkLabel(
                row,
                text=detail,
                font=font(12),
                text_color=PALETTE["text"],
                anchor="w",
                justify="left",
            ).grid(row=0, column=2, sticky="ew", pady=PAD_SM)

            SeverityChip(row, str(event.get("severity", Severity.INFO))).grid(
                row=0, column=3, padx=PAD_SM, pady=PAD_SM
            )

            row.activate_bindings()
            self._activity_rows.append(row)

    def _open_event(self, event: dict[str, Any]) -> None:
        """Drill into the timeline, filtered to the clicked event's subject."""
        subject = event.get("file_path") or event.get("remote_ip") or event.get("event_type") or ""
        self.app.open_timeline(source=str(event.get("source", "")), search=str(subject))

    # ==================================================================
    # Data refresh
    # ==================================================================
    def refresh(self) -> None:
        """Re-read all dashboard data and update every widget."""
        try:
            stats = self.db.get_dashboard_stats()
        except Exception as exc:
            logger.error("Dashboard refresh failed: %s", exc, exc_info=True)
            return

        antivirus = stats["antivirus"]
        firewall = stats["firewall"]

        # ---- protection status -------------------------------------------------
        label, color = self.app.protection_status(stats)
        self._status_label.configure(text=label, text_color=color)

        realtime = bool(antivirus["realtime_enabled"])
        profiles = firewall["profiles"]
        active_profiles = sum(1 for enabled in profiles.values() if enabled)
        self._status_detail.configure(
            text=(
                f"Real-time monitoring {'on' if realtime else 'off'}  ·  "
                f"Firewall active on {active_profiles} of 3 profiles  ·  "
                f"{stats['timeline']['events_today']} timeline event(s) today, "
                f"{stats['timeline']['high_today']} high or critical"
            )
        )
        self._profile_chip.update_chip(
            f"NETWORK: {str(firewall['current_profile']).upper()}",
            PALETTE["accent"] if firewall["current_profile"] != "Unknown" else PALETTE["neutral"],
        )

        self._sync_switch(self._realtime_switch, realtime)
        for profile, switch in self._profile_switches.items():
            self._sync_switch(switch, bool(profiles.get(profile, False)))
        self._master_button.configure(
            text="Disable all firewall protection"
            if active_profiles
            else "Enable all firewall protection",
            fg_color=PALETTE["danger"] if active_profiles else PALETTE["success"],
            hover_color="#b03a35" if active_profiles else "#25823a",
        )

        # ---- antivirus summary -------------------------------------------------
        last_scan = antivirus["last_scan"]
        if last_scan:
            self._av_lines["last_scan"].set_value(
                f"{str(last_scan.get('scan_type', '?')).title()} · "
                f"{_fmt_datetime(last_scan.get('end_time') or last_scan.get('start_time'))}"
            )
            threats = int(last_scan.get("threats_found") or 0)
            self._av_lines["last_result"].set_value(
                f"{threats} threat(s) in {int(last_scan.get('files_scanned') or 0):,} file(s)",
                PALETTE["danger"] if threats else PALETTE["success"],
            )
            self._av_lines["severity"].set_value(
                _fmt_severity_summary(last_scan.get("severity_summary"))
            )
        else:
            self._av_lines["last_scan"].set_value("Never", PALETTE["warning"])
            self._av_lines["last_result"].set_value("—")
            self._av_lines["severity"].set_value("—")

        lifetime = int(antivirus["threats_found_total"])
        self._av_lines["threats"].set_value(
            f"{lifetime:,}", PALETTE["danger"] if lifetime else PALETTE["text"]
        )
        quarantined = int(antivirus["quarantined"])
        self._av_lines["quarantine"].set_value(
            f"{quarantined:,}", PALETTE["warning"] if quarantined else PALETTE["text"]
        )
        self._av_lines["signatures"].set_value(
            f"{antivirus['signature_version']} · {antivirus['signature_count']:,} hashes"
        )
        updated = antivirus["signature_updated_at"]
        self._av_lines["updated"].set_value(
            _fmt_datetime(updated) if updated else "Never",
            PALETTE["text"] if updated else PALETTE["warning"],
        )
        # The button also reflects an in-flight update, so a user watching a slow network
        # fetch can see it is working instead of clicking again.
        updater_ready = module_available("core.antivirus.updater")
        if not updater_ready:
            self._update_button.configure(state="disabled", text="Update Now (soon)")
        elif self.app.signature_update_running:
            self._update_button.configure(state="disabled", text="Updating…")
        else:
            self._update_button.configure(state="normal", text="Update Now")

        # ---- firewall summary --------------------------------------------------
        self._fw_lines["inbound"].set_value(f"{firewall['rules_inbound']:,}")
        self._fw_lines["outbound"].set_value(f"{firewall['rules_outbound']:,}")
        self._fw_lines["enabled"].set_value(f"{firewall['rules_enabled']:,}")
        blocked_today = int(firewall["blocked_today"])
        self._fw_lines["blocked_today"].set_value(
            f"{blocked_today:,}", PALETTE["warning"] if blocked_today else PALETTE["text"]
        )
        ids_today = int(firewall["ids_alerts_today"])
        self._fw_lines["ids_today"].set_value(
            f"{ids_today:,}", severity_color(Severity.HIGH) if ids_today else PALETTE["text"]
        )
        self._fw_lines["profile"].set_value(str(firewall["current_profile"]))
        self._fw_lines["blocked_ips"].set_value(f"{firewall['blocked_ips']:,}")
        self._fw_lines["trusted_ips"].set_value(f"{firewall['trusted_ips']:,}")

        enforcing = bool(self.cfg.get("firewall.enforce_rules", False))
        if enforcing and self.app.elevated:
            self._enforcement_label.configure(
                text="Enforcement ON — rules are applied to the operating system firewall.",
                text_color=PALETTE["success"],
            )
        elif enforcing:
            self._enforcement_label.configure(
                text="Enforcement is ON in config but ShieldEX is not elevated, so rules "
                     "cannot reach the OS firewall. Restart as administrator.",
                text_color=PALETTE["danger"],
            )
        else:
            self._enforcement_label.configure(
                text="DRY-RUN — rules are stored and the exact OS command is written to the "
                     "log, but nothing is applied. Set firewall.enforce_rules to true in "
                     "config.json to enforce.",
                text_color=PALETTE["warning"],
            )

        # ---- activity feed (only rebuild when something changed) ---------------
        events = self.timeline.recent(int(self.cfg.get("ui.recent_activity_count", 10)))
        newest = events[0]["id"] if events else None
        if newest != self._newest_event_id or len(events) != len(self._activity_rows):
            self._newest_event_id = newest
            self._rebuild_activity(events)

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        """Live engine events arrived — refresh instead of waiting for the poll.

        Debounced to one per second: during a scan the pump delivers batches several
        times a second, and each unthrottled refresh ran a dozen counting queries plus
        ~30 widget updates, freezing the UI on the dashboard while it happened.
        """
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
