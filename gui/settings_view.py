"""Settings view — runtime settings the user can flip without editing config.json.

Split into what a security product's settings page actually holds:

* protection toggles that persist through the engine registry (real-time monitor,
  connection monitor, IDS, packet inspector, firewall enforcement);
* signature database: version, counts, manual update, last check outcome;
* environment info: elevation, enforcement mode, watched paths, database location.

Firewall enforcement has a switch here *with* a confirmation dialog and an elevation
check: it is the one setting that can change the machine's networking, so it gets the
same treatment as deleting a quarantined file — explicit user intent, recorded on the
timeline. Other dangerous keys still belong in config.json, not behind a switch.
"""

from __future__ import annotations

import logging
import platform
from typing import Any

import customtkinter as ctk

from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, StatLine

logger = logging.getLogger(__name__)


class SettingsView(BaseView):
    """Runtime settings and environment information."""

    title = "Settings"
    subtitle = "Protection toggles, signature database and environment info"

    def build(self) -> None:
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(4, weight=1)

        self._build_protection()
        self._build_signatures()
        self._build_policy()
        self._build_environment()

    # ==================================================================
    # Protection toggles
    # ==================================================================
    def _build_protection(self) -> None:
        card = Card(self.content, title="Protection")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body

        self._switches: dict[str, ctk.CTkSwitch] = {}

        self._realtime_switch = ctk.CTkSwitch(
            body, text="Real-time file monitoring", font=font(12),
            command=self._toggle_realtime, progress_color=PALETTE["success"],
        )
        self._realtime_switch.grid(row=0, column=0, sticky="w", pady=2)
        self._switches["realtime"] = self._realtime_switch

        self._connmon_switch = ctk.CTkSwitch(
            body, text="Connection monitoring (live sockets)", font=font(12),
            command=self._toggle_connmon, progress_color=PALETTE["success"],
        )
        self._connmon_switch.grid(row=1, column=0, sticky="w", pady=2)
        self._switches["connection_monitor"] = self._connmon_switch

        self._ids_switch = ctk.CTkSwitch(
            body, text="Intrusion detection (IDS)", font=font(12),
            command=self._toggle_ids, progress_color=PALETTE["success"],
        )
        self._ids_switch.grid(row=2, column=0, sticky="w", pady=2)
        self._switches["ids"] = self._ids_switch

        self._ids_auto_block_switch = ctk.CTkSwitch(
            body, text="Auto-block IDS alert sources", font=font(12),
            command=self._toggle_auto_block, progress_color=PALETTE["warning"],
        )
        self._ids_auto_block_switch.grid(row=3, column=0, sticky="w", pady=2)

        self._packet_switch = ctk.CTkSwitch(
            body, text="Raw packet inspector (needs Npcap)", font=font(12),
            command=self._toggle_packet, progress_color=PALETTE["success"],
        )
        self._packet_switch.grid(row=4, column=0, sticky="w", pady=2)
        self._switches["packet_inspector"] = self._packet_switch

        self._enforce_switch = ctk.CTkSwitch(
            body, text="Firewall enforcement (apply rules to the OS firewall)", font=font(12),
            command=self._toggle_enforcement, progress_color=PALETTE["danger"],
        )
        self._enforce_switch.grid(row=5, column=0, sticky="w", pady=2)
        self._switches["enforcement"] = self._enforce_switch

        self._notes = ctk.CTkLabel(
            body, text="", font=font(11), text_color=PALETTE["text_muted"],
            anchor="w", justify="left", wraplength=700,
        )
        self._notes.grid(row=6, column=0, sticky="w", pady=(PAD_SM, 0))

    def _toggle_enforcement(self) -> None:
        """Flip ``firewall.enforce_rules`` — with a hard confirmation when enabling.

        Enforcement is the one setting that can break the machine's networking (a
        wrong block rule with enforcement on really does block traffic), which is why
        it lives behind an explicit dialog instead of a silent switch flip. Disabling
        is always safe and needs no prompt.
        """
        enabled = bool(self._enforce_switch.get())
        if enabled:
            if not self.app.elevated:
                self.app.show_error(
                    "Administrator required",
                    "Firewall enforcement needs administrator privileges.\n"
                    "Restart ShieldEX as administrator, then enable enforcement.",
                )
                self._sync_switch("enforcement", False)
                return
            if not self.app.ask_yes_no(
                "Enable firewall enforcement?",
                "ShieldEX will program your Windows firewall from its rule table.\n\n"
                "Only rules you create in the Rules view are applied, and every OS\n"
                "rule it creates is named 'ShieldEX-…' so it can be audited and\n"
                "removed. Disabling enforcement removes nothing.\n\n"
                "Enable enforcement now?",
            ):
                self._sync_switch("enforcement", False)
                return
        self.cfg.set("firewall.enforce_rules", enabled)
        self._persist_config()
        self.app.set_status_message(
            f"Firewall enforcement {'enabled' if enabled else 'disabled'} — "
            f"{'rules now apply to the OS firewall' if enabled else 'dry-run mode restored'}"
        )
        self.refresh()

    def _toggle_realtime(self) -> None:
        enabled = bool(self._realtime_switch.get())
        if not self.app.set_realtime_monitoring(enabled):
            self._sync_switch("realtime", not enabled)
        self.refresh()

    def _toggle_connmon(self) -> None:
        engine = self.app.get_engine("connection_monitor")
        if engine is None:
            self.app.show_error(
                "Connection monitor", "The connection monitor engine is not loaded."
            )
            self._sync_switch("connection_monitor", False)
            return
        enabled = bool(self._connmon_switch.get())
        try:
            if enabled:
                started = engine.start()
                if not started:
                    self.app.set_status_message(
                        "Connection monitor is disabled in config.json "
                        "(firewall.connection_monitor.enabled)"
                    )
                    self._sync_switch("connection_monitor", False)
                    return
            else:
                engine.stop()
            self.app.set_status_message(
                f"Connection monitor {'started' if enabled else 'stopped'}"
            )
        except Exception as exc:
            logger.error("Connection monitor toggle failed: %s", exc, exc_info=True)
            self.app.show_error("Connection monitor", str(exc))
            self._sync_switch("connection_monitor", not enabled)
        self.refresh()

    def _toggle_ids(self) -> None:
        # The IDS has no background thread of its own; the config key is what its
        # observe_* entry points check, so flipping it is the whole action.
        enabled = bool(self._ids_switch.get())
        self.cfg.set("firewall.ids.enabled", enabled)
        self._persist_config()
        self.app.set_status_message(f"Intrusion detection {'enabled' if enabled else 'disabled'}")
        self.refresh()

    def _toggle_auto_block(self) -> None:
        enabled = bool(self._ids_auto_block_switch.get())
        self.cfg.set("firewall.ids.auto_block_source", enabled)
        self._persist_config()
        self.app.set_status_message(
            f"IDS auto-block {'enabled' if enabled else 'disabled'} (applies to future alerts)"
        )

    def _toggle_packet(self) -> None:
        engine = self.app.get_engine("packet_inspector")
        if engine is None:
            self.app.show_error(
                "Packet inspector", "The packet inspector engine is not loaded."
            )
            self._sync_switch("packet_inspector", False)
            return
        enabled = bool(self._packet_switch.get())
        if enabled and not engine.check_available():
            self.app.show_error(
                "Packet inspector unavailable",
                "Scapy or a capture driver (Npcap on Windows) is missing.\n"
                "Install Npcap from https://npcap.com and restart ShieldEX.",
            )
            self._sync_switch("packet_inspector", False)
            return
        try:
            if enabled:
                engine.start()
            else:
                engine.stop()
        except Exception as exc:
            logger.error("Packet inspector toggle failed: %s", exc, exc_info=True)
            self.app.show_error("Packet inspector", str(exc))
            self._sync_switch("packet_inspector", not enabled)
            return
        self.cfg.set("firewall.packet_inspector.enabled", enabled)
        self._persist_config()
        self.app.set_status_message(f"Packet inspector {'started' if enabled else 'stopped'}")
        self.refresh()

    def _persist_config(self) -> None:
        """Write config.json so toggle changes survive a restart.

        Without this the switches only mutated the in-memory tree: every settings
        change silently reset on the next launch, while the status messages claimed
        persistence ("applies to future alerts").
        """
        if self.cfg.save():
            logger.debug("config.json persisted by settings view")
        else:
            self.app.show_error(
                "Could not save settings",
                f"Changes apply now but could not be written to\n{self.cfg.path}\n\n"
                "Check that the file is writable.",
            )

    def _sync_switch(self, key: str, on: bool) -> None:
        switch = self._switches.get(key)
        if switch is None:
            return
        if on:
            switch.select()
        else:
            switch.deselect()

    # ==================================================================
    # Signature database
    # ==================================================================
    def _build_signatures(self) -> None:
        card = Card(self.content, title="Signature database")
        card.grid(row=1, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body

        self._sig_lines: dict[str, StatLine] = {}
        for index, (key, label) in enumerate((
            ("version", "Version"),
            ("count", "Signatures"),
            ("updated", "Last updated"),
            ("checked", "Last check"),
            ("outcome", "Last check outcome"),
        )):
            line = StatLine(body, label)
            line.grid(row=index, column=0, sticky="ew", pady=2)
            self._sig_lines[key] = line

        self._update_button = ctk.CTkButton(
            body, text="Check for updates now", height=32, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=self.app.request_signature_update,
        )
        self._update_button.grid(row=5, column=0, sticky="ew", pady=(PAD_SM, 0))

    # ==================================================================
    # Response policy & scheduled scans
    # ==================================================================
    def _build_policy(self) -> None:
        from core.policy import ResponsePolicy

        card = Card(
            self.content, title="Response policy & scheduled scans",
            subtitle="What happens automatically per severity, and when scans run themselves",
        )
        card.grid(row=2, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        body.grid_columnconfigure(1, weight=1)

        self._policy = ResponsePolicy(self.cfg)
        self._policy_switches: dict[str, ctk.CTkSwitch] = {}
        for index, (level, quarantine) in enumerate(self._policy.describe()):
            switch = ctk.CTkSwitch(
                body, text=f"{level}: auto-quarantine signature matches",
                font=font(12),
                command=lambda lv=level: self._toggle_policy(lv),
                progress_color=PALETTE["success"],
            )
            switch.grid(row=index, column=0, columnspan=2, sticky="w", pady=2)
            self._policy_switches[level] = switch

        row = 4
        ctk.CTkLabel(
            body, text="Scheduled scan", font=font(12, "bold"),
            text_color=PALETTE["text"], anchor="w",
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(PAD_SM, 2))
        row += 1

        self._sched_switch = ctk.CTkSwitch(
            body, text="Run a scan automatically every day", font=font(12),
            command=self._toggle_scheduler, progress_color=PALETTE["success"],
        )
        self._sched_switch.grid(row=row, column=0, columnspan=2, sticky="w", pady=2)
        row += 1

        sched_row = ctk.CTkFrame(body, fg_color="transparent")
        sched_row.grid(row=row, column=0, columnspan=2, sticky="ew")
        ctk.CTkLabel(
            sched_row, text="Type:", font=font(12), text_color=PALETTE["text_muted"]
        ).grid(row=0, column=0, padx=(0, PAD_SM))
        self._sched_type = ctk.CTkOptionMenu(
            sched_row, values=["quick", "full"], width=110, height=28, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=self._change_sched_type,
        )
        self._sched_type.grid(row=0, column=1, padx=(0, PAD))
        ctk.CTkLabel(
            sched_row, text="Time (HH:MM):", font=font(12), text_color=PALETTE["text_muted"]
        ).grid(row=0, column=2, padx=(0, PAD_SM))
        self._sched_time = ctk.CTkEntry(sched_row, width=80, height=28, font=font(12))
        self._sched_time.grid(row=0, column=3, padx=(0, PAD_SM))
        self._sched_time.bind("<Return>", lambda _e: self._change_sched_time())
        ctk.CTkButton(
            sched_row, text="Apply time", width=90, height=28, font=font(12, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._change_sched_time,
        ).grid(row=0, column=4, padx=(0, PAD_SM))
        ctk.CTkButton(
            sched_row, text="Run now", width=90, height=28, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=self._run_scheduled_now,
        ).grid(row=0, column=5)
        row += 1

        self._sched_info = ctk.CTkLabel(
            body, text="", font=font(11), text_color=PALETTE["text_muted"],
            anchor="w", justify="left",
        )
        self._sched_info.grid(row=row, column=0, columnspan=2, sticky="w", pady=(2, 0))

    def _toggle_policy(self, level: str) -> None:
        enabled = bool(self._policy_switches[level].get())
        if not self._policy.set_quarantine(level, enabled):
            self._sync_switch_state(self._policy_switches[level], not enabled)
            return
        self._persist_config()
        self.app.set_status_message(
            f"Policy: {level} signature matches "
            f"{'will' if enabled else 'will not'} be auto-quarantined"
        )
        self.refresh()

    def _sync_switch_state(self, switch: ctk.CTkSwitch, on: bool) -> None:
        if on:
            switch.select()
        else:
            switch.deselect()

    def _toggle_scheduler(self) -> None:
        enabled = bool(self._sched_switch.get())
        self.cfg.set("antivirus.scheduled_scans.enabled", enabled)
        self._persist_config()
        engine = self.app.get_engine("scheduler")
        if engine is not None:
            try:
                if enabled:
                    engine.start()
                else:
                    engine.stop()
            except Exception as exc:
                logger.error("Scheduler toggle failed: %s", exc, exc_info=True)
                self.app.show_error("Scheduled scans", f"Could not toggle the scheduler:\n\n{exc}")
                self._sync_switch_state(self._sched_switch, not enabled)
                return
        self.app.set_status_message(
            f"Scheduled scans {'enabled' if enabled else 'disabled'}"
            + (" — takes effect on next launch" if engine is None else "")
        )
        self.refresh()

    def _change_sched_type(self, value: str) -> None:
        if value not in ("quick", "full"):
            return
        self.cfg.set("antivirus.scheduled_scans.scan_type", value)
        self._persist_config()
        self._restart_scheduler_if_running("scan type updated — next run uses it")

    def _change_sched_time(self) -> None:
        from core.antivirus.scheduler import ScanScheduler

        value = self._sched_time.get().strip()
        if not ScanScheduler._valid_time(value):
            self.app.show_error("Scheduled scans", f"'{value}' is not a valid HH:MM time.")
            self.refresh()
            return
        self.cfg.set("antivirus.scheduled_scans.time", value)
        self._persist_config()
        self._restart_scheduler_if_running(f"next run at {value}")

    def _restart_scheduler_if_running(self, note: str) -> None:
        engine = self.app.get_engine("scheduler")
        if engine is not None and engine.running:
            try:
                engine.stop()
                engine.start()
            except Exception as exc:
                logger.error("Scheduler restart failed: %s", exc, exc_info=True)
        self.app.set_status_message(f"Scheduled scans: {note}")
        self.refresh()

    def _run_scheduled_now(self) -> None:
        engine = self.app.get_engine("scheduler")
        if engine is None:
            self.app.show_error("Scheduled scans", "The scheduler engine is not loaded.")
            return
        import threading

        self.app.set_status_message("Running scheduled scan in the background…")

        def worker() -> None:
            try:
                engine.run_now()
            except Exception as exc:
                logger.error("Manual scheduled scan failed: %s", exc, exc_info=True)

        threading.Thread(target=worker, name="ShieldEX-SchedOnce", daemon=True).start()

    # ==================================================================
    # Environment
    # ==================================================================
    def _build_environment(self) -> None:
        card = Card(self.content, title="Environment")
        card.grid(row=3, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body

        self._env_lines: dict[str, StatLine] = {}
        rows = (
            ("privilege", "Process privilege"),
            ("enforce", "Firewall enforcement"),
            ("os", "Operating system"),
            ("python", "Python"),
            ("app", "Application"),
            ("watched", "Real-time watched paths"),
            ("database", "Database file"),
            ("log", "Log file"),
        )
        for index, (key, label) in enumerate(rows):
            line = StatLine(body, label)
            line.grid(row=index, column=0, sticky="ew", pady=2)
            self._env_lines[key] = line

    # ==================================================================
    # Refresh
    # ==================================================================
    def refresh(self) -> None:
        # Protection switches reflect *actual* engine state, not just the desired
        # database flag: a monitor that failed to start must not show as On.
        realtime_running = bool(
            (engine := self.app.get_engine("realtime_monitor")) is not None and engine.running
        )
        self._sync_switch("realtime", realtime_running)

        connmon = self.app.get_engine("connection_monitor")
        self._sync_switch("connection_monitor", bool(connmon is not None and connmon.running))

        ids_enabled = bool(self.cfg.get("firewall.ids.enabled", True))
        self._sync_switch("ids", ids_enabled)

        auto_block = bool(self.cfg.get("firewall.ids.auto_block_source", False))
        if auto_block:
            self._ids_auto_block_switch.select()
        else:
            self._ids_auto_block_switch.deselect()

        packet = self.app.get_engine("packet_inspector")
        packet_on = bool(packet is not None and packet.running)
        self._sync_switch("packet_inspector", packet_on)

        enforcing_cfg = bool(self.cfg.get("firewall.enforce_rules", False))
        self._sync_switch("enforcement", enforcing_cfg and self.app.elevated)

        # Response policy rows reflect the effective table (config or defaults).
        for level, quarantine in self._policy.describe():
            self._sync_switch_state(self._policy_switches[level], quarantine)

        # Scheduler controls reflect config + engine state.
        sched_on = bool(self.cfg.get("antivirus.scheduled_scans.enabled", False))
        self._sync_switch_state(self._sched_switch, sched_on)
        self._sched_type.set(str(self.cfg.get("antivirus.scheduled_scans.scan_type", "quick")))
        current_time = str(self.cfg.get("antivirus.scheduled_scans.time", "02:00"))
        if self._sched_time.get().strip() != current_time:
            self._sched_time.delete(0, "end")
            self._sched_time.insert(0, current_time)
        engine = self.app.get_engine("scheduler")
        info = engine.next_run_info() if engine is not None else "scheduler engine not loaded"
        last = self.db.get_setting("scheduled_scan_last_run", "") or ""
        self._sched_info.configure(
            text=f"Next: {info}" + (f"  ·  last run: {last}" if last else "")
        )

        engines_online = {
            "realtime monitor": realtime_running,
            "connection monitor": connmon is not None and connmon.running,
            "IDS": ids_enabled,
            "packet inspector": packet_on,
        }
        offline = [name for name, on in engines_online.items() if not on]
        self._notes.configure(
            text="All engines report running." if not offline
            else "Not running: " + ", ".join(offline)
        )

        # Signature database.
        self._sig_lines["version"].set_value(
            str(self.db.get_setting("signature_db_version", "none") or "none")
        )
        self._sig_lines["count"].set_value(f"{self.db.signature_count():,}")
        updated = self.db.get_setting("signature_db_updated_at", "") or ""
        self._sig_lines["updated"].set_value(updated[:19] if updated else "Never")
        checked = self.db.get_setting("signature_db_last_checked", "") or ""
        self._sig_lines["checked"].set_value(checked[:19] if checked else "Never")

        updater = self.app.get_engine("updater")
        if updater is not None:
            outcome = str(updater.last_result.get("outcome", "never checked"))
            self._sig_lines["outcome"].set_value(outcome)
        else:
            self._sig_lines["outcome"].set_value("updater engine not loaded", PALETTE["warning"])

        if self.app.signature_update_running:
            self._update_button.configure(state="disabled", text="Checking…")
        else:
            self._update_button.configure(state="normal", text="Check for updates now")

        # Environment.
        self._env_lines["privilege"].set_value(
            "Administrator" if self.app.elevated else "Limited (no admin)",
            PALETTE["success"] if self.app.elevated else PALETTE["danger"],
        )
        enforcing = bool(self.cfg.get("firewall.enforce_rules", False))
        if enforcing and self.app.elevated:
            self._env_lines["enforce"].set_value("ON — rules reach the OS", PALETTE["success"])
        elif enforcing:
            self._env_lines["enforce"].set_value("ON but not elevated", PALETTE["danger"])
        else:
            self._env_lines["enforce"].set_value("DRY-RUN (stored only)", PALETTE["warning"])
        self._env_lines["os"].set_value(f"{platform.system()} {platform.release()}")
        self._env_lines["python"].set_value(platform.python_version())
        self._env_lines["app"].set_value(
            f"{self.cfg.get('app.name', 'ShieldEX')} {self.cfg.get('app.version', '')}"
        )

        realtime_cfg = self.app.get_engine("realtime_monitor")
        if realtime_cfg is not None:
            paths = realtime_cfg.watched_paths()
            text = ", ".join(str(p) for p in paths) if paths else "none configured"
        else:
            text = "monitor engine not loaded"
        self._env_lines["watched"].set_value(text)
        self._env_lines["database"].set_value(str(self.cfg.database_path))
        self._env_lines["log"].set_value(str(self.cfg.log_path))

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        """Signature updates change the version lines; monitor events change switches."""
        if any(
            event.get("event_type") in
            ("SIGNATURE_DB_UPDATED", "MONITOR_STARTED", "MONITOR_STOPPED")
            for event in events
        ):
            self.refresh()
