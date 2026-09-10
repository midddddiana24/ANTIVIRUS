"""Firewall Rules view — create, edit, enable, disable and delete stored rules.

Rule persistence is the database's job; pushing rules to the OS is the engine's, and
this view calls the engine after every mutation so enforcement (when enabled) tracks
the stored state. Editing reuses the create dialog pre-filled with the rule's row.
"""

from __future__ import annotations

import logging
from tkinter import messagebox
from typing import Any

import customtkinter as ctk

from gui.base_view import BaseView
from gui.theme import PAD, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, StatLine, exclude_from_row_bindings

logger = logging.getLogger(__name__)

_DIRECTIONS = ("Outbound", "Inbound")
_ACTIONS = ("Block", "Allow", "Monitor")
_PROTOCOLS = ("Any", "TCP", "UDP", "ICMP")
_PROFILES = ("Any", "Domain", "Private", "Public")


class RulesView(BaseView):
    """Manage the stored firewall rule table."""

    title = "Firewall Rules"
    subtitle = "Per-application, per-IP, per-port allow and block rules"

    def build(self) -> None:
        self._rows: list[ctk.CTkFrame] = []
        self._filter_direction = "All"
        self._expanded_id: int | None = None

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(2, weight=1)

        self._build_summary()
        self._build_toolbar()
        self._build_table()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build_summary(self) -> None:
        card = Card(self.content, title="Overview")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body
        for column in range(4):
            body.grid_columnconfigure(column, weight=1, uniform="rules")

        self._summary: dict[str, StatLine] = {}
        for column, (key, label) in enumerate((
            ("inbound", "Inbound rules"),
            ("outbound", "Outbound rules"),
            ("enabled", "Enabled rules"),
            ("mode", "Enforcement"),
        )):
            line = StatLine(body, label)
            line.grid(row=0, column=column, sticky="ew", padx=PAD_SM)
            self._summary[key] = line

    def _build_toolbar(self) -> None:
        bar = Card(self.content)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, PAD_SM))
        body = bar.body
        body.grid_columnconfigure(3, weight=1)

        ctk.CTkButton(
            body, text="+ New rule", width=110, height=30, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=self._new_rule,
        ).grid(row=0, column=0, padx=(0, PAD_SM))

        ctk.CTkButton(
            body, text="Apply all to OS", width=130, height=30, font=font(12, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._apply_all,
        ).grid(row=0, column=1, padx=(0, PAD_SM))

        ctk.CTkLabel(
            body, text="DIRECTION", font=font(10, "bold"), text_color=PALETTE["text_muted"],
        ).grid(row=0, column=2, padx=(PAD, PAD_SM))
        self._direction_menu = ctk.CTkOptionMenu(
            body, values=["All", *_DIRECTIONS], width=120, height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
            command=lambda value: self._on_direction(value),
        )
        self._direction_menu.grid(row=0, column=3, sticky="w")

        self._count_label = ctk.CTkLabel(
            body, text="", font=font(11), text_color=PALETTE["text_muted"], anchor="e"
        )
        self._count_label.grid(row=0, column=4, sticky="e")

    def _build_table(self) -> None:
        card = Card(self.content, title="Rules", subtitle="Click a row to expand edit/delete")
        card.grid(row=2, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        for column, (text, width) in enumerate((
            ("NAME", 210), ("DIR", 90), ("ACTION", 90), ("PROTOCOL", 90),
            ("PORT(S)", 100), ("REMOTE IP", 160), ("APP", 0), ("PROFILE", 90),
            ("HITS", 70), ("ON", 60),
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
            self._scroll, "No rules stored yet.\nCreate one, or instantiate a template."
        )

    # ==================================================================
    # Data
    # ==================================================================
    def _engine(self) -> Any | None:
        return self.app.get_engine("firewall")

    def _on_direction(self, value: str) -> None:
        self._filter_direction = value
        self._expanded_id = None
        self.refresh()

    def refresh(self) -> None:
        direction = None if self._filter_direction == "All" else self._filter_direction
        rules = self.db.get_firewall_rules(direction=direction)

        self._summary["inbound"].set_value(f"{self.db.count_firewall_rules('INBOUND'):,}")
        self._summary["outbound"].set_value(f"{self.db.count_firewall_rules('OUTBOUND'):,}")
        self._summary["enabled"].set_value(f"{self.db.count_firewall_rules(enabled=True):,}")

        enforcing = bool(self.cfg.get("firewall.enforce_rules", False))
        if enforcing and self.app.elevated:
            mode, color = "ENFORCING", PALETTE["success"]
        elif enforcing:
            mode, color = "DRY (needs admin)", PALETTE["danger"]
        else:
            mode, color = "DRY-RUN", PALETTE["warning"]
        self._summary["mode"].set_value(mode, color)

        self._count_label.configure(text=f"{len(rules)} rule(s) shown")
        self._hit_counts = self.db.get_rule_match_counts()
        self._render(rules)

    def _render(self, rules: list[dict[str, Any]]) -> None:
        for row in self._rows:
            row.destroy()
        self._rows.clear()

        if not rules:
            self._empty.grid(row=0, column=0, pady=PAD_SM * 4)
            return
        self._empty.grid_remove()

        for index, rule in enumerate(rules):
            self._rows.append(self._build_row(index, rule))

    def _build_row(self, index: int, rule: dict[str, Any]) -> HoverRow:
        rule_id = int(rule.get("id") or 0)
        row = HoverRow(self._scroll, on_click=lambda rid=rule_id: self._toggle(rid))
        row.grid(row=index, column=0, sticky="ew", pady=2)

        def cell(text: str, column: int, width: int, mono: bool = False) -> None:
            ctk.CTkLabel(
                row, text=text or "—", font=mono_font(11) if mono else font(12),
                text_color=PALETTE["text"], anchor="w", width=width, justify="left",
            ).grid(row=0, column=column, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)

        cell(str(rule.get("name") or "?"), 0, 200)
        cell(str(rule.get("direction") or "").title(), 1, 80)
        action = str(rule.get("action") or "").title()
        cell(action, 2, 80)
        cell(str(rule.get("protocol") or "Any"), 3, 80)
        cell(str(rule.get("remote_port") or "any"), 4, 90, mono=True)
        cell(str(rule.get("remote_ip") or "any"), 5, 150, mono=True)
        cell(str(rule.get("app_path") or "any app"), 6, 0)
        cell(str(rule.get("profile") or "Any"), 7, 80)
        hits = self._hit_counts.get(str(rule.get("name") or ""), 0) if hasattr(self, "_hit_counts") else 0
        cell(f"{hits:,}", 8, 60, mono=True)
        enabled = bool(rule.get("enabled"))
        Chip(row, "On" if enabled else "Off", PALETTE["success"] if enabled else PALETTE["neutral"]).grid(
            row=0, column=9, padx=PAD_SM, pady=PAD_SM
        )

        # Bind before the panel so panel buttons keep their own commands.
        row.activate_bindings()
        if rule_id and rule_id == self._expanded_id:
            self._build_action_panel(row, rule)
        return row

    def _toggle(self, rule_id: int) -> None:
        self._expanded_id = None if self._expanded_id == rule_id else rule_id
        self.refresh()

    def _build_action_panel(self, row: ctk.CTkFrame, rule: dict[str, Any]) -> None:
        panel = exclude_from_row_bindings(
            ctk.CTkFrame(row, fg_color=PALETTE["surface"], corner_radius=6)
        )
        panel.grid(row=1, column=0, columnspan=10, sticky="ew", padx=PAD_SM, pady=(0, PAD_SM))

        if str(rule.get("description") or "").strip():
            ctk.CTkLabel(
                panel, text=str(rule["description"]), font=font(11),
                text_color=PALETTE["text_muted"], anchor="w", justify="left", wraplength=700,
            ).grid(row=0, column=0, columnspan=4, sticky="ew", padx=PAD_SM, pady=PAD_SM)

        buttons = ctk.CTkFrame(panel, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="w", padx=PAD_SM, pady=(0, PAD_SM))
        rule_id = int(rule.get("id") or 0)
        enabled = bool(rule.get("enabled"))

        ctk.CTkButton(
            buttons, text="Edit", width=90, height=28, font=font(11, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=lambda rid=rule_id: self._edit_rule(rid),
        ).grid(row=0, column=0, padx=(0, PAD_SM))

        ctk.CTkButton(
            buttons, text="Disable" if enabled else "Enable", width=100, height=28,
            font=font(11, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"],
            command=lambda rid=rule_id, to=not enabled: self._set_enabled(rid, to),
        ).grid(row=0, column=1, padx=(0, PAD_SM))

        ctk.CTkButton(
            buttons, text="Delete", width=90, height=28, font=font(11, "bold"),
            fg_color=PALETTE["danger"], hover_color="#b03a35",
            command=lambda rid=rule_id: self._delete_rule(rid),
        ).grid(row=0, column=2)

    # ==================================================================
    # Mutations
    # ==================================================================
    def _new_rule(self) -> None:
        self._rule_dialog(None)

    def _edit_rule(self, rule_id: int) -> None:
        rule = self.db.get_firewall_rule(rule_id)
        if rule is None:
            self.app.show_error("Edit rule", f"No rule with id {rule_id}.")
            return
        self._rule_dialog(rule)

    def _rule_dialog(self, rule: dict[str, Any] | None) -> None:
        """Modal create/edit dialog (a Toplevel so it can block with grab_set)."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Edit rule" if rule else "New rule")
        dialog.geometry("460x620")
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()

        fields: dict[str, ctk.CTkEntry | ctk.CTkOptionMenu | ctk.CTkSwitch] = {}
        body = ctk.CTkFrame(dialog, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=PAD, pady=PAD)
        body.grid_columnconfigure(1, weight=1)

        def add_label(text: str, row: int) -> None:
            ctk.CTkLabel(
                body, text=text, font=font(11, "bold"), text_color=PALETTE["text_muted"],
                anchor="w",
            ).grid(row=row, column=0, sticky="w", pady=(PAD_SM, 0))

        add_label("Rule name (unique)", 0)
        fields["name"] = ctk.CTkEntry(body, height=30, font=font(12))
        fields["name"].insert(0, str(rule.get("name", "")) if rule else "")
        fields["name"].grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Direction", 2)
        fields["direction"] = ctk.CTkOptionMenu(
            body, values=list(_DIRECTIONS), height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
        )
        fields["direction"].set(
            str(rule.get("direction", "Outbound")).title() if rule else "Outbound"
        )
        fields["direction"].grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Action", 4)
        fields["action"] = ctk.CTkOptionMenu(
            body, values=list(_ACTIONS), height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
        )
        fields["action"].set(str(rule.get("action", "Block")).title() if rule else "Block")
        fields["action"].grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Protocol", 6)
        fields["protocol"] = ctk.CTkOptionMenu(
            body, values=list(_PROTOCOLS), height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
        )
        fields["protocol"].set(str(rule.get("protocol", "Any") or "Any") if rule else "Any")
        fields["protocol"].grid(row=7, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Remote port (blank = any)", 8)
        fields["remote_port"] = ctk.CTkEntry(body, height=30, font=mono_font(12))
        fields["remote_port"].insert(0, str(rule.get("remote_port") or "") if rule else "")
        fields["remote_port"].grid(row=9, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Remote IP / CIDR (blank = any)", 10)
        fields["remote_ip"] = ctk.CTkEntry(body, height=30, font=mono_font(12))
        fields["remote_ip"].insert(0, str(rule.get("remote_ip") or "") if rule else "")
        fields["remote_ip"].grid(row=11, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Application name or path (optional)", 12)
        fields["app_path"] = ctk.CTkEntry(body, height=30, font=font(12))
        fields["app_path"].insert(0, str(rule.get("app_path") or "") if rule else "")
        fields["app_path"].grid(row=13, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Profile", 14)
        fields["profile"] = ctk.CTkOptionMenu(
            body, values=list(_PROFILES), height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], button_color=PALETTE["accent"],
            button_hover_color=PALETTE["accent_hover"], text_color=PALETTE["text"],
        )
        fields["profile"].set(str(rule.get("profile", "Any") or "Any") if rule else "Any")
        fields["profile"].grid(row=15, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Description", 16)
        fields["description"] = ctk.CTkEntry(body, height=30, font=font(12))
        fields["description"].insert(0, str(rule.get("description") or "") if rule else "")
        fields["description"].grid(row=17, column=0, columnspan=2, sticky="ew", pady=(0, PAD_SM))

        add_label("Enabled", 18)
        fields["enabled"] = ctk.CTkSwitch(body, text="Rule active", font=font(12))
        if not rule or bool(rule.get("enabled")):
            fields["enabled"].select()
        fields["enabled"].grid(row=19, column=0, columnspan=2, sticky="w", pady=(0, PAD))

        def submit() -> None:
            name = str(fields["name"].get()).strip()
            if not name:
                messagebox.showwarning("Missing name", "Give the rule a name.", parent=dialog)
                return
            port = str(fields["remote_port"].get()).strip()
            if port and not port.isdigit():
                messagebox.showwarning(
                    "Invalid port", "Port must be a number or blank.", parent=dialog
                )
                return
            remote_ip = str(fields["remote_ip"].get()).strip()
            if remote_ip:
                import ipaddress

                try:
                    if "/" in remote_ip:
                        ipaddress.ip_network(remote_ip, strict=False)
                    else:
                        ipaddress.ip_address(remote_ip)
                except ValueError:
                    messagebox.showwarning(
                        "Invalid address", f"'{remote_ip}' is not an IP or CIDR.", parent=dialog
                    )
                    return

            payload = dict(
                name=name,
                direction=str(fields["direction"].get()).upper(),
                action=str(fields["action"].get()).upper(),
                protocol=str(fields["protocol"].get()),
                remote_port=port or None,
                remote_ip=remote_ip or None,
                app_path=str(fields["app_path"].get()).strip() or None,
                profile=str(fields["profile"].get()),
                description=str(fields["description"].get()).strip() or None,
                enabled=bool(fields["enabled"].get()),
            )
            if rule is None:
                created = self.db.add_firewall_rule(**payload)
                if created <= 0:
                    messagebox.showerror(
                        "Duplicate", f"A rule named '{name}' already exists.", parent=dialog
                    )
                    return
            else:
                self.db.update_firewall_rule(int(rule["id"]), **payload)
            self._after_mutation(f"{'Updated' if rule else 'Created'} rule '{name}'")
            dialog.destroy()

        buttons = ctk.CTkFrame(body, fg_color="transparent")
        buttons.grid(row=20, column=0, columnspan=2, sticky="ew")
        ctk.CTkButton(
            buttons, text="Save", width=110, height=32, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"], command=submit,
        ).grid(row=0, column=0, padx=(0, PAD_SM))
        ctk.CTkButton(
            buttons, text="Cancel", width=110, height=32, font=font(12),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=dialog.destroy,
        ).grid(row=0, column=1)

    def _set_enabled(self, rule_id: int, enabled: bool) -> None:
        if self.db.set_firewall_rule_enabled(rule_id, enabled):
            self._after_mutation(f"Rule {'enabled' if enabled else 'disabled'}")
        else:
            self.app.show_error("Firewall", f"Could not update rule {rule_id}.")

    def _delete_rule(self, rule_id: int) -> None:
        rule = self.db.get_firewall_rule(rule_id)
        name = str(rule.get("name")) if rule else str(rule_id)
        if self.app.ask_yes_no("Delete rule", f"Delete the rule '{name}'?"):
            if self.db.delete_firewall_rule(rule_id):
                self._after_mutation(f"Rule '{name}' deleted")
            else:
                self.app.show_error("Firewall", f"Could not delete rule {rule_id}.")

    def _apply_all(self) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("Firewall", "The firewall engine is not loaded.")
            return
        try:
            applied = engine.apply_all()
        except Exception as exc:
            logger.error("Apply-all failed: %s", exc, exc_info=True)
            self.app.show_error("Firewall", f"Could not apply rules:\n{exc}")
            return
        if not applied:
            self.app.set_status_message(
                "Rules stored (dry-run or not elevated); nothing sent to the OS"
            )
        self.refresh()

    def _after_mutation(self, message: str) -> None:
        """Refresh the list, tell the user, and re-sync the OS rules when enforcing."""
        self.app.set_status_message(message)
        self._expanded_id = None
        engine = self._engine()
        if engine is not None:
            try:
                engine.apply_all()
            except Exception as exc:
                logger.debug("Post-mutation apply_all skipped: %s", exc)
        self.refresh()

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        if any(
            event.get("event_type") in ("RULE_CREATED", "RULE_MODIFIED", "RULE_DELETED")
            for event in events
        ):
            self.refresh()
