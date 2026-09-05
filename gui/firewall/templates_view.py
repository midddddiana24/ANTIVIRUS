"""Rule Templates view — one-click instantiation of curated firewall rules.

The template definitions live on the rule engine (``create_rule_from_template``), so
the data has one home; this view is purely their storefront: what each template does,
whether it is already instantiated (rule names are unique), and a button to add it.
"""

from __future__ import annotations

import logging
from typing import Any

import customtkinter as ctk

from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, StatLine

logger = logging.getLogger(__name__)

#: (template key, title, description) — the keys must match the engine's table.
_TEMPLATES: tuple[tuple[str, str, str], ...] = (
    (
        "block_rdp_in",
        "Block inbound RDP",
        "Deny TCP 3389 from any remote address — closes the Remote Desktop door to "
        "the network.",
    ),
    (
        "block_smb_out",
        "Block outbound SMB",
        "Deny TCP 445 outbound — stops lateral-movement file sharing and many "
        "ransomware propagation paths.",
    ),
    (
        "allow_updates",
        "Allow OS update traffic",
        "Permit TCP 443 for the Windows Update client (wuauclt.exe) — update delivery "
        "keeps working under stricter policies.",
    ),
    (
        "block_telnet_out",
        "Block outbound Telnet",
        "Deny TCP 23 outbound — Telnet sends credentials in clear text and has no "
        "legitimate modern use.",
    ),
)


class TemplatesView(BaseView):
    """Instantiate curated firewall rules."""

    title = "Rule Templates"
    subtitle = "Common-sense firewall rules, added with one click"

    def build(self) -> None:
        self._rows: list[ctk.CTkFrame] = []

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=1)

        self._build_note()
        self._build_list()

    # ==================================================================
    # Layout
    # ==================================================================
    def _build_note(self) -> None:
        card = Card(self.content, title="How templates work")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        body = card.body

        enforcing = bool(self.cfg.get("firewall.enforce_rules", False))
        self._mode_line = StatLine(body, "Enforcement mode")
        self._mode_line.grid(row=0, column=0, sticky="ew")
        self._applied_line = StatLine(body, "Rules created from templates")
        self._applied_line.grid(row=1, column=0, sticky="ew")

        self._mode_line.set_value(
            "ENFORCING" if enforcing else "DRY-RUN",
            PALETTE["success"] if enforcing else PALETTE["warning"],
        )

    def _build_list(self) -> None:
        card = Card(self.content, title="Available templates")
        card.grid(row=1, column=0, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        self._scroll = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._scroll.grid(row=1, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        self._empty = EmptyState(
            self._scroll, "No templates available.\nThe rule engine could not be loaded."
        )

    # ==================================================================
    # Data
    # ==================================================================
    def _engine(self) -> Any | None:
        return self.app.get_engine("firewall")

    def refresh(self) -> None:
        engine = self._engine()

        enforcing = bool(self.cfg.get("firewall.enforce_rules", False))
        self._mode_line.set_value(
            "ENFORCING" if enforcing else "DRY-RUN (stored only)",
            PALETTE["success"] if enforcing else PALETTE["warning"],
        )

        if engine is None:
            self._empty.grid(row=0, column=0, pady=PAD_LG)
            for row in self._rows:
                row.destroy()
            self._rows.clear()
            self._applied_line.set_value("—")
            return

        # Which templates are already instantiated? Match on the template's rule name,
        # which is what both the engine and the OS use to identify a rule.
        applied_names = {
            str(rule.get("name"))
            for rule in self.db.get_firewall_rules()
        }
        applied_count = sum(1 for _key, title, _desc in _TEMPLATES if title in applied_names)
        self._applied_line.set_value(f"{applied_count} of {len(_TEMPLATES)}")

        for row in self._rows:
            row.destroy()
        self._rows.clear()
        self._empty.grid_remove()

        for index, (key, title, description) in enumerate(_TEMPLATES):
            self._rows.append(self._build_row(index, key, title, description, title in applied_names))

    def _build_row(
        self, index: int, key: str, title: str, description: str, applied: bool
    ) -> HoverRow:
        row = HoverRow(self._scroll)
        row.grid(row=index, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            row, text=title, font=font(13, "bold"), text_color=PALETTE["text"], anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=(PAD_SM, PAD_SM), pady=PAD_SM)
        ctk.CTkLabel(
            row, text=description, font=font(11), text_color=PALETTE["text_muted"],
            anchor="w", justify="left", wraplength=560,
        ).grid(row=0, column=1, sticky="ew", pady=PAD_SM)

        if applied:
            Chip(row, "Added", PALETTE["success"]).grid(row=0, column=2, padx=PAD_SM, pady=PAD_SM)
        else:
            ctk.CTkButton(
                row, text="Add rule", width=100, height=28, font=font(11, "bold"),
                fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
                command=lambda template_key=key, template_title=title: self._add(
                    template_key, template_title
                ),
            ).grid(row=0, column=2, padx=PAD_SM, pady=PAD_SM)

        row.activate_bindings()
        return row

    def _add(self, key: str, title: str) -> None:
        engine = self._engine()
        if engine is None:
            self.app.show_error("Rule Templates", "The firewall engine is not loaded.")
            return
        try:
            rule_id = engine.create_rule_from_template(key)
        except Exception as exc:
            logger.error("Template instantiation failed: %s", exc, exc_info=True)
            self.app.show_error("Rule Templates", f"Could not add '{title}':\n{exc}")
            return
        if rule_id:
            self.app.set_status_message(f"Template added: {title}")
            # The engine already logged the creation to the timeline; enforcement
            # re-sync happens through its own apply_all call path when enforcing.
            try:
                engine.apply_all()
            except Exception as exc:
                logger.debug("Post-template apply_all skipped: %s", exc)
        else:
            self.app.set_status_message(
                f"'{title}' already exists or the template key was not found"
            )
        self.refresh()

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        if any(event.get("event_type") == "RULE_CREATED" for event in events):
            self.refresh()
