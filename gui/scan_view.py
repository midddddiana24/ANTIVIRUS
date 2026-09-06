"""Scan view — start, watch and review on-demand scans.

Three scan types map to :meth:`core.antivirus.scanner.Scanner.run` targets: quick
(configured hot spots), full (all fixed disks) and custom (a chosen path). The scan
itself runs on a worker thread because ``Scanner.run`` is deliberately blocking — the
UI keeps its responsiveness contract by feeding progress through
:meth:`ShieldEXApp.post_to_ui` and never touching widgets from the worker.

The view also honours the shell's pending-scan contract: dashboard buttons land here
with a scan type pre-selected via :meth:`ShieldEXApp.take_pending_scan_request`, and the
view pre-selects it without auto-starting (the user always confirms what gets scanned).
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from tkinter import filedialog
from typing import Any

import customtkinter as ctk

from core.antivirus.quarantine import QuarantineManager
from core.antivirus.scanner import Detection, Scanner
from core.timeline import Severity
from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font, severity_color
from gui.widgets import Card, Chip, EmptyState, HoverRow, SeverityChip, StatLine

logger = logging.getLogger(__name__)

_SCAN_TYPES: tuple[tuple[str, str], ...] = (
    ("quick", "Quick Scan"),
    ("full", "Full Scan"),
    ("custom", "Custom Path"),
)


class ScanView(BaseView):
    """Run scans and show live progress plus the resulting detections."""

    title = "Malware Scanner"
    subtitle = "On-demand scans of the whole system, hot spots or a chosen path"

    def build(self) -> None:
        self._scan_type = ctk.StringVar(value="quick")
        self._custom_path = ctk.StringVar(value=str(Path.home()))
        self._scan_thread: threading.Thread | None = None
        self._cancel_event = threading.Event()
        self._results: list[Detection] = []
        self._progress_files = 0
        self._progress_threats = 0

        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(2, weight=1)

        self._build_actions()
        self._build_config_card()
        self._build_progress_card()
        self._build_results_card()
        self._set_running(False)
        self._update_last_scan()

    # ================================================================== header
    def _build_actions(self) -> None:
        self._start_button = ctk.CTkButton(
            self.actions, text="Start Scan", width=120, height=30, font=font(12, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=self._start,
        )
        self._start_button.grid(row=0, column=0, padx=(0, PAD_SM))
        self._cancel_button = ctk.CTkButton(
            self.actions, text="Cancel", width=90, height=30, font=font(12, "bold"),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._cancel, state="disabled",
        )
        self._cancel_button.grid(row=0, column=1)

    # ================================================================== config
    def _build_config_card(self) -> None:
        card = Card(self.content, title="Scan target")
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD))
        body = card.body
        body.grid_columnconfigure(1, weight=1)

        for index, (value, label) in enumerate(_SCAN_TYPES):
            ctk.CTkRadioButton(
                body, text=label, value=value, variable=self._scan_type,
                font=font(12), command=self._on_type_changed,
            ).grid(row=index, column=0, sticky="w", padx=(0, PAD), pady=2)

        self._path_row = ctk.CTkFrame(body, fg_color="transparent")
        self._path_row.grid(row=0, column=1, columnspan=2, sticky="ew", padx=(0, 0))
        self._path_row.grid_columnconfigure(0, weight=1)
        self._path_entry = ctk.CTkEntry(
            self._path_row, textvariable=self._custom_path, font=mono_font(12),
            placeholder_text="Path to scan (file or folder)",
        )
        self._path_entry.grid(row=0, column=0, sticky="ew", padx=(0, PAD_SM))
        ctk.CTkButton(
            self._path_row, text="Browse...", width=90, height=28, font=font(12),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._browse,
        ).grid(row=0, column=1)

        self._hint = ctk.CTkLabel(
            body, text="", font=font(11), text_color=PALETTE["text_muted"], anchor="w",
            justify="left",
        )
        self._hint.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(PAD_SM, 0))
        self._on_type_changed()

    def _on_type_changed(self) -> None:
        scan_type = self._scan_type.get()
        custom = scan_type == "custom"
        self._path_row.grid() if custom else self._path_row.grid_remove()
        if scan_type == "quick":
            paths = self.cfg.resolve_paths("antivirus.quick_scan_paths", directories_only=True)
            joined = ", ".join(path.name or str(path) for path in paths[:6])
            self._hint.configure(
                text=(
                    "Quick scan — the usual infection sites (%TEMP%, Startup, Downloads and\n"
                    f"browser caches), two folder levels deep. Typically 1–3 minutes.\n"
                    f"Locations: {joined}" + (" …" if len(paths) > 6 else "")
                )
            )
        elif scan_type == "full":
            self._hint.configure(
                text=(
                    "Full scan — every fixed disk, every folder level. The thorough option\n"
                    "when you suspect a deep infection. Can take 30+ minutes; progress and\n"
                    "cancel stay live throughout."
                )
            )
        else:
            self._hint.configure(
                text=(
                    "Custom scan — exactly the file or folder you choose, at full depth.\n"
                    "The result card shows how many files were examined even when clean."
                )
            )

    def _browse(self) -> None:
        chosen = filedialog.askdirectory(initialdir=self._custom_path.get() or str(Path.home()))
        if chosen:
            self._custom_path.set(chosen)

    # ================================================================== progress
    def _build_progress_card(self) -> None:
        card = Card(self.content, title="Progress")
        card.grid(row=1, column=0, sticky="ew", pady=(0, PAD))
        body = card.body
        body.grid_columnconfigure(0, weight=1)

        self._progress_bar = ctk.CTkProgressBar(body, height=10)
        self._progress_bar.grid(row=0, column=0, sticky="ew", pady=(0, PAD_SM))
        self._progress_bar.set(0)

        stats = ctk.CTkFrame(body, fg_color="transparent")
        stats.grid(row=1, column=0, sticky="ew")
        stats.grid_columnconfigure(0, weight=1)
        stats.grid_columnconfigure(1, weight=1)
        stats.grid_columnconfigure(2, weight=1)
        stats.grid_columnconfigure(3, weight=1)

        self._stat_files = StatLine(stats, "Files scanned", "0")
        self._stat_files.grid(row=0, column=0, sticky="ew")
        self._stat_threats = StatLine(stats, "Threats found", "0", value_color=PALETTE["success"])
        self._stat_threats.grid(row=0, column=1, sticky="ew")
        self._stat_rate = StatLine(stats, "Speed", "—")
        self._stat_rate.grid(row=0, column=2, sticky="ew")
        self._stat_state = StatLine(stats, "State", "Idle")
        self._stat_state.grid(row=0, column=3, sticky="ew")

        self._current_file = ctk.CTkLabel(
            body, text="", font=mono_font(11), text_color=PALETTE["text_muted"],
            anchor="w", justify="left",
        )
        self._current_file.grid(row=2, column=0, sticky="ew", pady=(PAD_SM, 0))

    # ================================================================== results
    def _build_results_card(self) -> None:
        self._results_card = Card(self.content, title="Detections")
        self._results_card.grid(row=2, column=0, sticky="nsew")
        body = self._results_card.body
        body.grid_rowconfigure(0, weight=1)

        self._results_frame = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._results_frame.grid(row=0, column=0, sticky="nsew")
        self._results_frame.grid_columnconfigure(0, weight=1)
        self._results_empty = EmptyState(self._results_frame, "No detections in this scan")
        self._results_empty.grid(row=0, column=0, pady=PAD_LG)

    def _render_results(self) -> None:
        for child in self._results_frame.winfo_children():
            child.destroy()
        if not self._results:
            EmptyState(
                self._results_frame,
                "No threats found — the scanned locations are clean",
            ).grid(row=0, column=0, pady=PAD_LG)
        else:
            for detection in self._results:
                self._render_detection_row(detection)

        running = self._scan_thread is not None and self._scan_thread.is_alive()
        if running:
            self._results_card.title_label.configure(text="DETECTIONS (scanning…)")
        elif self._results:
            self._results_card.title_label.configure(
                text=f"DETECTIONS ({len(self._results)})"
            )
        elif self._progress_files:
            # A finished clean scan must still show evidence it *did* something:
            # "no threats" over a blank panel read as "scan didn't run".
            self._results_card.title_label.configure(
                text=f"DETECTIONS — none in {self._progress_files:,} file(s) scanned "
                f"({self._progress_threats} threat(s))"
            )
        else:
            self._results_card.title_label.configure(text="DETECTIONS")

    def _render_detection_row(self, detection: Detection) -> None:
        row = HoverRow(self._results_frame)
        row.grid(sticky="ew", pady=(0, PAD_SM))
        row.grid_columnconfigure(1, weight=1)

        SeverityChip(row, detection.severity).grid(row=0, column=0, padx=(0, PAD), pady=PAD_SM)
        row.activate_bindings()

        text_frame = ctk.CTkFrame(row, fg_color="transparent")
        text_frame.grid(row=0, column=1, sticky="ew", padx=(0, PAD))
        text_frame.grid_columnconfigure(0, weight=1)

        path_text = str(Path(detection.path).name)
        ctk.CTkLabel(
            text_frame, text=path_text, font=font(12, "bold"), anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            text_frame, text=str(Path(detection.path).parent), font=mono_font(11),
            text_color=PALETTE["text_muted"], anchor="w",
        ).grid(row=1, column=0, sticky="ew")
        detail = detection.threat_name
        if detection.kind == "signature":
            detail += "  ·  known malware (signature match)"
        else:
            detail += "  ·  suspicious behaviour"
        if detection.quarantined:
            detail += "  ·  quarantined"
        elif detection.quarantine_error:
            detail += f"  ·  quarantine failed: {detection.quarantine_error}"
        ctk.CTkLabel(
            text_frame, text=detail, font=font(11), text_color=PALETTE["text_muted"], anchor="w",
        ).grid(row=2, column=0, sticky="ew")

    # ================================================================== engine
    def _scanner(self) -> Scanner:
        engine = self.app.get_engine("scanner")
        if engine is not None:
            return engine
        quarantine = QuarantineManager(self.cfg, self.db, self.timeline)
        return Scanner(self.cfg, self.db, self.timeline, quarantine)

    # ================================================================== run
    def _start(self) -> None:
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self.app.set_status_message("A scan is already running")
            return

        scan_type = self._scan_type.get()
        target: str | None = None
        if scan_type == "custom":
            target = self._custom_path.get().strip()
            if not target or not Path(target).exists():
                self.app.show_error("Custom scan", "Choose an existing file or folder to scan.")
                return

        self._cancel_event.clear()
        self._results = []
        self._progress_files = 0
        self._progress_threats = 0
        self._scan_started_at = time.monotonic()
        self._set_running(True)
        self._stat_state.set_value("Running", PALETTE["warning"])
        self._stat_rate.set_value("…")
        self._current_file.configure(text="Preparing…")
        self._render_results()

        scanner = self._scanner()

        def on_progress(files: int, threats: int, current: str) -> None:
            def apply() -> None:
                self._stat_files.set_value(f"{files:,}")
                self._stat_threats.set_value(
                    f"{threats:,}", PALETTE["danger"] if threats else PALETTE["success"]
                )
                elapsed = time.monotonic() - self._scan_started_at
                if elapsed > 2 and files > 50:
                    rate = files / elapsed
                    self._stat_rate.set_value(f"{rate:,.0f} files/s")
                self._current_file.configure(text=current)
            self.app.post_to_ui(apply)

        def worker() -> None:
            try:
                result = scanner.run(
                    scan_type,
                    target=target,
                    on_progress=on_progress,
                    should_cancel=self._cancel_event.is_set,
                )
                self.app.post_to_ui(lambda: self._finish(result))
            except Exception as exc:
                logger.exception("Scan worker failed")
                message = str(exc)
                self.app.post_to_ui(lambda: self._failed(message))

        self._scan_thread = threading.Thread(target=worker, name="shieldex-scan", daemon=True)
        self._scan_thread.start()
        self.app.set_status_message(f"{scan_type.title()} scan started")

    def _finish(self, result: Any) -> None:
        self._set_running(False)
        self._results = list(result.detections)
        self._progress_files = result.files_scanned
        self._progress_threats = result.threats_found
        self._stat_files.set_value(f"{result.files_scanned:,}")
        self._stat_threats.set_value(
            f"{result.threats_found:,}", PALETTE["danger"] if result.threats_found else PALETTE["success"]
        )
        self._progress_bar.set(1.0)
        if result.status == "CANCELLED":
            self._stat_state.set_value("Cancelled", PALETTE["warning"])
            self._current_file.configure(text="")
        elif result.status == "FAILED":
            self._stat_state.set_value("Failed", PALETTE["danger"])
            self._current_file.configure(text=f"Scan failed: {result.error}")
        else:
            self._stat_state.set_value("Completed", PALETTE["success"])
            self._current_file.configure(
                text=f"Finished in {result.duration_seconds:.1f}s "
                f"({result.files_skipped} skipped — too large or unreadable)"
            )
        self._render_results()
        self._update_last_scan()
        self.app.set_status_message(
            f"Scan finished: {result.files_scanned} files, {result.threats_found} threats"
        )

    def _failed(self, message: str) -> None:
        self._set_running(False)
        self._stat_state.set_value("Failed", PALETTE["danger"])
        self._current_file.configure(text=f"Scan failed: {message}")
        self.app.show_error("Scan failed", message)

    def _cancel(self) -> None:
        self._cancel_event.set()
        self._stat_state.set_value("Cancelling…", PALETTE["warning"])
        self.app.set_status_message("Cancelling scan — finishing the current file")

    def _set_running(self, running: bool) -> None:
        self._start_button.configure(state="disabled" if running else "normal")
        self._cancel_button.configure(state="normal" if running else "disabled")
        for child in self._path_row.winfo_children():
            try:
                child.configure(state="disabled" if running else "normal")
            except ctk.TkinterError:
                pass

    # ================================================================== last scan
    def _update_last_scan(self) -> None:
        """Show the last completed scan's headline numbers as the initial state."""
        last = self.db.get_last_scan()
        if last is None:
            self._stat_state.set_value("Never scanned", PALETTE["text_muted"])
            return
        files = int(last.get("files_scanned") or 0)
        threats = int(last.get("threats_found") or 0)
        self._stat_files.set_value(f"{files:,}")
        self._stat_threats.set_value(
            f"{threats:,}", PALETTE["danger"] if threats else PALETTE["success"]
        )
        self._stat_state.set_value(f"Last: {last.get('scan_type', '?')} scan", PALETTE["text_muted"])
        self._current_file.configure(
            text=f"Last scan {str(last.get('end_time') or last.get('start_time') or '')[:16]}"
        )

    # ================================================================== lifecycle
    def on_show(self) -> None:
        pending = self.app.take_pending_scan_request()
        if pending:
            scan_type = str(pending.get("scan_type", "quick")).lower()
            if scan_type in {value for value, _ in _SCAN_TYPES}:
                self._scan_type.set(scan_type)
            target = pending.get("target")
            if target:
                self._custom_path.set(str(target))
            self._on_type_changed()
        if not (self._scan_thread and self._scan_thread.is_alive()):
            self._update_last_scan()
        self.refresh()

    def on_hide(self) -> None:
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self._cancel_event.set()

    def refresh(self) -> None:
        running = self._scan_thread is not None and self._scan_thread.is_alive()
        if not running and not self._results:
            self._update_last_scan()
