"""Scan view — quick/full/custom scans with live progress, cancellation and results.

The scanner runs on a worker thread (it is deliberately blocking, see
``core.antivirus.scanner``) and reports through the app's ``post_to_ui`` queue; this
view never touches the database from the worker and never lets Tk be called off the
main thread. The pending-request contract from :meth:`gui.app.ShieldEXApp.open_scan`
is honoured in ``on_show``: a Quick/FulL scan request pre-selects the type rather
than auto-starting, because a scan started behind the user's back is surprising and
hard to cancel from another view.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from tkinter import filedialog
from typing import Any

import customtkinter as ctk

from core.timeline import EventType, Severity
from gui.base_view import BaseView
from gui.theme import PAD, PAD_LG, PAD_SM, PALETTE, font, mono_font
from gui.widgets import Card, Chip, EmptyState, HoverRow, SeverityChip, StatLine

logger = logging.getLogger(__name__)

#: (key, label, description) for the three scan types the UI offers.
_SCAN_TYPES: tuple[tuple[str, str, str], ...] = (
    ("quick", "Quick Scan", "Usual infection sites: TEMP, Downloads, Startup, app data"),
    ("full", "Full Scan", "Every fixed disk — slow, but nothing hides"),
    ("custom", "Custom Scan", "Choose exactly which file or folder to inspect"),
)


class ScanView(BaseView):
    """Run on-demand scans and review their detections."""

    title = "Virus Scan"
    subtitle = "Hash → signature match → heuristic classification, on demand"

    def build(self) -> None:
        self._scan_thread: threading.Thread | None = None
        self._cancel_flag = threading.Event()
        self._custom_target: Path | None = None
        self._result: Any | None = None
        self._detection_rows: list[ctk.CTkFrame] = []

        self.content.grid_columnconfigure(0, weight=2, uniform="scan")
        self.content.grid_columnconfigure(1, weight=3, uniform="scan")
        self.content.grid_rowconfigure(2, weight=1)

        self._build_launcher()
        self._build_progress()
        self._build_results()

    # ==================================================================
    # Launcher card
    # ==================================================================
    def _build_launcher(self) -> None:
        card = Card(self.content, title="Start a scan")
        card.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_SM), pady=(0, PAD))
        body = card.body

        self._type_buttons: dict[str, ctk.CTkButton] = {}
        for index, (key, label, description) in enumerate(_SCAN_TYPES):
            button = ctk.CTkButton(
                body,
                text=label,
                font=font(13, "bold"),
                height=44,
                anchor="w",
                fg_color=PALETTE["surface_alt"],
                hover_color=PALETTE["surface_hover"],
                text_color=PALETTE["text"],
                command=lambda kind=key: self._select_type(kind),
            )
            button.grid(row=index, column=0, sticky="ew", pady=(0, PAD_SM))
            self._type_buttons[key] = button
            ctk.CTkLabel(
                body, text=description, font=font(11), text_color=PALETTE["text_muted"],
                anchor="w", justify="left",
            ).grid(row=index, column=1, sticky="ew", padx=(PAD_SM, 0), pady=(0, PAD_SM))

        self._target_label = ctk.CTkLabel(
            body, text="Custom target: not chosen", font=mono_font(11),
            text_color=PALETTE["text_muted"], anchor="w", wraplength=340, justify="left",
        )
        self._target_label.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(PAD_SM, 0))

        self._choose_button = ctk.CTkButton(
            body, text="Choose file or folder…", height=30, font=font(12),
            fg_color=PALETTE["surface_alt"], text_color=PALETTE["text"],
            hover_color=PALETTE["surface_hover"], command=self._choose_target,
        )
        self._choose_button.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(PAD_SM, 0))

        self._start_button = ctk.CTkButton(
            body, text="Start Quick Scan", height=40, font=font(13, "bold"),
            fg_color=PALETTE["accent"], hover_color=PALETTE["accent_hover"],
            command=self._start_scan,
        )
        self._start_button.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(PAD, 0))

        self._select_type("quick")

    def _select_type(self, scan_type: str) -> None:
        """Highlight the chosen scan type and relabel the start button."""
        self._scan_type = scan_type
        for key, button in self._type_buttons.items():
            selected = key == scan_type
            button.configure(
                fg_color=PALETTE["accent"] if selected else PALETTE["surface_alt"],
                text_color="#ffffff" if selected else PALETTE["text"],
            )
        self._choose_button.configure(state="normal" if scan_type == "custom" else "disabled")
        self._start_button.configure(text=f"Start {_label_for(scan_type)} Scan")
        if scan_type != "custom":
            self._custom_target = None
            self._target_label.configure(text="Custom target: not chosen")

    def _choose_target(self) -> None:
        """Pick the custom-scan target with the OS dialog."""
        chosen = filedialog.askopenfilename(
            parent=self,
            title="Choose a file to scan",
            filetypes=[("All files", "*.*")],
        )
        if not chosen:
            directory = filedialog.askdirectory(parent=self, title="Choose a folder to scan")
            if not directory:
                return
            self._custom_target = Path(directory)
        else:
            self._custom_target = Path(chosen)
        self._target_label.configure(text=f"Custom target: {self._custom_target}")

    # ==================================================================
    # Progress card
    # ==================================================================
    def _build_progress(self) -> None:
        card = Card(self.content, title="Progress")
        card.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(PAD_SM, 0), pady=(0, PAD))
        body = card.body

        self._status_chip = Chip(body, "IDLE", PALETTE["neutral"])
        self._status_chip.grid(row=0, column=0, sticky="w", pady=(0, PAD_SM))

        self._progress_bar = ctk.CTkProgressBar(body, height=14)
        self._progress_bar.set(0)
        self._progress_bar.grid(row=1, column=0, sticky="ew", pady=(0, PAD_SM))

        self._status_line = ctk.CTkLabel(
            body, text="No scan running.", font=font(12), text_color=PALETTE["text"],
            anchor="w", justify="left", wraplength=430,
        )
        self._status_line.grid(row=2, column=0, sticky="ew")

        self._live_lines: dict[str, StatLine] = {}
        for index, (key, label) in enumerate((
            ("files", "Files scanned"),
            ("threats", "Threats found"),
            ("skipped", "Files skipped"),
            ("elapsed", "Elapsed"),
        )):
            line = StatLine(body, label)
            line.grid(row=3 + index, column=0, sticky="ew", pady=2)
            self._live_lines[key] = line

        self._cancel_button = ctk.CTkButton(
            body, text="Cancel scan", height=32, font=font(12, "bold"),
            fg_color=PALETTE["danger"], hover_color="#b03a35",
            command=self._cancel_scan, state="disabled",
        )
        self._cancel_button.grid(row=7, column=0, sticky="ew", pady=(PAD, 0))

    # ==================================================================
    # Results card
    # ==================================================================
    def _build_results(self) -> None:
        card = Card(self.content, title="Detections", subtitle="Latest scan's findings")
        card.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(0, 0))
        card.grid_rowconfigure(1, weight=1)
        body = card.body
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        self._summary_label = ctk.CTkLabel(
            body, text="No scan has run yet.", font=font(12),
            text_color=PALETTE["text_muted"], anchor="w",
        )
        self._summary_label.grid(row=0, column=0, sticky="w", pady=(0, PAD_SM))

        self._results_scroll = ctk.CTkScrollableFrame(body, fg_color="transparent")
        self._results_scroll.grid(row=1, column=0, sticky="nsew")
        self._results_scroll.grid_columnconfigure(0, weight=1)

        self._results_empty = EmptyState(
            self._results_scroll,
            "No detections to show.\nRun a scan — clean files stay off this list by design.",
        )

    # ==================================================================
    # Scanning
    # ==================================================================
    def _start_scan(self) -> None:
        """Launch the selected scan on a worker thread (guarded against re-entry)."""
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self.app.set_status_message("A scan is already running")
            return

        scanner = self.app.get_engine("scanner")
        if scanner is None:
            self.app.show_error(
                "Scan unavailable",
                "The scanner engine could not be loaded.\n\nSee logs/shieldex.log.",
            )
            return

        scan_type = self._scan_type
        target = None
        if scan_type == "custom":
            if self._custom_target is None or not self._custom_target.exists():
                self.app.show_error("Custom scan", "Choose a file or folder to scan first.")
                return
            target = self._custom_target

        label = _label_for(scan_type)
        self._cancel_flag.clear()
        self._set_running_ui(True, label)
        self._render_detections([])  # clear last run's rows
        self._summary_label.configure(text=f"{label} scan started…")

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scanner, scan_type, target),
            name="ShieldEX-Scan",
            daemon=True,
        )
        self._scan_thread.start()

    def _run_scan(self, scanner: Any, scan_type: str, target: Path | None) -> None:
        """Worker thread: run the blocking scan and post UI updates through the queue."""

        def on_progress(files: int, threats: int, current: str) -> None:
            name = Path(current).name
            self.app.post_to_ui(
                lambda f=files, t=threats, n=name: self._update_progress(f, t, n)
            )

        def should_cancel() -> bool:
            return self._cancel_flag.is_set()

        try:
            result = scanner.run(
                scan_type, target, on_progress=on_progress, should_cancel=should_cancel
            )
        except Exception as exc:  # a worker crash must not strand the UI in "running"
            logger.error("Scan worker failed: %s", exc, exc_info=True)
            self.app.post_to_ui(lambda: self._scan_finished(None, error=str(exc)))
            return
        self.app.post_to_ui(lambda: self._scan_finished(result, error=None))

    def _update_progress(self, files: int, threats: int, current: str) -> None:
        """UI thread: one progress tick from the scanner."""
        if not self._scan_running():
            return
        self._live_lines["files"].set_value(f"{files:,}")
        self._live_lines["threats"].set_value(
            f"{threats:,}", PALETTE["danger"] if threats else PALETTE["text"]
        )
        self._status_line.configure(text=f"Scanning… {current}")
        # Indeterminate sweep: total file counts are unknown until the walk finishes.
        self._progress_bar.set((self._progress_bar.get() + 0.03) % 1.0)

    def _scan_finished(self, result: Any, error: str | None) -> None:
        """UI thread: scan done (completed, cancelled or failed)."""
        self._set_running_ui(False, "")
        if result is None:
            self._status_chip.update_chip("FAILED", PALETTE["danger"])
            self._status_line.configure(text=f"Scan failed: {error}")
            self._summary_label.configure(text=f"Scan failed: {error}")
            self.app.set_status_message("Scan failed")
            return

        self._result = result
        self._live_lines["files"].set_value(f"{result.files_scanned:,}")
        self._live_lines["threats"].set_value(f"{result.threats_found:,}")
        self._live_lines["skipped"].set_value(f"{result.files_skipped:,}")
        self._live_lines["elapsed"].set_value(f"{result.duration_seconds:.1f}s")

        chip_text, chip_color = {
            "COMPLETED": ("COMPLETED", PALETTE["success"]),
            "CANCELLED": ("CANCELLED", PALETTE["warning"]),
            "FAILED": ("FAILED", PALETTE["danger"]),
        }[result.status]
        self._status_chip.update_chip(chip_text, chip_color)
        self._status_line.configure(
            text=f"{_label_for(result.scan_type)} scan of {result.target} finished "
                 f"({result.status.lower()})."
        )

        self._render_detections(result.detections)
        clean = result.status == "COMPLETED" and not result.detections
        self._summary_label.configure(
            text=(
                f"No threats in {result.files_scanned:,} file(s) — system clean."
                if clean
                else f"{len(result.detections)} detection(s) in {result.files_scanned:,} file(s)."
            ),
            text_color=PALETTE["success"] if clean else PALETTE["text"],
        )
        self.app.set_status_message(
            f"{_label_for(result.scan_type)} scan {result.status.lower()}: "
            f"{result.threats_found} threat(s)"
        )

    def _cancel_scan(self) -> None:
        """Ask the worker to stop at the next file boundary."""
        if self._scan_running():
            self._cancel_flag.set()
            self._cancel_button.configure(state="disabled", text="Cancelling…")
            self.app.set_status_message("Cancelling scan…")

    def _scan_running(self) -> bool:
        return self._scan_thread is not None and self._scan_thread.is_alive()

    def _set_running_ui(self, running: bool, label: str) -> None:
        """Flip every control between idle and running states."""
        for button in self._type_buttons.values():
            button.configure(state="disabled" if running else "normal")
        self._choose_button.configure(
            state="disabled" if running or self._scan_type != "custom" else "normal"
        )
        self._start_button.configure(
            state="disabled" if running else "normal",
            text=f"Scanning… ({label})" if running else f"Start {_label_for(self._scan_type)} Scan",
        )
        self._cancel_button.configure(
            state="normal" if running else "disabled", text="Cancel scan"
        )
        if running:
            self._status_chip.update_chip("SCANNING", PALETTE["accent"])
            for key in ("files", "threats", "skipped", "elapsed"):
                self._live_lines[key].set_value("0")
            self._progress_bar.configure(mode="indeterminate")
            self._progress_bar.start()
        else:
            self._progress_bar.stop()
            self._progress_bar.configure(mode="determinate")
            self._progress_bar.set(1.0 if self._result is not None else 0)

    # ==================================================================
    # Detections list
    # ==================================================================
    def _render_detections(self, detections: list[Any]) -> None:
        """Redraw the detections list for the latest result."""
        for row in self._detection_rows:
            row.destroy()
        self._detection_rows.clear()

        if not detections:
            self._results_empty.grid(row=0, column=0, pady=PAD_LG)
            return
        self._results_empty.grid_remove()

        for index, detection in enumerate(detections):
            row = HoverRow(
                self._results_scroll,
                on_click=lambda det=detection: self._open_detection(det),
            )
            row.grid(row=index, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(2, weight=1)

            SeverityChip(row, detection.severity).grid(
                row=0, column=0, padx=(PAD_SM, PAD_SM), pady=PAD_SM
            )
            ctk.CTkLabel(
                row, text=detection.threat_name, font=font(12, "bold"),
                text_color=PALETTE["text"], anchor="w",
            ).grid(row=0, column=1, sticky="w", padx=(0, PAD_SM), pady=PAD_SM)
            ctk.CTkLabel(
                row, text=detection.path, font=mono_font(11),
                text_color=PALETTE["text_muted"], anchor="w", justify="left",
            ).grid(row=0, column=2, sticky="ew", pady=PAD_SM)

            state_text, color = (
                ("Quarantined", PALETTE["success"])
                if detection.quarantined
                else ("Not quarantined", PALETTE["danger"] if detection.quarantine_error else PALETTE["warning"])
            )
            Chip(row, state_text, color).grid(row=0, column=3, padx=PAD_SM, pady=PAD_SM)
            row.activate_bindings()

    def _open_detection(self, detection: Any) -> None:
        """Drill into the timeline narrative for this detection."""
        self.app.open_timeline(
            source="ANTIVIRUS", search=str(Path(detection.path).name)
        )

    # ==================================================================
    # Lifecycle
    # ==================================================================
    def on_show(self) -> None:
        """Pre-select (not auto-start) any scan the dashboard requested."""
        pending = self.app.take_pending_scan_request()
        if pending:
            scan_type = str(pending.get("scan_type", "")).lower()
            if scan_type in ("quick", "full", "custom"):
                self._select_type(scan_type)
            if pending.get("target"):
                target = Path(str(pending["target"]))
                if target.exists():
                    self._custom_target = target
                    self._target_label.configure(text=f"Custom target: {target}")
        self._sync_idle_state()

    def _sync_idle_state(self) -> None:
        """Reflect a scan that is still running from before the view was hidden."""
        if not self._scan_running():
            return
        self._set_running_ui(True, _label_for(self._scan_type))

    def on_hide(self) -> None:
        """Scans keep running when the view is hidden; nothing to pause."""

    def on_timeline_events(self, events: list[dict[str, Any]]) -> None:
        """Detection narrative events arriving while a scan runs.

        Threat counts come from the scanner's own progress callbacks, so the timeline
        feed needs no counting here; the card stays consistent through those callbacks.
        """

    def refresh(self) -> None:
        """Show the last recorded scan summary when idle (first paint and polling)."""
        if self._scan_running() or self._result is not None:
            return
        last = self.db.get_last_scan()
        if last is None:
            return
        self._live_lines["files"].set_value(f"{int(last.get('files_scanned') or 0):,}")
        self._live_lines["threats"].set_value(f"{int(last.get('threats_found') or 0):,}")
        self._status_line.configure(
            text=f"Last scan: {str(last.get('scan_type', '?')).title()} of "
                 f"{last.get('target') or 'system locations'} at "
                 f"{str(last.get('end_time') or last.get('start_time') or '')[:16]}"
        )
        self._summary_label.configure(
            text=f"Last recorded scan: {int(last.get('threats_found') or 0)} threat(s) in "
                 f"{int(last.get('files_scanned') or 0):,} file(s)."
        )


def _label_for(scan_type: str) -> str:
    """Human label for a scan type key."""
    return {"quick": "Quick", "full": "Full", "custom": "Custom"}.get(scan_type, scan_type.title())
