"""ShieldEX application shell: window, sidebar navigation and cross-view plumbing.

The shell owns everything the individual views should not care about:

* the window, theme and status bar;
* a **registry-driven sidebar**. Each entry names the module and class that implements it,
  and availability is probed with :func:`importlib.util.find_spec`. A view whose module
  does not exist yet is listed but disabled, and lights up automatically the moment the
  module is added — no edits to this file required;
* marshalling background-thread work onto the Tk thread through two queues — one for
  timeline events, one for arbitrary UI callbacks (:meth:`ShieldEXApp.post_to_ui`) — since
  Tk widgets may only be touched from the thread that created them. Note that ``after()``
  is *not* an escape hatch: it calls into the Tcl interpreter and is itself unsafe off the
  main thread, so background code must use the queue;
* an **engine registry**. Long-running engines (real-time monitor, firewall rule engine,
  connection monitor) register themselves here, and the shell's toggles drive them
  through a uniform interface while always persisting the desired state to the database.
"""

from __future__ import annotations

import importlib
import logging
import queue
import threading
import tkinter
from dataclasses import dataclass
from tkinter import messagebox
from typing import Any, Callable

import customtkinter as ctk

from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger
from gui.base_view import BaseView, module_available
from gui.theme import (
    NAV_ROW_HEIGHT,
    PAD,
    PAD_LG,
    PAD_SM,
    PALETTE,
    SIDEBAR_WIDTH,
    SP_LG,
    SP_MD,
    SP_SM,
    STATUS_BAR_HEIGHT,
    TYPE_BODY,
    TYPE_CAPTION,
    TYPE_MICRO,
    apply_appearance,
    font,
)
from gui.widgets import Banner, Chip

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ViewSpec:
    """Declarative description of one navigable view."""

    key: str
    label: str
    module: str
    class_name: str
    section: str


#: Sidebar layout. Order here is the order on screen.
VIEW_SPECS: tuple[ViewSpec, ...] = (
    ViewSpec("dashboard", "Dashboard", "gui.dashboard", "DashboardView", "Overview"),
    ViewSpec("timeline", "Threat Timeline", "gui.timeline_view", "TimelineView", "Overview"),
    ViewSpec("scan", "Scan", "gui.scan_view", "ScanView", "Antivirus"),
    ViewSpec("quarantine", "Quarantine", "gui.quarantine_view", "QuarantineView", "Antivirus"),
    ViewSpec("history", "Scan History", "gui.history_view", "HistoryView", "Antivirus"),
    ViewSpec("fw_rules", "Rules", "gui.firewall.rules_view", "RulesView", "Firewall"),
    ViewSpec(
        "fw_connections", "Live Connections", "gui.firewall.connections_view",
        "ConnectionsView", "Firewall",
    ),
    ViewSpec("fw_blocklist", "IP Lists", "gui.firewall.blocklist_view", "BlocklistView", "Firewall"),
    ViewSpec("fw_alerts", "IDS Alerts", "gui.firewall.alerts_view", "AlertsView", "Firewall"),
    ViewSpec(
        "fw_templates", "Rule Templates", "gui.firewall.templates_view",
        "TemplatesView", "Firewall",
    ),
    ViewSpec("settings", "Settings", "gui.settings_view", "SettingsView", "System"),
)

SECTION_ORDER: tuple[str, ...] = ("Overview", "Antivirus", "Firewall", "System")

#: How often the visible view's ``refresh()`` runs, and how often the event queue drains.
_EVENT_PUMP_MS = 400
_MAX_EVENTS_PER_PUMP = 250


class ShieldEXApp(ctk.CTk):
    """The main ShieldEX window."""

    def __init__(
        self,
        config: Config,
        db: Database,
        timeline: TimelineLogger,
        elevated: bool = False,
        request_elevation: Callable[[], bool] | None = None,
    ) -> None:
        super().__init__()

        # ``self.config`` is Tk's own method — the configuration object lives in ``cfg``.
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.elevated = elevated
        self._request_elevation = request_elevation

        self._views: dict[str, BaseView] = {}
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        self._engines: dict[str, Any] = {}
        self._current_key: str | None = None
        self._event_queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=4000)
        #: Callables posted by worker threads for the UI thread to run. Background code must
        #: never touch a widget — not even via ``after()``, which is itself a Tcl call and
        #: raises "main thread is not in main loop" when made off the main thread.
        self._ui_calls: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._after_ids: set[str] = set()
        self._closing = False
        #: Guards against a second signature update while one is still running.
        self._update_in_flight = False

        #: Filters handed to the timeline view by :meth:`open_timeline`; the view consumes
        #: and clears this on show, which is how "click a dashboard event to drill in" works.
        self.pending_timeline_filter: dict[str, Any] = {}

        #: Scan handed to the scan view by :meth:`open_scan`, consumed the same way. This is
        #: what makes the dashboard's Quick and Full scan buttons two different actions.
        self.pending_scan_request: dict[str, Any] = {}

        apply_appearance(
            str(config.get("app.theme", "dark")), str(config.get("app.accent_color", "#2f6fb0"))
        )
        self._configure_window()
        self._build_layout()
        self._build_sidebar()
        self._build_status_bar()

        self.timeline.subscribe(self._enqueue_event)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        start_view = str(config.get("app.start_view", "dashboard"))
        # CHANGED: also require the view's module to exist on disk. _find_spec only proves the
        # key is registered, and most keys are registered before their module is written, so
        # a config pointing at an unbuilt view used to leave the window completely blank.
        if not self._view_is_loadable(start_view):
            if start_view != "dashboard":
                logger.warning("Configured start_view %r is not available; using dashboard", start_view)
            start_view = "dashboard"
        self.navigate(start_view)

        self._schedule(self._pump_events, _EVENT_PUMP_MS)
        # A 0 or negative interval would turn _periodic_refresh into an after(0) busy loop
        # that re-queries the database as fast as Tk can dispatch, so clamp to 1 second.
        refresh_seconds = max(1, int(config.get("ui.dashboard_refresh_seconds", 5)))
        self._schedule(self._periodic_refresh, refresh_seconds * 1000)
        logger.info("GUI ready (elevated=%s)", elevated)

    # ==================================================================
    # Window construction
    # ==================================================================
    def _configure_window(self) -> None:
        name = str(self.cfg.get("app.name", "ShieldEX"))
        version = str(self.cfg.get("app.version", ""))
        mode = "Administrator" if self.elevated else "Limited Mode"
        self.title(f"{name} {version} — Security Suite [{mode}]")

        width = int(self.cfg.get("app.window.width", 1320))
        height = int(self.cfg.get("app.window.height", 840))
        self.geometry(f"{width}x{height}")
        self.minsize(
            int(self.cfg.get("app.window.min_width", 1080)),
            int(self.cfg.get("app.window.min_height", 680)),
        )
        self.configure(fg_color=PALETTE["window"])

        icon = self.cfg.app_root / "assets" / "icons" / "shieldex.ico"
        if icon.exists():
            try:
                self.iconbitmap(str(icon))
            except tkinter.TclError as exc:  # unsupported format on this platform
                logger.debug("Could not set window icon: %s", exc)

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)

        row = 0
        if not self.elevated:
            action_text = "Restart as Administrator" if self._request_elevation else None
            banner = Banner(
                self,
                "Limited mode — ShieldEX is not elevated. Firewall rules cannot be applied to "
                "the operating system and some protected folders cannot be scanned.",
                PALETTE["warning"],
                action_text=action_text,
                action=self._elevate if action_text else None,
            )
            banner.grid(row=0, column=0, columnspan=2, sticky="ew")
            self.grid_rowconfigure(0, weight=0)
            row = 1

        self._body_row = row
        # CHANGED: only the body row may absorb vertical slack, and the rows around it are
        # pinned to 0. Previously row 1 was weighted unconditionally, so when the app *is*
        # elevated (the default) the body sat at row 0 and the 30px status bar at row 1 —
        # both weighted 1 — and Tk split the window evenly between content and status bar.
        self.grid_rowconfigure(self._body_row, weight=1)
        self.grid_rowconfigure(self._body_row + 1, weight=0)

        self.sidebar = ctk.CTkFrame(self, width=SIDEBAR_WIDTH, corner_radius=0, fg_color=PALETTE["sidebar"])
        self.sidebar.grid(row=row, column=0, sticky="nsw")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)

        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.grid(row=row, column=1, sticky="nsew")
        self.content_container.grid_columnconfigure(0, weight=1)
        self.content_container.grid_rowconfigure(0, weight=1)

    def _build_sidebar(self) -> None:
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=SP_LG, pady=(SP_LG, SP_MD))
        brand.grid_columnconfigure(1, weight=1)
        # Brand mark: accent tile with the product initial, beside the wordmark.
        # A drawn tile rather than an image asset — no file to lose in packaging.
        mark = ctk.CTkLabel(
            brand,
            text="S",
            font=font(16, "bold"),
            text_color="#ffffff",
            fg_color=PALETTE["accent"],
            corner_radius=8,
            width=36,
            height=36,
        )
        mark.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, SP_SM))
        ctk.CTkLabel(
            brand,
            text="SHIELDEX",
            font=font(17, "bold"),
            text_color=PALETTE["text"],
            anchor="w",
        ).grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            brand,
            text="Antivirus + Firewall",
            font=font(TYPE_MICRO),
            text_color=PALETTE["text_muted"],
            anchor="w",
        ).grid(row=1, column=1, sticky="w")

        row = 1
        for section in SECTION_ORDER:
            specs = [spec for spec in VIEW_SPECS if spec.section == section]
            if not specs:
                continue
            ctk.CTkLabel(
                self.sidebar,
                text=section.upper(),
                font=font(TYPE_MICRO, "bold"),
                text_color=PALETTE["text_muted"],
                anchor="w",
            ).grid(row=row, column=0, sticky="ew", padx=SP_LG, pady=(SP_MD, SP_SM))
            row += 1

            for spec in specs:
                available = module_available(spec.module)
                button = ctk.CTkButton(
                    self.sidebar,
                    text=spec.label if available else f"{spec.label}  ·  soon",
                    anchor="w",
                    height=NAV_ROW_HEIGHT,
                    corner_radius=8,
                    font=font(TYPE_BODY),
                    fg_color="transparent",
                    hover_color=PALETTE["surface_hover"],
                    text_color=PALETTE["text"] if available else PALETTE["text_muted"],
                    command=(lambda key=spec.key: self.navigate(key)) if available else None,
                    state="normal" if available else "disabled",
                )
                button.grid(row=row, column=0, sticky="ew", padx=SP_SM, pady=1)
                self._nav_buttons[spec.key] = button
                row += 1

        self.sidebar.grid_rowconfigure(row, weight=1)  # push the footer down
        self._sidebar_footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self._sidebar_footer.grid(row=row + 1, column=0, sticky="ew", padx=SP_MD, pady=SP_MD)
        self._sidebar_footer.grid_columnconfigure(0, weight=1)
        self._live_label = ctk.CTkLabel(
            self._sidebar_footer,
            text="Timeline events today: 0",
            font=font(TYPE_MICRO),
            text_color=PALETTE["text_muted"],
            anchor="w",
        )
        self._live_label.grid(row=0, column=0, sticky="ew")

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, height=STATUS_BAR_HEIGHT, corner_radius=0, fg_color=PALETTE["sidebar"])
        bar.grid(row=self._body_row + 1, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(4, weight=1)

        self._fw_mode_chip = Chip(
            bar,
            "FIREWALL: ENFORCING" if self._enforcing_config() else "FIREWALL: DRY-RUN",
            PALETTE["success"] if self._enforcing_config() else PALETTE["warning"],
        )
        self._fw_mode_chip.grid(row=0, column=0, padx=(SP_MD, SP_SM), pady=SP_SM)

        self._privilege_chip = Chip(
            bar,
            "ADMIN" if self.elevated else "LIMITED",
            PALETTE["success"] if self.elevated else PALETTE["danger"],
        )
        self._privilege_chip.grid(row=0, column=1, padx=(0, SP_SM), pady=SP_SM)

        divider = ctk.CTkFrame(bar, width=1, fg_color=PALETTE["border"])
        divider.grid(row=0, column=2, sticky="ns", padx=SP_SM, pady=8)

        self._signature_label = ctk.CTkLabel(
            bar, text="", font=font(TYPE_MICRO), text_color=PALETTE["text_muted"]
        )
        self._signature_label.grid(row=0, column=3, padx=(0, SP_MD), pady=SP_SM)

        self._status_message = ctk.CTkLabel(
            bar, text="", font=font(TYPE_MICRO), text_color=PALETTE["text_muted"], anchor="e"
        )
        self._status_message.grid(row=0, column=4, sticky="e", padx=SP_MD, pady=SP_SM)
        self._update_status_bar()

    def _enforcing_config(self) -> bool:
        """Whether the firewall is configured to enforce (dry-run otherwise)."""
        return bool(self.cfg.get("firewall.enforce_rules", False))

    def _update_status_bar(self) -> None:
        """Refresh the signature and event counters.

        Wrapped because this runs from two repeating ``after`` callbacks: an unreadable
        database (removed drive, revoked permissions) would otherwise raise inside the Tk
        callback several times a second and bury the real error in tracebacks.
        """
        if self._closing:
            return
        try:
            count = self.db.signature_count()
            version = self.db.get_setting("signature_db_version", "none")
            events_today = self.db.count_timeline_events(today=True)
        except Exception as exc:
            logger.error("Could not read status bar counters: %s", exc, exc_info=True)
            self._signature_label.configure(text="Signatures: unavailable")
            self._live_label.configure(text="Timeline: database unreadable")
            return
        self._signature_label.configure(text=f"Signatures: {count:,}  (db {version})")
        self._live_label.configure(text=f"Timeline events today: {events_today:,}")

    # ==================================================================
    # Navigation
    # ==================================================================
    @staticmethod
    def _find_spec(key: str) -> ViewSpec | None:
        """Look up a view spec by key."""
        for spec in VIEW_SPECS:
            if spec.key == key:
                return spec
        return None

    @classmethod
    def _view_is_loadable(cls, key: str) -> bool:
        """True when ``key`` is registered *and* its module is importable.

        The two conditions are separate because views are registered in
        :data:`VIEW_SPECS` before their module is written, which is what lets the sidebar
        show them greyed out and light them up automatically once the file lands.
        """
        spec = cls._find_spec(key)
        return spec is not None and module_available(spec.module)

    def navigate(self, key: str) -> bool:
        """Show the view registered under ``key``. Returns True when it is now visible."""
        spec = self._find_spec(key)
        if spec is None:
            logger.error("Unknown view key: %s", key)
            return False

        if key == self._current_key:
            # CHANGED: on_show() is what consumes pending_timeline_filter, and it is skipped
            # on this path. Without re-running it, drilling into the timeline *from* the
            # timeline silently dropped the filter and then applied it to a later, unrelated
            # navigation. Refresh still happens, because on_show ends in a refresh.
            view = self._views.get(key)
            if view is not None:
                try:
                    view.on_show()
                except Exception as exc:
                    logger.error("on_show failed for %s: %s", key, exc, exc_info=True)
                return True
            self.refresh_current_view()
            return True

        view = self._views.get(key)
        if view is None:
            view = self._instantiate_view(spec)
            if view is None:
                return False
            self._views[key] = view

        if self._current_key is not None:
            previous = self._views.get(self._current_key)
            if previous is not None:
                try:
                    previous.on_hide()
                except Exception as exc:
                    logger.error("on_hide failed for %s: %s", self._current_key, exc, exc_info=True)
                previous.grid_remove()

        view.grid(row=0, column=0, sticky="nsew")
        self._current_key = key
        self._highlight_nav(key)
        try:
            view.on_show()
        except Exception as exc:
            logger.error("on_show failed for %s: %s", key, exc, exc_info=True)
        logger.debug("Navigated to %s", key)
        return True

    def _instantiate_view(self, spec: ViewSpec) -> BaseView | None:
        """Import and construct a view, reporting failures instead of crashing the app."""
        try:
            module = importlib.import_module(spec.module)
            view_class = getattr(module, spec.class_name)
            return view_class(self.content_container, self)
        except Exception as exc:
            logger.error("Could not load view %s (%s): %s", spec.key, spec.module, exc, exc_info=True)
            self.show_error(
                "View unavailable",
                f"'{spec.label}' could not be loaded:\n\n{exc}\n\nSee logs/shieldex.log.",
            )
            return None

    def _highlight_nav(self, key: str) -> None:
        """Mark the active nav entry with an accent-tinted pill.

        A translucent-tint pill with accent text rather than a solid fill: solid
        accent blocks read as buttons (inviting a click on the page you are already
        on), while the pill reads as "you are here".
        """
        for nav_key, button in self._nav_buttons.items():
            if button.cget("state") == "disabled":
                continue
            selected = nav_key == key
            button.configure(
                fg_color=PALETTE["accent_soft"] if selected else "transparent",
                text_color=PALETTE["accent_text"] if selected else PALETTE["text"],
                font=font(TYPE_BODY, "bold" if selected else "normal"),
            )

    @property
    def current_view(self) -> BaseView | None:
        """The visible view, if any."""
        return self._views.get(self._current_key) if self._current_key else None

    def open_timeline(self, **filters: Any) -> None:
        """Jump to the Threat Behavior Timeline with filters pre-applied.

        Used by the dashboard activity feed so clicking an event drills straight into it.
        """
        self.pending_timeline_filter = dict(filters)
        self.navigate("timeline")

    def take_pending_timeline_filter(self) -> dict[str, Any]:
        """Return and clear any filter queued by :meth:`open_timeline`."""
        pending, self.pending_timeline_filter = self.pending_timeline_filter, {}
        return pending

    def open_scan(self, scan_type: str, target: str | None = None) -> None:
        """Jump to the scan view with a scan pre-selected.

        Contract for ``gui.scan_view``: read :meth:`take_pending_scan_request` in
        ``on_show`` and pre-select (not auto-start) the requested scan. This is how the
        dashboard's "Quick Scan" and "Full Scan" buttons stay distinct even though both
        land on the same view. ``target`` carries a chosen path for a custom scan.
        """
        self.pending_scan_request = {"scan_type": scan_type, "target": target}
        self.navigate("scan")

    def take_pending_scan_request(self) -> dict[str, Any]:
        """Return and clear any scan queued by :meth:`open_scan`."""
        pending, self.pending_scan_request = self.pending_scan_request, {}
        return pending

    def refresh_current_view(self) -> None:
        """Ask the visible view to re-read its data."""
        view = self.current_view
        if view is None:
            return
        try:
            view.refresh()
        except Exception as exc:
            logger.error("refresh failed for %s: %s", self._current_key, exc, exc_info=True)

    # ==================================================================
    # Scheduling / live events
    # ==================================================================
    def _schedule(self, callback: Callable[[], None], delay_ms: int) -> None:
        """Run ``callback`` after ``delay_ms``, tracking the id so shutdown can cancel it.

        The id is discarded as soon as the callback runs. Without that, the repeating
        400 ms event pump added an id every tick and never removed one, so a resident
        session accumulated hundreds of thousands of dead ids in :attr:`_after_ids`.
        """
        if self._closing:
            return

        holder: dict[str, str] = {}

        def run_once() -> None:
            self._after_ids.discard(holder.get("id", ""))
            callback()

        after_id = self.after(delay_ms, run_once)
        holder["id"] = after_id
        self._after_ids.add(after_id)

    def _enqueue_event(self, event: dict[str, Any]) -> None:
        """Timeline subscriber. Runs on the engine's thread, so it only touches the queue."""
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            logger.debug("Timeline event queue full; dropping UI update for event %s", event.get("id"))

    def post_to_ui(self, callback: Callable[[], None]) -> None:
        """Queue ``callback`` to run on the UI thread. Safe to call from any thread.

        This is the only sanctioned way for a background engine to cause a widget update.
        ``Widget.after`` is not an alternative: it calls into the Tcl interpreter and so is
        itself unsafe off the main thread.
        """
        self._ui_calls.put(callback)

    def _drain_ui_calls(self) -> None:
        """Run everything worker threads have posted. UI thread only."""
        while True:
            try:
                callback = self._ui_calls.get_nowait()
            except queue.Empty:
                return
            if self._closing:
                continue
            try:
                callback()
            except Exception as exc:
                logger.error("Queued UI callback failed: %s", exc, exc_info=True)

    def _pump_events(self) -> None:
        """Drain queued timeline events and hand them to the visible view (UI thread)."""
        if self._closing:
            return

        self._drain_ui_calls()

        batch: list[dict[str, Any]] = []
        while len(batch) < _MAX_EVENTS_PER_PUMP:
            try:
                batch.append(self._event_queue.get_nowait())
            except queue.Empty:
                break

        if batch:
            view = self.current_view
            if view is not None:
                try:
                    view.on_timeline_events(batch)
                except Exception as exc:
                    logger.error("on_timeline_events failed: %s", exc, exc_info=True)
            self._update_status_bar()

        self._schedule(self._pump_events, _EVENT_PUMP_MS)

    def _periodic_refresh(self) -> None:
        """Poll-refresh the visible view and the status bar."""
        if self._closing:
            return
        self.refresh_current_view()
        self._update_status_bar()
        self._schedule(
            self._periodic_refresh,
            max(1, int(self.cfg.get("ui.dashboard_refresh_seconds", 5))) * 1000,
        )

    # ==================================================================
    # Engine registry + protection toggles
    # ==================================================================
    def register_engine(self, name: str, engine: Any) -> None:
        """Register a long-running engine so the shell's toggles can drive it."""
        self._engines[name] = engine
        logger.info("Engine registered: %s (%s)", name, type(engine).__name__)

    def get_engine(self, name: str) -> Any | None:
        """Return a registered engine, or ``None`` when that engine is not loaded."""
        return self._engines.get(name)

    def set_realtime_monitoring(self, enabled: bool) -> bool:
        """Persist and apply the real-time file monitoring state.

        The desired state always goes to the database first, so it survives a restart and
        the monitor picks it up on next launch even if no monitor is registered yet.
        """
        self.db.set_bool_setting("realtime_monitoring_enabled", enabled)
        self.timeline.log_antivirus(
            EventType.MONITOR_STARTED if enabled else EventType.MONITOR_STOPPED,
            "Real-time file monitoring enabled by user"
            if enabled
            else "Real-time file monitoring disabled by user",
            Severity.INFO if enabled else Severity.LOW,
        )

        monitor = self.get_engine("realtime_monitor")
        if monitor is None:
            self.set_status_message(
                "Real-time monitoring state saved (monitor engine not loaded yet)"
            )
            return True
        try:
            if enabled:
                monitor.start()
            else:
                monitor.stop()
            self.set_status_message(
                f"Real-time monitoring {'started' if enabled else 'stopped'}"
            )
            return True
        except Exception as exc:
            logger.error("Real-time monitor toggle failed: %s", exc, exc_info=True)
            self.show_error("Real-time monitoring", f"Could not toggle the monitor:\n\n{exc}")
            return False

    def set_firewall_profile(self, profile: str, enabled: bool) -> bool:
        """Persist and apply the firewall on/off state for one network profile."""
        profile_key = profile.strip().lower()
        if profile_key not in {"domain", "private", "public"}:
            logger.error("Unknown firewall profile: %s", profile)
            return False

        self.db.set_bool_setting(f"firewall_enabled_{profile_key}", enabled)
        self.timeline.log_firewall(
            EventType.FIREWALL_ENABLED if enabled else EventType.FIREWALL_DISABLED,
            f"{profile.title()} profile firewall turned {'on' if enabled else 'off'} by user",
            Severity.INFO if enabled else Severity.HIGH,
        )

        engine = self.get_engine("firewall")
        if engine is None:
            self.set_status_message(
                f"{profile.title()} profile state saved (firewall engine not loaded yet)"
            )
            return True
        try:
            engine.set_profile_enabled(profile_key, enabled)
            self.set_status_message(f"{profile.title()} profile firewall updated")
            return True
        except Exception as exc:
            logger.error("Firewall profile toggle failed: %s", exc, exc_info=True)
            self.show_error("Firewall", f"Could not change the {profile} profile:\n\n{exc}")
            return False

    def request_signature_update(self) -> None:
        """Run a malware-signature database update in the background.

        Contract for ``core.antivirus.updater``: the engine registered under the name
        ``"updater"`` must expose ``update_now()``, returning the number of new signatures
        merged. It is called on a worker thread, and the result comes back through
        :meth:`post_to_ui` so no widget is touched off the main thread.
        """
        updater = self.get_engine("updater")
        if updater is None:
            self.set_status_message("Signature updater engine is not loaded yet")
            return

        # One update at a time: each run does its own network fetch and writes
        # signature_db_version, so parallel runs waste bandwidth and race on that value.
        if self._update_in_flight:
            self.set_status_message("A signature update is already running")
            return
        self._update_in_flight = True

        def worker() -> None:
            """Runs off the main thread; must not touch a widget."""
            try:
                # Contract: SignatureUpdater.update_now() returns (applied, human_message).
                applied, message = updater.update_now()
                if not applied and not message.startswith("Update check failed"):
                    message = "Signature update failed: unknown outcome"
            except Exception as exc:  # network/parse failures must not kill the thread
                logger.error("Signature update failed: %s", exc, exc_info=True)
                message = f"Signature update failed: {exc}"
            # Inside the try/except's scope on purpose: whatever happened, the flag is
            # cleared and the UI is told, so the button can never latch permanently.
            self.post_to_ui(lambda: self._finish_signature_update(message))

        self.set_status_message("Checking for signature database updates...")
        threading.Thread(target=worker, name="ShieldEX-Updater", daemon=True).start()

    def _finish_signature_update(self, message: str) -> None:
        """UI-thread completion handler for :meth:`request_signature_update`."""
        self._update_in_flight = False
        if self._closing:
            return
        self.set_status_message(message)
        self._update_status_bar()
        self.refresh_current_view()

    @property
    def signature_update_running(self) -> bool:
        """True while a background signature update is in flight (for button state)."""
        return self._update_in_flight

    def protection_status(self, stats: dict[str, Any] | None = None) -> tuple[str, str]:
        """Return ``(label, colour)`` describing overall protection state."""
        data = stats or self.db.get_dashboard_stats()
        realtime = bool(data["antivirus"]["realtime_enabled"])
        profiles = data["firewall"]["profiles"]
        firewall_on = all(profiles.values())
        firewall_any = any(profiles.values())

        if realtime and firewall_on:
            return "PROTECTED", PALETTE["success"]
        if not realtime and not firewall_any:
            return "AT RISK", PALETTE["danger"]
        return "PARTIAL", PALETTE["warning"]

    # ==================================================================
    # Small UI services used by views
    # ==================================================================
    def set_status_message(self, message: str) -> None:
        """Show a transient message in the status bar."""
        self._status_message.configure(text=message)
        logger.debug("Status: %s", message)

    def show_info(self, title: str, message: str) -> None:
        """Modal information dialog."""
        messagebox.showinfo(title, message, parent=self)

    def show_error(self, title: str, message: str) -> None:
        """Modal error dialog."""
        messagebox.showerror(title, message, parent=self)

    def ask_yes_no(self, title: str, message: str) -> bool:
        """Modal confirmation dialog; returns the user's answer."""
        return bool(messagebox.askyesno(title, message, parent=self))

    def _elevate(self) -> None:
        """Relaunch elevated via the callback supplied by ``main``."""
        if self._request_elevation is None:
            return
        if not self.ask_yes_no(
            "Restart as administrator",
            "ShieldEX will close and reopen with administrator privileges.\n\nContinue?",
        ):
            return
        try:
            if self._request_elevation():
                self.on_close()
            else:
                self.show_error(
                    "Elevation failed",
                    "The elevation request was declined or unavailable.\n\n"
                    "ShieldEX will keep running in limited mode.",
                )
        except Exception as exc:
            logger.error("Elevation request failed: %s", exc, exc_info=True)
            self.show_error("Elevation failed", str(exc))

    # ==================================================================
    # Shutdown
    # ==================================================================
    def on_close(self) -> None:
        """Stop timers and engines, then destroy the window."""
        if self._closing:
            return
        self._closing = True
        logger.info("Shutting down GUI")

        for after_id in list(self._after_ids):
            try:
                self.after_cancel(after_id)
            except (tkinter.TclError, ValueError) as exc:
                # An id that already fired is normal here; log it rather than swallowing
                # it silently, so a genuine Tk problem during shutdown is still traceable.
                logger.debug("Could not cancel timer %s: %s", after_id, exc)
        self._after_ids.clear()

        try:
            self.timeline.unsubscribe(self._enqueue_event)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Unsubscribe failed: %s", exc)

        for name, engine in self._engines.items():
            stop = getattr(engine, "stop", None)
            if callable(stop):
                try:
                    stop()
                    logger.info("Engine stopped: %s", name)
                except Exception as exc:
                    logger.error("Engine %s failed to stop: %s", name, exc, exc_info=True)

        view = self.current_view
        if view is not None:
            try:
                view.on_hide()
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("on_hide during shutdown failed: %s", exc)

        self.destroy()
