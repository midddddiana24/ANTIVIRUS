#!/usr/bin/env python3
"""ShieldEX — All-in-One Desktop Security Suite (antivirus + firewall).

Entry point. Responsibilities, in order:

1. Start logging into an in-memory buffer, so anything the next two steps report is kept
   and later replayed into the real log file (see :class:`_StartupBuffer`).
2. Parse arguments, load ``config.json`` and create the runtime directories (``logs/``,
   ``.quarantine/``), then install the rotating file handler and replay the buffer.
3. Detect administrator/root privileges. Firewall rule enforcement needs them, so if the
   process is not elevated ShieldEX asks the OS to relaunch it elevated **once** (guarded
   by an environment flag so a declined UAC prompt can never cause a relaunch loop). If
   the user declines, ShieldEX continues in limited mode and the UI says so.
4. Open the unified database, create the schema, merge the bundled signature seed.
5. Launch the GUI.

Run with ``--skip-admin-check`` during development to stay unelevated without prompting.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import platform
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
if str(APP_ROOT) not in sys.path:  # allow ``python main.py`` from any working directory
    sys.path.insert(0, str(APP_ROOT))

from core.config import Config  # noqa: E402  (import after sys.path setup)
from core.database import Database, now_str  # noqa: E402
from core.timeline import EventType, Severity, TimelineLogger  # noqa: E402
from core.versions import is_newer_version, same_version_scheme, version_key  # noqa: E402

logger = logging.getLogger("shieldex")

#: Set in the environment before a UAC relaunch so the elevated child never re-prompts.
RELAUNCH_FLAG = "SHIELDEX_ELEVATION_ATTEMPTED"

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ----------------------------------------------------------------------------------
# Startup plumbing
# ----------------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="shieldex", description="ShieldEX desktop security suite"
    )
    parser.add_argument("--config", default=None, help="path to config.json")
    parser.add_argument("--debug", action="store_true", help="force DEBUG logging")
    parser.add_argument(
        "--skip-admin-check",
        action="store_true",
        help="do not attempt privilege elevation (development mode)",
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="initialise config, database and signatures, then exit (smoke test)",
    )
    return parser.parse_args(argv)


class _StartupBuffer(logging.Handler):
    """Keeps early log records in memory until the real handlers are installed.

    Configuration loading and directory creation both report problems through ``logging``,
    but they must run *before* logging can be configured — the log path and rotation
    settings come from the very file being loaded. Previously those records went nowhere:
    "config file was missing keys", "could not read config.json", "could not create
    .quarantine" were emitted with no handler attached and vanished, so ``logs/shieldex.log``
    always began after the interesting part. This handler captures them and
    :meth:`replay` re-emits them into the file handler once it exists.
    """

    #: Cap so a pathological early loop cannot grow this without bound.
    LIMIT = 500

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self._overflowed = False

    def emit(self, record: logging.LogRecord) -> None:
        """Store a record instead of writing it anywhere."""
        if len(self.records) < self.LIMIT:
            self.records.append(record)
        elif not self._overflowed:
            self._overflowed = True

    def replay(self, handlers: list[logging.Handler], level: int) -> None:
        """Re-emit buffered records into ``handlers``, dropping those below ``level``.

        The level filter is applied by hand because :meth:`logging.Handler.handle` bypasses
        logger levels: the buffer deliberately captured at DEBUG so nothing early could be
        lost, and without this filter a config of ``level: "WARNING"`` would still see the
        startup DEBUG lines appear in the file.
        """
        pending, self.records = self.records, []
        targets = [handler for handler in handlers if handler is not self]
        for record in pending:
            if record.levelno < level:
                continue
            for handler in targets:
                handler.handle(record)
        if self._overflowed:
            self._overflowed = False
            # Handed to the handlers directly rather than logged: this note matters most
            # when the configured level would filter it out, and it has to land *after* the
            # records it describes rather than ahead of them.
            self._emit_directly(
                targets,
                f"More than {self.LIMIT} startup log records were buffered; the excess "
                "was dropped",
            )

    def dump_to_stderr(self) -> None:
        """Last-resort flush used when startup fails before real logging exists.

        Without this, an exception raised while loading the config or configuring logging
        would discard the very records explaining why — the user would see only the
        traceback of the secondary failure.
        """
        pending, self.records = self.records, []
        if not pending:
            return
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
        for record in pending:
            handler.handle(record)
        handler.flush()

    @staticmethod
    def _emit_directly(handlers: list[logging.Handler], message: str) -> None:
        """Push a synthetic WARNING into ``handlers``, bypassing every level check."""
        record = logging.LogRecord(
            name=__name__, level=logging.WARNING, pathname=__file__, lineno=0,
            msg=message, args=(), exc_info=None,
        )
        for handler in handlers:
            handler.handle(record)


def begin_logging() -> _StartupBuffer:
    """Attach a buffer so nothing logged before the config is read gets lost.

    Deliberately *no* console handler: anything captured here is replayed into the real
    handlers moments later, and a temporary console would print those same records a second
    time — once on stderr now and once on stdout after the replay, in unpredictable order.
    :meth:`_StartupBuffer.dump_to_stderr` covers the failure case where the replay never
    happens, so nothing is hidden by leaving the console out.

    There is no ``debug`` parameter because the buffer captures at DEBUG unconditionally;
    ``--debug`` is applied by :func:`configure_logging` when the records are replayed.
    """
    root = logging.getLogger()
    # DEBUG regardless of the flag: the buffer keeps everything, and the level configured
    # from config.json is applied at replay time. --debug still takes effect there.
    root.setLevel(logging.DEBUG)
    _clear_root_handlers()

    buffer = _StartupBuffer()
    root.addHandler(buffer)
    return buffer


def _clear_root_handlers(keep: logging.Handler | None = None) -> None:
    """Detach and close every root handler, so re-entry cannot leak file descriptors.

    Closing matters on Windows: an orphaned ``RotatingFileHandler`` keeps its own handle on
    ``shieldex.log``, and the replacement handler's first rollover then fails with
    ``PermissionError`` on every record because the file cannot be renamed while that stale
    handle is open. ``keep`` spares the startup buffer, whose records are still needed.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        if handler is keep:
            continue
        try:
            handler.close()
        except Exception as exc:  # pragma: no cover - handler already broken
            print(f"ShieldEX: could not close log handler {handler!r}: {exc}", file=sys.stderr)


#: Levels a configuration file may name, as numbers. Anything outside this range is a typo
#: or a misunderstanding: a level above CRITICAL silences the application completely.
_MIN_LOG_LEVEL = logging.NOTSET
_MAX_LOG_LEVEL = logging.CRITICAL


def _resolve_log_level(raw: object) -> int:
    """Map a ``logging.level`` config value to a numeric level, or INFO if unusable.

    ``logging.getLevelName`` is used instead of ``getattr(logging, name)`` because the
    latter happily returns any module attribute: ``"shutdown"`` and ``"Handler"`` are real
    names in :mod:`logging` and neither is a level, yet ``getattr`` would hand the object
    straight to ``setLevel``.

    Numbers are range-checked rather than passed through. ``level: 999999999`` is otherwise
    accepted in silence and suppresses every record — including the replayed startup
    backlog — leaving a completely empty log file with nothing explaining why.
    """
    if isinstance(raw, bool):  # bool is an int subclass; True would read as level 1
        logger.warning("logging.level must be a level name, not %r; using INFO", raw)
        return logging.INFO

    candidate: int | None = None
    if isinstance(raw, int):
        candidate = raw
    else:
        text = str(raw).strip()
        if text.isdecimal():  # a quoted number, e.g. "20", is treated like the bare int
            candidate = int(text)
        else:
            resolved = logging.getLevelName(text.upper())
            if isinstance(resolved, int):
                candidate = resolved

    if candidate is None:
        logger.warning("Unknown logging.level %r; using INFO", raw)
        return logging.INFO
    if not _MIN_LOG_LEVEL <= candidate <= _MAX_LOG_LEVEL:
        logger.warning(
            "logging.level %r is outside %d-%d; using INFO",
            raw, _MIN_LOG_LEVEL, _MAX_LOG_LEVEL,
        )
        return logging.INFO
    return candidate


def _non_negative_int(raw: object, default: int, key: str) -> int:
    """Coerce a config value to an int >= 0, falling back to ``default`` with a warning."""
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        # OverflowError is not a ValueError: JSON accepts ``Infinity`` and ``1e999``, both
        # of which parse to float('inf'), and int(inf) raises OverflowError.
        logger.warning("%s must be a whole number, got %r; using %d", key, raw, default)
        return default
    if value < 0:
        logger.warning("%s cannot be negative, got %r; using %d", key, raw, default)
        return default
    return value


def configure_logging(
    config: Config,
    debug: bool = False,
    startup_buffer: "_StartupBuffer | None" = None,
) -> None:
    """Install a rotating file handler (and optional console handler) on the root logger.

    Every value read from ``config.json`` here is validated rather than trusted. These
    three keys are the only ones consumed *before* logging works, so a bad value used to
    raise an exception that nothing could report: ``max_bytes: "2MB"`` raised ``ValueError``
    from ``int()``, and ``level: "SHUTDOWN"`` resolved via ``getattr(logging, ...)`` to the
    ``logging.shutdown`` *function*, which ``setLevel`` then rejected with ``TypeError``.
    Either way the user saw a bare traceback and an empty log file.
    """
    level = logging.DEBUG if debug else _resolve_log_level(config.get("logging.level", "INFO"))
    max_bytes = _non_negative_int(config.get("logging.max_bytes", 2_097_152), 2_097_152, "logging.max_bytes")
    backup_count = _non_negative_int(config.get("logging.backup_count", 5), 5, "logging.backup_count")

    root = logging.getLogger()
    root.setLevel(level)
    # Keeps re-entry idempotent, and closes what it detaches — see _clear_root_handlers.
    _clear_root_handlers(keep=startup_buffer)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    log_path = config.log_path
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:
        # No file logging available (read-only dir, locked file); console must still work.
        fallback = logging.StreamHandler(sys.stderr)
        fallback.setFormatter(formatter)
        root.addHandler(fallback)
        root.error("Could not open log file %s: %s", log_path, exc)
        if startup_buffer is not None:
            startup_buffer.replay(root.handlers, level)
        return

    if bool(config.get("logging.console", True)):
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        root.addHandler(console)

    if startup_buffer is not None:
        startup_buffer.replay(root.handlers, level)


def is_elevated() -> bool:
    """True when the process has administrator (Windows) or root (POSIX) privileges."""
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError) as exc:
            logger.warning("Could not determine elevation state: %s", exc)
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - non-POSIX, non-Windows
        return False


def relaunch_as_admin(argv: list[str], force: bool = False) -> bool:
    """Ask Windows to restart ShieldEX elevated. Returns True if the child was launched.

    The UAC consent dialog is the OS's own prompt, which is the correct way to ask — a
    custom in-app dialog cannot grant privileges. On non-Windows platforms this returns
    False; the user is told to re-run with ``sudo``.

    ``force`` bypasses the once-per-launch guard. Startup elevation is guarded so a
    declined UAC prompt can never loop, but the in-app "Restart as Administrator" button
    is an explicit user action and is always allowed to try again.
    """
    if platform.system() != "Windows":
        logger.warning(
            "Not elevated. Firewall enforcement needs root — re-run with: sudo python3 main.py"
        )
        return False

    if not force and os.environ.get(RELAUNCH_FLAG) == "1":
        logger.warning("Elevation was already attempted this launch; staying in limited mode")
        return False

    os.environ[RELAUNCH_FLAG] = "1"  # inherited by the child process

    try:
        if getattr(sys, "frozen", False):  # PyInstaller build
            executable = sys.executable
            params = subprocess.list2cmdline(argv[1:])
        else:
            executable = sys.executable
            params = subprocess.list2cmdline([str(APP_ROOT / "main.py"), *argv[1:]])

        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", executable, params, str(APP_ROOT), 1
        )
        if int(result) > 32:
            logger.info("Elevated instance launched; this instance will exit")
            return True
        logger.warning("Elevation declined or failed (ShellExecuteW=%s)", result)
        return False
    except OSError as exc:
        logger.error("Elevation attempt failed: %s", exc)
        return False


def ensure_directories(config: Config) -> None:
    """Create the log and quarantine directories, hiding the quarantine vault on Windows."""
    for directory in (config.log_path.parent, config.quarantine_path, config.app_root / "assets"):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logging.getLogger(__name__).error("Could not create %s: %s", directory, exc)

    if platform.system() == "Windows":
        # A leading dot means nothing on Windows, so set the hidden attribute explicitly.
        try:
            subprocess.run(
                ["attrib", "+h", str(config.quarantine_path)],
                capture_output=True,
                timeout=10,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logging.getLogger(__name__).warning("Could not hide quarantine folder: %s", exc)


def _version_key(version: str) -> tuple[int, ...]:
    """Backward-compatible alias — the implementation moved to :mod:`core.versions`."""
    return version_key(version)


def _same_version_scheme(left: str, right: str) -> bool:
    """Backward-compatible alias — see :func:`core.versions.same_version_scheme`."""
    return same_version_scheme(left, right)


def seed_signatures(db: Database, config: Config) -> int:
    """Merge ``assets/signatures.json`` into the local signature table.

    Uses INSERT OR IGNORE, so remote updates already merged by the updater are never
    overwritten and re-running this is harmless. Returns the number of new rows.
    """
    seed_file = config.app_root / "assets" / "signatures.json"
    if not seed_file.exists():
        logger.warning("Bundled signature seed missing at %s", seed_file)
        return 0

    try:
        payload = json.loads(seed_file.read_text(encoding="utf-8"))
        entries = payload.get("signatures", [])
        bundled_version = str(payload.get("version", "")).strip()
    except (OSError, ValueError) as exc:
        logger.error("Could not read signature seed %s: %s", seed_file, exc)
        return 0

    if not isinstance(entries, list):
        logger.error("Signature seed 'signatures' key must be a list")
        return 0

    inserted = db.add_signatures(entries)

    stored_version = db.get_setting("signature_db_version", "none") or "none"

    # An unparseable seed version is never stored, not even on a first run. Storing it
    # once ("bundled", "None", "") would leave a value that no later numeric version
    # can ever beat, freezing the version the dashboard reports for good — and an empty
    # one would re-stamp signature_db_updated_at on every single launch, so the UI would
    # claim a fresh update each time the app opened.
    if is_newer_version(bundled_version, stored_version):
        db.set_setting("signature_db_version", bundled_version)
        db.set_setting("signature_db_updated_at", now_str())
        logger.info("Signature database version set to %s", bundled_version)
    else:
        logger.debug(
            "Bundled seed version %r does not supersede stored %r; version untouched",
            bundled_version, stored_version,
        )

    return inserted


def open_database(config: Config) -> Database:
    """Open and initialise the unified database, seeding first-run runtime settings."""
    db = Database(config.database_path, int(config.get("database.busy_timeout_ms", 10_000)))
    db.initialize(
        {
            "realtime_monitoring_enabled": "1"
            if config.get("antivirus.realtime_monitor.enabled", False)
            else "0",
            "firewall_enabled_domain": "1" if config.get("firewall.profiles.domain", True) else "0",
            "firewall_enabled_private": "1"
            if config.get("firewall.profiles.private", True)
            else "0",
            "firewall_enabled_public": "1" if config.get("firewall.profiles.public", True) else "0",
        }
    )
    return db


def purge_old_data(db: Database, config: Config) -> None:
    """Drop expired timeline events and connection-log rows, per ``retention`` config.

    Without a cap the timeline grows by hundreds of rows per scan forever (a narrative
    chain is several rows per detection), the queries that drive the dashboard and the
    timeline view slow down proportionally, and the file itself never shrinks. Runs
    after the app's own startup rows exist so the current launch is never the thing
    being purged. VACUUM reclaims the space rather than leaving it as free pages.
    """
    if not bool(config.get("retention.purge_on_startup", True)):
        return

    timeline_days = int(config.get("retention.timeline_days", 90) or 0)
    connection_days = int(config.get("retention.connection_log_days", 30) or 0)

    try:
        removed = db.purge_timeline(timeline_days) if timeline_days > 0 else 0
        removed += db.purge_connection_log(connection_days) if connection_days > 0 else 0
        if removed:
            logger.info("Retention purge removed %d expired row(s)", removed)
            db.vacuum()
    except Exception as exc:  # a cleanup failure must never block startup
        logger.warning("Retention purge failed: %s", exc)


# ----------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """Start ShieldEX. Returns a process exit code."""
    raw_argv = list(sys.argv) if argv is None else [sys.argv[0], *argv]
    args = parse_args(raw_argv[1:])

    # CHANGED: logging is started before the config is touched. Config.load() and
    # ensure_directories() both report failures through logging ("could not read
    # config.json", "could not create .quarantine"), and those messages used to be emitted
    # with no handler installed and lost. They are buffered now and replayed into the log
    # file by configure_logging below.
    startup_buffer = begin_logging()
    try:
        config = Config.load(args.config, APP_ROOT)
        ensure_directories(config)
        configure_logging(config, args.debug, startup_buffer)
    except Exception as exc:
        # Nothing is logging yet, so the buffered records are the only account of what
        # happened; flush them to stderr before the traceback that follows.
        startup_buffer.dump_to_stderr()
        print(f"ShieldEX could not start: {exc}", file=sys.stderr)
        raise

    app_name = config.get("app.name", "ShieldEX")
    app_version = config.get("app.version", "0.0.0")
    logger.info("=" * 78)
    logger.info(
        "%s %s starting — %s %s, Python %s",
        app_name, app_version, platform.system(), platform.release(),
        platform.python_version(),
    )

    elevated = is_elevated()
    if not elevated and config.get("app.require_admin", True) and not args.skip_admin_check:
        if relaunch_as_admin(raw_argv):
            return 0  # the elevated child takes over
        logger.warning(
            "Running WITHOUT administrator privileges: firewall rules cannot be applied to "
            "the OS and some protected directories will be unreadable."
        )

    db: Database | None = None
    try:
        db = open_database(config)
        new_signatures = seed_signatures(db, config)

        timeline = TimelineLogger(db)
        timeline.log_system(
            EventType.APP_STARTED,
            f"{app_name} {app_version} started on {platform.system()} {platform.release()}",
            Severity.INFO,
        )
        purge_old_data(db, config)
        timeline.log_system(
            EventType.PRIVILEGE_STATE,
            "Elevated: firewall enforcement available"
            if elevated
            else "Limited mode: no administrator privileges, firewall enforcement unavailable",
            Severity.INFO if elevated else Severity.LOW,
        )
        if new_signatures:
            timeline.log_antivirus(
                EventType.SIGNATURE_DB_UPDATED,
                f"Merged {new_signatures} bundled signature(s); "
                f"{db.signature_count()} total",
                Severity.INFO,
            )

        if not config.get("firewall.enforce_rules", False):
            logger.info(
                "Firewall is in DRY-RUN mode: rules are stored and the exact OS command is "
                "logged, but nothing is applied. Set firewall.enforce_rules=true to enforce."
            )

        if args.no_gui:
            logger.info("--no-gui specified; initialisation complete, exiting")
            return 0

        try:
            from gui.app import ShieldEXApp
        except ImportError as exc:
            logger.critical(
                "GUI dependencies are missing (%s). Install them with: "
                "pip install -r requirements.txt",
                exc,
            )
            return 2

        from core.engines import build_engines

        engines = build_engines(config, db, timeline)

        app = ShieldEXApp(
            config=config,
            db=db,
            timeline=timeline,
            elevated=elevated,
            # Lets the in-app "Restart as Administrator" button trigger a real UAC prompt
            # without gui/ importing anything outside core/.
            request_elevation=None if elevated else (lambda: relaunch_as_admin(raw_argv, force=True)),
        )
        for name in engines.names():
            app.register_engine(name, engines.get(name))

        # Auto-start the engines the configuration wants running. Each start is
        # guarded: a driver-less packet inspector or permission-less monitor must not
        # take the launch down, and the failure already reached the timeline.
        for name in ("realtime_monitor", "connection_monitor", "packet_inspector", "scheduler"):
            engine = engines.get(name)
            if engine is None:
                continue
            if name == "realtime_monitor" and not db.get_bool_setting("realtime_monitoring_enabled", False):
                continue
            try:
                engine.start()
            except Exception as exc:
                logger.error("Could not auto-start %s: %s", name, exc, exc_info=True)

        if bool(config.get("updater.check_on_startup", True)):
            updater = engines.get("updater")
            if updater is not None:
                try:
                    updater.start_periodic_checks()
                except Exception as exc:
                    logger.error("Could not start periodic signature checks: %s", exc)

        app.mainloop()
        timeline.log_system(EventType.APP_STOPPED, f"{app_name} closed normally", Severity.INFO)
        engines.stop_all()
        return 0

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except Exception as exc:  # last-resort guard so crashes always reach the log file
        logger.critical("Fatal error: %s", exc, exc_info=True)
        return 1
    finally:
        if db is not None:
            db.close()
        logger.info("%s shutdown complete", app_name)
        logging.shutdown()


if __name__ == "__main__":
    sys.exit(main())
