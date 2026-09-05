"""Unified SQLite persistence layer for ShieldEX.

This is the **only** module in the project that talks to SQLite. Both the antivirus and
the firewall engines go through :class:`Database`, which keeps the schema, the
concurrency strategy and the timestamp format in one place.

Concurrency model
-----------------
Scans, the watchdog monitor, the connection poller and the packet inspector all run in
background threads. SQLite connections are not thread-safe, so:

* every thread gets its own connection (kept in :class:`threading.local`);
* connections are opened with ``check_same_thread=False`` purely so that
  :meth:`Database.close` can shut them down from the main thread at exit;
* the database runs in WAL mode, which lets readers work while a writer is active;
* all writes are additionally serialised through one process-wide lock, so two ShieldEX
  threads never fight over the write lock and trigger ``SQLITE_BUSY``.

Timestamps
----------
The spec's DDL used ``DEFAULT CURRENT_TIMESTAMP``, which SQLite evaluates in **UTC**.
Every "today" counter and every timestamp the user reads in the UI is local time, so
mixing the two produces off-by-hours bugs around midnight. All timestamp columns
therefore default to ``datetime('now','localtime')`` and application inserts pass an
explicit local timestamp from :func:`now_str`.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Sequence

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

#: Columns that :meth:`Database.update_firewall_rule` is allowed to write. Anything not
#: on this list is rejected, so a caller can never inject a column name into the SQL.
_FIREWALL_RULE_COLUMNS = frozenset(
    {
        "name", "direction", "action", "protocol", "local_port", "remote_port",
        "remote_ip", "app_path", "profile", "interface_type", "service", "edge_traversal",
        "require_auth", "description", "enabled",
    }
)


def now_str(moment: datetime | None = None) -> str:
    """Return a local-time timestamp in the canonical, sortable database format."""
    return (moment or datetime.now()).strftime(TIMESTAMP_FORMAT)


def _as_severity_list(severities: Sequence[str] | str | None) -> list[str]:
    """Normalise a severity filter to a list of level names.

    A bare string is wrapped rather than iterated. ``str`` satisfies ``Sequence[str]``, so
    ``severities="High"`` type-checks and would otherwise expand to the four characters
    ``H``, ``i``, ``g``, ``h`` — producing ``severity IN (?,?,?,?)`` that silently matches
    nothing instead of raising.
    """
    if not severities:
        return []
    if isinstance(severities, str):
        return [severities]
    return [str(level) for level in severities]


def days_ago_str(days: int) -> str:
    """Return the local-time timestamp ``days`` days in the past."""
    return now_str(datetime.now() - timedelta(days=days))


SCHEMA_STATEMENTS: tuple[str, ...] = (
    # ------------------------------------------------------------------ shared / meta
    """
    CREATE TABLE IF NOT EXISTS app_meta (
        key        TEXT PRIMARY KEY,
        value      TEXT,
        updated_at DATETIME DEFAULT (datetime('now','localtime'))
    )
    """,
    # ------------------------------------------------------------------ antivirus
    """
    CREATE TABLE IF NOT EXISTS malware_signatures (
        hash       TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        severity   TEXT NOT NULL,
        source     TEXT,
        date_added DATETIME DEFAULT (datetime('now','localtime'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_history (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type        TEXT,
        target           TEXT,
        start_time       DATETIME,
        end_time         DATETIME,
        files_scanned    INTEGER DEFAULT 0,
        threats_found    INTEGER DEFAULT 0,
        severity_summary TEXT,
        status           TEXT DEFAULT 'RUNNING'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS quarantine_log (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        original_path    TEXT,
        quarantine_path  TEXT,
        threat_name      TEXT,
        severity         TEXT,
        file_hash        TEXT,
        scan_id          INTEGER,
        date_quarantined DATETIME DEFAULT (datetime('now','localtime')),
        status           TEXT DEFAULT 'QUARANTINED'
    )
    """,
    # ------------------------------------------------------------------ firewall
    """
    CREATE TABLE IF NOT EXISTS firewall_rules (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        name           TEXT NOT NULL UNIQUE,
        direction      TEXT NOT NULL,
        action         TEXT NOT NULL,
        protocol       TEXT,
        local_port     TEXT,
        remote_port    TEXT,
        remote_ip      TEXT,
        app_path       TEXT,
        profile        TEXT,
        interface_type TEXT,
        service        TEXT,
        edge_traversal INTEGER DEFAULT 0,
        require_auth   INTEGER DEFAULT 0,
        description    TEXT,
        enabled        INTEGER DEFAULT 1,
        created_at     DATETIME DEFAULT (datetime('now','localtime'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS firewall_connection_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        process      TEXT,
        pid          INTEGER,
        protocol     TEXT,
        local_ip     TEXT,
        local_port   INTEGER,
        remote_ip    TEXT,
        remote_port  INTEGER,
        country      TEXT,
        direction    TEXT,
        action       TEXT,
        rule_matched TEXT,
        timestamp    DATETIME DEFAULT (datetime('now','localtime'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_or_cidr TEXT UNIQUE NOT NULL,
        reason     TEXT,
        auto_added INTEGER DEFAULT 0,
        date_added DATETIME DEFAULT (datetime('now','localtime'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS trusted_ips (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_or_cidr TEXT UNIQUE NOT NULL,
        label      TEXT,
        date_added DATETIME DEFAULT (datetime('now','localtime'))
    )
    """,
    # ------------------------------------------------------------------ shared timeline
    """
    CREATE TABLE IF NOT EXISTS threat_timeline (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        source       TEXT NOT NULL,
        file_path    TEXT,
        remote_ip    TEXT,
        event_type   TEXT NOT NULL,
        event_detail TEXT,
        severity     TEXT,
        timestamp    DATETIME DEFAULT (datetime('now','localtime'))
    )
    """,
    # ------------------------------------------------------------------ indexes
    "CREATE INDEX IF NOT EXISTS idx_timeline_ts ON threat_timeline(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_timeline_source ON threat_timeline(source)",
    "CREATE INDEX IF NOT EXISTS idx_timeline_severity ON threat_timeline(severity)",
    "CREATE INDEX IF NOT EXISTS idx_timeline_event_type ON threat_timeline(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_conn_ts ON firewall_connection_log(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_conn_remote ON firewall_connection_log(remote_ip)",
    "CREATE INDEX IF NOT EXISTS idx_conn_action ON firewall_connection_log(action)",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_log(status)",
    "CREATE INDEX IF NOT EXISTS idx_rules_direction ON firewall_rules(direction, enabled)",
    "CREATE INDEX IF NOT EXISTS idx_sig_name ON malware_signatures(name)",
)

#: Runtime state that lives in the database rather than config.json, because the user
#: toggles it at runtime and it must survive a restart.
DEFAULT_SETTINGS: dict[str, str] = {
    "schema_version": str(SCHEMA_VERSION),
    "signature_db_version": "none",
    "signature_db_updated_at": "",
    "signature_db_last_checked": "",
    "realtime_monitoring_enabled": "0",
    "firewall_enabled_domain": "1",
    "firewall_enabled_private": "1",
    "firewall_enabled_public": "1",
    "current_network_profile": "Unknown",
}


class Database:
    """Thread-safe SQLite gateway shared by the antivirus and firewall engines."""

    def __init__(self, db_path: Path | str, busy_timeout_ms: int = 10_000) -> None:
        self.path = Path(db_path)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self._local = threading.local()
        self._all_connections: list[sqlite3.Connection] = []
        self._registry_lock = threading.Lock()
        self._write_lock = threading.RLock()
        self._closed = False

    # ------------------------------------------------------------------ connections
    def _connection(self) -> sqlite3.Connection:
        """Return this thread's connection, opening it on first use."""
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            return conn

        if self._closed:
            raise RuntimeError("Database has been closed")

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            # Re-raised as a sqlite3 error on purpose: every caller in this module guards
            # against sqlite3.Error, so a removed drive or revoked permission is reported
            # through the normal "write failed / returning -1" path instead of escaping
            # into a Tk after-callback and repeating a traceback several times a second.
            raise sqlite3.OperationalError(
                f"Cannot create the database directory {self.path.parent}: {exc}"
            ) from exc

        conn = sqlite3.connect(
            str(self.path),
            timeout=self.busy_timeout_ms / 1000.0,
            check_same_thread=False,
            isolation_level=None,  # explicit transaction control via BEGIN/COMMIT
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")

        self._local.conn = conn
        with self._registry_lock:
            self._all_connections.append(conn)
        logger.debug("Opened SQLite connection for thread %s", threading.current_thread().name)
        return conn

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Cursor]:
        """Cursor for read-only work."""
        cursor = self._connection().cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Cursor]:
        """Cursor inside a serialised transaction; commits on success, rolls back on error."""
        with self._write_lock:
            conn = self._connection()
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                yield cursor
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except sqlite3.Error as rollback_error:  # pragma: no cover - defensive
                    logger.error("Rollback failed: %s", rollback_error)
                raise
            finally:
                cursor.close()

    def close(self) -> None:
        """Close every connection this database handed out.

        Holds the write lock for the whole teardown so a thread cannot slip past the
        ``self._closed`` check in :meth:`_connection` and register a fresh connection into
        a registry that has just been cleared — which would leak that connection and keep
        the WAL files locked after shutdown.
        """
        with self._write_lock:
            self._closed = True
            with self._registry_lock:
                for conn in self._all_connections:
                    try:
                        conn.close()
                    except sqlite3.Error as exc:  # pragma: no cover - defensive
                        logger.warning("Error closing SQLite connection: %s", exc)
                self._all_connections.clear()
            self._local = threading.local()
        logger.debug("All SQLite connections closed")

    # ------------------------------------------------------------------ schema
    def initialize(self, settings_defaults: dict[str, str] | None = None) -> None:
        """Create tables, indexes and default settings rows if they do not exist."""
        try:
            with self._write() as cur:
                for statement in SCHEMA_STATEMENTS:
                    cur.execute(statement)
                defaults = dict(DEFAULT_SETTINGS)
                if settings_defaults:
                    defaults.update({k: str(v) for k, v in settings_defaults.items()})
                for key, value in defaults.items():
                    cur.execute(
                        "INSERT OR IGNORE INTO app_meta(key, value, updated_at) VALUES (?,?,?)",
                        (key, value, now_str()),
                    )
        except sqlite3.Error as exc:
            logger.critical("Database initialisation failed: %s", exc)
            raise

        stored = self.get_setting("schema_version", str(SCHEMA_VERSION))
        if stored != str(SCHEMA_VERSION):
            logger.warning(
                "Database schema version %s differs from application version %s",
                stored, SCHEMA_VERSION,
            )
        logger.info("Database ready at %s", self.path)

    def vacuum(self) -> None:
        """Compact the database file."""
        try:
            self._connection().execute("VACUUM")
        except sqlite3.Error as exc:
            logger.warning("VACUUM failed: %s", exc)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
        return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def _row(cursor: sqlite3.Cursor) -> dict[str, Any] | None:
        row = cursor.fetchone()
        return dict(row) if row else None

    def _scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        try:
            with self._read() as cur:
                cur.execute(sql, tuple(params))
                row = cur.fetchone()
                return row[0] if row else None
        except sqlite3.Error as exc:
            logger.error("Query failed (%s): %s", sql.strip().split("\n")[0], exc)
            return None

    def _query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        try:
            with self._read() as cur:
                cur.execute(sql, tuple(params))
                return self._rows(cur)
        except sqlite3.Error as exc:
            logger.error("Query failed (%s): %s", sql.strip().split("\n")[0], exc)
            return []

    def _execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run an UPDATE/DELETE (or an upsert); returns affected rows, or -1 on failure.

        Only row counts are reported here. ``_insert`` is used for statements whose new
        rowid matters, because SQLite does **not** reset ``lastrowid`` between statements
        on the same connection: reading it after a DELETE returns the id of whatever was
        inserted last, which silently corrupts any "rows affected" answer.
        """
        try:
            with self._write() as cur:
                cur.execute(sql, tuple(params))
                return int(cur.rowcount)
        except sqlite3.Error as exc:
            logger.error("Write failed (%s): %s", sql.strip().split("\n")[0], exc)
            return -1

    def _insert(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run an INSERT; returns the new rowid, 0 if nothing was inserted, -1 on failure.

        ``lastrowid`` is only trusted when ``rowcount`` proves this statement inserted a
        row, so ``INSERT OR IGNORE`` on a duplicate correctly reports 0 rather than the
        previous insert's id.
        """
        try:
            with self._write() as cur:
                cur.execute(sql, tuple(params))
                return int(cur.lastrowid or 0) if cur.rowcount else 0
        except sqlite3.Error as exc:
            logger.error("Insert failed (%s): %s", sql.strip().split("\n")[0], exc)
            return -1

    # ==================================================================
    # Settings / metadata
    # ==================================================================
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        """Read a persisted runtime setting."""
        value = self._scalar("SELECT value FROM app_meta WHERE key = ?", (key,))
        return default if value is None else str(value)

    def set_setting(self, key: str, value: Any) -> bool:
        """Write a persisted runtime setting. ``True`` when the row was written."""
        result = self._execute(
            """
            INSERT INTO app_meta(key, value, updated_at) VALUES (?,?,?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, str(value), now_str()),
        )
        # An upsert always touches exactly one row, so a zero rowcount means the write
        # silently did nothing and the caller must not report success.
        return result > 0

    def get_bool_setting(self, key: str, default: bool = False) -> bool:
        """Read a setting stored as ``"1"``/``"0"``."""
        raw = self.get_setting(key)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def set_bool_setting(self, key: str, value: bool) -> bool:
        """Store a boolean setting as ``"1"``/``"0"``."""
        return self.set_setting(key, "1" if value else "0")

    def get_all_settings(self) -> dict[str, str]:
        """Return every persisted setting."""
        return {row["key"]: row["value"] for row in self._query("SELECT key, value FROM app_meta")}

    # ==================================================================
    # Malware signatures
    # ==================================================================
    def add_signature(
        self, file_hash: str, name: str, severity: str, source: str = "manual"
    ) -> bool:
        """Insert or update one signature. Returns ``True`` on success."""
        return (
            self._execute(
                """
                INSERT INTO malware_signatures(hash, name, severity, source, date_added)
                VALUES (?,?,?,?,?)
                ON CONFLICT(hash) DO UPDATE SET
                    name = excluded.name,
                    severity = excluded.severity,
                    source = excluded.source
                """,
                (file_hash.lower().strip(), name, severity, source, now_str()),
            )
            > 0  # upsert writes one row; 0 means the statement failed to take effect
        )

    def add_signatures(self, signatures: Sequence[dict[str, Any]]) -> int:
        """Bulk-insert signatures, skipping hashes already present.

        Each mapping needs ``hash`` and ``name``; ``severity`` defaults to ``High`` and
        ``source`` to ``bundled``. Returns the number of rows actually inserted.
        """
        payload: list[tuple[str, str, str, str, str]] = []
        stamp = now_str()
        for entry in signatures:
            file_hash = str(entry.get("hash", "")).lower().strip()
            name = str(entry.get("name", "")).strip()
            if len(file_hash) not in (32, 40, 64) or not name:
                logger.warning("Skipping malformed signature entry: %r", entry)
                continue
            payload.append(
                (file_hash, name, str(entry.get("severity", "High")),
                 str(entry.get("source", "bundled")), stamp)
            )
        if not payload:
            return 0
        try:
            with self._write() as cur:
                before = self._scalar_in_cursor(cur, "SELECT COUNT(*) FROM malware_signatures")
                cur.executemany(
                    """
                    INSERT OR IGNORE INTO malware_signatures(hash, name, severity, source, date_added)
                    VALUES (?,?,?,?,?)
                    """,
                    payload,
                )
                after = self._scalar_in_cursor(cur, "SELECT COUNT(*) FROM malware_signatures")
            inserted = int(after or 0) - int(before or 0)
            logger.info("Merged %d new signature(s) from %d candidate(s)", inserted, len(payload))
            return inserted
        except sqlite3.Error as exc:
            logger.error("Bulk signature insert failed: %s", exc)
            return 0

    @staticmethod
    def _scalar_in_cursor(cursor: sqlite3.Cursor, sql: str) -> Any:
        cursor.execute(sql)
        row = cursor.fetchone()
        return row[0] if row else None

    def lookup_hash(self, file_hash: str) -> dict[str, Any] | None:
        """Return the signature record for a hash, or ``None`` when unknown."""
        rows = self._query(
            "SELECT * FROM malware_signatures WHERE hash = ?", (file_hash.lower().strip(),)
        )
        return rows[0] if rows else None

    def delete_signature(self, file_hash: str) -> bool:
        """Remove a signature. ``True`` only when a row actually existed and was deleted."""
        return self._execute(
            "DELETE FROM malware_signatures WHERE hash = ?", (file_hash.lower().strip(),)
        ) > 0

    def signature_count(self) -> int:
        """Total signatures in the local database."""
        return int(self._scalar("SELECT COUNT(*) FROM malware_signatures") or 0)

    def search_signatures(self, term: str = "", limit: int = 200) -> list[dict[str, Any]]:
        """Search signatures by name or hash prefix."""
        like = f"%{term.strip()}%"
        return self._query(
            """
            SELECT * FROM malware_signatures
            WHERE (? = '' OR name LIKE ? OR hash LIKE ?)
            ORDER BY date_added DESC LIMIT ?
            """,
            (term.strip(), like, like, int(limit)),
        )

    # ==================================================================
    # Scan history
    # ==================================================================
    def start_scan(self, scan_type: str, target: str | None = None) -> int:
        """Open a scan_history row and return its id."""
        return self._insert(
            """
            INSERT INTO scan_history(scan_type, target, start_time, status)
            VALUES (?,?,?, 'RUNNING')
            """,
            (scan_type, target, now_str()),
        )

    def finish_scan(
        self,
        scan_id: int,
        files_scanned: int,
        threats_found: int,
        severity_summary: dict[str, int] | None = None,
        status: str = "COMPLETED",
    ) -> bool:
        """Close a scan_history row with its results.

        ``False`` means no scan carried that id, which is a caller bug worth surfacing
        rather than a silent no-op.
        """
        return (
            self._execute(
                """
                UPDATE scan_history
                   SET end_time = ?, files_scanned = ?, threats_found = ?,
                       severity_summary = ?, status = ?
                 WHERE id = ?
                """,
                (
                    now_str(),
                    int(files_scanned),
                    int(threats_found),
                    json.dumps(severity_summary or {}),
                    status,
                    int(scan_id),
                ),
            )
            > 0
        )

    def get_scan_history(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """Most recent scans first."""
        return self._query(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ? OFFSET ?",
            (int(limit), int(offset)),
        )

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        """One scan record by id."""
        rows = self._query("SELECT * FROM scan_history WHERE id = ?", (int(scan_id),))
        return rows[0] if rows else None

    def get_last_scan(self) -> dict[str, Any] | None:
        """Most recently completed scan, or ``None`` if the app has never scanned."""
        rows = self._query(
            "SELECT * FROM scan_history WHERE status != 'RUNNING' ORDER BY id DESC LIMIT 1"
        )
        return rows[0] if rows else None

    def scan_history_totals(self) -> dict[str, int]:
        """Lifetime aggregates for the Scan History view."""
        totals = self._query(
            "SELECT COUNT(*) AS n, COALESCE(SUM(files_scanned),0) AS files, "
            "COALESCE(SUM(threats_found),0) AS threats FROM scan_history"
        )
        failures = self._query(
            "SELECT COUNT(*) AS n FROM scan_history WHERE status != 'COMPLETED'"
        )
        row = totals[0] if totals else {}
        return {
            "scans": int(row.get("n") or 0),
            "files": int(row.get("files") or 0),
            "threats": int(row.get("threats") or 0),
            "failures": int(failures[0].get("n") or 0) if failures else 0,
        }

    def total_threats_found(self) -> int:
        """Lifetime threat counter across all scans."""
        return int(self._scalar("SELECT COALESCE(SUM(threats_found),0) FROM scan_history") or 0)

    # ==================================================================
    # Quarantine
    # ==================================================================
    def add_quarantine_entry(
        self,
        original_path: str,
        quarantine_path: str,
        threat_name: str,
        severity: str,
        file_hash: str | None = None,
        scan_id: int | None = None,
    ) -> int:
        """Record a quarantined file and return the entry id."""
        return self._insert(
            """
            INSERT INTO quarantine_log(original_path, quarantine_path, threat_name,
                                       severity, file_hash, scan_id, date_quarantined, status)
            VALUES (?,?,?,?,?,?,?, 'QUARANTINED')
            """,
            (original_path, quarantine_path, threat_name, severity, file_hash, scan_id, now_str()),
        )

    def get_quarantine_entries(
        self, status: str | None = "QUARANTINED", limit: int = 500
    ) -> list[dict[str, Any]]:
        """Quarantine entries, optionally filtered by status."""
        if status:
            return self._query(
                "SELECT * FROM quarantine_log WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, int(limit)),
            )
        return self._query(
            "SELECT * FROM quarantine_log ORDER BY id DESC LIMIT ?", (int(limit),)
        )

    def get_quarantine_entry(self, entry_id: int) -> dict[str, Any] | None:
        """One quarantine entry by id."""
        rows = self._query("SELECT * FROM quarantine_log WHERE id = ?", (int(entry_id),))
        return rows[0] if rows else None

    def set_quarantine_status(self, entry_id: int, status: str) -> bool:
        """Update an entry's status (``QUARANTINED`` / ``RESTORED`` / ``DELETED``).

        Returns True only when a row actually changed, so the GUI can tell the difference
        between "restored" and "that entry no longer exists".
        """
        return self._execute(
            "UPDATE quarantine_log SET status = ? WHERE id = ?", (status, int(entry_id))
        ) > 0

    def delete_quarantine_entry(self, entry_id: int) -> bool:
        """Remove a quarantine entry row entirely. True when a row was deleted."""
        return self._execute("DELETE FROM quarantine_log WHERE id = ?", (int(entry_id),)) > 0

    def quarantine_count(self, status: str | None = "QUARANTINED") -> int:
        """Number of quarantine entries, optionally filtered by status."""
        if status:
            return int(
                self._scalar("SELECT COUNT(*) FROM quarantine_log WHERE status = ?", (status,)) or 0
            )
        return int(self._scalar("SELECT COUNT(*) FROM quarantine_log") or 0)

    # ==================================================================
    # Firewall rules
    # ==================================================================
    def add_firewall_rule(
        self,
        name: str,
        direction: str,
        action: str,
        protocol: str = "Any",
        local_port: str | None = None,
        remote_port: str | None = None,
        remote_ip: str | None = None,
        app_path: str | None = None,
        profile: str = "Any",
        interface_type: str = "Any",
        service: str | None = None,
        edge_traversal: bool = False,
        require_auth: bool = False,
        description: str | None = None,
        enabled: bool = True,
    ) -> int:
        """Persist a firewall rule and return its id.

        This only records the rule. Pushing it to netsh/iptables is
        ``core.firewall.rule_engine``'s job, which reads rules back from here.

        Rule names are unique because that is how both netsh and this application address
        a rule, so a duplicate name returns -1 (logged) instead of raising.
        """
        return self._insert(
            """
            INSERT INTO firewall_rules(
                name, direction, action, protocol, local_port, remote_port, remote_ip,
                app_path, profile, interface_type, service, edge_traversal, require_auth,
                description, enabled, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                name, direction.upper(), action.upper(), protocol, local_port, remote_port,
                remote_ip, app_path, profile, interface_type, service,
                1 if edge_traversal else 0, 1 if require_auth else 0, description,
                1 if enabled else 0, now_str(),
            ),
        )

    def update_firewall_rule(self, rule_id: int, **fields: Any) -> bool:
        """Update selected columns of a rule.

        Column names are validated against :data:`_FIREWALL_RULE_COLUMNS`, so an unknown
        or hostile key is rejected instead of being interpolated into SQL. ``False`` means
        nothing was updated: either every key was rejected or no rule carries ``rule_id``.
        """
        updates: dict[str, Any] = {}
        for key, value in fields.items():
            if key not in _FIREWALL_RULE_COLUMNS:
                logger.warning("Rejected unknown firewall rule column: %s", key)
                continue
            if key in {"enabled", "edge_traversal", "require_auth"}:
                value = 1 if value else 0
            if key in {"direction", "action"} and isinstance(value, str):
                value = value.upper()
            updates[key] = value

        if not updates:
            return False

        assignments = ", ".join(f"{column} = ?" for column in updates)
        params = list(updates.values()) + [int(rule_id)]
        return self._execute(f"UPDATE firewall_rules SET {assignments} WHERE id = ?", params) > 0

    def set_firewall_rule_enabled(self, rule_id: int, enabled: bool) -> bool:
        """Enable or disable a stored rule."""
        return self.update_firewall_rule(rule_id, enabled=enabled)

    def delete_firewall_rule(self, rule_id: int) -> bool:
        """Delete a stored rule. ``True`` only when a row was actually removed."""
        return self._execute("DELETE FROM firewall_rules WHERE id = ?", (int(rule_id),)) > 0

    def get_firewall_rule(self, rule_id: int) -> dict[str, Any] | None:
        """One rule by id."""
        rows = self._query("SELECT * FROM firewall_rules WHERE id = ?", (int(rule_id),))
        return rows[0] if rows else None

    def get_firewall_rule_by_name(self, name: str) -> dict[str, Any] | None:
        """One rule by exact name (rule names are how the OS identifies them)."""
        rows = self._query("SELECT * FROM firewall_rules WHERE name = ? LIMIT 1", (name,))
        return rows[0] if rows else None

    def get_firewall_rules(
        self,
        direction: str | None = None,
        enabled: bool | None = None,
        action: str | None = None,
        profile: str | None = None,
    ) -> list[dict[str, Any]]:
        """Rules matching the given filters, newest first."""
        clauses: list[str] = []
        params: list[Any] = []
        if direction:
            clauses.append("direction = ?")
            params.append(direction.upper())
        if action:
            clauses.append("action = ?")
            params.append(action.upper())
        if enabled is not None:
            clauses.append("enabled = ?")
            params.append(1 if enabled else 0)
        if profile:
            clauses.append("(profile = ? OR profile = 'Any')")
            params.append(profile)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return self._query(f"SELECT * FROM firewall_rules {where} ORDER BY id DESC", params)

    def count_firewall_rules(
        self, direction: str | None = None, enabled: bool | None = None
    ) -> int:
        """Count rules matching the filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if direction:
            clauses.append("direction = ?")
            params.append(direction.upper())
        if enabled is not None:
            clauses.append("enabled = ?")
            params.append(1 if enabled else 0)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return int(self._scalar(f"SELECT COUNT(*) FROM firewall_rules {where}", params) or 0)

    def clear_firewall_rules(self) -> int:
        """Delete every stored rule (used by rule import/reset flows)."""
        return self._execute("DELETE FROM firewall_rules", ())

    # ==================================================================
    # Connection log
    # ==================================================================
    def log_connection(
        self,
        process: str | None,
        pid: int | None,
        protocol: str | None,
        local_ip: str | None,
        local_port: int | None,
        remote_ip: str | None,
        remote_port: int | None,
        direction: str,
        action: str,
        rule_matched: str | None = None,
        country: str | None = None,
    ) -> int:
        """Append one allowed/blocked connection to the log."""
        return self._insert(
            """
            INSERT INTO firewall_connection_log(
                process, pid, protocol, local_ip, local_port, remote_ip, remote_port,
                country, direction, action, rule_matched, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                process, pid, protocol, local_ip, local_port, remote_ip, remote_port,
                country, direction.upper(), action.upper(), rule_matched, now_str(),
            ),
        )

    def get_connection_log(
        self,
        process: str | None = None,
        remote_ip: str | None = None,
        port: int | None = None,
        action: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Filtered connection log, newest first."""
        clauses: list[str] = []
        params: list[Any] = []
        if process:
            clauses.append("process LIKE ?")
            params.append(f"%{process}%")
        if remote_ip:
            clauses.append("remote_ip LIKE ?")
            params.append(f"%{remote_ip}%")
        if port is not None:
            clauses.append("(local_port = ? OR remote_port = ?)")
            params.extend([int(port), int(port)])
        if action:
            clauses.append("action = ?")
            params.append(action.upper())
        if date_from:
            clauses.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("timestamp <= ?")
            params.append(date_to)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._query(
            f"SELECT * FROM firewall_connection_log {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        )

    def count_connections(self, action: str | None = None, today: bool = False) -> int:
        """Count logged connections, optionally only today's and/or by action."""
        clauses: list[str] = []
        params: list[Any] = []
        if action:
            clauses.append("action = ?")
            params.append(action.upper())
        if today:
            clauses.append("date(timestamp) = date('now','localtime')")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return int(
            self._scalar(f"SELECT COUNT(*) FROM firewall_connection_log {where}", params) or 0
        )

    def purge_connection_log(self, older_than_days: int) -> int:
        """Delete connection log rows older than N days."""
        return self._execute(
            "DELETE FROM firewall_connection_log WHERE timestamp < ?",
            (days_ago_str(older_than_days),),
        )

    # ==================================================================
    # Blocked / trusted IP lists
    # ==================================================================
    def add_blocked_ip(
        self, ip_or_cidr: str, reason: str = "", auto_added: bool = False
    ) -> bool:
        """Add an entry to the blocklist.

        Idempotent: re-adding an existing entry refreshes its reason and returns False, so
        the caller can say "already blocked" instead of claiming a new block. The existence
        check and the write are separate statements, but the write is an upsert, so a race
        only affects the advisory return value, never the stored data.
        """
        entry = ip_or_cidr.strip()
        existed = self.is_ip_blocked(entry)
        written = self._execute(
            """
            INSERT INTO blocked_ips(ip_or_cidr, reason, auto_added, date_added)
            VALUES (?,?,?,?)
            ON CONFLICT(ip_or_cidr) DO UPDATE SET reason = excluded.reason
            """,
            (entry, reason, 1 if auto_added else 0, now_str()),
        )
        return written > 0 and not existed

    def remove_blocked_ip(self, ip_or_cidr: str) -> bool:
        """Remove an entry from the blocklist. True when a row was deleted."""
        return self._execute(
            "DELETE FROM blocked_ips WHERE ip_or_cidr = ?", (ip_or_cidr.strip(),)
        ) > 0

    def get_blocked_ips(self) -> list[dict[str, Any]]:
        """Whole blocklist, newest first."""
        return self._query("SELECT * FROM blocked_ips ORDER BY id DESC")

    def is_ip_blocked(self, ip_or_cidr: str) -> bool:
        """Exact-match membership test.

        CIDR containment is deliberately not done here: it is network logic and belongs
        to ``core.firewall.ip_blocklist``, which loads this list and evaluates ranges.
        """
        return bool(
            self._scalar(
                "SELECT 1 FROM blocked_ips WHERE ip_or_cidr = ? LIMIT 1", (ip_or_cidr.strip(),)
            )
        )

    def blocked_ip_count(self) -> int:
        """Size of the blocklist."""
        return int(self._scalar("SELECT COUNT(*) FROM blocked_ips") or 0)

    def add_trusted_ip(self, ip_or_cidr: str, label: str = "") -> bool:
        """Add an entry to the trusted zone list.

        Idempotent, and mirrors :meth:`add_blocked_ip`: re-adding an existing entry
        refreshes its label and returns ``False`` so the caller can say "already trusted"
        rather than claiming a new entry.
        """
        entry = ip_or_cidr.strip()
        existed = self.is_ip_trusted(entry)
        written = self._execute(
            """
            INSERT INTO trusted_ips(ip_or_cidr, label, date_added) VALUES (?,?,?)
            ON CONFLICT(ip_or_cidr) DO UPDATE SET label = excluded.label
            """,
            (entry, label, now_str()),
        )
        return written > 0 and not existed

    def remove_trusted_ip(self, ip_or_cidr: str) -> bool:
        """Remove an entry from the trusted zone list. ``True`` when a row was deleted."""
        return self._execute(
            "DELETE FROM trusted_ips WHERE ip_or_cidr = ?", (ip_or_cidr.strip(),)
        ) > 0

    def get_trusted_ips(self) -> list[dict[str, Any]]:
        """Whole trusted list, newest first."""
        return self._query("SELECT * FROM trusted_ips ORDER BY id DESC")

    def is_ip_trusted(self, ip_or_cidr: str) -> bool:
        """Exact-match membership test, symmetric with :meth:`is_ip_blocked`.

        As with the blocklist, CIDR containment belongs to ``core.firewall.ip_blocklist``;
        this only answers "is this exact string in the trusted table".
        """
        return bool(
            self._scalar(
                "SELECT 1 FROM trusted_ips WHERE ip_or_cidr = ? LIMIT 1", (ip_or_cidr.strip(),)
            )
        )

    def trusted_ip_count(self) -> int:
        """Size of the trusted list."""
        return int(self._scalar("SELECT COUNT(*) FROM trusted_ips") or 0)

    # ==================================================================
    # Threat Behavior Timeline
    # ==================================================================
    def add_timeline_event(
        self,
        source: str,
        event_type: str,
        event_detail: str = "",
        severity: str | None = None,
        file_path: str | None = None,
        remote_ip: str | None = None,
        timestamp: str | None = None,
    ) -> int:
        """Insert one timeline event and return its id."""
        return self._insert(
            """
            INSERT INTO threat_timeline(
                source, file_path, remote_ip, event_type, event_detail, severity, timestamp)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                source.upper(), file_path, remote_ip, event_type, event_detail,
                severity, timestamp or now_str(),
            ),
        )

    def get_timeline_events(
        self,
        source: str | None = None,
        severities: Sequence[str] | str | None = None,  # CHANGED: a bare level is accepted
        event_type: str | None = None,
        event_type_prefix: str | None = None,
        search: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Filtered timeline events, newest first.

        ``search`` matches file path, remote IP, event type or detail text.
        ``event_type_prefix`` mirrors the escaped-prefix matching used by
        :meth:`count_timeline_events` so paged queries and their counts agree.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if source and source.upper() not in {"ALL", "BOTH"}:
            clauses.append("source = ?")
            params.append(source.upper())
        if severities:
            levels = _as_severity_list(severities)
            placeholders = ",".join("?" for _ in levels)
            clauses.append(f"severity IN ({placeholders})")
            params.extend(levels)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if event_type_prefix:
            escaped = (
                event_type_prefix.replace("\\", "\\\\").replace("_", "\\_").replace("%", "\\%")
            )
            clauses.append("event_type LIKE ? ESCAPE '\\'")
            params.append(f"{escaped}%")
        if search:
            like = f"%{search.strip()}%"
            clauses.append(
                "(COALESCE(file_path,'') LIKE ? OR COALESCE(remote_ip,'') LIKE ?"
                " OR event_type LIKE ? OR COALESCE(event_detail,'') LIKE ?)"
            )
            params.extend([like, like, like, like])
        if date_from:
            clauses.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("timestamp <= ?")
            params.append(date_to)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._query(
            f"SELECT * FROM threat_timeline {where} ORDER BY id DESC LIMIT ? OFFSET ?", params
        )

    def get_recent_timeline(self, limit: int = 10) -> list[dict[str, Any]]:
        """Newest timeline events, for the dashboard activity feed."""
        return self._query(
            "SELECT * FROM threat_timeline ORDER BY id DESC LIMIT ?", (int(limit),)
        )

    def count_timeline_events(
        self,
        source: str | None = None,
        event_type_prefix: str | None = None,
        severities: Sequence[str] | str | None = None,  # CHANGED: a bare level is accepted
        today: bool = False,
    ) -> int:
        """Count timeline events matching the filters.

        ``event_type_prefix`` uses ``LIKE`` with an explicit escape character so that an
        underscore in a prefix such as ``IDS_`` stays literal instead of acting as a
        single-character wildcard.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if source:
            clauses.append("source = ?")
            params.append(source.upper())
        if event_type_prefix:
            escaped = event_type_prefix.replace("\\", "\\\\").replace("_", "\\_").replace("%", "\\%")
            clauses.append("event_type LIKE ? ESCAPE '\\'")
            params.append(f"{escaped}%")
        if severities:
            levels = _as_severity_list(severities)
            placeholders = ",".join("?" for _ in levels)
            clauses.append(f"severity IN ({placeholders})")
            params.extend(levels)
        if today:
            clauses.append("date(timestamp) = date('now','localtime')")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return int(self._scalar(f"SELECT COUNT(*) FROM threat_timeline {where}", params) or 0)

    def purge_timeline(self, older_than_days: int) -> int:
        """Delete timeline events older than N days."""
        return self._execute(
            "DELETE FROM threat_timeline WHERE timestamp < ?", (days_ago_str(older_than_days),)
        )

    # ==================================================================
    # Dashboard aggregate
    # ==================================================================
    def get_dashboard_stats(self) -> dict[str, Any]:
        """One-shot aggregate of everything the unified dashboard displays."""
        last_scan = self.get_last_scan()
        return {
            "antivirus": {
                "last_scan": last_scan,
                "threats_found_total": self.total_threats_found(),
                "quarantined": self.quarantine_count("QUARANTINED"),
                "signature_count": self.signature_count(),
                "signature_version": self.get_setting("signature_db_version", "none"),
                "signature_updated_at": self.get_setting("signature_db_updated_at", ""),
                "realtime_enabled": self.get_bool_setting("realtime_monitoring_enabled", False),
            },
            "firewall": {
                "rules_inbound": self.count_firewall_rules("INBOUND"),
                "rules_outbound": self.count_firewall_rules("OUTBOUND"),
                "rules_enabled": self.count_firewall_rules(enabled=True),
                "blocked_today": self.count_connections(action="BLOCKED", today=True),
                "ids_alerts_today": self.count_timeline_events(
                    source="FIREWALL", event_type_prefix="IDS_", today=True
                ),
                "blocked_ips": self.blocked_ip_count(),
                "trusted_ips": self.trusted_ip_count(),
                "profiles": {
                    "domain": self.get_bool_setting("firewall_enabled_domain", True),
                    "private": self.get_bool_setting("firewall_enabled_private", True),
                    "public": self.get_bool_setting("firewall_enabled_public", True),
                },
                "current_profile": self.get_setting("current_network_profile", "Unknown"),
            },
            "timeline": {
                "events_today": self.count_timeline_events(today=True),
                "high_today": self.count_timeline_events(
                    severities=("High", "Critical"), today=True
                ),
            },
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Database path={self.path}>"
