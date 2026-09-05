"""Unit tests for the ShieldEX foundation layer.

Covers the three modules the whole application is built on — :mod:`core.database`,
:mod:`core.timeline` and :mod:`core.config` — plus a syntax check over the GUI package so
the suite catches a broken view even on a machine without ``customtkinter`` installed.

Run from the project root::

    python -m pytest tests -v
"""

from __future__ import annotations

import csv
import json
import logging
import os
import py_compile
import sqlite3
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import main as entrypoint
from core.config import Config, _path_key, resolve_token
from core.database import Database, days_ago_str, now_str
from core.timeline import EXPORT_COLUMNS, EventType, Severity, Source, TimelineLogger

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: Real EICAR test-file hash — the one signature that can be verified against a live file.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


# ======================================================================
# Fixtures
# ======================================================================
@pytest.fixture()
def db(tmp_path: Path):
    """An initialised database in a temp directory, closed on teardown."""
    database = Database(tmp_path / "shieldex.db")
    database.initialize()
    yield database
    database.close()


@pytest.fixture()
def timeline(db: Database) -> TimelineLogger:
    """A timeline logger bound to the temp database."""
    return TimelineLogger(db)


# ======================================================================
# Schema and settings
# ======================================================================
def test_initialize_creates_all_tables(db: Database, tmp_path: Path) -> None:
    """Every table the application queries must exist after initialize()."""
    with db._read() as cur:  # noqa: SLF001 - inspecting schema is the point of the test
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in cur.fetchall()}

    assert {
        "app_meta",
        "malware_signatures",
        "scan_history",
        "quarantine_log",
        "firewall_rules",
        "firewall_connection_log",
        "blocked_ips",
        "trusted_ips",
        "threat_timeline",
    } <= tables


def test_initialize_is_idempotent(tmp_path: Path) -> None:
    """Re-initialising must not raise or wipe existing rows."""
    database = Database(tmp_path / "twice.db")
    try:
        database.initialize()
        database.add_signature("a" * 64, "Test.Sig", Severity.HIGH)
        database.initialize()
        assert database.signature_count() == 1
    finally:
        database.close()


def test_settings_roundtrip_and_bools(db: Database) -> None:
    """Settings persist, and bool helpers survive the string round trip."""
    assert db.get_setting("schema_version") == "1"
    assert db.get_setting("missing_key", "fallback") == "fallback"

    db.set_setting("signature_db_version", "2026.09.02")
    assert db.get_setting("signature_db_version") == "2026.09.02"

    db.set_bool_setting("realtime_monitoring_enabled", True)
    assert db.get_bool_setting("realtime_monitoring_enabled") is True
    db.set_bool_setting("realtime_monitoring_enabled", False)
    assert db.get_bool_setting("realtime_monitoring_enabled") is False

    assert "schema_version" in db.get_all_settings()


def test_initialize_accepts_setting_overrides(tmp_path: Path) -> None:
    """main.py seeds runtime defaults from config.json on first run."""
    database = Database(tmp_path / "seeded.db")
    try:
        database.initialize({"firewall_enabled_public": "0"})
        assert database.get_bool_setting("firewall_enabled_public", True) is False
    finally:
        database.close()


# ======================================================================
# Signatures
# ======================================================================
def test_signature_bulk_insert_skips_duplicates_and_junk(db: Database) -> None:
    """add_signatures() returns only newly inserted rows and rejects malformed entries."""
    entries = [
        {"hash": EICAR_SHA256, "name": "EICAR-Test-File", "severity": "Medium"},
        {"hash": "B" * 64, "name": "Demo.Sample", "severity": "High"},
        {"hash": "tooshort", "name": "Broken"},          # bad hash length
        {"hash": "c" * 64, "name": ""},                   # missing name
    ]
    assert db.add_signatures(entries) == 2
    assert db.add_signatures(entries) == 0  # second pass inserts nothing
    assert db.signature_count() == 2


def test_signature_lookup_is_case_insensitive(db: Database) -> None:
    """Hashes are normalised to lower case on write and on lookup."""
    db.add_signatures([{"hash": EICAR_SHA256.upper(), "name": "EICAR-Test-File"}])
    record = db.lookup_hash(EICAR_SHA256.upper())
    assert record is not None
    assert record["name"] == "EICAR-Test-File"
    assert record["hash"] == EICAR_SHA256  # stored lower case
    assert db.lookup_hash("f" * 64) is None


def test_signature_search_and_delete(db: Database) -> None:
    """Search matches on name; delete removes the row."""
    db.add_signature("d" * 64, "Trojan.Win32.Agent", Severity.CRITICAL)
    db.add_signature("e" * 64, "Adware.Generic", Severity.LOW)

    assert len(db.search_signatures("trojan")) == 1
    assert len(db.search_signatures("")) == 2

    db.delete_signature("d" * 64)
    assert db.lookup_hash("d" * 64) is None
    assert db.signature_count() == 1


# ======================================================================
# Scan history
# ======================================================================
def test_scan_lifecycle(db: Database) -> None:
    """start_scan/finish_scan produce a completed row with a severity breakdown."""
    scan_id = db.start_scan("quick", target="%TEMP%")
    assert scan_id > 0

    running = db.get_scan(scan_id)
    assert running is not None
    assert running["status"] == "RUNNING"
    assert running["end_time"] in (None, "")

    db.finish_scan(scan_id, files_scanned=1200, threats_found=3,
                   severity_summary={"High": 2, "Low": 1})

    finished = db.get_scan(scan_id)
    assert finished is not None
    assert finished["status"] == "COMPLETED"
    assert finished["files_scanned"] == 1200
    assert finished["threats_found"] == 3
    assert json.loads(finished["severity_summary"]) == {"High": 2, "Low": 1}
    assert finished["end_time"]

    assert db.get_last_scan()["id"] == scan_id
    assert db.total_threats_found() == 3


def test_scan_history_ordering_and_paging(db: Database) -> None:
    """History is newest-first and honours limit/offset."""
    ids = [db.start_scan(kind) for kind in ("quick", "full", "custom")]
    for scan_id in ids:
        db.finish_scan(scan_id, 10, 0)

    history = db.get_scan_history(limit=2)
    assert [row["id"] for row in history] == [ids[2], ids[1]]
    assert [row["id"] for row in db.get_scan_history(limit=2, offset=2)] == [ids[0]]


def test_failed_scan_is_recorded(db: Database) -> None:
    """A crashed scan is closed with FAILED, not left RUNNING forever."""
    scan_id = db.start_scan("full")
    db.finish_scan(scan_id, 5, 0, status="FAILED")
    assert db.get_scan(scan_id)["status"] == "FAILED"


# ======================================================================
# Quarantine
# ======================================================================
def test_quarantine_entry_lifecycle(db: Database) -> None:
    """Quarantine rows move QUARANTINED → RESTORED and counts follow."""
    entry_id = db.add_quarantine_entry(
        original_path=r"C:\Users\demo\Downloads\invoice.pdf.exe",
        quarantine_path=r"C:\Users\demo\.quarantine\1.quar",
        threat_name="Trojan.Win32.Agent",
        severity=Severity.HIGH,
        file_hash="a" * 64,
    )
    assert entry_id > 0
    assert db.quarantine_count() == 1

    entry = db.get_quarantine_entry(entry_id)
    assert entry is not None
    assert entry["status"] == "QUARANTINED"
    assert entry["threat_name"] == "Trojan.Win32.Agent"

    db.set_quarantine_status(entry_id, "RESTORED")
    assert db.quarantine_count("QUARANTINED") == 0
    assert db.quarantine_count("RESTORED") == 1
    assert db.quarantine_count(None) == 1
    assert db.get_quarantine_entries(status="RESTORED")[0]["id"] == entry_id

    db.delete_quarantine_entry(entry_id)
    assert db.get_quarantine_entry(entry_id) is None


# ======================================================================
# Firewall rules
# ======================================================================
def test_firewall_rule_crud_and_counts(db: Database) -> None:
    """Rules can be created, filtered, toggled and deleted."""
    inbound = db.add_firewall_rule(
        name="Block SMB inbound", direction="INBOUND", action="BLOCK",
        protocol="TCP", local_port="445", description="Ransomware lateral movement",
    )
    outbound = db.add_firewall_rule(
        name="Block Tor exit", direction="OUTBOUND", action="BLOCK",
        protocol="TCP", remote_ip="185.220.101.4", enabled=False,
    )
    assert inbound > 0 and outbound > 0

    assert db.count_firewall_rules("INBOUND") == 1
    assert db.count_firewall_rules("OUTBOUND") == 1
    assert db.count_firewall_rules(enabled=True) == 1

    assert db.get_firewall_rule_by_name("Block SMB inbound")["id"] == inbound
    assert len(db.get_firewall_rules(direction="INBOUND")) == 1
    assert len(db.get_firewall_rules(action="BLOCK")) == 2
    assert len(db.get_firewall_rules(enabled=False)) == 1

    db.set_firewall_rule_enabled(outbound, True)
    assert db.count_firewall_rules(enabled=True) == 2

    db.delete_firewall_rule(inbound)
    assert db.get_firewall_rule(inbound) is None
    assert db.clear_firewall_rules() == 1
    assert db.count_firewall_rules() == 0


def test_firewall_rule_names_are_unique(db: Database) -> None:
    """The OS firewall keys rules by name, so duplicates must be rejected.

    The rejection is reported as ``-1`` rather than raised: a GUI callback must never be
    able to kill the app because the user retyped an existing rule name.
    """
    first = db.add_firewall_rule(name="Dup", direction="INBOUND", action="BLOCK")
    assert first > 0

    assert db.add_firewall_rule(name="Dup", direction="OUTBOUND", action="ALLOW") == -1
    assert db.count_firewall_rules() == 1
    # The original rule is untouched — the failed insert did not overwrite it.
    surviving = db.get_firewall_rule_by_name("Dup")
    assert surviving["direction"] == "INBOUND"
    assert surviving["action"] == "BLOCK"


def test_schema_enforces_rule_name_uniqueness_at_the_sql_layer(tmp_path: Path) -> None:
    """The uniqueness must live in the schema, not only in the Python wrapper.

    Checked against the raw file because a future direct-SQL caller (a migration, an
    import routine) would bypass ``add_firewall_rule`` entirely.
    """
    database = Database(tmp_path / "schema.db")
    database.initialize()
    database.add_firewall_rule(name="Solo", direction="INBOUND", action="BLOCK")
    database.close()

    raw = sqlite3.connect(tmp_path / "schema.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            raw.execute(
                "INSERT INTO firewall_rules(name, direction, action) VALUES ('Solo','OUTBOUND','ALLOW')"
            )
        assert raw.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        raw.close()


def test_update_firewall_rule_rejects_unknown_columns(db: Database) -> None:
    """The dynamic UPDATE builds column names, so it is whitelisted against injection."""
    rule_id = db.add_firewall_rule(name="Editable", direction="INBOUND", action="ALLOW")

    assert db.update_firewall_rule(rule_id, action="BLOCK", local_port="3389") is True
    updated = db.get_firewall_rule(rule_id)
    assert updated["action"] == "BLOCK"
    assert updated["local_port"] == "3389"

    # Neither a bogus column nor an injection attempt may reach the SQL string.
    assert db.update_firewall_rule(rule_id, id=999) is False
    assert db.update_firewall_rule(rule_id, **{"action = 'X' --": "y"}) is False
    assert db.get_firewall_rule(rule_id)["action"] == "BLOCK"


# ======================================================================
# Connection log
# ======================================================================
def test_connection_log_filters_and_counts(db: Database) -> None:
    """Connections are filterable by process, IP, port and action."""
    db.log_connection("chrome.exe", 4242, "TCP", "192.168.1.20", 51000,
                      "185.220.101.4", 443, "OUTBOUND", "BLOCKED",
                      rule_matched="Block Tor exit")
    db.log_connection("svchost.exe", 900, "TCP", "192.168.1.20", 445,
                      "10.0.0.9", 51001, "INBOUND", "ALLOWED")

    assert db.count_connections() == 2
    assert db.count_connections(action="BLOCKED") == 1
    assert db.count_connections(action="BLOCKED", today=True) == 1

    assert len(db.get_connection_log(process="chrome")) == 1
    assert len(db.get_connection_log(remote_ip="185.220.101.4")) == 1
    assert len(db.get_connection_log(port=445)) == 1
    assert len(db.get_connection_log(action="ALLOWED")) == 1


def test_purge_connection_log_keeps_recent_rows(db: Database) -> None:
    """Retention deletes only rows older than the cutoff."""
    db.log_connection("old.exe", 1, "TCP", "1.1.1.1", 1, "2.2.2.2", 2, "OUTBOUND", "ALLOWED")
    with db._write() as cur:  # noqa: SLF001 - back-date a row to test retention
        cur.execute("UPDATE firewall_connection_log SET timestamp = ?", (days_ago_str(40),))
    db.log_connection("new.exe", 2, "TCP", "1.1.1.1", 1, "3.3.3.3", 3, "OUTBOUND", "ALLOWED")

    assert db.purge_connection_log(30) == 1
    assert db.count_connections() == 1


# ======================================================================
# IP lists
# ======================================================================
def test_blocked_and_trusted_ip_lists(db: Database) -> None:
    """Blocklist and whitelist are independent, deduplicated sets."""
    assert db.add_blocked_ip("185.220.101.4", reason="Tor exit node") is True
    assert db.add_blocked_ip("185.220.101.4", reason="duplicate") is False
    assert db.add_blocked_ip("10.10.0.0/16", reason="lab range", auto_added=True) is True

    assert db.blocked_ip_count() == 2
    assert db.is_ip_blocked("185.220.101.4") is True
    assert db.is_ip_blocked("8.8.8.8") is False
    # Containment is firewall logic, not database logic — see is_ip_blocked's docstring.
    assert db.is_ip_blocked("10.10.5.5") is False

    auto = {row["ip_or_cidr"]: row["auto_added"] for row in db.get_blocked_ips()}
    assert auto["10.10.0.0/16"] == 1

    assert db.remove_blocked_ip("185.220.101.4") is True
    assert db.blocked_ip_count() == 1
    # Removing something that was never there is not a successful removal.
    assert db.remove_blocked_ip("185.220.101.4") is False

    assert db.add_trusted_ip("192.168.1.0/24", label="Home LAN") is True
    assert db.add_trusted_ip("192.168.1.0/24", label="Renamed") is False
    assert db.trusted_ip_count() == 1
    assert db.get_trusted_ips()[0]["label"] == "Renamed"  # re-adding refreshes the label
    assert db.is_ip_trusted("192.168.1.0/24") is True
    assert db.is_ip_trusted("192.168.1.50") is False  # containment is firewall logic
    assert db.remove_trusted_ip("192.168.1.0/24") is True
    assert db.remove_trusted_ip("192.168.1.0/24") is False
    assert db.trusted_ip_count() == 0

    # The two lists never leaked into each other.
    assert db.is_ip_blocked("10.10.0.0/16") is True
    assert db.is_ip_trusted("10.10.0.0/16") is False


def test_writes_report_rows_actually_affected(db: Database) -> None:
    """Regression test for a stale-``lastrowid`` bug in the write helpers.

    SQLite does not reset ``cursor.lastrowid`` between statements on a connection, so a
    helper that fell back to it after a DELETE reported the id of the last INSERT — which
    made every "did anything change?" answer a non-zero, and therefore truthy, lie.
    """
    scan_id = db.start_scan("Quick", "C:/")
    assert scan_id > 0

    # Each of these targets a row that does not exist and must say so.
    assert db.delete_signature("f" * 64) is False
    assert db.delete_firewall_rule(999_999) is False
    assert db.update_firewall_rule(999_999, action="BLOCK") is False
    assert db.finish_scan(999_999, files_scanned=1, threats_found=0) is False
    assert db.set_quarantine_status(999_999, "RESTORED") is False
    assert db.delete_quarantine_entry(999_999) is False

    # And the real row still updates, so the stricter check did not break the happy path.
    assert db.finish_scan(scan_id, files_scanned=12, threats_found=0) is True

    # Bulk deletes report their true count rather than a leftover rowid.
    db.add_firewall_rule(name="Bulk-1", direction="INBOUND", action="BLOCK")
    db.add_firewall_rule(name="Bulk-2", direction="OUTBOUND", action="ALLOW")
    assert db.clear_firewall_rules() == 2
    assert db.clear_firewall_rules() == 0


# ======================================================================
# Severity ordering
# ======================================================================
def test_severity_normalise_rank_and_expansion() -> None:
    """Severity ordering lives in one place and must be total and case-insensitive."""
    assert Severity.normalize("high") == Severity.HIGH
    assert Severity.normalize("CRITICAL") == Severity.CRITICAL
    assert Severity.normalize(None) == Severity.INFO
    assert Severity.normalize("nonsense", default=Severity.LOW) == Severity.LOW

    assert Severity.rank(Severity.INFO) < Severity.rank(Severity.LOW)
    assert Severity.rank(Severity.MEDIUM) < Severity.rank(Severity.HIGH)
    assert Severity.rank(Severity.HIGH) < Severity.rank(Severity.CRITICAL)

    assert Severity.at_least(Severity.CRITICAL, Severity.HIGH) is True
    assert Severity.at_least(Severity.LOW, Severity.HIGH) is False

    assert Severity.levels_at_least(Severity.HIGH) == (Severity.HIGH, Severity.CRITICAL)
    assert set(Severity.levels_at_least(Severity.INFO)) == set(Severity.ORDER)


# ======================================================================
# Timeline
# ======================================================================
def test_timeline_log_returns_event_and_persists(timeline: TimelineLogger, db: Database) -> None:
    """log() hands back the stored row so callers can echo it to the UI."""
    event = timeline.log_antivirus(
        EventType.MATCH_FOUND, "Trojan.Win32.Agent", Severity.HIGH,
        file_path=r"C:\Users\demo\Downloads\invoice.pdf.exe",
    )
    assert event["id"] > 0
    assert event["source"] == Source.ANTIVIRUS
    assert event["severity"] == Severity.HIGH
    assert event["timestamp"]

    stored = db.get_timeline_events(limit=10)
    assert len(stored) == 1
    assert stored[0]["event_type"] == EventType.MATCH_FOUND


def test_timeline_subscribers_receive_events_and_errors_are_contained(
    timeline: TimelineLogger,
) -> None:
    """A broken subscriber must never break the engine that logged the event."""
    received: list[dict] = []
    timeline.subscribe(received.append)

    def exploding(_event: dict) -> None:
        raise RuntimeError("subscriber blew up")

    timeline.subscribe(exploding)
    timeline.log_system(EventType.APP_STARTED, "started")

    assert len(received) == 1
    timeline.unsubscribe(received.append)
    timeline.log_system(EventType.APP_STOPPED, "stopped")
    assert len(received) == 1  # no longer subscribed


def test_timeline_filters(timeline: TimelineLogger) -> None:
    """Source, severity, type, text and paging filters all narrow the result set."""
    timeline.log_antivirus(EventType.FILE_DETECTED, "New file", Severity.INFO,
                           file_path=r"C:\Temp\dropper.exe")
    timeline.log_antivirus(EventType.MATCH_FOUND, "Trojan.Win32.Agent", Severity.HIGH,
                           file_path=r"C:\Temp\dropper.exe")
    timeline.log_firewall(EventType.CONNECTION_BLOCKED, "Outbound denied", Severity.MEDIUM,
                          remote_ip="185.220.101.4")
    timeline.log_system(EventType.APP_STARTED, "ShieldEX started", Severity.INFO)

    assert len(timeline.query(source=Source.ANTIVIRUS)) == 2
    assert len(timeline.query(source=Source.FIREWALL)) == 1
    assert len(timeline.query(min_severity=Severity.MEDIUM)) == 2
    assert len(timeline.query(min_severity=Severity.HIGH)) == 1
    assert len(timeline.query(event_type=EventType.MATCH_FOUND)) == 1
    assert len(timeline.query(search="dropper.exe")) == 2
    assert len(timeline.query(search="185.220.101.4")) == 1
    assert len(timeline.query(severities=[Severity.INFO])) == 2

    newest_first = timeline.query()
    assert newest_first[0]["event_type"] == EventType.APP_STARTED
    assert len(timeline.query(limit=2)) == 2
    assert timeline.query(limit=1, offset=1)[0]["id"] == newest_first[1]["id"]


def test_timeline_date_filter(timeline: TimelineLogger, db: Database) -> None:
    """Date bounds are inclusive and use the same local-time format as the writes."""
    db.add_timeline_event(Source.ANTIVIRUS, EventType.SCAN_COMPLETED, "old scan",
                          Severity.INFO, timestamp=days_ago_str(10))
    timeline.log_antivirus(EventType.SCAN_COMPLETED, "todays scan", Severity.INFO)

    today = datetime.now().strftime("%Y-%m-%d")
    assert len(timeline.query(date_from=f"{today} 00:00:00")) == 1
    assert len(timeline.query(date_to=f"{today} 23:59:59")) == 2

    start, end = TimelineLogger.date_range(3)
    assert len(timeline.query(date_from=start, date_to=end)) == 1
    assert start <= end


def test_ids_prefix_count_does_not_treat_underscore_as_wildcard(
    timeline: TimelineLogger, db: Database
) -> None:
    """``LIKE 'IDS_%'`` must match a literal underscore, hence ESCAPE in the query."""
    timeline.ids_alert(EventType.IDS_PORT_SCAN, "10.0.0.5", "22 ports in 4s")
    db.add_timeline_event(Source.FIREWALL, "IDSXPORT_SCAN", "not an IDS event", Severity.LOW)

    assert db.count_timeline_events(
        source=Source.FIREWALL, event_type_prefix=EventType.IDS_PREFIX
    ) == 1


def test_timeline_counts_today(timeline: TimelineLogger) -> None:
    """The dashboard counters split by engine and alert class."""
    timeline.log_antivirus(EventType.MATCH_FOUND, "threat", Severity.CRITICAL,
                           file_path="/tmp/x")
    timeline.log_firewall(EventType.CONNECTION_BLOCKED, "denied", Severity.MEDIUM,
                          remote_ip="1.2.3.4")
    timeline.ids_alert(EventType.IDS_SYN_FLOOD, "1.2.3.4", "2000 SYN/s")

    counts = timeline.counts_today()
    assert counts["total"] == 3
    assert counts["antivirus"] == 1
    assert counts["firewall"] == 2
    assert counts["ids_alerts"] == 1
    assert counts["high_or_worse"] == 2


def test_purge_timeline_keeps_recent_events(timeline: TimelineLogger, db: Database) -> None:
    """Retention deletes only events older than the cutoff."""
    db.add_timeline_event(Source.SYSTEM, EventType.APP_STARTED, "ancient",
                          Severity.INFO, timestamp=days_ago_str(120))
    timeline.log_system(EventType.APP_STARTED, "recent")

    assert db.purge_timeline(90) == 1
    assert len(timeline.query()) == 1


# ======================================================================
# The two spec narratives, reproduced end to end
# ======================================================================
def test_antivirus_detection_narrative(timeline: TimelineLogger) -> None:
    """Detect → hash → check → match → classify → quarantine, in that order."""
    path = r"C:\Users\demo\Downloads\invoice.pdf.exe"
    timeline.file_detected(path, origin="real-time monitor")
    timeline.hash_generated(path, "a" * 64)
    timeline.signature_check(path, 15_000)
    timeline.match_found(path, "Trojan.Win32.Agent", Severity.HIGH)
    timeline.threat_classified(path, Severity.HIGH)
    timeline.quarantine_action(path, r"C:\Users\demo\.quarantine\7.quar", Severity.HIGH)

    story = list(reversed(timeline.query()))  # query() is newest-first
    assert [event["event_type"] for event in story] == [
        EventType.FILE_DETECTED,
        EventType.HASH_GENERATED,
        EventType.SIGNATURE_CHECK,
        EventType.MATCH_FOUND,
        EventType.THREAT_CLASSIFIED,
        EventType.QUARANTINE_ACTION,
    ]
    assert all(event["source"] == Source.ANTIVIRUS for event in story)
    assert all(event["file_path"] == path for event in story)
    assert "Trojan.Win32.Agent" in story[3]["event_detail"]
    assert story[5]["severity"] == Severity.HIGH


def test_firewall_block_narrative(timeline: TimelineLogger) -> None:
    """Attempt → rule check → reputation → rule match → block, in that order."""
    ip = "185.220.101.4"
    timeline.connection_attempt("chrome.exe", ip, 443)
    timeline.rule_check(ip, 47)
    timeline.ip_reputation(ip, "listed in blocklist (Tor exit node)", Severity.MEDIUM)
    timeline.rule_matched(ip, "Block Tor exit", "BLOCK")
    timeline.connection_blocked(ip, "OUTBOUND", Severity.MEDIUM)

    story = list(reversed(timeline.query()))
    assert [event["event_type"] for event in story] == [
        EventType.CONNECTION_ATTEMPT,
        EventType.RULE_CHECK,
        EventType.IP_REPUTATION,
        EventType.RULE_MATCHED,
        EventType.CONNECTION_BLOCKED,
    ]
    assert all(event["source"] == Source.FIREWALL for event in story)
    assert all(event["remote_ip"] == ip for event in story)
    assert "chrome.exe" in story[0]["event_detail"]


def test_log_sequence_preserves_order(timeline: TimelineLogger) -> None:
    """log_sequence() is a convenience wrapper; ordering must still hold."""
    events = timeline.log_sequence(
        Source.FIREWALL,
        [
            (EventType.CONNECTION_ATTEMPT, "inbound 3389"),
            (EventType.RULE_MATCHED, "Block RDP"),
            (EventType.CONNECTION_BLOCKED, "denied"),
        ],
        severity=Severity.MEDIUM,
        remote_ip="203.0.113.9",
    )
    assert [event["event_type"] for event in events] == [
        EventType.CONNECTION_ATTEMPT,
        EventType.RULE_MATCHED,
        EventType.CONNECTION_BLOCKED,
    ]
    assert [event["id"] for event in events] == sorted(event["id"] for event in events)


# ======================================================================
# Export
# ======================================================================
def test_timeline_export_csv(timeline: TimelineLogger, tmp_path: Path) -> None:
    """CSV export writes the documented columns for every filtered row."""
    timeline.log_antivirus(EventType.MATCH_FOUND, "Trojan.Win32.Agent", Severity.HIGH,
                           file_path=r"C:\Temp\bad.exe")
    timeline.log_firewall(EventType.CONNECTION_BLOCKED, "denied", Severity.MEDIUM,
                          remote_ip="1.2.3.4")

    target = tmp_path / "export.csv"
    assert timeline.export(target, fmt="csv") == 2

    with target.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0].keys()) == list(EXPORT_COLUMNS)
    assert {row["source"] for row in rows} == {Source.ANTIVIRUS, Source.FIREWALL}


def test_timeline_export_respects_filters_and_explicit_events(
    timeline: TimelineLogger, tmp_path: Path
) -> None:
    """Exports match the filter set, or exactly the rows handed in."""
    timeline.log_antivirus(EventType.MATCH_FOUND, "threat", Severity.HIGH, file_path="/tmp/a")
    timeline.log_firewall(EventType.CONNECTION_BLOCKED, "denied", Severity.MEDIUM,
                          remote_ip="1.2.3.4")

    filtered = tmp_path / "av.csv"
    assert timeline.export(filtered, fmt="csv", source=Source.ANTIVIRUS) == 1

    single = tmp_path / "one.txt"
    events = timeline.query(limit=1)
    assert timeline.export(single, events=events, fmt="txt") == 1
    text = single.read_text(encoding="utf-8")
    assert "Threat Behavior Timeline" in text
    assert "1 event(s)" in text


def test_timeline_export_raises_on_unwritable_path(timeline: TimelineLogger, tmp_path: Path) -> None:
    """Export failures surface as OSError so the GUI can show a real error dialog."""
    timeline.log_system(EventType.APP_STARTED, "started")
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("i am a file", encoding="utf-8")
    with pytest.raises(OSError):
        timeline.export(blocker / "child" / "export.csv", fmt="csv")


# ======================================================================
# Dashboard aggregate
# ======================================================================
def test_dashboard_stats_shape_and_values(db: Database, timeline: TimelineLogger) -> None:
    """The dashboard reads one aggregate; its shape is part of the contract."""
    scan_id = db.start_scan("quick")
    db.finish_scan(scan_id, 500, 2, {"High": 1, "Medium": 1})
    db.add_quarantine_entry("/tmp/bad", "/tmp/q/1.quar", "Trojan.Test", Severity.HIGH)
    db.add_firewall_rule(name="Block SMB", direction="INBOUND", action="BLOCK")
    db.log_connection("x.exe", 1, "TCP", "10.0.0.1", 1, "1.2.3.4", 443, "OUTBOUND", "BLOCKED")
    db.add_blocked_ip("1.2.3.4")
    db.add_trusted_ip("192.168.0.0/24")
    timeline.ids_alert(EventType.IDS_PORT_SCAN, "1.2.3.4", "22 ports in 4s")
    db.set_bool_setting("realtime_monitoring_enabled", True)
    db.set_setting("current_network_profile", "Private")

    stats = db.get_dashboard_stats()

    assert set(stats) == {"antivirus", "firewall", "timeline"}
    antivirus = stats["antivirus"]
    assert antivirus["last_scan"]["id"] == scan_id
    assert antivirus["threats_found_total"] == 2
    assert antivirus["quarantined"] == 1
    assert antivirus["realtime_enabled"] is True

    firewall = stats["firewall"]
    assert firewall["rules_inbound"] == 1
    assert firewall["rules_outbound"] == 0
    assert firewall["rules_enabled"] == 1
    assert firewall["blocked_today"] == 1
    assert firewall["ids_alerts_today"] == 1
    assert firewall["blocked_ips"] == 1
    assert firewall["trusted_ips"] == 1
    assert set(firewall["profiles"]) == {"domain", "private", "public"}
    assert firewall["current_profile"] == "Private"

    assert stats["timeline"]["events_today"] == 1
    assert stats["timeline"]["high_today"] == 1


# ======================================================================
# Concurrency
# ======================================================================
def test_concurrent_writes_from_threads(db: Database) -> None:
    """Scans, the monitor and the connection watcher all write at once in production."""
    errors: list[Exception] = []

    def writer(index: int) -> None:
        try:
            for step in range(20):
                db.add_timeline_event(
                    Source.FIREWALL, EventType.CONNECTION_ATTEMPT,
                    f"worker {index} step {step}", Severity.INFO, remote_ip=f"10.0.{index}.1",
                )
        except Exception as exc:  # pragma: no cover - only fires on a locking bug
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors
    assert db.count_timeline_events() == 100


def test_read_after_close_is_reported_not_crashed(tmp_path: Path) -> None:
    """Using a closed database must raise a clear error rather than corrupt state."""
    database = Database(tmp_path / "closed.db")
    database.initialize()
    database.close()
    with pytest.raises(RuntimeError):
        database.signature_count()


# ======================================================================
# Config
# ======================================================================
def test_config_creates_file_with_defaults(tmp_path: Path) -> None:
    """First run writes a complete config.json."""
    config_path = tmp_path / "config.json"
    config = Config.load(config_path, tmp_path)

    assert config_path.exists()
    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert written["app"]["name"] == "ShieldEX"
    assert written["firewall"]["enforce_rules"] is False  # dry-run by default
    assert config.get("antivirus.max_file_size_mb") == written["antivirus"]["max_file_size_mb"]


def test_config_tops_up_missing_keys_without_losing_user_values(tmp_path: Path) -> None:
    """A partial config.json keeps the user's values and gains the missing defaults."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"app": {"theme": "light"}, "firewall": {"enforce_rules": True}}),
        encoding="utf-8",
    )
    config = Config.load(config_path, tmp_path)

    assert config.get("app.theme") == "light"           # preserved
    assert config.get("firewall.enforce_rules") is True  # preserved
    assert config.get("app.name") == "ShieldEX"          # topped up
    assert config.get("antivirus.heuristics.entropy.threshold") is not None

    reloaded = json.loads(config_path.read_text(encoding="utf-8"))
    assert reloaded["app"]["theme"] == "light"
    assert "logging" in reloaded  # the top-up was written back to disk


def test_config_recovers_from_corrupt_file(tmp_path: Path) -> None:
    """A truncated or hand-broken config must not stop the app from starting."""
    config_path = tmp_path / "config.json"
    config_path.write_text("{not valid json", encoding="utf-8")
    config = Config.load(config_path, tmp_path)
    assert config.get("app.name") == "ShieldEX"


def test_config_dotted_get_set_and_save(tmp_path: Path) -> None:
    """Dotted access reaches nested keys; save() persists atomically."""
    config = Config.load(tmp_path / "config.json", tmp_path)

    assert config.get("nope.not.here", "fallback") == "fallback"
    config.set("antivirus.heuristics.entropy.threshold", 7.9)
    assert config.get("antivirus.heuristics.entropy.threshold") == 7.9
    config.set("firewall.enforce_rules", True)
    assert config.save() is True

    reopened = Config.load(tmp_path / "config.json", tmp_path)
    assert reopened.get("antivirus.heuristics.entropy.threshold") == 7.9
    assert reopened.get("firewall.enforce_rules") is True

    reopened.reset_to_defaults()
    assert reopened.get("firewall.enforce_rules") is False


def test_config_paths_are_derived_not_hardcoded(tmp_path: Path) -> None:
    """Every runtime path hangs off the application root."""
    config = Config.load(tmp_path / "config.json", tmp_path)

    assert config.database_path.parent == tmp_path
    assert config.log_path.parent == tmp_path / "logs"
    assert config.quarantine_path == tmp_path / ".quarantine"
    assert config.app_path("assets/signatures.json") == tmp_path / "assets" / "signatures.json"


def test_resolve_token_expands_environment_paths(tmp_path: Path) -> None:
    """Path tokens resolve per platform; unknown tokens are treated as literal paths."""
    assert resolve_token("%APP_ROOT%", tmp_path) == [tmp_path]
    assert resolve_token("%QUARANTINE%", tmp_path) == [tmp_path / ".quarantine"]

    temp_paths = resolve_token("%TEMP%", tmp_path)
    assert temp_paths, "%TEMP% must resolve to at least one candidate on any platform"
    assert all(isinstance(path, Path) for path in temp_paths)

    literal = resolve_token(str(tmp_path / "explicit"), tmp_path)
    assert literal == [tmp_path / "explicit"]


def test_config_resolve_paths_filters_missing_targets(tmp_path: Path) -> None:
    """Scan targets that do not exist are dropped rather than crashing the scanner."""
    config = Config.load(tmp_path / "config.json", tmp_path)
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real_file = tmp_path / "file.txt"
    real_file.write_text("x", encoding="utf-8")

    tokens = [str(real_dir), str(real_file), str(tmp_path / "ghost")]
    assert set(config.resolve_paths(tokens)) == {real_dir, real_file}
    assert config.resolve_paths(tokens, directories_only=True) == [real_dir]
    assert len(config.resolve_paths(tokens, existing_only=False)) == 3


def test_config_exclusions(tmp_path: Path) -> None:
    """Excluded paths cover the target itself and everything beneath it."""
    config = Config.load(tmp_path / "config.json", tmp_path)
    excluded_dir = tmp_path / "skipme"
    excluded_dir.mkdir()
    config.set("antivirus.excluded_paths", [str(excluded_dir)])

    assert config.is_excluded(excluded_dir) is True
    assert config.is_excluded(excluded_dir / "deep" / "file.exe") is True
    assert config.is_excluded(tmp_path / "elsewhere" / "file.exe") is False
    # The quarantine vault must never be re-scanned, or restored files loop forever.
    assert config.is_excluded(config.quarantine_path / "1.quar") is True


# ======================================================================
# Shipped artefacts and GUI syntax
# ======================================================================
def test_bundled_signature_seed_is_valid() -> None:
    """assets/signatures.json must load and contain the verifiable EICAR hash."""
    payload = json.loads((PROJECT_ROOT / "assets" / "signatures.json").read_text(encoding="utf-8"))
    assert payload["version"]
    # seed_signatures() refuses to record an unparseable version, so the shipped seed has
    # to carry a numeric one or the app would never report a signature database version.
    assert entrypoint._version_key(str(payload["version"]))
    entries = payload["signatures"]
    assert entries

    for entry in entries:
        assert len(entry["hash"]) in (32, 40, 64)
        assert entry["name"]
        assert Severity.normalize(entry["severity"]) == entry["severity"]

    assert any(entry["hash"] == EICAR_SHA256 for entry in entries)


def test_bundled_demo_payload_hashes_match_their_signatures() -> None:
    """Demo entries carry the exact string whose SHA-256 they list, so they are testable."""
    import hashlib

    payload = json.loads((PROJECT_ROOT / "assets" / "signatures.json").read_text(encoding="utf-8"))
    checked = 0
    for entry in payload["signatures"]:
        sample = entry.get("test_payload")
        if not sample:
            continue
        digest = hashlib.sha256(sample.encode("utf-8")).hexdigest()
        assert digest == entry["hash"], f"{entry['name']} payload does not hash to its signature"
        checked += 1
    assert checked >= 1


def test_shipped_config_matches_defaults_shape() -> None:
    """The config.json in the repo must parse and keep the dry-run default."""
    shipped = json.loads((PROJECT_ROOT / "config.json").read_text(encoding="utf-8"))
    assert shipped["app"]["name"] == "ShieldEX"
    assert shipped["firewall"]["enforce_rules"] is False


@pytest.mark.parametrize(
    "module_path",
    [
        "gui/theme.py",
        "gui/widgets.py",
        "gui/base_view.py",
        "gui/app.py",
        "gui/dashboard.py",
        "gui/timeline_view.py",
        "gui/scan_view.py",
        "gui/quarantine_view.py",
        "gui/history_view.py",
        "gui/settings_view.py",
        "gui/firewall/rules_view.py",
        "gui/firewall/connections_view.py",
        "gui/firewall/blocklist_view.py",
        "gui/firewall/alerts_view.py",
        "gui/firewall/templates_view.py",
        "core/engines.py",
        "core/notifications.py",
        "main.py",
    ],
)
def test_module_compiles(module_path: str, tmp_path: Path) -> None:
    """Syntax-check the GUI without importing customtkinter, so CI stays headless."""
    source = PROJECT_ROOT / module_path
    assert source.exists(), f"missing module {module_path}"
    py_compile.compile(str(source), cfile=str(tmp_path / "out.pyc"), doraise=True)


def test_timestamp_helpers_are_consistent() -> None:
    """now_str/days_ago_str share one format so string comparison equals time comparison."""
    stamp = now_str()
    assert datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
    older = days_ago_str(5)
    assert older < stamp
    assert (
        datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
        - datetime.strptime(older, "%Y-%m-%d %H:%M:%S")
    ) >= timedelta(days=4)


# ======================================================================
# Regression tests for the audit fixes
# ======================================================================
def test_severity_filter_accepts_a_bare_level_string(
    db: Database, timeline: TimelineLogger
) -> None:
    """A single level may be passed as a string, not only as a one-element list.

    ``str`` satisfies ``Sequence[str]``, so ``severities="High"`` type-checked and then
    iterated character by character — building ``severity IN (?,?,?,?)`` bound to ``H``,
    ``i``, ``g``, ``h``, which matches nothing. A filter that silently returns no rows is
    worse than one that raises, so this must keep working.
    """
    timeline.log_antivirus(EventType.MATCH_FOUND, "critical thing", Severity.CRITICAL)
    timeline.log_antivirus(EventType.MATCH_FOUND, "high thing", Severity.HIGH)
    timeline.log_firewall(EventType.CONNECTION_BLOCKED, "low thing", Severity.LOW)

    single = db.get_timeline_events(severities="High")
    assert [event["event_detail"] for event in single] == ["high thing"]
    assert db.count_timeline_events(severities="High") == 1

    # The list form, and the min_severity expansion built on it, are unaffected.
    pair = db.get_timeline_events(severities=[Severity.HIGH, Severity.CRITICAL])
    assert len(pair) == 2
    assert len(timeline.query(min_severity=Severity.HIGH)) == 2
    assert len(timeline.query(severities=Severity.CRITICAL)) == 1

    # An empty filter still means "no severity restriction", not "match nothing".
    assert len(db.get_timeline_events(severities=[])) == 3
    assert db.count_timeline_events(severities=None) == 3


def test_path_dedup_key_respects_platform_semantics(tmp_path: Path) -> None:
    """Path de-duplication must not case-fold or strip separators where it is wrong to.

    The old key was ``str(path).rstrip("\\\\/").lower()``, which on POSIX merged
    ``/srv/Data`` with ``/srv/data`` (two different directories, so one silently dropped out
    of every scan) and truncated any filename ending in a backslash — a legal POSIX name.
    """
    assert _path_key(tmp_path / "sub") == _path_key(str(tmp_path / "sub") + os.sep)
    assert _path_key(tmp_path / "a" / ".." / "b") == _path_key(tmp_path / "b")

    if os.name == "nt":
        assert _path_key("C:/Windows/Temp") == _path_key("c:\\windows\\temp")
    else:
        assert _path_key("/srv/Data") != _path_key("/srv/data")
        assert _path_key("/tmp/back\\slash").endswith("back\\slash")

    # resolve_paths still collapses genuine duplicates that differ only by trailing sep.
    config = Config.load(tmp_path / "config.json", tmp_path)
    target = tmp_path / "scanme"
    target.mkdir()
    assert config.resolve_paths([str(target), str(target) + os.sep]) == [target]


def test_exclusion_roots_are_cached_but_still_follow_config_changes(tmp_path: Path) -> None:
    """The is_excluded cache must never outlive the values it was built from.

    ``is_excluded`` runs once per scanned file, so the resolved roots are cached — but a
    cache that missed a settings change would keep skipping a folder the user just removed
    from the exclusion list, which is a silent hole in the scan.
    """
    config = Config.load(tmp_path / "config.json", tmp_path)
    first = tmp_path / "old-exclusion"
    second = tmp_path / "new-exclusion"
    first.mkdir()
    second.mkdir()
    # The vault is one of the roots, and roots are only cached once they all exist — see
    # exclusion_roots(): a path resolved while missing can canonicalise differently later.
    config.quarantine_path.mkdir(parents=True, exist_ok=True)

    config.set("antivirus.excluded_paths", [str(first)])
    assert config.is_excluded(first / "x.exe") is True
    roots = config.exclusion_roots()
    assert config.exclusion_roots() is roots  # unchanged config -> same cached tuple

    config.set("antivirus.excluded_paths", [str(second)])
    assert config.is_excluded(first / "x.exe") is False
    assert config.is_excluded(second / "x.exe") is True
    assert config.exclusion_roots() is not roots

    # A root that does not exist yet is still honoured, but is deliberately not cached:
    # its canonical form can change the moment it is created (symlink, junction, 8.3 name).
    ghost = tmp_path / "not-created-yet"
    config.set("antivirus.excluded_paths", [str(ghost)])
    assert config.is_excluded(ghost / "x.exe") is True
    assert config.exclusion_roots() is not config.exclusion_roots()

    # Whatever the list says, the vault stays excluded and stays in the resolved roots.
    config.set("antivirus.excluded_paths", [])
    assert config.is_excluded(config.quarantine_path / "1.quar") is True
    assert config.quarantine_path.resolve() in config.exclusion_roots()


def test_logging_config_values_are_validated_not_trusted() -> None:
    """A hand-edited logging block must degrade to defaults instead of crashing startup.

    Logging is configured before anything can report a failure, so an exception here used
    to surface as a bare traceback and an empty log file. ``getattr(logging, name)`` was the
    sharp edge: ``logging.shutdown`` and ``logging.warn`` are real attributes and neither is
    a level, so ``setLevel`` got a function and raised ``TypeError``.
    """
    assert entrypoint._resolve_log_level("debug") == logging.DEBUG
    assert entrypoint._resolve_log_level("WARNING") == logging.WARNING
    assert entrypoint._resolve_log_level(logging.ERROR) == logging.ERROR
    assert entrypoint._resolve_log_level("20") == logging.INFO  # a quoted number is fine
    assert entrypoint._resolve_log_level("30") == logging.WARNING
    for bogus in ("SHUTDOWN", "shutdown", "Handler", "verbose", "", None, True, [1]):
        assert entrypoint._resolve_log_level(bogus) == logging.INFO
    # Out-of-range numbers are the dangerous case: a level above CRITICAL silences
    # everything, including the replayed startup backlog, with no clue left behind.
    for out_of_range in (999_999_999, -5, logging.CRITICAL + 1, "999999999"):
        assert entrypoint._resolve_log_level(out_of_range) == logging.INFO

    assert entrypoint._non_negative_int("1024", 5, "k") == 1024
    assert entrypoint._non_negative_int(0, 5, "k") == 0  # 0 = never roll over, legal
    for bogus in ("2MB", None, -1, "", [2], float("inf"), float("nan")):
        # float("inf") is the JSON `Infinity`/`1e999` case: int(inf) raises OverflowError,
        # which is neither a TypeError nor a ValueError.
        assert entrypoint._non_negative_int(bogus, 4096, "k") == 4096


def test_configure_logging_survives_a_hostile_config(tmp_path: Path) -> None:
    """End-to-end: a config full of invalid logging values still produces a usable log."""
    original_handlers = list(logging.getLogger().handlers)
    original_level = logging.getLogger().level
    try:
        config = Config.load(tmp_path / "config.json", tmp_path)
        config.set("logging.level", "SHUTDOWN")
        config.set("logging.max_bytes", "2MB")
        config.set("logging.backup_count", "many")
        config.set("logging.console", False)

        buffer = entrypoint.begin_logging()
        logging.getLogger("shieldex.early").warning("config was unreadable")
        entrypoint.configure_logging(config, debug=False, startup_buffer=buffer)
        logging.getLogger("shieldex.late").warning("after configuration")

        # Re-entry must not leave the previous file handler open (Windows rotation breaks
        # if it does) and must not duplicate any record.
        entrypoint.configure_logging(config, debug=False)
        logging.getLogger("shieldex.late").warning("after reconfiguration")
        logging.shutdown()

        written = config.log_path.read_text(encoding="utf-8")
        # The buffered pre-config record must appear, exactly once, and it must appear first.
        assert written.count("config was unreadable") == 1
        assert written.index("config was unreadable") < written.index("after configuration")
        assert written.count("after reconfiguration") == 1
    finally:
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in original_handlers:
            root.addHandler(handler)
        root.setLevel(original_level)


def test_startup_buffer_dumps_to_stderr_when_the_replay_never_happens() -> None:
    """If startup dies before logging is configured, the buffer is the only record left."""
    import io

    buffer = entrypoint._StartupBuffer()
    source = logging.getLogger("shieldex.test.dump")
    source.propagate = False
    source.setLevel(logging.DEBUG)
    source.addHandler(buffer)
    try:
        source.error("config.json is unreadable")
    finally:
        source.removeHandler(buffer)

    captured = io.StringIO()
    real_stderr, sys.stderr = sys.stderr, captured
    try:
        buffer.dump_to_stderr()
        buffer.dump_to_stderr()  # drained, so this must add nothing
    finally:
        sys.stderr = real_stderr

    assert captured.getvalue().count("config.json is unreadable") == 1


def test_startup_buffer_replays_only_records_at_or_above_the_final_level() -> None:
    """The buffer captures at DEBUG, so replay has to apply the configured level itself."""

    class Collector(logging.Handler):
        def __init__(self) -> None:
            super().__init__(level=logging.DEBUG)
            self.seen: list[str] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.seen.append(record.getMessage())

    buffer = entrypoint._StartupBuffer()
    source = logging.getLogger("shieldex.test.buffer")
    source.propagate = False
    source.setLevel(logging.DEBUG)
    source.addHandler(buffer)
    try:
        source.debug("noisy detail")
        source.error("real problem")
    finally:
        source.removeHandler(buffer)

    collector = Collector()
    buffer.replay([collector], logging.INFO)
    assert collector.seen == ["real problem"]
    assert buffer.records == []  # drained, so a second call cannot duplicate output


def test_signature_version_comparison_is_numeric_not_lexicographic(
    db: Database, tmp_path: Path
) -> None:
    """0.10.0 must count as newer than 0.9.0, and a seed must never downgrade the version.

    As strings, ``"0.10.0" < "0.9.0"``, so the recorded signature database version used to
    stick at the older value while the newer signatures were already merged — the dashboard
    then reported a version the user did not have.
    """
    assert entrypoint._version_key("0.10.0") > entrypoint._version_key("0.9.0")
    assert entrypoint._version_key("1.2.10") > entrypoint._version_key("1.2.9")
    assert entrypoint._version_key("1.2") < entrypoint._version_key("1.2.1")
    assert entrypoint._version_key("1.2.0-rc1") == (1, 2, 0)
    assert entrypoint._version_key("bundled") == ()
    # "²".isdigit() is True but int("²") raises, so isdecimal() is the right predicate:
    # a version string like this must yield a key, not crash startup.
    assert entrypoint._version_key("1.²") == (1,)

    # Two different numbering schemes must not be compared at all: as keys, (20260915,)
    # would beat (2026, 9, 1) on the first component even though it may well be older.
    assert entrypoint._same_version_scheme("0.10.0", "0.9.0") is True
    assert entrypoint._same_version_scheme("2026.09.01", "2026.9.1") is True
    assert entrypoint._same_version_scheme("20260915", "2026.09.01") is False

    # app_root points at the project so the real assets/signatures.json is used; the
    # database is still the throwaway one from the fixture.
    config = Config.load(tmp_path / "config.json", PROJECT_ROOT)
    assert entrypoint.seed_signatures(db, config) > 0
    seeded_version = db.get_setting("signature_db_version", "")
    assert seeded_version not in ("", "none")
    # The seed ships a date-style version (2026.09.01), so build "newer" from it rather
    # than assuming a semver-shaped value.
    newer_than_seed = ".".join(str(part + 1) for part in entrypoint._version_key(seeded_version))
    assert entrypoint._version_key(newer_than_seed) > entrypoint._version_key(seeded_version)

    # A remote update moved ahead of the bundled seed: re-seeding must not roll it back.
    db.set_setting("signature_db_version", newer_than_seed)
    assert entrypoint.seed_signatures(db, config) == 0  # idempotent merge
    assert db.get_setting("signature_db_version", "") == newer_than_seed

    # A non-numeric stored version is likewise left alone rather than compared as text.
    db.set_setting("signature_db_version", "vendor-feed")
    entrypoint.seed_signatures(db, config)
    assert db.get_setting("signature_db_version", "") == "vendor-feed"


def test_unparseable_seed_version_is_never_recorded(db: Database, tmp_path: Path) -> None:
    """A seed with no usable version must not poison the recorded version or its timestamp.

    Storing an unparseable value even once is a trap: no later numeric version can beat
    ``()``, so the reported signature version would be frozen forever — and an empty string
    would re-stamp ``signature_db_updated_at`` on every launch, making the dashboard claim
    a fresh update each time the app opened.
    """
    fake_root = tmp_path / "app"
    (fake_root / "assets").mkdir(parents=True)
    (fake_root / "assets" / "signatures.json").write_text(
        json.dumps(
            {
                "version": "",
                "signatures": [
                    {
                        "hash": "a" * 64,
                        "name": "Test.Unversioned",
                        "severity": "Low",
                        "threat_type": "Test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config = Config.load(tmp_path / "config.json", fake_root)

    assert entrypoint.seed_signatures(db, config) == 1  # signatures still merge
    assert db.get_setting("signature_db_version", "none") == "none"
    assert db.get_setting("signature_db_updated_at", "") == ""


# ======================================================================
# Engine wiring + "coming soon" view completion (this build)
# ======================================================================
from core.firewall.ip_blocklist import IPBlocklist  # noqa: E402
from core.firewall.rule_engine import RuleEngine  # noqa: E402


def _make_engines(tmp_path: Path, db: Database, timeline: TimelineLogger):
    """Build the full engine stack against a temp app root (no network, no GUI)."""
    from core.engines import build_engines

    config = Config.load(tmp_path / "config.json", tmp_path)
    config.set("updater.check_on_startup", False)
    config.set("firewall.connection_monitor.enabled", False)
    return build_engines(config, db, timeline), config


def test_rule_engine_evaluates_without_enabled_only_crash(tmp_path, db, timeline) -> None:
    """Regression: evaluate() called db.get_firewall_rules(enabled_only=True), which is
    not a parameter - every rule evaluation raised TypeError before the fix.
    """
    engines, _config = _make_engines(tmp_path, db, timeline)
    rule_engine = engines.get("firewall")
    assert rule_engine is not None

    # No rules: default verdict is monitor.
    verdict = rule_engine.evaluate("203.0.113.9", process_name="chrome.exe", remote_port=443)
    assert verdict.action == "monitor"

    # A stored block rule must match by port without the evaluation crashing.
    rule_id = db.add_firewall_rule(
        name="block telnet", direction="outbound", action="block",
        protocol="TCP", remote_port="23",
    )
    assert rule_id > 0
    verdict = rule_engine.evaluate("198.51.100.7", process_name="cmd.exe", remote_port=23)
    assert verdict.blocked is True
    assert verdict.rule_name == "block telnet"

    # apply_all() with enforcement off reports dry-run rather than raising.
    assert rule_engine.apply_all() is False


def test_profile_toggle_persists_the_key_the_ui_reads(tmp_path, db, timeline) -> None:
    """Regression: set_profile_enabled used to write firewall_profile_* while the app
    and dashboard read firewall_enabled_* � toggles reset on every restart."""
    engines, _config = _make_engines(tmp_path, db, timeline)
    rule_engine = engines.get("firewall")
    assert rule_engine is not None

    assert rule_engine.set_profile_enabled("public", False) is True
    assert db.get_bool_setting("firewall_enabled_public", True) is False
    assert "public" not in rule_engine.active_profiles()

    rule_engine.set_profile_enabled("public", True)
    assert db.get_bool_setting("firewall_enabled_public", False) is True
    assert "public" in rule_engine.active_profiles()


def test_build_engines_registers_the_full_stack(tmp_path, db, timeline) -> None:
    """The registry must contain every engine the views and the shell look up."""
    engines, _config = _make_engines(tmp_path, db, timeline)
    expected = {
        "quarantine", "scanner", "realtime_monitor", "updater",
        "blocklist", "firewall", "ids", "connection_monitor", "notifications",
    }
    assert expected <= set(engines.names())


def test_template_instantiation_round_trip(tmp_path, db, timeline) -> None:
    """create_rule_from_template stores a rule the Rules view can then list."""
    engines, _config = _make_engines(tmp_path, db, timeline)
    rule_engine = engines.get("firewall")

    rule_id = rule_engine.create_rule_from_template("block_rdp_in")
    assert rule_id and rule_id > 0
    stored = db.get_firewall_rule(rule_id)
    assert stored["name"] == "Block inbound RDP"
    assert stored["action"] == "BLOCK"

    # Duplicate names are unique-keyed; the engine must not create a second rule.
    assert rule_engine.create_rule_from_template("block_rdp_in") is None
    assert db.count_firewall_rules() == 1


def test_blocklist_cidr_and_trust_precedence(tmp_path, db, timeline) -> None:
    """Blocking a /24 covers its members, and a trusted host escapes the block."""
    engines, _config = _make_engines(tmp_path, db, timeline)
    blocklist = engines.get("blocklist")

    assert blocklist.block("10.66.0.0/16", label="bad range") is True
    assert blocklist.is_blocked("10.66.1.2") is True

    assert blocklist.trust("10.66.1.2", label="known good host") is True
    assert blocklist.is_blocked("10.66.1.2") is False  # trust overrides the range
    assert blocklist.is_trusted("10.66.1.2") is True

    assert blocklist.unblock("10.66.0.0/16") is True
    assert blocklist.is_blocked("10.66.5.5") is False


def test_updater_reports_tuple_contract_and_stamps_check_time(tmp_path, db, timeline) -> None:
    """update_now() returns (applied, message) and records the last-check timestamp."""
    engines, _config = _make_engines(tmp_path, db, timeline)
    updater = engines.get("updater")

    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps({"version": "2026.09.05", "signatures": [
            {"hash": "b" * 64, "name": "Test.Feed", "severity": "High"},
        ]}),
        encoding="utf-8",
    )
    applied, message = updater.update_now(str(feed))
    assert applied is True
    assert "1" in message
    assert db.signature_count() == 1
    assert db.get_setting("signature_db_version", "") == "2026.09.05"
    assert (db.get_setting("signature_db_last_checked", "") or "") != ""

    # A failing feed is reported, never raised.
    applied, message = updater.update_now(str(tmp_path / "missing.json"))
    assert applied is False
    assert message.startswith("Update check failed")


def test_timeline_query_filters_by_event_type_prefix(db, timeline) -> None:
    """The IDS Alerts view queries IDS_* events; the prefix filter must work and stay
    literal (an underscore is not a wildcard)."""
    timeline.log_firewall(EventType.IDS_PORT_SCAN, "scan from A", Severity.HIGH, "203.0.113.1")
    timeline.log_firewall(EventType.CONNECTION_BLOCKED, "blocked B", Severity.MEDIUM, "10.0.0.1")

    alerts = timeline.query(event_type_prefix="IDS_")
    assert [event["event_type"] for event in alerts] == [EventType.IDS_PORT_SCAN]

    all_fw = timeline.query(source="FIREWALL")
    assert len(all_fw) == 2


def test_scan_history_totals_aggregate_correctly(db) -> None:
    """The Scan History summary reads the new aggregate helper."""
    scan_id = db.start_scan("quick", "somewhere")
    db.finish_scan(scan_id, files_scanned=10, threats_found=2,
                   severity_summary={"High": 2}, status="COMPLETED")
    db.start_scan("full", "elsewhere")  # left RUNNING counts as a failure-ish row

    totals = db.scan_history_totals()
    assert totals["scans"] == 2
    assert totals["files"] == 10
    assert totals["threats"] == 2
    assert totals["failures"] == 1  # the RUNNING row is not COMPLETED
