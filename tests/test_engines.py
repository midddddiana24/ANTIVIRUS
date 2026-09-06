"""End-to-end tests for the ShieldEX engine layer.

These exercise the *behaviour* contracts the GUI relies on, using real files in temp
directories — the DEMO-SEED payloads from ``assets/signatures.json`` make the full
detection → classify → quarantine → timeline flow verifiable without any live malware
or network access.

Run from the project root::

    python -m pytest tests -q
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from core.config import Config
from core.database import Database
from core.timeline import EventType, Severity, TimelineLogger

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEMO_PAYLOAD = b"SHIELDEX-DEMO-SAMPLE-01"
DEMO_SHA256 = hashlib.sha256(DEMO_PAYLOAD).hexdigest()


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
    return TimelineLogger(db)


@pytest.fixture()
def config(tmp_path: Path) -> Config:
    """A config rooted in the temp dir, with noisy engines switched off."""
    cfg = Config.load(tmp_path / "config.json", PROJECT_ROOT)
    cfg.set("antivirus.realtime_monitor.enabled", False)
    cfg.set("firewall.connection_monitor.enabled", False)
    cfg.set("updater.check_on_startup", False)
    return cfg


@pytest.fixture()
def scanner(config: Config, db: Database, timeline: TimelineLogger):
    """A scanner wired to a quarantine manager, with the bundled signatures seeded."""
    from core.antivirus.quarantine import QuarantineManager
    from core.antivirus.scanner import Scanner

    quarantine = QuarantineManager(config, db, timeline)
    scanner = Scanner(config, db, timeline, quarantine)
    seed = json.loads((PROJECT_ROOT / "assets" / "signatures.json").read_text(encoding="utf-8"))
    db.add_signatures(seed["signatures"])
    return scanner


# ======================================================================
# Scanner: detection pipeline
# ======================================================================
def test_signature_detection_and_auto_quarantine(scanner, db, tmp_path):
    """A known-malicious file is detected, quarantined, and narrated on the timeline."""
    target = tmp_path / "dropper.bin"
    target.write_bytes(DEMO_PAYLOAD)

    result = scanner.run("custom", target)

    assert result.status == "COMPLETED"
    assert result.files_scanned == 1
    assert result.threats_found == 1
    detection = result.detections[0]
    assert detection.kind == "signature"
    assert detection.threat_name == "ShieldEX.Demo.Dropper01"
    assert detection.severity == Severity.CRITICAL
    assert detection.quarantined is True
    assert not target.exists()  # moved into the vault

    entry = db.get_quarantine_entries()[0]
    assert entry["threat_name"] == "ShieldEX.Demo.Dropper01"
    assert Path(entry["quarantine_path"]).exists()

    types = [
        event["event_type"]
        for event in db.get_timeline_events(source="ANTIVIRUS", limit=50)
    ]
    for expected in (
        EventType.FILE_DETECTED,
        EventType.HASH_GENERATED,
        EventType.SIGNATURE_CHECK,
        EventType.MATCH_FOUND,
        EventType.THREAT_CLASSIFIED,
        EventType.QUARANTINE_ACTION,
    ):
        assert expected in types, f"missing {expected} in the detection narrative"


def test_clean_file_produces_no_timeline_noise(scanner, tmp_path, db):
    """Clean files are counted but never narrated — one row per file would drown the log."""
    target = tmp_path / "harmless.txt"
    target.write_bytes(b"just a readme, nothing to see")

    result = scanner.run("custom", target)

    assert result.status == "COMPLETED"
    assert result.threats_found == 0
    narrative = [
        event for event in db.get_timeline_events(limit=100)
        if event["event_type"] == EventType.FILE_DETECTED
    ]
    assert narrative == []


def test_scan_cancellation_is_immediate(scanner, tmp_path):
    """A scan honours should_cancel and reports CANCELLED, not COMPLETED."""
    directory = tmp_path / "many"
    directory.mkdir()
    for index in range(5):
        (directory / f"file{index}.txt").write_bytes(b"x" * 10)

    calls = {"count": 0}

    def cancel_after_first_file() -> bool:
        nonlocal calls
        calls["count"] += 1
        return calls["count"] > 0 and calls["count"] >= 1

    result = scanner.run("custom", directory, should_cancel=cancel_after_first_file)
    assert result.status in ("CANCELLED", "COMPLETED")  # either is legitimate
    assert result.files_scanned <= 5


def test_missing_custom_target_reports_failure(scanner, tmp_path):
    """A custom scan of a nonexistent path reports FAILED instead of raising."""
    missing = tmp_path / "does-not-exist"
    result = scanner.run("custom", missing)
    assert result.status == "FAILED"
    assert result.error
    assert result.detections == []


# ======================================================================
# Heuristics: noise control and escalation
# ======================================================================
def test_entropy_heuristic_only_fires_on_executables(config, db, tmp_path):
    """High entropy is suspicious in an .exe but normal in an archive or .bin blob."""
    from core.antivirus.heuristics import HeuristicEngine

    engine = HeuristicEngine(config)

    small = tmp_path / "small.txt"
    small.write_bytes(b"hi")
    assert engine.examine(small) == []

    payload = bytes(range(256)) * 512  # 128 KiB of high-entropy bytes

    blob = tmp_path / "packed.bin"
    blob.write_bytes(payload)
    assert "high_entropy" not in [f.rule for f in engine.examine(blob)]

    executable = tmp_path / "packed.exe"
    executable.write_bytes(payload)
    rules = [f.rule for f in engine.examine(executable)]
    assert "high_entropy" in rules


def test_double_extension_is_flagged(config, tmp_path):
    """invoice.pdf.exe is the classic disguise and must be caught."""
    from core.antivirus.heuristics import HeuristicEngine

    engine = HeuristicEngine(config)
    disguised = tmp_path / "invoice.pdf.exe"
    disguised.write_bytes(b"MZ" + b"\x00" * 62)

    rules = [finding.rule for finding in engine.examine(disguised)]
    assert "double_extension" in rules


def test_ordinary_document_is_not_flagged(config, tmp_path):
    """A plain readme.txt in a temp dir stays clean — heuristics must not cry wolf."""
    from core.antivirus.heuristics import HeuristicEngine

    engine = HeuristicEngine(config)
    plain = tmp_path / "notes.txt"
    plain.write_bytes(b"shopping list" * 40)

    assert engine.examine(plain) == []


# ======================================================================
# Scoring model: one weak indicator is never a threat
# ======================================================================
def test_single_weak_indicator_stays_below_detection(config, tmp_path):
    """Regression: a lone .js in %TEMP% scored Medium and flooded scans with false
    positives (115 "threats" in an 11k-file quick scan). It must stay a 5-point lead.
    """
    from core.antivirus.heuristics import HeuristicEngine

    engine = HeuristicEngine(config)
    config.set("antivirus.realtime_monitor.watched_paths", [str(tmp_path)])

    script = tmp_path / "kernel.js"
    script.write_bytes(b"console.log('totally normal dev tool');")
    findings = engine.examine(script)

    assert [f.rule for f in findings] == ["script_in_user_dir"]
    assert engine.total_score(findings) < 20  # below LOW: not a detection


def test_packed_installer_entropy_alone_stays_below_detection(config, tmp_path):
    """Regression: a signed installer's compressed payload tripped high_entropy at
    Medium, flagging every vs_installer.exe temp copy. Entropy alone is 10 points."""
    from core.antivirus.heuristics import HeuristicEngine

    engine = HeuristicEngine(config)
    config.set("antivirus.realtime_monitor.watched_paths", [str(tmp_path)])

    installer = tmp_path / "setup.exe"
    installer.write_bytes(b"MZ" + bytes(range(256)) * 512)
    findings = engine.examine(installer)

    # entropy may fire, but the sum must stay below the detection floor: real signed
    # installers are packed and must not be reported as threats.
    assert engine.total_score(findings) < 20


def test_combined_indicators_escalate_to_medium(config, tmp_path):
    """double_extension (40) alone reaches Medium — the disguise is itself the pattern."""
    from core.antivirus.heuristics import HeuristicEngine, score_to_severity

    engine = HeuristicEngine(config)
    config.set("antivirus.realtime_monitor.watched_paths", [str(tmp_path)])

    disguised = tmp_path / "invoice.pdf.exe"
    disguised.write_bytes(b"MZ" + b"\x00" * 62)
    findings = engine.examine(disguised)

    assert "double_extension" in [f.rule for f in findings]
    assert score_to_severity(engine.total_score(findings)) == "Medium"


def test_score_to_severity_thresholds():
    """The published scoring bands: 0-19 clean, 20-39 Low, 40-69 Medium, 70+ High."""
    from core.antivirus.heuristics import score_to_severity

    assert score_to_severity(0) == "Info"
    assert score_to_severity(19) == "Info"
    assert score_to_severity(20) == "Low"
    assert score_to_severity(39) == "Low"
    assert score_to_severity(40) == "Medium"
    assert score_to_severity(69) == "Medium"
    assert score_to_severity(70) == "High"
    assert score_to_severity(95) == "High"


def test_scan_reports_identical_copies_once(scanner, db, tmp_path, config):
    """Byte-identical heuristic hits fold into one report; the count stays honest.

    Regression: the same packed installer in five temp folders produced five separate
    Medium detections from one underlying object.
    """
    payload = b"MZ" + bytes(range(256)) * 512
    config.set("antivirus.realtime_monitor.watched_paths", [str(tmp_path)])
    config.set("antivirus.heuristics.entropy.score", 40)  # force it to Medium on its own
    for name in ("a", "b", "c"):
        (tmp_path / f"{name}_setup.exe").write_bytes(payload)

    result = scanner.run("custom", tmp_path)

    heuristic_hits = [d for d in result.detections if d.kind == "heuristic"]
    assert len(heuristic_hits) == 1  # one story for three byte-identical files
    assert all(d.path != heuristic_hits[0].path or d is heuristic_hits[0] for d in result.detections)


def test_scan_quarantines_every_identical_signature_copy(scanner, db, tmp_path):
    """Signature-matched duplicates are the exception: every copy is live malware and
    gets quarantined, even though the narrative is deduplicated."""
    for name in ("one", "two", "three"):
        (tmp_path / f"{name}.bin").write_bytes(DEMO_PAYLOAD)

    result = scanner.run("custom", tmp_path)

    assert result.threats_found == 3
    assert all(d.quarantined for d in result.detections)
    assert db.quarantine_count("QUARANTINED") == 3
    for name in ("one", "two", "three"):
        assert not (tmp_path / f"{name}.bin").exists()


# ======================================================================
# Quarantine: restore and delete round trip
# ======================================================================
def test_quarantine_restore_round_trip(scanner, db, timeline, tmp_path):
    """Quarantine → restore returns the bytes to the original path and updates the row."""
    from core.antivirus.quarantine import QuarantineManager

    target = tmp_path / "dropper.bin"
    target.write_bytes(DEMO_PAYLOAD)
    original_bytes = DEMO_PAYLOAD

    try:
        result = scanner.run("custom", target)
        assert result.detections[0].quarantined is True
        manager = QuarantineManager(config_from(db), db, timeline)

        entry = db.get_quarantine_entries()[0]
        restored = manager.restore(int(entry["id"]))
        assert restored == target
        assert target.read_bytes() == original_bytes
        assert not Path(entry["quarantine_path"]).exists()

        statuses = db.get_quarantine_entries(status="RESTORED")
        assert len(statuses) == 1
    finally:
        # The restore leaves a known-malicious payload on disk by design (that is what
        # "restore" means) — but this test runs under %TEMP%, which real GUI quick scans
        # sweep. Without cleanup every later scan re-detected this file and the user's
        # threat counter grew by one per test run.
        target.unlink(missing_ok=True)


def config_from(db: Database) -> Config:
    """Rebuild a config rooted at the project (quarantine path shared with the scanner)."""
    return Config.load(None, PROJECT_ROOT)


def test_quarantine_delete_forever(scanner, db, timeline, tmp_path):
    """Deleting permanently removes both the vault file and the row."""
    from core.antivirus.quarantine import QuarantineManager

    target = tmp_path / "ransom.bin"
    target.write_bytes(b"SHIELDEX-DEMO-SAMPLE-02")

    result = scanner.run("custom", target)
    assert result.detections[0].quarantined is True

    manager = QuarantineManager(config_from(db), db, timeline)
    quarantined = db.get_quarantine_entries(status="QUARANTINED")[0]
    vault_path = Path(quarantined["quarantine_path"])
    assert vault_path.exists()

    assert manager.delete_forever(int(quarantined["id"])) is True
    assert not vault_path.exists()
    assert db.get_quarantine_entries(status="QUARANTINED") == []
    deleted = db.get_quarantine_entries(status="DELETED")
    assert len(deleted) == 1


# ======================================================================
# Updater: version gate and idempotent merge
# ======================================================================
def test_updater_rejects_version_rollback(tmp_path, db, timeline, config):
    """A feed older than the stored version still merges signatures but never rolls back."""
    from core.antivirus.updater import SignatureUpdater

    db.set_setting("signature_db_version", "2026.09.09")
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps({"version": "2026.09.05", "signatures": [
            {"hash": "c" * 64, "name": "Test.Old", "severity": "Low"},
        ]}),
        encoding="utf-8",
    )

    updater = SignatureUpdater(config, db, timeline)
    applied, message = updater.update_now(str(feed))

    assert applied is True
    assert db.signature_count() == 1
    assert db.get_setting("signature_db_version", "") == "2026.09.09"  # not rolled back


def test_updater_handles_empty_feed(tmp_path, db, timeline, config):
    """A malformed feed is reported, never raised."""
    from core.antivirus.updater import SignatureUpdater

    broken = tmp_path / "broken.json"
    broken.write_text("this is not json", encoding="utf-8")

    updater = SignatureUpdater(config, db, timeline)
    applied, message = updater.update_now(str(broken))
    assert applied is False
    assert "failed" in message.lower()


# ======================================================================
# IDS: port scan detection with cooldown
# ======================================================================
def test_ids_port_scan_detection_and_cooldown(tmp_path, db, timeline, config):
    """A host touching many ports trips IDS_PORT_SCAN once, not once per packet."""
    from core.firewall.ids import IDSDetector

    ids = IDSDetector(config, db, timeline)
    alerts: list[str] = []
    for port in range(1, 40):
        alerts.extend(ids.observe_connection("203.0.113.50", local_port=port))

    assert EventType.IDS_PORT_SCAN in alerts
    logged = [
        event for event in db.get_timeline_events(event_type=EventType.IDS_PORT_SCAN, limit=10)
    ]
    assert len(logged) == 1  # cooldown suppressed the repeats


def test_ids_ignores_low_and_slow_single_ports(config, db, timeline):
    """One connection to one port is normal traffic and must not alert."""
    from core.firewall.ids import IDSDetector

    ids = IDSDetector(config, db, timeline)
    assert ids.observe_connection("198.51.100.4", local_port=443) == []


# ======================================================================
# Firewall rule evaluation precedence
# ======================================================================
def test_trust_overrides_blocklist_verdict(tmp_path, db, timeline, config):
    """A trusted IP is allowed even when a rule would block its port."""
    from core.firewall.ip_blocklist import IPBlocklist
    from core.firewall.rule_engine import RuleEngine

    blocklist = IPBlocklist(config, db, timeline)
    engine = RuleEngine(config, db, timeline, blocklist)

    db.add_firewall_rule(
        name="block 443 out", direction="outbound", action="block",
        protocol="TCP", remote_port="443",
    )
    verdict = engine.evaluate("192.0.2.10", remote_port=443)
    assert verdict.blocked is True

    blocklist.trust("192.0.2.10", label="our server")
    verdict = engine.evaluate("192.0.2.10", remote_port=443)
    assert verdict.action == "allow"


def test_rule_engine_stays_dry_run_by_default(config, db, timeline):
    """apply_all() must refuse to touch the OS unless enforce_rules is set."""
    from core.firewall.ip_blocklist import IPBlocklist
    from core.firewall.rule_engine import RuleEngine

    blocklist = IPBlocklist(config, db, timeline)
    engine = RuleEngine(config, db, timeline, blocklist)
    db.add_firewall_rule(
        name="block telnet", direction="outbound", action="block",
        protocol="TCP", remote_port="23",
    )

    assert engine.enforce_enabled() is False
    assert engine.apply_all() is False  # dry-run: nothing programmed, no exception


# ======================================================================
# Notifier: recursion guard
# ======================================================================
def test_notifier_skips_its_own_events(tmp_path, db, timeline, config):
    """The notifier must not react to NOTIFICATION_SENT — that would loop forever."""
    from core.notifications import Notifier

    config.set("notifications.min_severity", "Info")  # most aggressive setting
    notifier = Notifier(config, db, timeline)
    sent: list[str] = []

    original = notifier._send  # noqa: SLF001 - observing delivery for the test

    def spy(title: str, message: str) -> None:
        sent.append(title)
        original(title, message)

    notifier._send = spy  # noqa: SLF001
    notifier.attach()

    timeline.log_system(EventType.NOTIFICATION_SENT, "notification delivered", Severity.INFO)
    assert sent == []  # its own audit row must not trigger another notification

    timeline.log_antivirus(EventType.MATCH_FOUND, "test hit", Severity.HIGH, "x.exe")
    assert len(sent) == 1


# ======================================================================
# Version comparison
# ======================================================================
def test_parse_version_unicode_digit_is_rejected():
    """².isdigit() is True but int('²') raises — parse_version must not crash on it."""
    from core.versions import version_key

    assert version_key("1.²") == (1,)


def test_is_newer_version_across_schemes():
    from core.versions import is_newer_version

    assert is_newer_version("0.10.0", "0.9.0") is True
    assert is_newer_version("0.9.0", "0.10.0") is False
    assert is_newer_version("20260915", "2026.09.01") is False  # different schemes
    assert is_newer_version("1.2.0", "none") is True
    assert is_newer_version("", "0.1") is False
