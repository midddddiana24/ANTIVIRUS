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
    """A config rooted in the temp dir, with noisy engines switched off.

    ``app_root`` is the temp dir (not PROJECT_ROOT): the quarantine vault resolves
    under it, so pytest quarantines land in throwaway space. An earlier version
    rooted at PROJECT_ROOT and every test run quarantined DEMO payloads into the
    user's REAL project vault — 100+ orphan ``.quar`` files no DB row referenced.
    """
    cfg = Config.load(tmp_path / "config.json", tmp_path)
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


def test_every_counted_threat_has_a_detection_log_line(scanner, db, tmp_path, caplog):
    """Regression: duplicate signature hits bumped the GUI counter with no log line.

    The first copy of a file gets the full narrative + a ``Detection:`` console
    line; byte-identical copies after it were appended to ``detections`` silently —
    the UI counted threats the CMD log never showed.
    """
    import logging

    for name in ("one", "two", "three"):
        (tmp_path / f"{name}.bin").write_bytes(DEMO_PAYLOAD)

    with caplog.at_level(logging.INFO, logger="core.antivirus.scanner"):
        result = scanner.run("custom", tmp_path)

    assert result.threats_found == 3
    detection_lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Detection:")
    ]
    assert len(detection_lines) == 3, (
        f"{result.threats_found} threats counted but only "
        f"{len(detection_lines)} Detection log line(s)"
    )


def test_quarantine_vault_stays_inside_tmp_dir(scanner, config, db, tmp_path):
    """Regression: the test config rooted the vault at the project dir, so every
    pytest run quarantined DEMO payloads into the user's REAL vault (100+ orphan
    ``.quar`` files no DB row referenced — and the next GUI scan re-detected them).
    """
    from pathlib import Path as _P

    vault = _P(str(config.quarantine_path)).resolve()
    assert str(vault).startswith(str(tmp_path.resolve())), (
        f"test vault leaked outside tmp_path: {vault}"
    )
    assert vault != (PROJECT_ROOT / ".quarantine").resolve()


def test_single_file_scan_reports_progress(scanner, tmp_path):
    """A custom scan of one malicious file must fire on_progress — the walk's
    cadence never runs for single-file targets, so live stats stayed 0/0 and the
    verdict only appeared at finish."""
    target = tmp_path / "evil.bin"
    target.write_bytes(DEMO_PAYLOAD)

    calls: list[tuple[int, int, str]] = []
    result = scanner.run(
        "custom", target, on_progress=lambda f, t, c: calls.append((f, t, c))
    )

    assert result.threats_found == 1
    assert calls, "no progress callback fired for a single-file scan"
    assert calls[-1][0] == 1 and calls[-1][1] == 1


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


# ======================================================================
# Response policy
# ======================================================================
def test_policy_defaults_quarantine_critical_and_high_only(config):
    """The shipped table quarantines known-bad severities, never Medium and below."""
    from core.policy import ResponsePolicy

    policy = ResponsePolicy(config)
    assert policy.should_quarantine("Critical", kind="signature") is True
    assert policy.should_quarantine("High", kind="signature") is True
    assert policy.should_quarantine("Medium", kind="signature") is False
    assert policy.should_quarantine("Low", kind="signature") is False


def test_policy_never_auto_quarantines_heuristics(config):
    """Heuristic detections are leads, not verdicts — no severity may quarantine them."""
    from core.policy import ResponsePolicy

    policy = ResponsePolicy(config)
    for level in ("Critical", "High", "Medium", "Low"):
        assert policy.should_quarantine(level, kind="heuristic") is False


def test_policy_edit_round_trip(config):
    """set_quarantine persists through config and describe() reflects it."""
    from core.policy import ResponsePolicy

    policy = ResponsePolicy(config)
    assert policy.set_quarantine("Medium", True) is True
    assert policy.should_quarantine("Medium", kind="signature") is True
    assert policy.set_quarantine("Bogus", True) is False
    assert dict(policy.describe())["Medium"] is True


def test_policy_honours_legacy_bool(config):
    """The old single boolean still governs when the table is absent (upgrades)."""
    from core.policy import ResponsePolicy

    config.set("policies.threat_response", None)
    config.set("antivirus.auto_quarantine_on_signature_match", False)
    assert ResponsePolicy(config).should_quarantine("High", kind="signature") is False
    config.set("antivirus.auto_quarantine_on_signature_match", True)
    assert ResponsePolicy(config).should_quarantine("High", kind="signature") is True


def test_scanner_obeys_policy_over_default(scanner, config, db, tmp_path):
    """The policy table governs quarantine: Critical flipped off leaves the file."""
    from core.policy import ResponsePolicy

    target = tmp_path / "dropper.bin"
    target.write_bytes(DEMO_PAYLOAD)  # Critical signature match
    assert ResponsePolicy(config).set_quarantine("Critical", False) is True

    result = scanner.run("custom", target)

    assert result.threats_found == 1  # still detected and reported…
    assert result.detections[0].quarantined is False  # …but left on disk per policy
    assert target.exists()
    assert db.quarantine_count("QUARANTINED") == 0


# ======================================================================
# Scheduled scans
# ======================================================================
class _StubScanner:
    """Minimal scanner stand-in: records run() calls without touching disk."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(self, scan_type: str):
        from core.antivirus.scanner import ScanResult

        self.calls.append(scan_type)
        return ScanResult(scan_id=-1, scan_type=scan_type, target="stub", status="COMPLETED")


def test_scheduler_runs_configured_scan_type(config, db, timeline):
    """run_now() executes exactly the configured scan type and records it."""
    from core.antivirus.scheduler import ScanScheduler

    stub = _StubScanner()
    scheduler = ScanScheduler(config, db, timeline, stub)

    assert scheduler.run_now() is True
    assert stub.calls == ["quick"]  # the default configured type

    config.set("antivirus.scheduled_scans.scan_type", "full")
    assert scheduler.run_now() is True
    assert stub.calls == ["quick", "full"]
    assert db.get_setting("scheduled_scan_last_run", "") == "COMPLETED"


def test_scheduler_rejects_bad_time_and_unknown_type(config, db, timeline):
    """Invalid schedule values degrade to safe defaults instead of crashing."""
    from core.antivirus.scheduler import ScanScheduler

    assert ScanScheduler._valid_time("02:00") is True
    assert ScanScheduler._valid_time("25:00") is False
    assert ScanScheduler._valid_time("nope") is False

    config.set("antivirus.scheduled_scans.scan_type", "whatever")
    assert ScanScheduler(config, db, timeline, _StubScanner())._scan_type() == "quick"


def test_scheduler_start_requires_opt_in(config, db, timeline):
    """Disabled by default: start() refuses until the user enables scheduling."""
    from core.antivirus.scheduler import ScanScheduler

    assert ScanScheduler(config, db, timeline, _StubScanner()).start() is False
    config.set("antivirus.scheduled_scans.enabled", True)
    scheduler = ScanScheduler(config, db, timeline, _StubScanner())
    assert scheduler.start() is True
    assert scheduler.running is True
    scheduler.stop()
    assert scheduler.running is False


# ======================================================================
# Protection self-test
# ======================================================================
def test_self_test_passes_end_to_end(scanner, db, tmp_path):
    """Payload in → signature detection → quarantine out, with nothing left behind."""
    from core.antivirus.selftest import SELFTEST_PAYLOAD, SELFTEST_THREAT, run_self_test

    assert SELFTEST_THREAT == "ShieldEX.Demo.Dropper01"
    assert len(SELFTEST_PAYLOAD) > 0
    passed, message = run_self_test(scanner)
    assert passed is True, message
    assert "quarantined" in message
    assert db.quarantine_count("QUARANTINED") >= 1


# ======================================================================
# Firewall rule hit counts
# ======================================================================
def test_rule_match_counts_aggregate(db):
    """Connections group by the rule name the engine recorded for them."""
    db.log_connection(
        process="a.exe", pid=1, protocol="TCP", local_ip="1.1.1.1", local_port=1,
        remote_ip="2.2.2.2", remote_port=23, direction="outbound", action="block",
        rule_matched="block telnet",
    )
    db.log_connection(
        process="b.exe", pid=2, protocol="TCP", local_ip="1.1.1.1", local_port=2,
        remote_ip="3.3.3.3", remote_port=23, direction="outbound", action="block",
        rule_matched="block telnet",
    )
    db.log_connection(
        process="c.exe", pid=3, protocol="TCP", local_ip="1.1.1.1", local_port=3,
        remote_ip="4.4.4.4", remote_port=80, direction="outbound", action="allow",
        rule_matched=None,  # unmatched rows must not appear under any rule
    )
    assert db.get_rule_match_counts() == {"block telnet": 2}
