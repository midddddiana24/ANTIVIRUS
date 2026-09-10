"""Protection self-test — prove the pipeline works with a known inert payload.

The test writes a ShieldEX DEMO-SEED string to disk and scans it through the real
pipeline (hash → signature match → classify → quarantine → timeline), checking the
outcome against the known-good expectation. That is exactly what a user needs after
changing settings: "did I break protection?"

Why a DEMO string and not the industry-standard EICAR file: on any machine with
Windows Defender real-time protection active, Defender's minifilter intercepts every
``open()`` of EICAR content (reads fail with ``[Errno 22]`` while the file still
"exists"), so an EICAR self-test can never complete there — it would always report
failure for environmental reasons. The DEMO strings are ShieldEX-specific, inert,
and readable, so they verify *our* pipeline instead of fighting Defender. (The EICAR
signature stays in the database for real-world EICAR encounters.)

The test file is created in the system temp dir, scanned, and — when the pipeline
works — auto-quarantined away. On success nothing is left behind; on failure the
leftover file is removed so an inert test string never litters %TEMP%.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["SELFTEST_PAYLOAD", "SELFTEST_THREAT", "run_self_test"]

#: Inert ShieldEX DEMO-SEED payload and the signature name it must match.
#: SAMPLE-01 is Critical, so the test passes under the default policy (which
#: quarantines Critical/High) — a Medium payload would report PARTIAL out of the box.
SELFTEST_PAYLOAD = b"SHIELDEX-DEMO-SAMPLE-01"
SELFTEST_THREAT = "ShieldEX.Demo.Dropper01"


def run_self_test(scanner: Any, timeline: Any = None) -> tuple[bool, str]:
    """Write the payload, scan it, and check the pipeline did its job.

    Returns ``(passed, human_message)``. Never raises — a self-test that crashes
    tells the user nothing, while a clean failure message tells them exactly what
    broke. The scanner's own quarantine manager handles the test file when the
    pipeline works; the ``finally`` deletes it when it does not.
    """
    from core.timeline import EventType, Severity

    target = Path(tempfile.gettempdir()) / "shieldex-selftest-payload.bin"
    try:
        target.write_bytes(SELFTEST_PAYLOAD)

        result = scanner.run("custom", target)
        if result.status != "COMPLETED":
            return False, f"Self-test scan did not complete (status {result.status})"
        if result.threats_found != 1:
            return (
                False,
                f"Self-test FAILED: test payload was not detected "
                f"({result.threats_found} threat(s) in {result.files_scanned} file(s))",
            )
        detection = result.detections[0]
        if detection.kind != "signature" or detection.threat_name != SELFTEST_THREAT:
            return (
                False,
                f"Self-test FAILED: payload matched '{detection.threat_name}' "
                f"({detection.kind}), expected signature '{SELFTEST_THREAT}'",
            )
        if not detection.quarantined:
            return (
                False,
                "Self-test PARTIAL: payload detected but not quarantined — "
                "check the quarantine policy in Settings",
            )

        message = (
            f"Self-test PASSED: payload detected as '{detection.threat_name}' "
            f"({detection.severity}) and quarantined"
        )
        if timeline is not None:
            try:
                timeline.log_antivirus(EventType.SCAN_COMPLETED, message, Severity.INFO)
            except Exception:
                pass
        return True, message
    except Exception as exc:
        logger.exception("Self-test crashed")
        return False, f"Self-test errored: {exc}"
    finally:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
