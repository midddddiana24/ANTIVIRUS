"""Protection self-test — prove the pipeline works with the industry-standard EICAR file.

EICAR is a 68-byte ASCII string that every antivirus product agrees to treat as
malware without it being malware at all. Writing it to disk and scanning the file
exercises the *entire* detection path end to end (hash → signature match →
classify → quarantine → timeline) against a known-good expectation, which is exactly
what a user needs after changing settings: "did I break protection?"

The test file is created in the system temp dir, scanned, and — when the pipeline
works — auto-quarantined away. On success nothing is left behind; on failure the
leftover file is removed so a inert test string never litters %TEMP%.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["EICAR_STRING", "run_self_test"]

#: The standard EICAR test string (68 bytes, no trailing newline). Its SHA-256 is
#: the EICAR entry seeded into every ShieldEX database.
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def run_self_test(scanner: Any, timeline: Any = None) -> tuple[bool, str]:
    """Write EICAR, scan it, and check the pipeline did its job.

    Returns ``(passed, human_message)``. Never raises — a self-test that crashes
    tells the user nothing, while a clean failure message tells them exactly what
    broke. The scanner's own quarantine manager handles the test file when the
    pipeline works; the ``finally`` deletes it when it does not.
    """
    from core.timeline import EventType, Severity

    target = Path(tempfile.gettempdir()) / "shieldex-selftest-eicar.com"
    try:
        target.write_bytes(EICAR_STRING.encode("ascii"))

        result = scanner.run("custom", target)
        if result.status != "COMPLETED":
            return False, f"Self-test scan did not complete (status {result.status})"
        if result.threats_found != 1:
            return (
                False,
                f"Self-test FAILED: EICAR file was not detected "
                f"({result.threats_found} threat(s) in {result.files_scanned} file(s))",
            )
        detection = result.detections[0]
        if detection.kind != "signature":
            return False, "Self-test FAILED: EICAR matched heuristically, not by signature"
        if not detection.quarantined:
            return (
                False,
                "Self-test PARTIAL: EICAR detected but not quarantined — "
                "check the Critical/High quarantine policy in Settings",
            )

        message = (
            f"Self-test PASSED: EICAR detected as '{detection.threat_name}' "
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
