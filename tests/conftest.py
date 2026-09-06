"""Sys.path bootstrap so ``tests/`` can import the ShieldEX packages.

The tests directory is deliberately not a package, so pytest puts ``tests/`` on
``sys.path`` rather than the project root. This adds the project root back.

The session-finish hook below exists because pytest's default basetemp lives under
``%TEMP%`` — inside the very locations a real ShieldEX quick scan sweeps. Tests that
restore quarantined files or write heuristic fixtures leave byte patterns the GUI
scanner treats as detections, so every later scan "found" a threat that was really our
own test garbage (and the lifetime threat counter crept up on every test run). The
suite now removes its temp trees when it exits; the per-test ``finally`` blocks handle
the known-malicious payloads individually.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

#: The pytest basetemp roots used this session, removed again at exit so test fixtures
#: (which live inside %TEMP%, where real quick scans sweep) never linger on disk.
_SEEN_TEMP_ROOTS: set[Path] = set()


@pytest.fixture(autouse=True)
def _track_tmp_root(tmp_path: Path):
    """Remember the basetemp root — ``tmp_path`` itself is ``<basetemp>/<test_N>``,
    so the basetemp is exactly one level up. (Two levels up is the shared ``opencode``
    temp workspace, which must never be deleted.)
    """
    root = tmp_path.parent
    if root.exists():
        _SEEN_TEMP_ROOTS.add(root)


@pytest.fixture()
def db(tmp_path: Path):
    """An initialised database in a temp directory, closed on teardown."""
    from core.database import Database

    database = Database(tmp_path / "shieldex.db")
    database.initialize()
    yield database
    database.close()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Best-effort removal of this session's pytest basetemp tree."""
    if not _SEEN_TEMP_ROOTS:
        return
    for root in sorted(_SEEN_TEMP_ROOTS, key=lambda p: len(p.parts), reverse=True):
        try:
            shutil.rmtree(root, ignore_errors=True)
        except OSError:  # a locked file must never fail the test session
            pass
