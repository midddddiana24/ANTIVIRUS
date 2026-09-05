"""Sys.path bootstrap so ``tests/`` can import the ShieldEX packages.

The tests directory is deliberately not a package, so pytest puts ``tests/`` on
``sys.path`` rather than the project root. This adds the project root back.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
