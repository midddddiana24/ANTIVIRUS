"""Signature database version comparison.

Standalone rather than in ``main`` because ``core.antivirus.updater`` needs the same
numeric-aware comparison when merging remote feeds, and importing the entry point from
a library module would drag argparse and the elevation code along with it.
"""

from __future__ import annotations

import re

__all__ = ["version_key", "same_version_scheme", "is_newer_version"]


def version_key(version: str) -> tuple[int, ...]:
    """Parse a dotted numeric version into a comparable tuple, or ``()`` if unparseable.

    Needed because comparing version strings lexicographically is not version order:
    ``"0.10.0" > "0.9.0"`` is ``False`` because ``"1" < "9"`` character-wise. That
    silently pinned a reported signature database version at 0.9.0 forever while it
    actually held newer signatures.
    """
    chunks = re.split(r"[._\-+]", (version or "").strip())
    parts: list[int] = []
    for chunk in chunks:
        # isdecimal(), not isdigit(): "²".isdigit() is True but int("²") raises ValueError,
        # so a Unicode digit in a remotely-supplied version string would crash here.
        if not (chunk.isdecimal() and chunk.isascii()):
            break  # stop at the first non-numeric part ("1.2.0-rc1" -> (1, 2, 0))
        parts.append(int(chunk))
    return tuple(parts)


def same_version_scheme(left: str, right: str) -> bool:
    """True when two version strings look like the same numbering scheme.

    Guards against comparing a compact date against a dotted one: ``version_key`` turns
    ``"20260915"`` into ``(20260915,)`` and ``"2026.09.01"`` into ``(2026, 9, 1)``, so
    the dotted — and possibly newer — version compares as older on the first component
    alone. Requiring the leading component to have the same number of digits rejects
    that pairing while leaving ordinary comparisons (``0.10.0`` vs ``0.9.0``, ``1.2``
    vs ``1.2.1``) intact.
    """
    left_head = re.split(r"[._\-+]", (left or "").strip())[0]
    right_head = re.split(r"[._\-+]", (right or "").strip())[0]
    return len(left_head) == len(right_head)


def is_newer_version(candidate: str, stored: str) -> bool:
    """True when ``candidate`` should replace ``stored`` as the recorded db version.

    Centralises the policy the seed merge and the remote updater both follow:

    * an unparseable candidate never wins (it would freeze the version forever);
    * an empty/``"none"`` stored value is always replaced;
    * an unparseable stored value came from somewhere else (a vendor feed with its own
      naming) and is left alone — a merge must not overwrite what it cannot compare;
    * versions from different numbering schemes are never compared.
    """
    candidate_key = version_key(candidate)
    if not candidate_key:
        return False

    if not stored or stored == "none":
        return True
    stored_key = version_key(stored)
    if not stored_key:
        return False
    if not same_version_scheme(candidate, stored):
        return False
    return candidate_key > stored_key
