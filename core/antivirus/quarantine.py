"""The quarantine vault — where detected files go so they can do no harm.

Moving the file (rather than deleting) keeps the evidence: the original bytes, the
original path and the scan that put it there, which makes a mistaken detection fixable
with one click ("Restore"). Two properties matter most:

* **Neutralised**: the stored file gets the ``.quar`` extension from config, so the OS
  no longer treats it as executable, and it is excluded from every scan by
  :meth:`core.config.Config.is_excluded` (which always excludes the vault, whatever the
  exclusion list says — otherwise a restored file would be re-detected forever).
* **Reversible**: ``restore()`` puts the bytes back where they came from, overwriting
  whatever moved in since; ``delete_forever()`` removes both the vault copy and the
  record row.
"""

from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

from core.config import Config
from core.database import Database, now_str
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["QuarantineManager", "QuarantineError"]


class QuarantineError(Exception):
    """A quarantine action failed; the message is safe to show the user."""


class QuarantineManager:
    """Stores detected files in the vault and tracks them in ``quarantine_log``."""

    def __init__(self, config: Config, db: Database, timeline: TimelineLogger) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.vault = config.quarantine_path
        self._extension = str(config.get("antivirus.quarantine.extension", ".quar"))

    # ------------------------------------------------------------------ quarantine
    def quarantine(
        self,
        path: Path,
        threat_name: str,
        severity: str,
        file_hash: str | None = None,
        scan_id: int | None = None,
    ) -> int:
        """Move ``path`` into the vault and record it. Returns the quarantine entry id.

        Raises :class:`QuarantineError` when the move fails, so the scanner can mark the
        detection "found but not quarantined" rather than losing the file silently.
        """
        path = Path(path)
        if not path.exists():
            raise QuarantineError(f"{path} does not exist (already removed?)")

        try:
            self.vault.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise QuarantineError(f"Could not create the quarantine vault: {exc}") from exc

        stamp = now_str().replace(":", "").replace(" ", "_").replace("-", "")
        stored_name = f"{stamp}_{uuid.uuid4().hex[:8]}{self._extension}"
        destination = self.vault / stored_name

        try:
            shutil.move(str(path), str(destination))
        except (OSError, shutil.Error) as exc:
            raise QuarantineError(f"Could not move {path} to quarantine: {exc}") from exc

        entry_id = self.db.add_quarantine_entry(
            original_path=str(path),
            quarantine_path=str(destination),
            threat_name=threat_name,
            severity=Severity.normalize(severity),
            file_hash=file_hash,
            scan_id=scan_id,
        )
        if entry_id <= 0:
            # The move already succeeded, so the file is safe in the vault; only the
            # bookkeeping failed. Remove the stored copy rather than leave an untracked
            # file, but the original location is already lost — surface that honestly.
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass  # an untracked vault file is inert: wrong extension, excluded from scans
            raise QuarantineError(f"{path} was moved but could not be recorded")

        self.timeline.quarantine_action(path, destination, severity)
        logger.info("Quarantined %s → %s (%s)", path, destination.name, threat_name)
        return entry_id

    # ------------------------------------------------------------------ restore
    def restore(self, entry_id: int, overwrite: bool = True) -> Path:
        """Move a vault copy back to its original location. Returns the restored path.

        ``overwrite`` controls what happens when something new now lives at the original
        path: overwriting is the expected behaviour ("put my file back"), and the caller
        (the GUI) confirms first.
        """
        entry = self.db.get_quarantine_entry(entry_id)
        if entry is None:
            raise QuarantineError(f"No quarantine entry with id {entry_id}")
        if entry["status"] != "QUARANTINED":
            raise QuarantineError(f"Entry is {entry['status']}, not QUARANTINED")

        stored = Path(entry["quarantine_path"])
        original = Path(entry["original_path"])
        if not stored.exists():
            raise QuarantineError(f"The quarantined file is missing: {stored}")

        if original.exists() and not overwrite:
            raise QuarantineError(f"{original} already exists; not overwriting")

        try:
            original.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise QuarantineError(f"Could not recreate {original.parent}: {exc}") from exc

        try:
            if original.exists():
                original.unlink()
            shutil.move(str(stored), str(original))
        except (OSError, shutil.Error) as exc:
            raise QuarantineError(f"Could not restore to {original}: {exc}") from exc

        if not self.db.set_quarantine_status(entry_id, "RESTORED"):
            logger.warning("Restored %s but could not update its database row", original)

        self.timeline.log_antivirus(
            EventType.QUARANTINE_RESTORED,
            f"Restored {original.name} to {original.parent}",
            Severity.INFO,
            original,
        )
        logger.info("Restored %s → %s", stored.name, original)
        return original

    # ------------------------------------------------------------------ delete
    def delete_forever(self, entry_id: int) -> bool:
        """Remove the vault copy and mark the entry DELETED. True when the row updated."""
        entry = self.db.get_quarantine_entry(entry_id)
        if entry is None:
            return False

        stored = Path(entry["quarantine_path"])
        if stored.exists():
            try:
                stored.unlink()
            except OSError as exc:
                raise QuarantineError(f"Could not delete {stored}: {exc}") from exc

        updated = self.db.set_quarantine_status(entry_id, "DELETED")
        self.timeline.log_antivirus(
            EventType.THREAT_REMOVED,
            f"Deleted {Path(str(entry['original_path'])).name} from quarantine permanently",
            Severity.INFO,
            str(entry["original_path"]),
        )
        return updated

    # ------------------------------------------------------------------ listing
    def entries(self, status: str | None = "QUARANTINED") -> list[dict[str, Any]]:
        """Quarantine rows for display."""
        return self.db.get_quarantine_entries(status=status)

    def count(self, status: str | None = "QUARANTINED") -> int:
        """How many entries are in the given state."""
        return self.db.quarantine_count(status)

    # ------------------------------------------------------------------ maintenance
    def delete_missing_files(self) -> int:
        """Drop entries whose vault file is gone (external cleanup, disk wipe)."""
        removed = 0
        for entry in self.db.get_quarantine_entries(status="QUARANTINED", limit=100_000):
            stored = Path(entry["quarantine_path"])
            if not stored.exists():
                if self.db.delete_quarantine_entry(int(entry["id"])):
                    removed += 1
        if removed:
            logger.info("Dropped %d quarantine entries whose vault file was missing", removed)
        return removed
