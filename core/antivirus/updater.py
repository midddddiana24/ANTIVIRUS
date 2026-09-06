"""Signature database updater — merges remote or local feeds into the local db.

Feed formats supported:

* **ShieldEX JSON** (the bundled ``assets/signatures.json`` schema)::
      {"version": "2026.09.04", "signatures": [{"hash": ..., "name": ..., "severity": ...}]}
* **MalwareBazaar CSV** (``https://bazaar.abuse.ch/export/csv/recent/``): one malware
  sample per line with the SHA-256 in the second column and the malware family in the
  ``signature`` column. This is real, daily-refreshed intelligence, which is what
  makes "Update Now" actually do something on a default install.

Both ``http(s)://`` and local paths (``file:///`` or a bare path) work, which is what
makes the updater testable: a test writes a feed to a temp directory and points
``update_now(feed_path)`` at it — no network, no mocking of ``requests``.

A failed check must never break startup: each feed is tried independently and a dead
feed only affects itself. The periodic checker thread uses a :class:`threading.Event`
for its sleep, so ``stop()`` takes effect immediately instead of waiting out the
interval.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

from core.config import Config
from core.database import Database, now_str
from core.timeline import EventType, Severity, TimelineLogger
from core.versions import is_newer_version

logger = logging.getLogger(__name__)

__all__ = ["SignatureUpdater"]

#: Feeds merged on every update, in order. The bundled-style JSON feed URL is taken
#: from config (``updater.feed_url``); the MalwareBazaar CSV is real public
#: intelligence and needs no account. A ``#``-prefixed URL is ignored, so a user can
#: disable a feed by commenting it out in config.json.
DEFAULT_FEEDS: tuple[str, ...] = (
    "https://bazaar.abuse.ch/export/csv/recent/",
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

#: How MalwareBazaar families map onto ShieldEX severities. Unknown families default
#: to High: the feed is curated malware, so nothing in it is "Low".
_FAMILY_SEVERITY: dict[str, str] = {
    "Ransom": Severity.CRITICAL,
    "NanoCore": Severity.CRITICAL,
    "Gh0stRAT": Severity.CRITICAL,
}


class SignatureUpdater:
    """Checks signature feeds and merges new signatures into the database."""

    def __init__(self, config: Config, db: Database, timeline: TimelineLogger) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_result: dict[str, Any] = {"checked_at": None, "outcome": "never checked"}

    # ------------------------------------------------------------------ public API
    @property
    def last_result(self) -> dict[str, Any]:
        """The most recent check outcome, for the settings view."""
        return dict(self._last_result)

    def update_now(self, feed_url: str | None = None) -> tuple[bool, str]:
        """Fetch and merge feeds right now. Returns ``(applied, human_message)``.

        ``feed_url`` overrides the configured feed list (used by tests with a local
        file). Never raises: any failure is reported through the returned message and
        the timeline, because a dead feed must not take the app down with it.
        """
        urls = [feed_url] if feed_url else self._feed_urls()
        started = time.monotonic()

        total_inserted = 0
        applied_feeds = 0
        failures: list[str] = []

        for url in urls:
            try:
                inserted, version = self._merge_one_feed(url)
                if inserted is None:
                    failures.append(f"{self._short_name(url)}: {version}")
                    continue
                total_inserted += inserted
                applied_feeds += 1
                self._bump_version(version)
            except Exception as exc:
                failures.append(f"{self._short_name(url)}: {exc}")
                logger.warning("Feed %s failed: %s", url, exc)

        self.db.set_setting("signature_db_last_checked", now_str())
        elapsed = time.monotonic() - started

        if applied_feeds == 0:
            message = "Update check failed: " + "; ".join(failures or ["no feeds configured"])
            self._last_result = {"checked_at": now_str(), "outcome": f"failed: {message}"}
            self.timeline.log_system(
                EventType.SIGNATURE_DB_UPDATED,
                f"Signature update check failed: {'; '.join(failures)}",
                Severity.MEDIUM,
            )
            return False, message

        if total_inserted > 0:
            message = (
                f"Applied {total_inserted:,} new signature(s) from {applied_feeds} feed(s) "
                f"in {elapsed:.1f}s"
            )
            severity = Severity.INFO
        else:
            message = f"Signatures already up to date ({applied_feeds} feed(s) checked)"
            severity = Severity.INFO
        if failures:
            message += f"  ({len(failures)} feed(s) failed)"
        self.timeline.log_system(EventType.SIGNATURE_DB_UPDATED, message, severity)
        self._last_result = {"checked_at": now_str(), "outcome": message}
        return True, message

    def start_periodic_checks(self) -> bool:
        """Start the background periodic checker. True when it is now running."""
        if not bool(self.cfg.get("updater.enabled", True)):
            return False
        if self._thread is not None and self._thread.is_alive():
            return True

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._periodic_loop, name="shieldex-updater", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop the periodic checker (immediate, thanks to the Event-based sleep)."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        self._thread = None

    # ------------------------------------------------------------------ feeds
    def _feed_urls(self) -> list[str]:
        """Configured feed list: ``updater.feed_url`` (JSON) plus any ``extra_feeds``."""
        urls: list[str] = []
        primary = str(self.cfg.get("updater.feed_url", "") or "").strip()
        if primary and not primary.startswith("#") and "example.invalid" not in primary:
            urls.append(primary)
        raw = self.cfg.get("updater.extra_feeds", None)
        if raw is None:
            urls.extend(DEFAULT_FEEDS)  # first run: sensible real-world default
        else:
            for entry in raw if isinstance(raw, list) else [raw]:
                text = str(entry).strip()
                if text and not text.startswith("#"):
                    urls.append(text)
        return urls

    def _merge_one_feed(self, url: str) -> tuple[int | None, str]:
        """Fetch, parse and merge one feed.

        Returns ``(inserted_count, version)`` on success, or ``(None, error)`` — the
        version doubling as the error message keeps the failure path allocation-free.
        """
        raw = self._fetch(url)
        if not raw:
            return None, "feed is empty or unreachable"

        if url.endswith(".csv") or "bazaar.abuse.ch" in url or url.endswith("recent/"):
            entries, version = self._parse_malwarebazaar_csv(raw)
        else:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                return None, "feed is not a JSON object"
            entries = payload.get("signatures")
            version = str(payload.get("version", "")).strip()
            if not isinstance(entries, list):
                return None, "feed has no 'signatures' list"
            if not version:
                return None, "feed has no version"

        if not entries:
            return None, "feed parsed but contained no signatures"
        inserted = self.db.add_signatures(entries)
        return inserted, version

    def _bump_version(self, version: str) -> None:
        """Record the feed's version when it supersedes the stored one."""
        if not version:
            return
        stored = self.db.get_setting("signature_db_version", "none") or "none"
        if is_newer_version(version, stored):
            self.db.set_setting("signature_db_version", version)
            self.db.set_setting("signature_db_updated_at", now_str())

    # ------------------------------------------------------------------ parsing
    @staticmethod
    def _parse_malwarebazaar_csv(raw: str) -> tuple[list[dict[str, Any]], str]:
        """Parse MalwareBazaar's recent-samples CSV into signature entries.

        Column 1 is the SHA-256, column 8 the malware family ("n/a" when untagged).
        Comment lines starting with ``#`` are skipped; the file's own "Last updated"
        stamp becomes the feed version, so the version advances every time the feed
        does instead of freezing at the first merge.
        """
        entries: list[dict[str, Any]] = []
        version = ""
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row:
                continue
            first = row[0].strip()
            if first.startswith("#"):
                match = re.search(r"Last updated:\s*([\d\- :]+) UTC", raw)
                if match:
                    version = match.group(1).strip().replace("-", ".")
                continue
            if len(row) < 2:
                continue
            file_hash = row[1].strip().strip('"')
            if not _SHA256_RE.match(file_hash):
                continue
            family = row[8].strip().strip('"') if len(row) > 8 else "n/a"
            name = f"MalwareBazaar.{family}" if family and family != "n/a" else "MalwareBazaar.Untagged"
            severity = _FAMILY_SEVERITY.get(family, Severity.HIGH)
            entries.append(
                {"hash": file_hash, "name": name, "severity": severity, "source": "MalwareBazaar"}
            )
        if not version:
            version = time.strftime("%Y.%m.%d")
        return entries, version

    # ------------------------------------------------------------------ transport
    def _fetch(self, url: str) -> str | None:
        """Retrieve a feed over HTTP(S) or from a local path."""
        if url.lower().startswith(("http://", "https://")):
            return self._fetch_http(url)
        return self._fetch_local(url)

    def _fetch_http(self, url: str) -> str | None:
        """Download the feed over HTTP(S), honouring the configured timeout."""
        import requests

        timeout = float(self.cfg.get("updater.timeout_seconds", 15))
        verify_tls = bool(self.cfg.get("updater.verify_tls", True))
        response = requests.get(url, timeout=timeout, verify=verify_tls)
        response.raise_for_status()
        return response.text

    def _fetch_local(self, url: str) -> str | None:
        """Read the feed from a local path (``file://`` URL or plain filesystem path)."""
        from urllib.parse import unquote, urlparse

        parsed = urlparse(url)
        path = Path(unquote(parsed.path) if parsed.scheme == "file" else url)
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")

    # ------------------------------------------------------------------ internals
    def _periodic_loop(self) -> None:
        """Sleep on the stop Event so ``stop()`` wakes us immediately."""
        interval = max(1.0, float(self.cfg.get("updater.check_interval_hours", 24)) * 3600)
        while not self._stop_event.wait(interval):
            try:
                self.update_now()
            except Exception:  # the loop must survive any single failure
                logger.exception("Periodic signature update failed")

    @staticmethod
    def _short_name(url: str) -> str:
        """A feed's display name: its host, or the file name for local paths."""
        if "bazaar.abuse.ch" in url:
            return "MalwareBazaar"
        try:
            from urllib.parse import urlparse

            host = urlparse(url).netloc
            if host:
                return host
        except Exception:
            pass
        return url.rsplit("/", 1)[-1] or url
