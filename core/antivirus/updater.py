"""Signature database updater — merges remote or local feeds into the local db.

The feed format is the same JSON schema as the bundled ``assets/signatures.json``::

    {"version": "2026.09.04", "signatures": [{"hash": ..., "name": ..., "severity": ...}]}

Both ``http(s)://`` and local paths (``file:///`` or a bare path) are supported, which
is what makes the updater testable: a test writes a feed to a temp directory and points
``updater.check_and_apply(feed_path)`` at it — no network, no mocking of ``requests``.

A failed check must never break startup: the feed URL ships as a placeholder
(``example.invalid``), so :meth:`update_now` treats every failure as "no update" and
returns a reason string the settings view can show. The periodic checker thread uses a
:class:`threading.Event` for its sleep, so ``stop()`` takes effect immediately instead
of waiting out the interval.
"""

from __future__ import annotations

import json
import logging
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
        """Fetch and merge a feed right now. Returns ``(applied, human_message)``.

        Never raises: any failure is reported through the returned message and the
        timeline, because a dead feed URL must not take the app down with it.
        """
        url = feed_url or str(self.cfg.get("updater.feed_url", ""))
        started = time.monotonic()
        payload, error = self._fetch_feed(url)
        self.db.set_setting("signature_db_last_checked", now_str())
        if payload is None:
            self._last_result = {
                "checked_at": now_str(),
                "outcome": f"failed: {error}",
            }
            self.timeline.log_system(
                EventType.SIGNATURE_DB_UPDATED,
                f"Signature update check failed: {error}",
                Severity.MEDIUM,
            )
            return False, f"Update check failed: {error}"

        entries = payload.get("signatures")
        version = str(payload.get("version", "")).strip()
        if not isinstance(entries, list):
            message = "feed has no 'signatures' list"
            self._record_failure(message)
            return False, f"Update check failed: {message}"
        if not version:
            message = "feed has no version"
            self._record_failure(message)
            return False, f"Update check failed: {message}"

        stored_version = self.db.get_setting("signature_db_version", "none") or "none"
        inserted = self.db.add_signatures(entries)

        if is_newer_version(version, stored_version):
            self.db.set_setting("signature_db_version", version)
            self.db.set_setting("signature_db_updated_at", now_str())
        else:
            logger.debug(
                "Feed version %r does not supersede stored %r; version untouched",
                version, stored_version,
            )

        elapsed = time.monotonic() - started
        if inserted > 0:
            message = f"Applied {inserted} new signature(s) (feed {version}) in {elapsed:.1f}s"
            self.timeline.log_system(
                EventType.SIGNATURE_DB_UPDATED, message, Severity.INFO
            )
        else:
            message = f"Signatures already up to date (feed {version})"
            self.timeline.log_system(
                EventType.SIGNATURE_DB_UPDATED, message, Severity.INFO
            )
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

    # ------------------------------------------------------------------ internals
    def _periodic_loop(self) -> None:
        """Sleep on the stop Event so ``stop()`` wakes us immediately."""
        interval = max(1.0, float(self.cfg.get("updater.check_interval_hours", 24)) * 3600)
        while not self._stop_event.wait(interval):
            try:
                self.update_now()
            except Exception:  # the loop must survive any single failure
                logger.exception("Periodic signature update failed")

    def _fetch_feed(self, url: str) -> tuple[dict[str, Any] | None, str]:
        """Retrieve and parse the feed. Returns ``(payload, None)`` or ``(None, error)``."""
        if not url:
            return None, "no feed URL configured"
        try:
            if url.lower().startswith(("http://", "https://")):
                raw = self._fetch_http(url)
            else:
                raw = self._fetch_local(url)
            if raw is None:
                return None, "feed is empty"
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                return None, "feed is not a JSON object"
            return payload, ""
        except Exception as exc:
            return None, str(exc)

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

    def _record_failure(self, message: str) -> None:
        self._last_result = {"checked_at": now_str(), "outcome": f"failed: {message}"}
        self.timeline.log_system(
            EventType.SIGNATURE_DB_UPDATED,
            f"Signature update check failed: {message}",
            Severity.MEDIUM,
        )
