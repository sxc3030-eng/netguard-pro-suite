# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""
Argus Surveillance V1 — encrypted forensic ring buffer with HMAC chain.

Surveillance is the second pillar of Argus (after sandbox, before Claude
arbitrage). Every meaningful event observed by Argus's web engine is logged
to a tamper-evident, encrypted forensic store.

Storage layout (under ``argus_data/surveillance/``)
---------------------------------------------------
* ``events_<YYYY-MM-DD>.jsonl.enc`` — daily file, AES-256-GCM, append-only.
  Each on-disk record is::

      <4-byte big-endian payload length><12-byte nonce><AES-GCM ciphertext+tag>

  where the ciphertext decrypts to a single JSON line ending in ``\\n``.
  Records are buffered in memory and flushed every 5 seconds OR every
  100 events OR on ``atexit``.
* ``chain_<YYYY-MM-DD>.hmac`` — HMAC-SHA256 chain. Each line is the hex
  digest of HMAC(key, prev_hash || canonical_event_bytes). The genesis
  digest for a date is HMAC(key, "GENESIS_<YYYY-MM-DD>"). The same hex
  digest is also embedded in each event under ``prev_hash`` (i.e. the
  hash of the *previous* event), making the chain double-anchored: any
  byte mutation in one file is detectable by re-computing the other.

Retention
---------
Default 7 days. ``surveil_init(retention_days=N)`` prunes anything older
than N full days on entry.

Public API (the names that other modules import)
------------------------------------------------
``surveil_init``, ``surveil_log_event``, ``surveil_query``,
``surveil_export``, ``surveil_stats``, ``surveil_verify_chain``.

Threading model
---------------
``surveil_log_event`` enqueues the event onto a bounded ``queue.Queue``
and returns immediately. A daemon writer thread drains the queue, batches
records, and flushes to disk. ``atexit`` joins the writer.

Privacy / redaction
-------------------
The ``data`` payload is walked recursively before any bytes hit the queue.
Any key matching the regex ``(?i)(password|token|secret|api[_-]?key|
credit[_-]?card|cvv)`` has its value replaced with ``"[REDACTED]"``. This
is a defence-in-depth measure — callers should still avoid handing PII to
the surveillance log in the first place.

Key management
--------------
The encryption key is a 32-byte value stored in the Argus vault under the
name ``SURVEILLANCE_KEY``. ``surveil_init`` will lazily create one if the
vault is initialised but the entry is missing. If the vault is not
initialised at all (e.g. CI / test environments without DPAPI), the module
falls back to a deterministic key derived from a stable machine identifier
and emits a single warning. That fallback is NOT suitable for production
forensic use.
"""

from __future__ import annotations

import atexit
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import platform
import queue
import re
import secrets
import struct
import threading
import time
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

KEY_BYTES = 32
NONCE_BYTES = 12
RECORD_LEN_BYTES = 4  # big-endian uint32 framing

VAULT_KEY_NAME = "SURVEILLANCE_KEY"

DEFAULT_RETENTION_DAYS = 7
FLUSH_INTERVAL_SECONDS = 5.0
FLUSH_BATCH_SIZE = 100
QUEUE_MAX = 10_000  # back-pressure: drop with a warning rather than OOM

EventType = Literal[
    "navigation",
    "download",
    "form_submit",
    "auth_attempt",
    "script_block",
    "tracker_block",
    "cert_warning",
    "user_action",
    "tab_open",
    "tab_close",
    "mode_switch",
    "arbiter_decision",
]

_VALID_EVENT_TYPES = frozenset(
    {
        "navigation",
        "download",
        "form_submit",
        "auth_attempt",
        "script_block",
        "tracker_block",
        "cert_warning",
        "user_action",
        "tab_open",
        "tab_close",
        "mode_switch",
        "arbiter_decision",
    }
)

# Redaction regex applied to dict keys (case-insensitive).
_REDACT_RE = re.compile(
    r"(?i)(password|token|secret|api[_-]?key|credit[_-]?card|cvv)"
)
_REDACTED = "[REDACTED]"

_LOG = logging.getLogger("argus.surveillance")


# --------------------------------------------------------------------------- #
# Module-level state (guarded by _STATE_LOCK)
# --------------------------------------------------------------------------- #


class _State:
    """Container for the writer thread and shared mutable state."""

    def __init__(self) -> None:
        self.key: Optional[bytes] = None
        self.queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(
            maxsize=QUEUE_MAX
        )
        self.thread: Optional[threading.Thread] = None
        self.stop_evt = threading.Event()
        # last_hash is per-date so a date rollover at midnight starts a new
        # chain anchored on its own GENESIS marker.
        self.last_hash: Dict[str, bytes] = {}
        self.initialized = False
        self.retention_days = DEFAULT_RETENTION_DAYS


_STATE = _State()
_STATE_LOCK = threading.RLock()


# --------------------------------------------------------------------------- #
# Path helpers — honour ARGUS_SURVEILLANCE_ROOT for tests
# --------------------------------------------------------------------------- #


def _surveillance_root() -> Path:
    """Resolve the surveillance directory.

    Priority:
        1. ``ARGUS_SURVEILLANCE_ROOT`` env var (test / sandbox redirect).
        2. ``ARGUS_VAULT_ROOT``/surveillance — kept in sync with the vault.
        3. ``<repo>/argus_data/surveillance``.
    """
    override = os.environ.get("ARGUS_SURVEILLANCE_ROOT")
    if override:
        return Path(override) / "surveillance"
    vault_override = os.environ.get("ARGUS_VAULT_ROOT")
    if vault_override:
        return Path(vault_override) / "surveillance"
    return Path(__file__).resolve().parent / "argus_data" / "surveillance"


def _events_path(date_str: str) -> Path:
    return _surveillance_root() / f"events_{date_str}.jsonl.enc"


def _chain_path(date_str: str) -> Path:
    return _surveillance_root() / f"chain_{date_str}.hmac"


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _genesis_input(date_str: str) -> bytes:
    return f"GENESIS_{date_str}".encode("utf-8")


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


def _redact(value: Any) -> Any:
    """Recursively redact secret-like fields inside a dict/list payload.

    Matching is by *key name* — the regex looks for password / token /
    secret / api_key / api-key / credit_card / cvv (case-insensitive).
    Values are not inspected, since arbitrary bytes are easy to false-flag.
    """
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _REDACT_RE.search(k):
                out[k] = _REDACTED
            else:
                out[k] = _redact(v)
        return out
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact(v) for v in value)
    return value


# --------------------------------------------------------------------------- #
# Key acquisition
# --------------------------------------------------------------------------- #


def _machine_id() -> str:
    """Stable-ish identifier used only for the vault-less fallback path."""
    parts = [platform.node() or "", platform.machine() or "", platform.system() or ""]
    return "|".join(parts)


def _acquire_key() -> bytes:
    """Fetch (or lazily mint) the surveillance key.

    Order of attempts:
        1. ``argus_vault.vault_get(SURVEILLANCE_KEY)`` — preferred path.
        2. If the vault is initialised but the entry is missing, generate
           a fresh 32-byte key, store it, and return it.
        3. If the vault is not initialised, derive a deterministic key
           from the machine identifier and emit a warning. Test
           environments hit this branch by design.
    """
    try:
        import argus_vault  # local import keeps this module standalone-importable
    except Exception:
        argus_vault = None  # type: ignore[assignment]

    if argus_vault is not None:
        try:
            if argus_vault.vault_exists():
                stored = argus_vault.vault_get(VAULT_KEY_NAME)
                if stored:
                    raw = bytes.fromhex(stored)
                    if len(raw) == KEY_BYTES:
                        return raw
                    # Wrong-shaped entry — overwrite it rather than crash.
                fresh = secrets.token_bytes(KEY_BYTES)
                try:
                    argus_vault.vault_set(
                        VAULT_KEY_NAME, fresh.hex(), owner="surveillance"
                    )
                    return fresh
                except Exception as exc:  # pragma: no cover - defensive
                    _LOG.warning(
                        "vault_set failed for SURVEILLANCE_KEY: %s", exc
                    )
        except Exception as exc:
            _LOG.warning("vault unavailable, falling back: %s", exc)

    # Vault-less fallback: deterministic key derived from machine id.
    # NOT cryptographically meaningful for forensic use — meant only to
    # let the module operate in CI / sandbox.
    warnings.warn(
        "argus_surveillance: vault unavailable, using machine-derived "
        "fallback key (NOT for production use)",
        RuntimeWarning,
        stacklevel=3,
    )
    derived = hashlib.sha256(
        b"argus-surveillance-fallback|" + _machine_id().encode("utf-8")
    ).digest()
    assert len(derived) == KEY_BYTES
    return derived


# --------------------------------------------------------------------------- #
# Canonical serialisation + framing
# --------------------------------------------------------------------------- #


def _canonical(event: Dict[str, Any]) -> bytes:
    """Deterministic JSON serialisation used both on disk and for HMAC."""
    return json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _encrypt_record(plaintext: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    payload = nonce + ct
    return struct.pack(">I", len(payload)) + payload


def _read_records(path: Path) -> List[bytes]:
    """Yield framed (nonce + ct) blobs from an events file.

    A truncated trailing record is dropped silently; that's the only
    write-failure mode possible (we always write fully or not at all on
    success because we use ``open(...,'ab')``). Returning a list keeps
    the call sites simple.
    """
    if not path.exists() or path.stat().st_size == 0:
        return []
    out: List[bytes] = []
    with path.open("rb") as fh:
        while True:
            header = fh.read(RECORD_LEN_BYTES)
            if not header:
                break
            if len(header) < RECORD_LEN_BYTES:
                break
            (payload_len,) = struct.unpack(">I", header)
            payload = fh.read(payload_len)
            if len(payload) < payload_len:
                break
            out.append(payload)
    return out


def _decrypt_records(records: List[bytes], key: bytes) -> List[Dict[str, Any]]:
    """Decrypt a list of framed records to event dicts. Skips broken ones."""
    aead = AESGCM(key)
    events: List[Dict[str, Any]] = []
    for blob in records:
        if len(blob) <= NONCE_BYTES:
            continue
        nonce = blob[:NONCE_BYTES]
        ct = blob[NONCE_BYTES:]
        try:
            pt = aead.decrypt(nonce, ct, None)
        except Exception:
            # Tampered / corrupted record — skip but keep the rest.
            continue
        try:
            evt = json.loads(pt.decode("utf-8"))
        except Exception:
            continue
        if isinstance(evt, dict):
            events.append(evt)
    return events


# --------------------------------------------------------------------------- #
# HMAC chain
# --------------------------------------------------------------------------- #


def _hmac(key: bytes, *parts: bytes) -> bytes:
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()


def _load_chain_tail(date_str: str, key: bytes) -> bytes:
    """Return the last hash on disk for ``date_str``, or the genesis hash."""
    path = _chain_path(date_str)
    if path.exists() and path.stat().st_size > 0:
        last_hex = ""
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last_hex = line
        if last_hex:
            try:
                return bytes.fromhex(last_hex)
            except ValueError:
                pass  # corrupt tail — fall through to genesis
    return _hmac(key, _genesis_input(date_str))


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #


def _prune_old_files(retention_days: int) -> None:
    """Delete any events_/chain_ files older than ``retention_days``."""
    root = _surveillance_root()
    if not root.exists():
        return
    cutoff = (
        datetime.now(timezone.utc).date() - timedelta(days=retention_days)
    )
    for entry in root.iterdir():
        if not entry.is_file():
            continue
        name = entry.name
        date_str: Optional[str] = None
        if name.startswith("events_") and name.endswith(".jsonl.enc"):
            date_str = name[len("events_") : -len(".jsonl.enc")]
        elif name.startswith("chain_") and name.endswith(".hmac"):
            date_str = name[len("chain_") : -len(".hmac")]
        if not date_str:
            continue
        try:
            file_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            continue
        if file_date < cutoff:
            try:
                entry.unlink()
            except OSError as exc:  # pragma: no cover
                _LOG.warning("failed to prune %s: %s", entry, exc)


# --------------------------------------------------------------------------- #
# Writer thread
# --------------------------------------------------------------------------- #


def _writer_loop() -> None:
    """Drain the queue, batch encrypt, append to disk."""
    pending: List[Dict[str, Any]] = []
    last_flush = time.monotonic()
    while True:
        timeout = max(0.0, FLUSH_INTERVAL_SECONDS - (time.monotonic() - last_flush))
        try:
            item = _STATE.queue.get(timeout=timeout)
        except queue.Empty:
            item = None  # treat as flush tick

        if item is not None:
            if item.get("__sentinel__"):
                # Final flush requested by shutdown.
                if pending:
                    _flush_batch(pending)
                    pending = []
                return
            pending.append(item)

        if pending and (
            len(pending) >= FLUSH_BATCH_SIZE
            or (time.monotonic() - last_flush) >= FLUSH_INTERVAL_SECONDS
        ):
            _flush_batch(pending)
            pending = []
            last_flush = time.monotonic()

        if _STATE.stop_evt.is_set() and _STATE.queue.empty():
            if pending:
                _flush_batch(pending)
            return


def _flush_batch(events: List[Dict[str, Any]]) -> None:
    """Append a batch of events to today's encrypted file + chain."""
    if not events:
        return
    with _STATE_LOCK:
        key = _STATE.key
        if key is None:
            return  # not initialised — drop the batch silently

        root = _surveillance_root()
        root.mkdir(parents=True, exist_ok=True)

        # Group by date (UTC). Almost always a single bucket, but a
        # midnight-rollover could span two.
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for evt in events:
            date_str = evt.get("__date__") or _today_str()
            buckets.setdefault(date_str, []).append(evt)

        for date_str, bucket in buckets.items():
            events_file = _events_path(date_str)
            chain_file = _chain_path(date_str)

            if date_str not in _STATE.last_hash:
                _STATE.last_hash[date_str] = _load_chain_tail(date_str, key)
            prev = _STATE.last_hash[date_str]

            with events_file.open("ab") as ef, chain_file.open(
                "a", encoding="utf-8"
            ) as cf:
                for evt in bucket:
                    evt.pop("__date__", None)
                    # Stamp prev_hash *before* serialising so the on-disk
                    # event includes its predecessor's digest.
                    evt["prev_hash"] = prev.hex()
                    canon = _canonical(evt)
                    ef.write(_encrypt_record(canon, key))
                    digest = _hmac(key, prev, canon)
                    cf.write(digest.hex() + "\n")
                    prev = digest

            _STATE.last_hash[date_str] = prev


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def surveil_init(retention_days: int = DEFAULT_RETENTION_DAYS) -> None:
    """Bootstrap surveillance: derive the key, prune old files, start writer.

    Idempotent — calling this multiple times is safe; later calls only
    update ``retention_days`` and re-run pruning.
    """
    if not isinstance(retention_days, int) or retention_days < 1:
        raise ValueError("retention_days must be a positive int")

    with _STATE_LOCK:
        _STATE.retention_days = retention_days
        _surveillance_root().mkdir(parents=True, exist_ok=True)
        _prune_old_files(retention_days)

        if _STATE.initialized and _STATE.thread and _STATE.thread.is_alive():
            return

        _STATE.key = _acquire_key()
        _STATE.last_hash.clear()
        _STATE.stop_evt.clear()
        # Drain any queued items from a previous (now-stopped) run.
        try:
            while True:
                _STATE.queue.get_nowait()
        except queue.Empty:
            pass

        thread = threading.Thread(
            target=_writer_loop, name="argus-surveillance", daemon=True
        )
        thread.start()
        _STATE.thread = thread
        _STATE.initialized = True

    atexit.register(_shutdown)


def _shutdown() -> None:
    """Send a sentinel to the writer and join it. Safe to call repeatedly."""
    with _STATE_LOCK:
        if not _STATE.initialized:
            return
        _STATE.stop_evt.set()
        try:
            _STATE.queue.put_nowait({"__sentinel__": True})
        except queue.Full:  # pragma: no cover - extremely unlikely
            pass
        thread = _STATE.thread
    if thread is not None:
        thread.join(timeout=5.0)
    with _STATE_LOCK:
        _STATE.initialized = False
        _STATE.thread = None


def surveil_log_event(
    event_type: EventType,
    data: dict,
    tab_id: Optional[str] = None,
) -> str:
    """Enqueue an event for encrypted append. Returns the event id (hex).

    Non-blocking: the actual encryption / write happens on the writer
    thread. If the queue is full (unlikely under realistic load) the
    event is dropped with a warning rather than blocking the caller.
    """
    if event_type not in _VALID_EVENT_TYPES:
        raise ValueError(f"unknown event_type: {event_type!r}")
    if not isinstance(data, dict):
        raise TypeError("data must be a dict")

    if not _STATE.initialized:
        surveil_init()

    safe_data = _redact(data)
    ts = datetime.now(timezone.utc)
    ts_iso = ts.isoformat()

    # Event id: first 16 hex chars of sha256(type || ts_iso || canonical_data || nonce).
    nonce_seed = secrets.token_bytes(8)
    digest_src = b"|".join(
        [
            event_type.encode("utf-8"),
            ts_iso.encode("utf-8"),
            _canonical({"data": safe_data, "tab_id": tab_id}),
            nonce_seed,
        ]
    )
    event_id = hashlib.sha256(digest_src).hexdigest()[:16]

    event = {
        "event_id": event_id,
        "type": event_type,
        "ts_iso": ts_iso,
        "tab_id": tab_id,
        "data": safe_data,
        "__date__": ts.strftime("%Y-%m-%d"),
    }

    try:
        _STATE.queue.put_nowait(event)
    except queue.Full:
        _LOG.warning("surveillance queue full, dropping event %s", event_id)
    return event_id


def _flush_now() -> None:
    """Block until the queue is drained — used by query/export/stats."""
    if not _STATE.initialized:
        return
    # Wait for queue to empty.
    while not _STATE.queue.empty():
        time.sleep(0.01)
    # Then nudge writer to flush its in-memory pending list. We do this
    # by injecting a no-op marker that forces the loop to evaluate the
    # batch-flush condition on the next iteration. Simpler: just wait
    # for one full FLUSH_INTERVAL.
    time.sleep(FLUSH_INTERVAL_SECONDS + 0.05)


def _list_dates_on_disk() -> List[str]:
    root = _surveillance_root()
    if not root.exists():
        return []
    dates: List[str] = []
    for entry in root.iterdir():
        if entry.is_file() and entry.name.startswith("events_") and entry.name.endswith(
            ".jsonl.enc"
        ):
            date_str = entry.name[len("events_") : -len(".jsonl.enc")]
            try:
                datetime.strptime(date_str, "%Y-%m-%d")
            except ValueError:
                continue
            dates.append(date_str)
    return sorted(dates)


def _all_events() -> List[Dict[str, Any]]:
    """Decrypt every event currently on disk, ordered chronologically."""
    if _STATE.key is None:
        return []
    out: List[Dict[str, Any]] = []
    for date_str in _list_dates_on_disk():
        records = _read_records(_events_path(date_str))
        out.extend(_decrypt_records(records, _STATE.key))
    return out


def surveil_query(
    event_types: Optional[List[EventType]] = None,
    tab_id: Optional[str] = None,
    since_iso: Optional[str] = None,
    until_iso: Optional[str] = None,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """Decrypt + filter events. Newest filters applied in order.

    Filters
    -------
    * ``event_types`` — keep events whose ``type`` is in this list.
    * ``tab_id`` — keep events whose ``tab_id`` matches exactly.
    * ``since_iso`` / ``until_iso`` — ISO-8601 inclusive range.
    * ``limit`` — return at most this many events (most recent first
      after sorting by ``ts_iso``).
    """
    if not _STATE.initialized:
        surveil_init()
    _flush_now()

    types_set = set(event_types) if event_types else None
    since_dt = _parse_iso(since_iso) if since_iso else None
    until_dt = _parse_iso(until_iso) if until_iso else None

    out: List[Dict[str, Any]] = []
    for evt in _all_events():
        if types_set is not None and evt.get("type") not in types_set:
            continue
        if tab_id is not None and evt.get("tab_id") != tab_id:
            continue
        if since_dt or until_dt:
            evt_ts = _parse_iso(evt.get("ts_iso", ""))
            if evt_ts is None:
                continue
            if since_dt and evt_ts < since_dt:
                continue
            if until_dt and evt_ts > until_dt:
                continue
        out.append(evt)

    out.sort(key=lambda e: e.get("ts_iso", ""), reverse=True)
    if limit and len(out) > limit:
        out = out[:limit]
    # Restore chronological ascending order in returned slice.
    out.sort(key=lambda e: e.get("ts_iso", ""))
    return out


def _parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        # Python <3.11 needed Z-replacement; 3.11+ handles Z directly,
        # but we keep the fallback for safety.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def surveil_export(
    fmt: Literal["jsonl", "csv", "html"] = "jsonl",
    out_path: Optional[Path] = None,
) -> Path:
    """Decrypt the entire retention window and write it to disk."""
    if fmt not in ("jsonl", "csv", "html"):
        raise ValueError(f"unsupported fmt: {fmt!r}")
    if not _STATE.initialized:
        surveil_init()
    _flush_now()

    events = _all_events()
    events.sort(key=lambda e: e.get("ts_iso", ""))

    if out_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = _surveillance_root() / f"export_{ts}.{fmt}"
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "jsonl":
        with out_path.open("w", encoding="utf-8") as fh:
            for evt in events:
                fh.write(json.dumps(evt, ensure_ascii=False) + "\n")
    elif fmt == "csv":
        # Flatten ``data`` to a JSON string for the CSV cell.
        with out_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["event_id", "type", "ts_iso", "tab_id", "data", "prev_hash"])
            for evt in events:
                writer.writerow(
                    [
                        evt.get("event_id", ""),
                        evt.get("type", ""),
                        evt.get("ts_iso", ""),
                        evt.get("tab_id", "") or "",
                        json.dumps(evt.get("data", {}), ensure_ascii=False),
                        evt.get("prev_hash", ""),
                    ]
                )
    else:  # html
        rows_html = io.StringIO()
        for evt in events:
            rows_html.write(
                "<tr>"
                f"<td>{_html_escape(evt.get('ts_iso', ''))}</td>"
                f"<td>{_html_escape(evt.get('type', ''))}</td>"
                f"<td>{_html_escape(evt.get('tab_id', '') or '')}</td>"
                f"<td>{_html_escape(evt.get('event_id', ''))}</td>"
                f"<td><pre>{_html_escape(json.dumps(evt.get('data', {}), indent=2))}</pre></td>"
                "</tr>"
            )
        body = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>Argus surveillance export</title>"
            "<style>body{font-family:monospace;font-size:12px;}"
            "table{border-collapse:collapse;width:100%;}"
            "th,td{border:1px solid #888;padding:4px;vertical-align:top;}"
            "</style></head><body>"
            f"<h1>Argus surveillance export ({len(events)} events)</h1>"
            "<table><tr><th>ts_iso</th><th>type</th><th>tab_id</th>"
            "<th>event_id</th><th>data</th></tr>"
            f"{rows_html.getvalue()}</table></body></html>"
        )
        out_path.write_text(body, encoding="utf-8")

    return out_path


def _html_escape(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def surveil_stats() -> Dict[str, Any]:
    """Return aggregate counts across the entire retention window."""
    if not _STATE.initialized:
        surveil_init()
    _flush_now()

    events = _all_events()
    by_type: Dict[str, int] = {}
    oldest = ""
    newest = ""
    for evt in events:
        t = str(evt.get("type", "unknown"))
        by_type[t] = by_type.get(t, 0) + 1
        ts = evt.get("ts_iso", "")
        if ts:
            if not oldest or ts < oldest:
                oldest = ts
            if not newest or ts > newest:
                newest = ts

    disk_bytes = 0
    root = _surveillance_root()
    if root.exists():
        for entry in root.iterdir():
            if entry.is_file():
                try:
                    disk_bytes += entry.stat().st_size
                except OSError:  # pragma: no cover
                    pass

    return {
        "total_events": len(events),
        "oldest_iso": oldest or None,
        "newest_iso": newest or None,
        "by_type": by_type,
        "disk_bytes": disk_bytes,
    }


def surveil_verify_chain(date: Optional[str] = None) -> bool:
    """Recompute the HMAC chain for ``date`` (default today). True if intact."""
    if not _STATE.initialized:
        surveil_init()
    _flush_now()

    if _STATE.key is None:
        return False
    date_str = date or _today_str()

    events_file = _events_path(date_str)
    chain_file = _chain_path(date_str)
    if not events_file.exists() and not chain_file.exists():
        # Nothing to verify is trivially "intact".
        return True
    if not events_file.exists() or not chain_file.exists():
        return False

    records = _read_records(events_file)
    events = _decrypt_records(records, _STATE.key)

    expected_chain: List[str] = []
    prev = _hmac(_STATE.key, _genesis_input(date_str))
    for evt in events:
        canon = _canonical(evt)
        prev = _hmac(_STATE.key, prev, canon)
        expected_chain.append(prev.hex())

    with chain_file.open("r", encoding="utf-8") as fh:
        on_disk = [line.strip() for line in fh if line.strip()]

    if len(expected_chain) != len(on_disk):
        return False
    for a, b in zip(expected_chain, on_disk):
        if not hmac.compare_digest(a, b):
            return False

    # Cross-check: each event's embedded prev_hash must equal the chain
    # entry one step back. Genesis case: the first event's prev_hash is
    # the genesis digest itself.
    genesis_hex = _hmac(_STATE.key, _genesis_input(date_str)).hex()
    for i, evt in enumerate(events):
        embedded = evt.get("prev_hash", "")
        expected_prev = genesis_hex if i == 0 else on_disk[i - 1]
        if not hmac.compare_digest(str(embedded), expected_prev):
            return False
    return True
