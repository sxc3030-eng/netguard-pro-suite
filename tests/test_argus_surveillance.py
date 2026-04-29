# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_surveillance V1.

Every test redirects the surveillance root into ``tmp_path`` via the
``ARGUS_SURVEILLANCE_ROOT`` env var, and reloads the module to wipe the
process-wide writer thread / queue / key state between tests.

No real secrets appear in this file — placeholders only. All "tokens" /
"passwords" are obviously-fake test fixtures used solely to exercise the
redaction regex.
"""

from __future__ import annotations

import importlib
import json
import struct
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_surveillance  # noqa: E402


# A short flush wait used by tests that need the writer to drain.
# Slightly larger than FLUSH_INTERVAL_SECONDS to give a comfortable margin
# without making the suite slow.
FLUSH_WAIT = 0.3


@pytest.fixture(autouse=True)
def _isolated_root(tmp_path, monkeypatch):
    """Redirect storage and reset module state per test."""
    monkeypatch.setenv("ARGUS_SURVEILLANCE_ROOT", str(tmp_path))
    # Vault path also redirected so vault_get/vault_set lands in tmp.
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))

    # Make flush snappy so tests don't wait 5s.
    monkeypatch.setattr(
        argus_surveillance, "FLUSH_INTERVAL_SECONDS", 0.1, raising=True
    )

    # Force fresh module-level state. We can't simply reload because
    # atexit handlers from previous reloads stay registered; instead,
    # rebuild the _State container in place.
    if argus_surveillance._STATE.initialized:
        argus_surveillance._shutdown()
    argus_surveillance._STATE = argus_surveillance._State()

    yield tmp_path

    # Tear down the writer thread before the next test redirects paths.
    if argus_surveillance._STATE.initialized:
        argus_surveillance._shutdown()


def _wait_for_flush(extra: float = 0.0) -> None:
    """Sleep just over one flush interval (test-shrunk to 0.1s)."""
    time.sleep(argus_surveillance.FLUSH_INTERVAL_SECONDS + 0.05 + extra)


# --------------------------------------------------------------------------- #
# Init / paths
# --------------------------------------------------------------------------- #


def test_init_creates_dirs(tmp_path):
    surveillance_dir = tmp_path / "surveillance"
    assert not surveillance_dir.exists()

    argus_surveillance.surveil_init()

    assert surveillance_dir.exists() and surveillance_dir.is_dir()
    assert argus_surveillance._STATE.initialized is True
    assert argus_surveillance._STATE.key is not None
    assert len(argus_surveillance._STATE.key) == argus_surveillance.KEY_BYTES


def test_init_rejects_zero_retention():
    with pytest.raises(ValueError):
        argus_surveillance.surveil_init(retention_days=0)


def test_init_is_idempotent():
    argus_surveillance.surveil_init()
    first_thread = argus_surveillance._STATE.thread
    argus_surveillance.surveil_init()
    assert argus_surveillance._STATE.thread is first_thread


# --------------------------------------------------------------------------- #
# Log + query roundtrip
# --------------------------------------------------------------------------- #


def test_log_then_query_roundtrip():
    argus_surveillance.surveil_init()
    eid = argus_surveillance.surveil_log_event(
        "navigation", {"url": "https://example.invalid/page"}, tab_id="tab-1"
    )
    assert isinstance(eid, str) and len(eid) == 16

    events = argus_surveillance.surveil_query(limit=10)
    assert len(events) == 1
    evt = events[0]
    assert evt["event_id"] == eid
    assert evt["type"] == "navigation"
    assert evt["tab_id"] == "tab-1"
    assert evt["data"]["url"] == "https://example.invalid/page"
    assert "prev_hash" in evt
    assert "ts_iso" in evt


def test_log_event_returns_short_id():
    argus_surveillance.surveil_init()
    eid = argus_surveillance.surveil_log_event(
        "user_action", {"action": "click"}
    )
    assert len(eid) == 16
    int(eid, 16)  # must be hex


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #


def test_filter_by_event_type():
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event("navigation", {"url": "u1"})
    argus_surveillance.surveil_log_event("download", {"file": "f1"})
    argus_surveillance.surveil_log_event("tab_open", {"id": "t1"})

    nav_only = argus_surveillance.surveil_query(event_types=["navigation"])
    assert len(nav_only) == 1
    assert nav_only[0]["type"] == "navigation"

    nav_dl = argus_surveillance.surveil_query(
        event_types=["navigation", "download"]
    )
    assert {e["type"] for e in nav_dl} == {"navigation", "download"}


def test_filter_by_tab_id():
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event("navigation", {"u": 1}, tab_id="A")
    argus_surveillance.surveil_log_event("navigation", {"u": 2}, tab_id="B")
    argus_surveillance.surveil_log_event("navigation", {"u": 3}, tab_id="A")

    a_events = argus_surveillance.surveil_query(tab_id="A")
    assert len(a_events) == 2
    assert all(e["tab_id"] == "A" for e in a_events)


def test_filter_by_time_window():
    argus_surveillance.surveil_init()
    # Log a baseline event, capture timestamps around it.
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    argus_surveillance.surveil_log_event("navigation", {"u": 1})
    _wait_for_flush()
    after = datetime.now(timezone.utc) + timedelta(seconds=1)

    # since/until in window — event should be included.
    in_window = argus_surveillance.surveil_query(
        since_iso=before.isoformat(), until_iso=after.isoformat()
    )
    assert len(in_window) == 1

    # since after the event — should be excluded.
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    none = argus_surveillance.surveil_query(since_iso=future)
    assert len(none) == 0


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


def test_redaction_strips_password_field():
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event(
        "form_submit",
        {"username": "alice", "password": "PLACEHOLDER_NOT_REAL"},
    )
    events = argus_surveillance.surveil_query(limit=10)
    assert len(events) == 1
    assert events[0]["data"]["username"] == "alice"
    assert events[0]["data"]["password"] == "[REDACTED]"


def test_redaction_strips_token_field():
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event(
        "auth_attempt",
        {
            "auth_token": "fake_token_xyz",
            "API_KEY": "fake_key",
            "user": "bob",
            "nested": {"secret": "fake_secret", "ok": "visible"},
        },
    )
    events = argus_surveillance.surveil_query(limit=10)
    d = events[0]["data"]
    assert d["auth_token"] == "[REDACTED]"
    assert d["API_KEY"] == "[REDACTED]"
    assert d["user"] == "bob"
    # Nested redaction
    assert d["nested"]["secret"] == "[REDACTED]"
    assert d["nested"]["ok"] == "visible"


def test_redaction_handles_credit_card_and_cvv():
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event(
        "form_submit",
        {"credit_card": "0000-0000-0000-0000", "cvv": "000", "name": "Carol"},
    )
    events = argus_surveillance.surveil_query(limit=10)
    d = events[0]["data"]
    assert d["credit_card"] == "[REDACTED]"
    assert d["cvv"] == "[REDACTED]"
    assert d["name"] == "Carol"


# --------------------------------------------------------------------------- #
# Chain verification
# --------------------------------------------------------------------------- #


def test_chain_verify_intact_returns_true():
    argus_surveillance.surveil_init()
    for i in range(5):
        argus_surveillance.surveil_log_event("navigation", {"i": i})
    assert argus_surveillance.surveil_verify_chain() is True


def test_chain_verify_tampered_returns_false(tmp_path):
    argus_surveillance.surveil_init()
    for i in range(3):
        argus_surveillance.surveil_log_event("navigation", {"i": i})
    _wait_for_flush()
    # Force flush by shutting the writer down then restarting state.
    argus_surveillance._shutdown()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    events_file = tmp_path / "surveillance" / f"events_{today}.jsonl.enc"
    assert events_file.exists() and events_file.stat().st_size > 0

    # Flip a single byte well past the framing header so we hit ciphertext.
    raw = bytearray(events_file.read_bytes())
    # Skip the first 4-byte length + 12-byte nonce; flip the next byte.
    flip_idx = 4 + 12
    raw[flip_idx] ^= 0xFF
    events_file.write_bytes(bytes(raw))

    # Re-init (writer thread must come back) and verify.
    argus_surveillance._STATE = argus_surveillance._State()
    argus_surveillance.surveil_init()
    assert argus_surveillance.surveil_verify_chain() is False


def test_chain_verify_tampered_chain_file(tmp_path):
    argus_surveillance.surveil_init()
    for i in range(3):
        argus_surveillance.surveil_log_event("user_action", {"i": i})
    _wait_for_flush()
    argus_surveillance._shutdown()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    chain_file = tmp_path / "surveillance" / f"chain_{today}.hmac"
    lines = chain_file.read_text(encoding="utf-8").splitlines()
    # Mutate the last hex digest.
    lines[-1] = "deadbeef" * 8
    chain_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    argus_surveillance._STATE = argus_surveillance._State()
    argus_surveillance.surveil_init()
    assert argus_surveillance.surveil_verify_chain() is False


def test_chain_verify_empty_date_is_intact():
    argus_surveillance.surveil_init()
    # No events logged for an arbitrary date — verifier returns True.
    assert argus_surveillance.surveil_verify_chain(date="1999-01-01") is True


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #


def test_retention_prunes_old_files(tmp_path):
    surveillance_dir = tmp_path / "surveillance"
    surveillance_dir.mkdir(parents=True, exist_ok=True)

    old_date = (
        datetime.now(timezone.utc).date() - timedelta(days=30)
    ).strftime("%Y-%m-%d")
    young_date = (
        datetime.now(timezone.utc).date() - timedelta(days=2)
    ).strftime("%Y-%m-%d")

    old_events = surveillance_dir / f"events_{old_date}.jsonl.enc"
    old_chain = surveillance_dir / f"chain_{old_date}.hmac"
    young_events = surveillance_dir / f"events_{young_date}.jsonl.enc"
    young_chain = surveillance_dir / f"chain_{young_date}.hmac"
    for p in (old_events, old_chain, young_events, young_chain):
        p.write_bytes(b"x")

    argus_surveillance.surveil_init(retention_days=7)

    assert not old_events.exists()
    assert not old_chain.exists()
    assert young_events.exists()
    assert young_chain.exists()


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


def test_stats_returns_counts():
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event("navigation", {"u": 1})
    argus_surveillance.surveil_log_event("navigation", {"u": 2})
    argus_surveillance.surveil_log_event("download", {"f": "x"})

    stats = argus_surveillance.surveil_stats()
    assert stats["total_events"] == 3
    assert stats["by_type"]["navigation"] == 2
    assert stats["by_type"]["download"] == 1
    assert stats["disk_bytes"] > 0
    assert stats["oldest_iso"] is not None
    assert stats["newest_iso"] is not None
    # Newest is at least as recent as oldest.
    assert stats["newest_iso"] >= stats["oldest_iso"]


def test_stats_empty():
    argus_surveillance.surveil_init()
    stats = argus_surveillance.surveil_stats()
    assert stats["total_events"] == 0
    assert stats["by_type"] == {}
    assert stats["oldest_iso"] is None
    assert stats["newest_iso"] is None


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #


def test_export_jsonl_roundtrip(tmp_path):
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event(
        "navigation", {"url": "https://example.invalid"}, tab_id="t1"
    )
    argus_surveillance.surveil_log_event(
        "tab_open", {"id": "t1"}, tab_id="t1"
    )

    out = argus_surveillance.surveil_export(fmt="jsonl")
    assert out.exists()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert {p["type"] for p in parsed} == {"navigation", "tab_open"}


def test_export_csv_has_header(tmp_path):
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event("user_action", {"k": "v"})
    out = argus_surveillance.surveil_export(fmt="csv")
    text = out.read_text(encoding="utf-8")
    assert text.startswith("event_id,type,ts_iso,tab_id,data,prev_hash")


def test_export_html_has_table(tmp_path):
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event("navigation", {"u": "x"})
    out = argus_surveillance.surveil_export(fmt="html")
    body = out.read_text(encoding="utf-8")
    assert "<table>" in body and "</table>" in body
    assert "navigation" in body


def test_export_rejects_bad_format():
    argus_surveillance.surveil_init()
    with pytest.raises(ValueError):
        argus_surveillance.surveil_export(fmt="xml")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Atexit / shutdown flush
# --------------------------------------------------------------------------- #


def test_atexit_flushes_buffer(tmp_path):
    argus_surveillance.surveil_init()
    argus_surveillance.surveil_log_event("navigation", {"u": 1})
    argus_surveillance.surveil_log_event("navigation", {"u": 2})

    # Don't wait for the timer — just shut down. Pending events must
    # have been flushed by the sentinel path.
    argus_surveillance._shutdown()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    events_file = tmp_path / "surveillance" / f"events_{today}.jsonl.enc"
    assert events_file.exists()
    assert events_file.stat().st_size > 0


# --------------------------------------------------------------------------- #
# Limits / validation
# --------------------------------------------------------------------------- #


def test_invalid_event_type_raises():
    argus_surveillance.surveil_init()
    with pytest.raises(ValueError):
        argus_surveillance.surveil_log_event(
            "totally_made_up_type",  # type: ignore[arg-type]
            {"k": "v"},
        )


def test_invalid_data_type_raises():
    argus_surveillance.surveil_init()
    with pytest.raises(TypeError):
        argus_surveillance.surveil_log_event(
            "navigation", "not-a-dict"  # type: ignore[arg-type]
        )


def test_query_limit_caps_results():
    argus_surveillance.surveil_init()
    for i in range(20):
        argus_surveillance.surveil_log_event("navigation", {"i": i})

    capped = argus_surveillance.surveil_query(limit=5)
    assert len(capped) == 5
