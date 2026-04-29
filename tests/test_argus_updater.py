# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_updater.

Strategy
--------
* Every test redirects ``argus_data/`` into ``tmp_path`` via the
  ``ARGUS_UPDATER_DATA_DIR`` env var, then reloads the module so paths
  are recomputed.
* ``urllib.request.urlopen`` is mocked — no real network in unit tests.
* ARGUS_VERSION is patched per-test rather than mutating the module
  permanently, so a 'newer' or 'same' release can be simulated without
  bumping the real version constant.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_updater  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolated_data(tmp_path, monkeypatch):
    """Redirect every disk write into tmp_path."""
    monkeypatch.setenv("ARGUS_UPDATER_DATA_DIR", str(tmp_path))
    # Reload so module-level path helpers (if any) re-read the env var.
    importlib.reload(argus_updater)
    yield tmp_path


def _fake_release(
    tag: str = "v3.0.1",
    sha: str | None = None,
    body: str | None = None,
    asset_name: str = "Argus-3.0.1-setup.exe",
) -> dict:
    body = body if body is not None else (
        f"## What's new\n* a thing\n\nSHA256: {sha}\n" if sha else "Notes."
    )
    return {
        "tag_name": tag,
        "name": tag,
        "published_at": "2026-04-28T12:00:00Z",
        "body": body,
        "assets": [
            {
                "name": asset_name,
                "browser_download_url": (
                    "https://github.com/sxc3030-eng/netguard-pro-suite/"
                    f"releases/download/{tag}/{asset_name}"
                ),
            }
        ],
    }


class _FakeResp:
    """Minimal context-manager response stand-in for urlopen."""

    def __init__(self, payload: bytes):
        self._buf = io.BytesIO(payload)

    def read(self, *_args, **_kwargs):
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(payload: dict):
    raw = json.dumps(payload).encode("utf-8")

    def _opener(_req, timeout=None):  # noqa: ARG001
        return _FakeResp(raw)

    return _opener


# ─────────────────────────────────────────────────────────────────────────────
# check_for_update
# ─────────────────────────────────────────────────────────────────────────────


def test_check_returns_update_info_when_newer(monkeypatch):
    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.0.0")
    payload = _fake_release(tag="v3.0.1", sha="a" * 64)

    with patch.object(
        argus_updater.urllib.request, "urlopen", _fake_urlopen(payload)
    ):
        info = argus_updater.check_for_update(timeout_s=1.0, cooldown_s=0)

    assert info is not None
    assert info.version == "3.0.1"
    assert info.published_at == "2026-04-28T12:00:00Z"
    assert info.sha256 == "a" * 64
    assert info.download_url.endswith("Argus-3.0.1-setup.exe")
    assert "What's new" in info.changelog


def test_check_returns_none_when_current(monkeypatch):
    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.0.1")
    payload = _fake_release(tag="v3.0.1")

    with patch.object(
        argus_updater.urllib.request, "urlopen", _fake_urlopen(payload)
    ):
        info = argus_updater.check_for_update(timeout_s=1.0, cooldown_s=0)

    assert info is None


def test_check_returns_none_when_remote_older(monkeypatch):
    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.5.0")
    payload = _fake_release(tag="v3.0.1")

    with patch.object(
        argus_updater.urllib.request, "urlopen", _fake_urlopen(payload)
    ):
        info = argus_updater.check_for_update(timeout_s=1.0, cooldown_s=0)

    assert info is None


def test_check_returns_none_on_timeout(monkeypatch):
    def _raises(*_a, **_kw):
        raise TimeoutError("simulated timeout")

    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.0.0")
    with patch.object(argus_updater.urllib.request, "urlopen", _raises):
        info = argus_updater.check_for_update(timeout_s=0.1, cooldown_s=0)

    assert info is None


def test_check_returns_none_on_url_error(monkeypatch):
    import urllib.error

    def _raises(*_a, **_kw):
        raise urllib.error.URLError("dns failure")

    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.0.0")
    with patch.object(argus_updater.urllib.request, "urlopen", _raises):
        info = argus_updater.check_for_update(timeout_s=0.1, cooldown_s=0)

    assert info is None


def test_check_respects_cooldown(monkeypatch):
    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.0.0")
    payload = _fake_release(tag="v3.0.1", sha="b" * 64)
    calls = {"n": 0}

    def _counted(*_a, **_kw):
        calls["n"] += 1
        return _FakeResp(json.dumps(payload).encode("utf-8"))

    with patch.object(argus_updater.urllib.request, "urlopen", _counted):
        first = argus_updater.check_for_update(timeout_s=1.0, cooldown_s=3600)
        second = argus_updater.check_for_update(timeout_s=1.0, cooldown_s=3600)

    assert first is not None and second is not None
    # Second call must be served from cache, not a second HTTP call.
    assert calls["n"] == 1
    assert second.version == first.version


def test_check_disabled_returns_none(monkeypatch):
    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.0.0")
    argus_updater.set_check_enabled(False)

    payload = _fake_release(tag="v3.0.1")
    calls = {"n": 0}

    def _counted(*_a, **_kw):
        calls["n"] += 1
        return _FakeResp(json.dumps(payload).encode("utf-8"))

    with patch.object(argus_updater.urllib.request, "urlopen", _counted):
        info = argus_updater.check_for_update(timeout_s=1.0, cooldown_s=0)

    assert info is None
    assert calls["n"] == 0  # never even hit the network


# ─────────────────────────────────────────────────────────────────────────────
# Settings persistence
# ─────────────────────────────────────────────────────────────────────────────


def test_set_check_enabled_persists():
    assert argus_updater.is_check_enabled() is True  # default
    argus_updater.set_check_enabled(False)
    assert argus_updater.is_check_enabled() is False
    argus_updater.set_check_enabled(True)
    assert argus_updater.is_check_enabled() is True


def test_settings_default_is_enabled_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_UPDATER_DATA_DIR", str(tmp_path / "fresh"))
    importlib.reload(argus_updater)
    assert argus_updater.is_check_enabled() is True


# ─────────────────────────────────────────────────────────────────────────────
# Download + verify
# ─────────────────────────────────────────────────────────────────────────────


def _staged_download(monkeypatch, payload_bytes: bytes):
    """Replace urlopen so download_update reads ``payload_bytes`` instead."""

    def _open(_req, timeout=None):  # noqa: ARG001
        return _FakeResp(payload_bytes)

    monkeypatch.setattr(argus_updater.urllib.request, "urlopen", _open)


def test_download_verifies_sha256(monkeypatch, tmp_path):
    body = b"fake installer payload"
    digest = hashlib.sha256(body).hexdigest()
    info = argus_updater.UpdateInfo(
        version="3.0.1",
        published_at="2026-04-28T12:00:00Z",
        changelog="—",
        download_url="https://example.invalid/Argus-3.0.1-setup.exe",
        sha256=digest,
    )
    _staged_download(monkeypatch, body)

    out = argus_updater.download_update(info, dest_dir=tmp_path)
    assert out.exists()
    assert out.read_bytes() == body
    assert argus_updater.verify_update(out, digest) is True


def test_download_rejects_bad_sha256(monkeypatch, tmp_path):
    body = b"fake installer payload"
    wrong = "0" * 64
    info = argus_updater.UpdateInfo(
        version="3.0.1",
        published_at="2026-04-28T12:00:00Z",
        changelog="—",
        download_url="https://example.invalid/Argus-3.0.1-setup.exe",
        sha256=wrong,
    )
    _staged_download(monkeypatch, body)

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        argus_updater.download_update(info, dest_dir=tmp_path)
    # Partial file must have been cleaned up.
    assert not any(tmp_path.iterdir())


def test_verify_update_constant_time(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello")
    real = hashlib.sha256(b"hello").hexdigest()
    assert argus_updater.verify_update(f, real) is True
    assert argus_updater.verify_update(f, "f" * 64) is False
    # Bad-length digest is rejected up front.
    assert argus_updater.verify_update(f, "short") is False


def test_download_skips_verification_when_no_sha(monkeypatch, tmp_path):
    body = b"unsigned blob"
    info = argus_updater.UpdateInfo(
        version="3.0.1",
        published_at="2026-04-28T12:00:00Z",
        changelog="—",
        download_url="https://example.invalid/Argus-3.0.1-setup.exe",
        sha256=None,
    )
    _staged_download(monkeypatch, body)

    out = argus_updater.download_update(info, dest_dir=tmp_path)
    assert out.read_bytes() == body


# ─────────────────────────────────────────────────────────────────────────────
# install_update_hint
# ─────────────────────────────────────────────────────────────────────────────


def test_install_hint_never_replaces_running_binary(tmp_path):
    fake = tmp_path / "Argus-3.0.1-setup.exe"
    fake.write_bytes(b"")
    msg = argus_updater.install_update_hint(fake)

    assert isinstance(msg, str)
    assert "Quittez" in msg or "Quit" in msg
    assert str(fake) in msg
    # The hint MUST NOT spawn anything — it's a string, that's all.
    assert "JAMAIS" in msg or "never" in msg.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Helper: version comparison
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "remote, local, expected",
    [
        ("3.0.1", "3.0.0", True),
        ("v3.0.1", "3.0.0", True),
        ("3.0.0", "3.0.0", False),
        ("3.0.0-beta", "3.0.0", False),  # pre-release < final
        ("3.0.0", "3.0.0-beta", True),
        ("3.1.0", "3.0.99", True),
        ("2.9.9", "3.0.0", False),
        ("garbage", "3.0.0", False),
    ],
)
def test_is_newer(remote, local, expected):
    assert argus_updater._is_newer(remote, local) is expected


def test_check_persists_last_check_timestamp(monkeypatch):
    monkeypatch.setattr(argus_updater, "ARGUS_VERSION", "3.0.0")
    payload = _fake_release(tag="v3.0.1", sha="c" * 64)

    with patch.object(
        argus_updater.urllib.request, "urlopen", _fake_urlopen(payload)
    ):
        argus_updater.check_for_update(timeout_s=1.0, cooldown_s=0)

    last = json.loads(argus_updater._last_check_file().read_text("utf-8"))
    assert last["result"] == "found_update"
    assert isinstance(last["ts"], (int, float))
    assert last["ts"] <= time.time() + 1
