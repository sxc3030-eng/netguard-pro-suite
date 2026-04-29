# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_arbiter.

The Anthropic API is mocked at the ``_http_post`` seam in argus_arbiter
-- no real network calls and no real key are involved. The test API key
``"sk-ant-test-fake"`` is a placeholder; it is set via env var so the
``_resolve_api_key`` path returns truthy without hitting the vault.
"""

from __future__ import annotations

import importlib
import json
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

# Make sibling argus_arbiter.py importable.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_arbiter  # noqa: E402

FAKE_API_KEY = "sk-ant-test-fake"


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #


def _make_claude_response(verdict: str, reason: str = "ok",
                          confidence: float = 0.9) -> bytes:
    """Build a realistic Claude messages-API response body."""
    body = {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-haiku-4-5-20251001",
        "content": [{
            "type": "text",
            "text": json.dumps({
                "verdict": verdict,
                "reason": reason,
                "confidence": confidence,
            }),
        }],
    }
    return json.dumps(body).encode("utf-8")


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    """Reload argus_arbiter so cache + counters reset between tests.

    Plus set the placeholder API key into env so the BYOK fallback
    isn't triggered unless the test explicitly clears it.

    We also stub ``_surveil_log`` to a no-op: importing
    ``argus_surveillance`` triggers its module-level ``surveil_init()``
    which writes to the filesystem and would pollute test-ordering
    expectations of other test files. The surveillance hook itself is
    covered by argus_surveillance's own test suite.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_API_KEY)
    # Stop config.get_secret from peeking at a real vault.
    monkeypatch.setenv("ARGUS_VAULT_ROOT", "/tmp/arbiter-tests-fake-vault")
    importlib.reload(argus_arbiter)
    monkeypatch.setattr(argus_arbiter, "_surveil_log", lambda *_a, **_k: None)
    argus_arbiter.arbiter_init("balanced")
    yield


# --------------------------------------------------------------------------- #
# init / threshold
# --------------------------------------------------------------------------- #


def test_init_loads_threshold():
    argus_arbiter.arbiter_init("strict")
    assert argus_arbiter._S.threshold_name == "strict"
    assert argus_arbiter._S.threshold_value == 0.35


def test_init_rejects_unknown_threshold():
    with pytest.raises(ValueError):
        argus_arbiter.arbiter_init("ridiculous")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Heuristic-only fast paths
# --------------------------------------------------------------------------- #


def test_low_risk_auto_allow_no_claude_call():
    """A vanilla navigation to a well-known domain: never asks Claude."""
    with patch.object(argus_arbiter, "_http_post") as mocked:
        decision = argus_arbiter.arbiter_decide(
            "navigation",
            {"url": "https://github.com/anthropics"},
        )

    assert decision.verdict == "allow"
    assert decision.used_claude is False
    assert decision.cached is False
    mocked.assert_not_called()


def test_executable_download_high_score():
    """Heuristic alone should already flag a typosquat .exe download."""
    score = argus_arbiter._heuristic_score(
        "download",
        {
            "url": "https://chr0me-update.example.tk/setup.exe",
            "filename": "chr0me_setup.exe",
            "size_bytes": 5000,
            "domain": "chr0me-update.example.tk",
        },
    )
    # exe (+0.3) + non-mainstream (+0.2) + typo of chrome (+0.3)
    # + tiny size (+0.2) = 1.0 (clamped).
    assert score >= 0.9


def test_password_form_https_lower_score_than_http():
    base = {
        "page_url": "example.com/login",
        "action_url": "example.com/login",
        "has_password_field": True,
    }
    insecure = argus_arbiter._heuristic_score(
        "form_submit",
        {**base, "scheme": "http"},
    )
    secure = argus_arbiter._heuristic_score(
        "form_submit",
        {**base, "scheme": "https"},
    )
    assert insecure > secure


def test_vault_mode_uses_stricter_threshold():
    """In ``mode=vault`` a balanced threshold tightens to ``strict``."""
    argus_arbiter.arbiter_init("balanced")
    # Heuristic for navigation to a generic site: roughly 0 risk in
    # normal mode -> allow without Claude. But vault mode entry adds
    # +0.5 baseline, so it should consult Claude.
    with patch.object(argus_arbiter, "_http_post") as mocked:
        mocked.return_value = (200, _make_claude_response("warn", "ok"))
        decision = argus_arbiter.arbiter_decide(
            "vault_mode_entry", {"reason": "user clicked unlock"},
            mode="vault",
        )
    assert decision.used_claude is True
    assert mocked.called


# --------------------------------------------------------------------------- #
# Claude integration -- mocked
# --------------------------------------------------------------------------- #


def test_high_risk_typosquat_calls_claude():
    """A paypa1.com login form crosses the threshold -> Claude is consulted.

    Navigation alone gets +0.4 for typosquat (below 0.6 balanced) but a
    form_submit with password over HTTP to a typosquat is +0.4 (HTTP)
    +0.5 (typo) = 0.9, well above threshold.
    """
    with patch.object(argus_arbiter, "_http_post") as mocked:
        mocked.return_value = (
            200,
            _make_claude_response("block", "Looks like a paypal typosquat"),
        )
        decision = argus_arbiter.arbiter_decide(
            "form_submit",
            {
                "page_url": "http://paypa1.com/login",
                "action_url": "http://paypa1.com/login",
                "scheme": "http",
                "has_password_field": True,
            },
        )

    assert mocked.called
    assert decision.verdict == "block"
    assert decision.used_claude is True
    assert "typosquat" in decision.reason.lower()


# Common context that crosses the balanced threshold for the
# Claude-integration tests below: vault_mode_entry has a +0.5 baseline,
# easily nudged over 0.6 in vault mode (which tightens to strict=0.35).
_RISKY_FORM_CTX = {
    "page_url": "http://paypa1.com/login",
    "action_url": "http://paypa1.com/login",
    "scheme": "http",
    "has_password_field": True,
}


def test_claude_timeout_fallback_to_heuristic():
    """A urllib timeout must yield a heuristic-only ``warn``, not crash."""
    import urllib.error

    with patch.object(argus_arbiter, "_http_post",
                      side_effect=urllib.error.URLError("timed out")):
        decision = argus_arbiter.arbiter_decide(
            "form_submit", _RISKY_FORM_CTX,
        )

    assert decision.used_claude is False
    assert decision.verdict == "warn"
    assert "verify" in decision.reason.lower() or "unreachable" in decision.reason.lower()


def test_claude_malformed_response_falls_to_warn():
    """Garbage JSON in Claude's text block -> warn, used_claude=True."""
    bad_body = json.dumps({
        "content": [{"type": "text", "text": "not JSON at all"}],
    }).encode("utf-8")

    with patch.object(argus_arbiter, "_http_post",
                      return_value=(200, bad_body)):
        decision = argus_arbiter.arbiter_decide(
            "form_submit", _RISKY_FORM_CTX,
        )

    assert decision.verdict == "warn"
    assert decision.used_claude is True
    assert "unparseable" in decision.reason.lower()


def test_claude_invalid_verdict_falls_to_warn():
    """Claude returns ``{"verdict": "obliterate"}`` -> still safe."""
    body = json.dumps({
        "content": [{"type": "text", "text": json.dumps({
            "verdict": "obliterate", "reason": "uh", "confidence": 0.5,
        })}],
    }).encode("utf-8")
    with patch.object(argus_arbiter, "_http_post",
                      return_value=(200, body)):
        decision = argus_arbiter.arbiter_decide(
            "form_submit", _RISKY_FORM_CTX,
        )
    assert decision.verdict == "warn"
    assert "invalid" in decision.reason.lower()


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


def test_cache_hit_skips_claude():
    """Two calls with the same context: only one Claude round-trip."""
    with patch.object(argus_arbiter, "_http_post") as mocked:
        mocked.return_value = (200, _make_claude_response("block", "typo"))
        first = argus_arbiter.arbiter_decide("form_submit", _RISKY_FORM_CTX)
        second = argus_arbiter.arbiter_decide("form_submit", _RISKY_FORM_CTX)

    assert mocked.call_count == 1
    assert first.cached is False
    assert second.cached is True
    assert second.verdict == first.verdict


def test_cache_expires_after_ttl(monkeypatch):
    """Past the TTL, the same context goes back to Claude."""
    fake_now = [1000.0]

    def _fake_now():
        return fake_now[0]

    monkeypatch.setattr(argus_arbiter, "_now", _fake_now)

    with patch.object(argus_arbiter, "_http_post") as mocked:
        mocked.return_value = (200, _make_claude_response("block", "typo"))
        argus_arbiter.arbiter_decide("form_submit", _RISKY_FORM_CTX)
        # Jump well past the 5-min TTL.
        fake_now[0] += argus_arbiter._CACHE_TTL_SEC + 60
        argus_arbiter.arbiter_decide("form_submit", _RISKY_FORM_CTX)

    assert mocked.call_count == 2


def test_clear_cache_returns_count():
    ctx_a = {**_RISKY_FORM_CTX, "page_url": "http://paypa1.com/a"}
    ctx_b = {
        "page_url": "http://amaz0n.com/b",
        "action_url": "http://amaz0n.com/b",
        "scheme": "http",
        "has_password_field": True,
    }
    with patch.object(argus_arbiter, "_http_post") as mocked:
        mocked.return_value = (200, _make_claude_response("block", "x"))
        argus_arbiter.arbiter_decide("form_submit", ctx_a)
        argus_arbiter.arbiter_decide("form_submit", ctx_b)

    cleared = argus_arbiter.arbiter_clear_cache()
    assert cleared == 2
    # Second clear sees an empty cache.
    assert argus_arbiter.arbiter_clear_cache() == 0


# --------------------------------------------------------------------------- #
# Async
# --------------------------------------------------------------------------- #


def test_async_decide_calls_callback():
    """Callback runs exactly once, with a Decision instance."""
    received: list[argus_arbiter.Decision] = []
    done = threading.Event()

    def cb(decision):
        received.append(decision)
        done.set()

    with patch.object(argus_arbiter, "_http_post") as mocked:
        mocked.return_value = (200, _make_claude_response("allow", "ok"))
        argus_arbiter.arbiter_decide_async(
            "navigation", {"url": "https://github.com"}, cb,
        )

    assert done.wait(timeout=5.0), "callback never fired"
    assert len(received) == 1
    assert isinstance(received[0], argus_arbiter.Decision)


# --------------------------------------------------------------------------- #
# BYOK / missing key
# --------------------------------------------------------------------------- #


def test_missing_api_key_falls_back_to_heuristic(monkeypatch):
    """No key + risky action -> warn, used_claude=False."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Also stub config.get_secret so it doesn't see a vault either.
    import config
    monkeypatch.setattr(config, "get_secret", lambda *_a, **_k: None)

    with patch.object(argus_arbiter, "_http_post") as mocked:
        decision = argus_arbiter.arbiter_decide("form_submit", _RISKY_FORM_CTX)

    mocked.assert_not_called()
    assert decision.used_claude is False
    assert decision.verdict == "warn"


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


def test_stats_tracks_decisions_and_claude_calls():
    """Stats reflect verdict mix, claude calls, and cache hit rate."""
    with patch.object(argus_arbiter, "_http_post") as mocked:
        mocked.return_value = (200, _make_claude_response("block", "x"))

        # Risky -> Claude (block)
        argus_arbiter.arbiter_decide("form_submit", _RISKY_FORM_CTX)
        # Same again -> cache hit (still counts as block in by_verdict)
        argus_arbiter.arbiter_decide("form_submit", _RISKY_FORM_CTX)
        # Safe -> heuristic allow
        argus_arbiter.arbiter_decide(
            "navigation", {"url": "https://github.com"})

    stats = argus_arbiter.arbiter_stats()
    assert stats["total_decisions"] == 3
    assert stats["by_verdict"]["block"] == 2
    assert stats["by_verdict"]["allow"] == 1
    assert stats["claude_calls"] == 1
    assert 0 < stats["cache_hit_rate"] <= 1.0


# --------------------------------------------------------------------------- #
# Heuristic edge cases (sanity checks for the score table)
# --------------------------------------------------------------------------- #


def test_navigation_well_known_domain_is_low_risk():
    score = argus_arbiter._heuristic_score(
        "navigation", {"url": "https://www.google.com/search?q=foo"},
    )
    assert score < 0.3  # well below the balanced threshold (0.6)


def test_external_link_from_email_with_typosquat_is_high():
    score = argus_arbiter._heuristic_score(
        "external_link",
        {"url": "https://paypa1.com/reset", "from_email": True},
    )
    # email (+0.3) + paypal typo (+0.4) = 0.7
    assert score >= 0.6


def test_idn_homograph_increases_navigation_risk():
    # "аpple.com" -- the first 'a' is U+0430 CYRILLIC SMALL LETTER A
    score = argus_arbiter._heuristic_score(
        "navigation", {"url": "https://аpple.com/"},
    )
    assert score >= 0.3
