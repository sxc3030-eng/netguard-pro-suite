# Copyright (C) 2026 NetGuard Pro Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""
Tests for argus_sandbox — profile factories + tracker interceptor.

We do NOT use ``pytest-qt`` (it's not installed in this repo's CI). Instead:

* Pure-logic tests run unconditionally — they exercise
  ``TrackerInterceptor.should_block`` / ``is_tracker`` / ``is_third_party``
  without any Qt object construction.
* Qt-dependent tests construct a single module-level ``QApplication`` in a
  fixture. They are skipped via ``pytest.skip`` if Qt fails to initialise
  (e.g. headless CI without a display).

This mirrors the convention in ``tests/test_argus_vault.py``: redirect
all on-disk writes to ``tmp_path`` via ``ARGUS_VAULT_ROOT`` and never
touch the real ``argus_data/``.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_sandbox  # noqa: E402

# ─────────────────────────────────────────────────────────────────
# Optional Qt setup — single QApplication per test session.
# ─────────────────────────────────────────────────────────────────
_QT_INIT_ERROR: Optional[str] = None
_qapp = None


def _ensure_qapp():
    """Lazily build a QApplication. Returns it or sets _QT_INIT_ERROR."""
    global _qapp, _QT_INIT_ERROR
    if _qapp is not None or _QT_INIT_ERROR is not None:
        return _qapp
    try:
        from PyQt6.QtWidgets import QApplication

        # QApplication.instance() may already exist if pytest is reused.
        existing = QApplication.instance()
        if existing is not None:
            _qapp = existing
            return _qapp
        # Headless: prefer offscreen so this works on CI without a display.
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        _qapp = QApplication(sys.argv[:1])
    except Exception as exc:  # pragma: no cover — only on Qt-less boxes
        _QT_INIT_ERROR = f"{type(exc).__name__}: {exc}"
        _qapp = None
    return _qapp


def _skip_if_no_qt():
    """Skip the calling test if QtWebEngine isn't usable."""
    if not argus_sandbox._QT_AVAILABLE:
        pytest.skip("PyQt6.QtWebEngineCore not importable")
    app = _ensure_qapp()
    if app is None:
        pytest.skip(f"QApplication unavailable: {_QT_INIT_ERROR}")


@pytest.fixture(autouse=True)
def _reset_blocklist_cache():
    """Force re-read of trackers_blocklist.txt for each test."""
    argus_sandbox._BLOCKLIST_CACHE = None
    yield
    argus_sandbox._BLOCKLIST_CACHE = None


# ─────────────────────────────────────────────────────────────────
# Pure-logic tests (no Qt)
# ─────────────────────────────────────────────────────────────────
class TestBlocklistLoader:
    def test_get_tracker_blocklist_returns_nonempty_set(self):
        blocklist = argus_sandbox.get_tracker_blocklist()
        assert isinstance(blocklist, set)
        assert len(blocklist) >= 100, (
            f"expected >=100 trackers, got {len(blocklist)}"
        )

    def test_get_tracker_blocklist_contains_well_known(self):
        blocklist = argus_sandbox.get_tracker_blocklist()
        # Well-known trackers that MUST be in any sane list.
        for must_have in (
            "doubleclick.net",
            "googletagmanager.com",
            "scorecardresearch.com",
            "hotjar.com",
        ):
            assert must_have in blocklist, (
                f"{must_have} missing from blocklist"
            )

    def test_get_tracker_blocklist_skips_comments_and_blanks(self):
        blocklist = argus_sandbox.get_tracker_blocklist()
        # No comment markers should leak through as domains.
        assert not any(d.startswith("#") for d in blocklist)
        assert "" not in blocklist

    def test_blocklist_caches_result(self):
        # Read twice — second call should hit cache, returning a *copy*.
        first = argus_sandbox.get_tracker_blocklist()
        second = argus_sandbox.get_tracker_blocklist()
        assert first == second
        # The two calls must not return the SAME object (defensive copy).
        first.add("synthetic.test")
        third = argus_sandbox.get_tracker_blocklist()
        assert "synthetic.test" not in third


class TestCdnAllowlist:
    def test_get_vault_cdn_allowlist_contains_cloudflare(self):
        allow = argus_sandbox.get_vault_cdn_allowlist()
        assert "cloudflare.com" in allow
        assert "cdnjs.cloudflare.com" in allow

    def test_get_vault_cdn_allowlist_contains_akamai(self):
        allow = argus_sandbox.get_vault_cdn_allowlist()
        # Banks rely on Akamai heavily; this MUST be in the allow set.
        assert "akamaized.net" in allow

    def test_get_vault_cdn_allowlist_returns_mutable_copy(self):
        allow = argus_sandbox.get_vault_cdn_allowlist()
        before = len(argus_sandbox.get_vault_cdn_allowlist())
        allow.add("synthetic.test")
        after = len(argus_sandbox.get_vault_cdn_allowlist())
        # Mutating returned set must NOT affect the source.
        assert before == after


class TestInterceptorPureLogic:
    """Exercise the decision logic without instantiating Qt classes.

    ``TrackerInterceptor.__init__`` calls ``super().__init__()`` which
    requires Qt — so we skip these unless Qt is available. The decision
    methods themselves are pure Python and would work without Qt.
    """

    def setup_method(self):
        _skip_if_no_qt()

    def test_interceptor_blocks_known_tracker(self):
        ic = argus_sandbox.TrackerInterceptor(mode="normal")
        blocked, reason = ic.should_block(
            host="doubleclick.net", first_party="news.example.com"
        )
        assert blocked is True
        assert reason == "tracker"

    def test_interceptor_blocks_tracker_subdomain(self):
        ic = argus_sandbox.TrackerInterceptor(mode="normal")
        blocked, reason = ic.should_block(
            host="stats.g.doubleclick.net",
            first_party="news.example.com",
        )
        assert blocked is True
        assert reason == "tracker"

    def test_interceptor_allows_first_party(self):
        ic = argus_sandbox.TrackerInterceptor(mode="private")
        blocked, _ = ic.should_block(
            host="news.example.com", first_party="news.example.com"
        )
        assert blocked is False

    def test_interceptor_allows_first_party_subdomain(self):
        ic = argus_sandbox.TrackerInterceptor(mode="private")
        blocked, _ = ic.should_block(
            host="api.example.com", first_party="example.com"
        )
        assert blocked is False

    def test_normal_mode_allows_third_party(self):
        ic = argus_sandbox.TrackerInterceptor(mode="normal")
        blocked, _ = ic.should_block(
            host="api.partner.com", first_party="news.example.com"
        )
        # Normal mode does NOT block 3rd parties unless they're trackers.
        assert blocked is False

    def test_private_mode_blocks_random_third_party(self):
        ic = argus_sandbox.TrackerInterceptor(mode="private")
        blocked, reason = ic.should_block(
            host="random-cdn.partner.com",
            first_party="news.example.com",
        )
        assert blocked is True
        assert reason == "3rd_party"

    def test_private_mode_allows_cdn_third_party(self):
        ic = argus_sandbox.TrackerInterceptor(mode="private")
        blocked, _ = ic.should_block(
            host="cdnjs.cloudflare.com",
            first_party="news.example.com",
        )
        assert blocked is False

    def test_vault_interceptor_blocks_third_party_outside_cdn_allowlist(self):
        ic = argus_sandbox.TrackerInterceptor(
            mode="vault", allowed_domain="rbcroyalbank.com"
        )
        blocked, reason = ic.should_block(
            host="random-tracker.io",
            first_party="rbcroyalbank.com",
        )
        assert blocked is True
        assert reason == "3rd_party_strict"

    def test_vault_interceptor_allows_allowed_domain_subdomain(self):
        ic = argus_sandbox.TrackerInterceptor(
            mode="vault", allowed_domain="rbcroyalbank.com"
        )
        blocked, _ = ic.should_block(
            host="online.rbcroyalbank.com",
            first_party="rbcroyalbank.com",
        )
        assert blocked is False

    def test_vault_interceptor_allows_cdn_third_party(self):
        ic = argus_sandbox.TrackerInterceptor(
            mode="vault", allowed_domain="rbcroyalbank.com"
        )
        blocked, _ = ic.should_block(
            host="akamaized.net",
            first_party="rbcroyalbank.com",
        )
        assert blocked is False

    def test_vault_interceptor_blocks_known_tracker_even_under_allowed_domain(
        self,
    ):
        # If a tracker happens to be served from a subdomain that
        # otherwise matches the allowed domain, it MUST still be blocked.
        ic = argus_sandbox.TrackerInterceptor(
            mode="vault", allowed_domain="example-bank.com"
        )
        blocked, reason = ic.should_block(
            host="doubleclick.net", first_party="example-bank.com"
        )
        assert blocked is True
        assert reason == "tracker"

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError):
            argus_sandbox.TrackerInterceptor(mode="invalid")


class TestUserAgentRandomization:
    def test_random_ua_is_plausible_chrome(self):
        # Build 20 fake profiles + capture each UA — they must all
        # match the Chrome UA pattern.
        chrome_re = re.compile(
            r"^Mozilla/5\.0 \(.+\) AppleWebKit/537\.36 "
            r"\(KHTML, like Gecko\) Chrome/\d+\.\d+\.\d+\.\d+ "
            r"Safari/537\.36$"
        )
        # randomize_user_agent does not need a real profile when Qt is
        # not available — it falls through gracefully and still returns
        # the chosen UA.
        seen = set()
        for _ in range(50):
            fake_profile = MagicMock()
            ua = argus_sandbox.randomize_user_agent(fake_profile)
            assert chrome_re.match(ua), f"UA does not match Chrome: {ua!r}"
            seen.add(ua)
        # Over 50 picks from a pool of 10, should have hit at least 3
        # distinct UAs (probability of NOT seeing 3 is astronomically low).
        assert len(seen) >= 3, (
            f"Random UA pool seems too small or seeded: {seen}"
        )

    def test_user_agent_set_on_profile(self):
        # When Qt IS available, randomize_user_agent should call
        # setHttpUserAgent on the profile.
        fake_profile = MagicMock()
        ua = argus_sandbox.randomize_user_agent(fake_profile)
        if argus_sandbox._QT_AVAILABLE:
            fake_profile.setHttpUserAgent.assert_called_once_with(ua)


class TestAntiSkimmerScript:
    def test_anti_skimmer_script_contains_mutation_observer(self):
        js = argus_sandbox.anti_skimmer_js()
        assert "MutationObserver" in js
        assert ".observe(" in js

    def test_anti_skimmer_script_contains_cc_field_handling(self):
        js = argus_sandbox.anti_skimmer_js()
        # Must hook cc field types per the Web Payments spec.
        assert "cc-" in js
        assert "input" in js.lower()

    def test_anti_skimmer_script_exposes_report_hook(self):
        js = argus_sandbox.anti_skimmer_js()
        # Host page can implement window.argusReportSkimmerSuspicion
        # to capture suspicions; the script must call it.
        assert "argusReportSkimmerSuspicion" in js

    def test_anti_skimmer_script_is_iife(self):
        js = argus_sandbox.anti_skimmer_js()
        # Confirm it's an IIFE so it doesn't pollute global scope.
        assert js.strip().startswith("(function")

    def test_install_anti_skimmer_calls_addScript(self):
        _skip_if_no_qt()
        # We use a real QWebEngineProfile to verify the script lands in
        # its scripts() collection.
        from PyQt6.QtWebEngineCore import QWebEngineProfile  # noqa: WPS433

        profile = QWebEngineProfile()
        before = len(list(profile.scripts().toList()))
        argus_sandbox.install_anti_skimmer_script(profile)
        after = len(list(profile.scripts().toList()))
        assert after == before + 1
        names = [s.name() for s in profile.scripts().toList()]
        assert "argus-anti-skimmer" in names


# ─────────────────────────────────────────────────────────────────
# Profile factory tests (Qt-dependent)
# ─────────────────────────────────────────────────────────────────
class TestProfileFactories:
    def setup_method(self):
        _skip_if_no_qt()

    def test_normal_profile_persistent(self, tmp_path, monkeypatch):
        # Redirect DATA_ROOT to tmp_path so we don't touch real argus_data/.
        monkeypatch.setattr(
            argus_sandbox, "DATA_ROOT", tmp_path / "argus_data"
        )
        profile = argus_sandbox.make_normal_profile()
        # Off-the-record on QWebEngineProfile is False when a name was set.
        assert profile.isOffTheRecord() is False
        assert profile.persistentStoragePath()  # non-empty
        assert (
            profile.persistentCookiesPolicy()
            == argus_sandbox.QWebEngineProfile
            .PersistentCookiesPolicy.AllowPersistentCookies
        )
        # Interceptor attached + reachable.
        assert hasattr(profile, "_argus_interceptor")
        assert profile._argus_interceptor.mode == "normal"

    def test_private_profile_off_the_record(self):
        profile = argus_sandbox.make_private_profile()
        # The semantic OTR check — Qt 6 may still report a default
        # persistentStoragePath() string, but isOffTheRecord() is the
        # source of truth for "nothing hits disk".
        assert profile.isOffTheRecord() is True
        assert (
            profile.persistentCookiesPolicy()
            == argus_sandbox.QWebEngineProfile
            .PersistentCookiesPolicy.NoPersistentCookies
        )
        assert (
            profile.httpCacheType()
            == argus_sandbox.QWebEngineProfile.HttpCacheType.MemoryHttpCache
        )
        assert profile._argus_interceptor.mode == "private"

    def test_vault_profile_off_the_record(self):
        profile = argus_sandbox.make_vault_profile(
            allowed_domain="rbcroyalbank.com"
        )
        assert profile.isOffTheRecord() is True
        assert (
            profile.httpCacheType()
            == argus_sandbox.QWebEngineProfile.HttpCacheType.MemoryHttpCache
        )
        assert profile._argus_interceptor.mode == "vault"
        assert profile._argus_interceptor.allowed_domain == "rbcroyalbank.com"
        # Anti-skimmer script attached.
        names = [s.name() for s in profile.scripts().toList()]
        assert "argus-anti-skimmer" in names
        # Cert pin table attached for the cert error handler to read.
        assert hasattr(profile, "_argus_cert_pins")
        assert isinstance(profile._argus_cert_pins, dict)

    def test_vault_profile_without_allowed_domain_blocks_all_third_party(
        self,
    ):
        profile = argus_sandbox.make_vault_profile(allowed_domain=None)
        ic = profile._argus_interceptor
        # No allowed domain → only CDN allowlist saves a 3rd-party request.
        blocked, reason = ic.should_block(
            host="random.io", first_party="bank.example.com"
        )
        assert blocked is True
        assert reason == "3rd_party_strict"

    def test_private_profiles_are_independent_instances(self):
        # Two private profiles must be distinct OTR objects (so they
        # don't share cookies/cache via Chromium's profile registry).
        p1 = argus_sandbox.make_private_profile()
        p2 = argus_sandbox.make_private_profile()
        assert p1 is not p2
        assert p1.isOffTheRecord() and p2.isOffTheRecord()
        # Each gets its own interceptor instance — verifies factory
        # isn't memoizing.
        assert p1._argus_interceptor is not p2._argus_interceptor


# ─────────────────────────────────────────────────────────────────
# DoH env-var helper
# ─────────────────────────────────────────────────────────────────
class TestDohResolver:
    def test_install_doh_resolver_sets_env_var(self, monkeypatch):
        if not argus_sandbox._QT_AVAILABLE:
            pytest.skip("Qt not available")
        monkeypatch.delenv("QTWEBENGINE_CHROMIUM_FLAGS", raising=False)
        # Pass a fake profile — the function does not introspect it for
        # DoH; it only mutates the env var.
        argus_sandbox.install_doh_resolver(MagicMock())
        flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
        assert "DnsOverHttps" in flags
        assert "cloudflare-dns.com" in flags

    def test_install_doh_resolver_idempotent(self, monkeypatch):
        if not argus_sandbox._QT_AVAILABLE:
            pytest.skip("Qt not available")
        monkeypatch.setenv(
            "QTWEBENGINE_CHROMIUM_FLAGS",
            "--enable-features=DnsOverHttps existing-flag",
        )
        argus_sandbox.install_doh_resolver(MagicMock())
        # Should not append a second copy.
        flags = os.environ["QTWEBENGINE_CHROMIUM_FLAGS"]
        assert flags.count("DnsOverHttps") == 1
