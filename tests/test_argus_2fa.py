# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_2fa.

Strategy
--------
* Vault is redirected to ``tmp_path`` via ``ARGUS_VAULT_ROOT``.
* The Qt dialogs are NOT exercised — every public function takes a
  ``code_provider`` / ``confirm_provider`` injection seam, so unit tests
  feed deterministic inputs without spinning up a QApplication.
* Test secret is the canonical RFC 6238 example string
  ``"JBSWY3DPEHPK3PXP"`` so anyone can recompute expected codes.
"""

from __future__ import annotations

import importlib
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_2fa  # noqa: E402
import argus_vault  # noqa: E402


TEST_SECRET = "JBSWY3DPEHPK3PXP"
PASSPHRASE = "test-passphrase-not-a-real-secret"


@pytest.fixture(autouse=True)
def isolated_vault_and_2fa(tmp_path, monkeypatch):
    """Per-test vault redirect + module reload + initialised vault."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    importlib.reload(argus_vault)
    importlib.reload(argus_2fa)
    argus_vault.vault_init(passphrase=PASSPHRASE)
    # vault_set/get with PBKDF2 wrap requires the passphrase. argus_2fa
    # calls vault_get/set without one, so we patch the wrapper to
    # transparently inject the passphrase for tests.
    real_get = argus_vault.vault_get
    real_set = argus_vault.vault_set

    def _patched_get(key, passphrase=None):
        return real_get(key, passphrase=passphrase or PASSPHRASE)

    def _patched_set(key, value, owner="system", passphrase=None):
        return real_set(key, value, owner=owner, passphrase=passphrase or PASSPHRASE)

    monkeypatch.setattr(argus_vault, "vault_get", _patched_get)
    monkeypatch.setattr(argus_vault, "vault_set", _patched_set)
    # argus_2fa imported argus_vault as a module ref — it picks up the
    # monkeypatch automatically because we patch the attribute on the
    # module, not a re-bound name.
    yield tmp_path


# --------------------------------------------------------------------------- #
# Setup
# --------------------------------------------------------------------------- #


def test_setup_generates_valid_base32_secret():
    captured = {}

    def provider(secret, uri):
        captured["secret"] = secret
        captured["uri"] = uri
        return pyotp.TOTP(secret).now()

    assert argus_2fa.two_fa_setup_wizard(code_provider=provider) is True

    secret = captured["secret"]
    # base32 alphabet = A-Z 2-7 padding =. pyotp.random_base32 yields 32 chars.
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in secret)
    assert len(secret) >= 16
    # URI is otpauth://
    assert captured["uri"].startswith("otpauth://totp/")
    assert "Argus" in captured["uri"]

    # Secret is stored in vault.
    assert argus_2fa.two_fa_is_setup() is True


def test_setup_rejects_wrong_confirmation_code():
    def provider(secret, uri):
        return "000000"  # almost certainly wrong

    assert argus_2fa.two_fa_setup_wizard(code_provider=provider) is False
    assert argus_2fa.two_fa_is_setup() is False


def test_setup_user_cancellation_returns_false():
    def provider(secret, uri):
        return None

    assert argus_2fa.two_fa_setup_wizard(code_provider=provider) is False
    assert argus_2fa.two_fa_is_setup() is False


def test_setup_refuses_when_already_set_up():
    # First setup ok.
    argus_2fa.two_fa_setup_wizard(
        code_provider=lambda s, u: pyotp.TOTP(s).now()
    )
    # Second setup must refuse — no silent overwrite.
    captured = {}

    def provider(s, u):
        captured["called"] = True
        return pyotp.TOTP(s).now()

    assert argus_2fa.two_fa_setup_wizard(code_provider=provider) is False
    assert "called" not in captured


# --------------------------------------------------------------------------- #
# Challenge
# --------------------------------------------------------------------------- #


def _seed_test_secret():
    """Bypass the wizard and write the canonical test secret directly."""
    argus_vault.vault_set(
        argus_2fa.VAULT_KEY_SECRET, TEST_SECRET, owner="argus_2fa"
    )


def test_challenge_accepts_valid_totp():
    _seed_test_secret()
    valid_code = pyotp.TOTP(TEST_SECRET).now()
    provider = lambda attempt: valid_code  # noqa: E731
    assert argus_2fa.two_fa_challenge(code_provider=provider) is True


def test_challenge_rejects_invalid_totp():
    _seed_test_secret()
    provider = lambda attempt: "000000"  # noqa: E731
    assert argus_2fa.two_fa_challenge(code_provider=provider) is False


def test_challenge_rejects_3_times_then_locks():
    _seed_test_secret()
    calls = {"n": 0}

    def provider(attempt):
        calls["n"] += 1
        return "000000"

    assert argus_2fa.two_fa_challenge(code_provider=provider) is False
    assert calls["n"] == 3

    # Lockout engaged: a subsequent call should NOT prompt the provider at all.
    calls["n"] = 0
    assert argus_2fa.two_fa_challenge(code_provider=provider) is False
    assert calls["n"] == 0  # short-circuited by lockout


def test_challenge_returns_false_when_not_setup():
    # No vault entry yet.
    provider = lambda attempt: pyotp.TOTP(TEST_SECRET).now()  # noqa: E731
    assert argus_2fa.two_fa_challenge(code_provider=provider) is False


def test_challenge_user_cancellation_returns_false():
    _seed_test_secret()
    # First attempt cancels.
    provider = lambda attempt: None  # noqa: E731
    assert argus_2fa.two_fa_challenge(code_provider=provider) is False


def test_challenge_succeeds_on_second_attempt():
    _seed_test_secret()
    valid_code = pyotp.TOTP(TEST_SECRET).now()

    def provider(attempt):
        return "000000" if attempt == 0 else valid_code

    assert argus_2fa.two_fa_challenge(code_provider=provider) is True


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #


def test_recovery_code_format():
    _seed_test_secret()
    codes = argus_2fa.two_fa_generate_recovery_codes()
    assert len(codes) == argus_2fa.RECOVERY_COUNT
    assert len(codes) == len(set(codes))  # all unique
    for c in codes:
        # XXXX-XXXX-XXXX
        groups = c.split("-")
        assert len(groups) == argus_2fa.RECOVERY_GROUPS
        for g in groups:
            assert len(g) == argus_2fa.RECOVERY_GROUP_LEN
            for ch in g:
                assert ch in argus_2fa.RECOVERY_ALPHABET
                # Spec forbids ambiguous chars: 0/O, 1/I.
                assert ch not in "0O1I"


def test_recovery_code_single_use():
    _seed_test_secret()
    codes = argus_2fa.two_fa_generate_recovery_codes()
    target = codes[3]
    # First use: ok.
    assert argus_2fa.two_fa_verify_recovery_code(target) is True
    # Second use: rejected.
    assert argus_2fa.two_fa_verify_recovery_code(target) is False


def test_recovery_code_wrong_rejected():
    _seed_test_secret()
    argus_2fa.two_fa_generate_recovery_codes()
    assert argus_2fa.two_fa_verify_recovery_code("ZZZZ-ZZZZ-ZZZZ") is False
    # Empty / garbage too.
    assert argus_2fa.two_fa_verify_recovery_code("") is False
    assert argus_2fa.two_fa_verify_recovery_code("not a code") is False


def test_recovery_code_case_insensitive_input():
    _seed_test_secret()
    codes = argus_2fa.two_fa_generate_recovery_codes()
    code = codes[0]
    # Lower-case + extra spaces should still verify.
    assert argus_2fa.two_fa_verify_recovery_code(f"  {code.lower()}  ") is True


def test_recovery_codes_replaced_on_regenerate():
    _seed_test_secret()
    first = argus_2fa.two_fa_generate_recovery_codes()
    second = argus_2fa.two_fa_generate_recovery_codes()
    # Old codes no longer work.
    assert argus_2fa.two_fa_verify_recovery_code(first[0]) is False
    assert argus_2fa.two_fa_verify_recovery_code(second[0]) is True


# --------------------------------------------------------------------------- #
# Required-for / configuration
# --------------------------------------------------------------------------- #


def test_required_for_vault_mode_entry_default_true():
    assert argus_2fa.two_fa_required_for("vault_mode_entry") is True


def test_required_for_unknown_action_default_false():
    assert argus_2fa.two_fa_required_for("send_email") is False
    assert argus_2fa.two_fa_required_for("") is False


def test_required_for_override_via_vault():
    # Disable the default for vault_mode_entry.
    argus_vault.vault_set(
        argus_2fa.VAULT_KEY_REQUIRED,
        json.dumps({"vault_mode_entry": False, "download_install": True}),
        owner="argus_2fa",
    )
    assert argus_2fa.two_fa_required_for("vault_mode_entry") is False
    assert argus_2fa.two_fa_required_for("download_install") is True


# --------------------------------------------------------------------------- #
# Disable
# --------------------------------------------------------------------------- #


def test_disable_clears_vault_entries():
    _seed_test_secret()
    argus_2fa.two_fa_generate_recovery_codes()
    assert argus_2fa.two_fa_is_setup() is True

    argus_2fa.two_fa_disable(confirm_provider=lambda: True)

    assert argus_2fa.two_fa_is_setup() is False
    # Recovery store also wiped.
    assert argus_vault.vault_get(argus_2fa.VAULT_KEY_RECOVERY) is None


def test_disable_aborts_on_no_confirmation():
    _seed_test_secret()
    argus_2fa.two_fa_disable(confirm_provider=lambda: False)
    # Still set up.
    assert argus_2fa.two_fa_is_setup() is True
