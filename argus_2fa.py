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
argus_2fa — TOTP gate (RFC 6238) for entering Argus Coffre Mode.

Coffre Mode runs a hardened browser profile for banking / payment / crypto
sessions. This module adds an explicit 2FA challenge before Coffre Mode is
entered: friction is the feature — it forces the user to confirm intent and
makes silent / scripted entry impossible.

Stored material (in ``argus_vault``):

* ``TOTP_SECRET``           — base32-encoded 160-bit secret
* ``TOTP_RECOVERY_CODES``   — JSON list of bcrypt hashes; consumed entries
                              get nulled out (still present, but a "" hash)
* ``TOTP_REQUIRED_ACTIONS`` — JSON dict of action -> bool overrides
* ``TOTP_LOCKOUT_UNTIL``    — ISO timestamp; while in the past, no lockout

Public API
----------
* ``two_fa_is_setup()``                 -> bool
* ``two_fa_setup_wizard(parent_widget)`` -> bool
* ``two_fa_challenge(parent_widget)``   -> bool
* ``two_fa_required_for(action)``       -> bool
* ``two_fa_disable()``                  -> None
* ``two_fa_generate_recovery_codes()``  -> list[str]
* ``two_fa_verify_recovery_code(code)`` -> bool

Hard constraints
----------------
* No real secrets in tests — use deterministic placeholders.
* Surveillance integration is best-effort: if ``argus_surveillance`` cannot
  be imported, calls become no-ops.
* The Qt dialogs are split out from the verification logic so the core
  behaviour can be unit-tested without spinning up a QApplication.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, List, Optional

import bcrypt
import pyotp

import argus_vault

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

VAULT_KEY_SECRET = "TOTP_SECRET"
VAULT_KEY_RECOVERY = "TOTP_RECOVERY_CODES"
VAULT_KEY_REQUIRED = "TOTP_REQUIRED_ACTIONS"
VAULT_KEY_LOCKOUT = "TOTP_LOCKOUT_UNTIL"

ISSUER_NAME = "Argus"
ACCOUNT_LABEL_DEFAULT = "argus-user"

MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 60

# Recovery codes: 8 codes, "XXXX-XXXX-XXXX". Drop ambiguous chars (0/O, 1/I).
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RECOVERY_GROUP_LEN = 4
RECOVERY_GROUPS = 3
RECOVERY_COUNT = 8

DEFAULT_REQUIRED_ACTIONS = {
    "vault_mode_entry": True,
}

_LOG = logging.getLogger("argus.2fa")


# --------------------------------------------------------------------------- #
# Surveillance integration (best-effort, no-op if unavailable)
# --------------------------------------------------------------------------- #


def _surveil(action: str, result: str, extra: Optional[dict] = None) -> None:
    """Log a 2FA event to argus_surveillance if available."""
    try:
        import argus_surveillance  # local import: keep this module standalone
    except ImportError:
        return
    payload = {"action": action, "result": result}
    if extra:
        payload.update(extra)
    try:
        argus_surveillance.surveil_log_event("auth_attempt", payload)
    except Exception as exc:  # pragma: no cover — defensive
        _LOG.warning("surveil_log_event failed: %s", exc)


# --------------------------------------------------------------------------- #
# Recovery-code helpers (pure)
# --------------------------------------------------------------------------- #


def _generate_one_recovery_code() -> str:
    parts: List[str] = []
    for _ in range(RECOVERY_GROUPS):
        chars = "".join(
            secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_GROUP_LEN)
        )
        parts.append(chars)
    return "-".join(parts)


def _normalise_recovery_code(code: str) -> str:
    """Upper-case, strip whitespace, allow lower or upper input."""
    if not isinstance(code, str):
        return ""
    return code.strip().upper().replace(" ", "")


def _hash_recovery(code: str) -> str:
    """bcrypt-hash a recovery code. Returns the hash as a UTF-8 string."""
    return bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_recovery(code: str, hashed: str) -> bool:
    if not hashed:  # consumed slot
        return False
    try:
        return bcrypt.checkpw(code.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# Vault helpers (best-effort: vault may not be initialised)
# --------------------------------------------------------------------------- #


def _vault_get(key: str) -> Optional[str]:
    if not argus_vault.vault_exists():
        return None
    try:
        return argus_vault.vault_get(key)
    except Exception as exc:  # pragma: no cover — defensive
        _LOG.warning("vault_get(%s) failed: %s", key, exc)
        return None


def _vault_set(key: str, value: str) -> None:
    argus_vault.vault_set(key, value, owner="argus_2fa")


def _vault_delete(key: str) -> None:
    if not argus_vault.vault_exists():
        return
    try:
        argus_vault.vault_delete(key)
    except Exception as exc:  # pragma: no cover — defensive
        _LOG.warning("vault_delete(%s) failed: %s", key, exc)


# --------------------------------------------------------------------------- #
# Lockout state
# --------------------------------------------------------------------------- #


def _is_locked_out() -> bool:
    raw = _vault_get(VAULT_KEY_LOCKOUT)
    if not raw:
        return False
    try:
        until = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < until


def _engage_lockout(seconds: int = LOCKOUT_SECONDS) -> None:
    until = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    _vault_set(VAULT_KEY_LOCKOUT, until.isoformat())


# --------------------------------------------------------------------------- #
# Public API — setup / status
# --------------------------------------------------------------------------- #


def two_fa_is_setup() -> bool:
    """True if a TOTP secret has been stored."""
    return bool(_vault_get(VAULT_KEY_SECRET))


def two_fa_required_for(action: str) -> bool:
    """True if ``action`` requires 2FA.

    Defaults: ``vault_mode_entry`` -> True, everything else -> False.
    Overrides live in ``TOTP_REQUIRED_ACTIONS`` (JSON dict in the vault).
    """
    if not isinstance(action, str) or not action:
        return False

    overrides_raw = _vault_get(VAULT_KEY_REQUIRED)
    overrides: dict = {}
    if overrides_raw:
        try:
            parsed = json.loads(overrides_raw)
            if isinstance(parsed, dict):
                overrides = parsed
        except json.JSONDecodeError:
            pass

    if action in overrides:
        return bool(overrides[action])
    return DEFAULT_REQUIRED_ACTIONS.get(action, False)


# --------------------------------------------------------------------------- #
# Setup wizard — split into testable core + Qt UI
# --------------------------------------------------------------------------- #


def _provisioning_uri(secret: str, account: str = ACCOUNT_LABEL_DEFAULT) -> str:
    """Build the otpauth:// URI used to encode the QR code."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=account, issuer_name=ISSUER_NAME
    )


def _generate_secret() -> str:
    """Fresh 160-bit base32 secret (pyotp default length)."""
    return pyotp.random_base32()


def _setup_finalise(secret: str, confirmation_code: str) -> bool:
    """Pure logic of the wizard's confirm step.

    Verifies the user-entered 6-digit code against the freshly generated
    secret. On success, stores the secret in the vault.
    """
    if not pyotp.TOTP(secret).verify(confirmation_code, valid_window=1):
        _surveil("2fa_setup", "verify_fail")
        return False
    _vault_set(VAULT_KEY_SECRET, secret)
    _surveil("2fa_setup", "ok")
    return True


def two_fa_setup_wizard(
    parent_widget: Any = None,
    code_provider: Optional[Callable[[str, str], Optional[str]]] = None,
) -> bool:
    """Run first-time TOTP setup.

    Parameters
    ----------
    parent_widget
        Qt parent for the dialog (forwarded to QDialog).
    code_provider
        Optional injection seam for tests. Signature:
        ``(secret, provisioning_uri) -> Optional[str]``. Return the
        confirmation code, or ``None`` to cancel. When omitted, a Qt
        wizard dialog is shown.

    Returns
    -------
    bool
        ``True`` when setup completed and the secret was stored.
    """
    if two_fa_is_setup():
        # Refuse to overwrite silently — caller must disable first.
        return False

    secret = _generate_secret()
    uri = _provisioning_uri(secret)

    if code_provider is None:
        code_provider = _qt_setup_code_provider

    confirmation = code_provider(secret, uri)
    if confirmation is None:
        return False
    return _setup_finalise(secret, confirmation)


# --------------------------------------------------------------------------- #
# Challenge — split into testable core + Qt UI
# --------------------------------------------------------------------------- #


def _challenge_verify_attempt(secret: str, code: str) -> bool:
    """Verify a single 6-digit attempt, ±1 window for clock drift."""
    if not isinstance(code, str):
        return False
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != 6:
        return False
    return pyotp.TOTP(secret).verify(cleaned, valid_window=1)


def two_fa_challenge(
    parent_widget: Any = None,
    code_provider: Optional[Callable[[int], Optional[str]]] = None,
) -> bool:
    """Show a TOTP challenge dialog.

    Parameters
    ----------
    parent_widget
        Qt parent for the modal dialog.
    code_provider
        Optional test seam. Signature: ``(attempt_index) -> Optional[str]``
        where ``attempt_index`` is 0..MAX_ATTEMPTS-1. Return the entered
        code, or ``None`` to cancel.

    Returns
    -------
    bool
        ``True`` on success, ``False`` on cancel or 3 wrong codes.
    """
    if not two_fa_is_setup():
        _surveil("2fa_challenge", "not_setup")
        return False

    if _is_locked_out():
        _surveil("2fa_challenge", "locked_out")
        return False

    secret = _vault_get(VAULT_KEY_SECRET)
    if not secret:
        _surveil("2fa_challenge", "secret_missing")
        return False

    if code_provider is None:
        code_provider = _qt_challenge_code_provider

    for attempt in range(MAX_ATTEMPTS):
        code = code_provider(attempt)
        if code is None:
            _surveil("2fa_challenge", "cancel", {"attempt": attempt})
            return False
        if _challenge_verify_attempt(secret, code):
            _surveil("2fa_challenge", "ok", {"attempt": attempt})
            return True
        _surveil("2fa_challenge", "fail", {"attempt": attempt})

    # Three fails -> lockout.
    _engage_lockout(LOCKOUT_SECONDS)
    _surveil("auth_attempt", "fail_3x", {"action": "2fa"})
    return False


# --------------------------------------------------------------------------- #
# Disable
# --------------------------------------------------------------------------- #


def two_fa_disable(
    confirm_provider: Optional[Callable[[], bool]] = None,
) -> None:
    """Remove all TOTP material from the vault.

    Parameters
    ----------
    confirm_provider
        Optional test seam returning the user's double-confirm decision.
        When omitted, a Qt confirmation dialog is shown. Return ``False``
        to abort.
    """
    if confirm_provider is None:
        confirm_provider = _qt_disable_confirm_provider

    if not confirm_provider():
        _surveil("2fa_disable", "cancel")
        return

    for key in (
        VAULT_KEY_SECRET,
        VAULT_KEY_RECOVERY,
        VAULT_KEY_REQUIRED,
        VAULT_KEY_LOCKOUT,
    ):
        _vault_delete(key)
    _surveil("2fa_disable", "ok")


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #


def two_fa_generate_recovery_codes() -> List[str]:
    """Mint 8 new recovery codes, store hashes, return plaintext ONCE.

    Any previously stored recovery codes are replaced. Caller MUST display
    the returned list to the user immediately and not persist it; only the
    bcrypt hashes hit disk.
    """
    plain = [_generate_one_recovery_code() for _ in range(RECOVERY_COUNT)]
    hashes_arr = [_hash_recovery(c) for c in plain]
    _vault_set(VAULT_KEY_RECOVERY, json.dumps(hashes_arr))
    _surveil("2fa_recovery_generate", "ok", {"count": RECOVERY_COUNT})
    return plain


def two_fa_verify_recovery_code(code: str) -> bool:
    """Single-use recovery code verification.

    Returns ``True`` if the code matches one of the stored hashes; on
    success the hash entry is overwritten with ``""`` so it cannot be
    re-used.
    """
    norm = _normalise_recovery_code(code)
    if not norm:
        _surveil("2fa_recovery_verify", "empty")
        return False

    raw = _vault_get(VAULT_KEY_RECOVERY)
    if not raw:
        _surveil("2fa_recovery_verify", "no_codes_stored")
        return False
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _surveil("2fa_recovery_verify", "vault_corrupt")
        return False
    if not isinstance(parsed, list):
        return False

    for idx, hashed in enumerate(parsed):
        if not isinstance(hashed, str):
            continue
        if _verify_recovery(norm, hashed):
            parsed[idx] = ""
            _vault_set(VAULT_KEY_RECOVERY, json.dumps(parsed))
            _surveil("2fa_recovery_verify", "ok", {"index": idx})
            return True

    _surveil("2fa_recovery_verify", "fail")
    return False


# --------------------------------------------------------------------------- #
# Qt providers (kept thin so they don't run in test envs)
# --------------------------------------------------------------------------- #


def _qt_setup_code_provider(secret: str, uri: str) -> Optional[str]:  # pragma: no cover - GUI
    """Display the QR code + ask for confirmation digits.

    Returns the entered code, or None if the user cancels. Imports Qt
    lazily so headless / test environments can use ``code_provider``
    without dragging in PyQt6.
    """
    try:
        import qrcode
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QPixmap
        from PyQt6.QtWidgets import (
            QDialog,
            QDialogButtonBox,
            QLabel,
            QLineEdit,
            QVBoxLayout,
        )
    except ImportError:
        _LOG.error("Qt or qrcode not available; cannot run setup wizard")
        return None

    dlg = QDialog()
    dlg.setWindowTitle("Argus — Set up two-factor authentication")
    layout = QVBoxLayout(dlg)

    layout.addWidget(QLabel("1. Scan this QR code with an authenticator app:"))

    try:
        img = qrcode.make(uri)
        # qrcode.PilImage exposes .save into a buffer
        from io import BytesIO
        buf = BytesIO()
        img.save(buf, format="PNG")
        pix = QPixmap()
        pix.loadFromData(buf.getvalue(), "PNG")
        qr_label = QLabel()
        qr_label.setPixmap(pix)
        qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(qr_label)
    except Exception as exc:
        layout.addWidget(QLabel(f"(QR rendering failed: {exc})"))

    layout.addWidget(QLabel(
        "2. Or enter this secret manually:\n" + secret
    ))
    layout.addWidget(QLabel("3. Enter the 6-digit code from your app:"))

    code_input = QLineEdit()
    code_input.setMaxLength(6)
    layout.addWidget(code_input)

    buttons = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
    )
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None
    return code_input.text()


def _qt_challenge_code_provider(attempt: int) -> Optional[str]:  # pragma: no cover - GUI
    try:
        from PyQt6.QtWidgets import (
            QDialog,
            QDialogButtonBox,
            QLabel,
            QLineEdit,
            QVBoxLayout,
        )
    except ImportError:
        _LOG.error("PyQt6 not available; cannot show 2FA challenge")
        return None

    dlg = QDialog()
    dlg.setWindowTitle("Argus — Coffre Mode authentication")
    layout = QVBoxLayout(dlg)

    msg = "Enter the 6-digit code from your authenticator."
    if attempt > 0:
        msg += f"\n(Attempt {attempt + 1} of {MAX_ATTEMPTS})"
    layout.addWidget(QLabel(msg))

    code_input = QLineEdit()
    code_input.setMaxLength(6)
    layout.addWidget(code_input)

    buttons = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
    )
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)

    if dlg.exec() != QDialog.DialogCode.Accepted:
        return None
    return code_input.text()


def _qt_disable_confirm_provider() -> bool:  # pragma: no cover - GUI
    try:
        from PyQt6.QtWidgets import QMessageBox
    except ImportError:
        _LOG.error("PyQt6 not available; refusing to disable 2FA without confirmation")
        return False

    first = QMessageBox.question(
        None,
        "Disable two-factor authentication?",
        "This will remove your TOTP secret and recovery codes. Continue?",
    )
    if first != QMessageBox.StandardButton.Yes:
        return False
    second = QMessageBox.question(
        None,
        "Are you sure?",
        "Coffre Mode will no longer require 2FA. Confirm once more.",
    )
    return second == QMessageBox.StandardButton.Yes
