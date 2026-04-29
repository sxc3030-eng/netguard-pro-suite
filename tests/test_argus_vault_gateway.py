# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_vault_gateway V2.

Each test isolates state via tmp_path + ARGUS_VAULT_ROOT, runs the
server with tls=False (plaintext over loopback), and uses
ARGUS_GATEWAY_SKIP_LIVE_REHASH=1 so we don't depend on a real
psutil port-to-PID lookup (which is racy in test fixtures).

No real secrets — placeholders only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import socket
import sys
import time
from pathlib import Path

import pytest

# Make sibling modules importable.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_vault  # noqa: E402
import argus_vault_gateway as gw  # noqa: E402

PASSPHRASE = "test-passphrase-not-a-real-secret"
SECRET_VALUE = "test_value_xyz_placeholder"
SECRET_KEY = "MY_TEST_SECRET"
OTHER_SECRET = "RESTRICTED_SECRET"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _free_port() -> int:
    """Pick a free TCP port on 127.0.0.1."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_fake_binary(tmp_path: Path, name: str = "fake_prog.bin") -> str:
    """Drop a deterministic fake binary in tmp_path and return its path.

    Using sys.executable on Windows-Store Python triggers an
    [Errno 22] Invalid argument because the install is in a sandboxed
    package container. A plain file in tmp_path is portable.
    """
    p = tmp_path / name
    p.write_bytes(b"#!/usr/bin/env python\n# fake binary for tests\n" + b"x" * 64)
    return str(p)


@pytest.fixture
def isolated_gateway(tmp_path, monkeypatch):
    """tmp_path-isolated gateway + vault. Yields (port, fake_hash)."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    monkeypatch.setenv("ARGUS_GATEWAY_SKIP_LIVE_REHASH", "1")
    importlib.reload(argus_vault)
    importlib.reload(gw)

    # Init vault and stash a test secret
    assert argus_vault.vault_init(passphrase=PASSPHRASE) is True
    argus_vault.vault_set(SECRET_KEY, SECRET_VALUE, passphrase=PASSPHRASE)
    argus_vault.vault_set(OTHER_SECRET, "not_for_you", passphrase=PASSPHRASE)

    # Register a fake program (synthetic binary file in tmp_path)
    fake_binary = _make_fake_binary(tmp_path)
    fake_hash = gw.gateway_register_program(
        binary_path=fake_binary,
        allowed_secrets=[SECRET_KEY],
        permissions={SECRET_KEY: ["read", "write"]},
        program_label="pytest_fixture",
        rate_per_min=600,  # high so we don't hit it accidentally
        burst=20,
    )

    port = _free_port()
    gw._reset_state_for_tests()
    gw.gateway_start(host="127.0.0.1", port=port, tls=False,
                     vault_passphrase=PASSPHRASE)
    # Brief settle
    time.sleep(0.05)
    try:
        yield port, fake_hash
    finally:
        try:
            gw.gateway_stop()
        except gw.GatewayNotRunning:
            pass


# --------------------------------------------------------------------------- #
# Low-level HTTP client helpers (we don't import the client lib here so that
# the gateway tests stand alone; the client gets its own test file)
# --------------------------------------------------------------------------- #


def _http(method: str, port: int, path: str, body=None, headers=None):
    import urllib.request
    import urllib.error
    url = f"http://127.0.0.1:{port}{path}"
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            payload = resp.read().decode("utf-8")
            return resp.status, json.loads(payload) if payload else {}
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read().decode("utf-8")
            return exc.code, json.loads(payload) if payload else {}
        except Exception:
            return exc.code, {}


# --------------------------------------------------------------------------- #
# Handshake tests
# --------------------------------------------------------------------------- #


def test_handshake_with_correct_hash_succeeds(isolated_gateway):
    port, fake_hash = isolated_gateway
    code, body = _http("POST", port, "/vault/handshake",
                       {"program_hash": fake_hash, "nonce": "abc123"})
    assert code == 200
    assert "session_token" in body
    assert "session_key_b64" in body
    assert body["expires_in_s"] == 300


def test_handshake_with_wrong_hash_rejected(isolated_gateway):
    port, _ = isolated_gateway
    bogus = "0" * 64
    code, body = _http("POST", port, "/vault/handshake",
                       {"program_hash": bogus, "nonce": "x"})
    assert code == 403
    assert "not whitelisted" in body.get("error", "")


# --------------------------------------------------------------------------- #
# /vault/get tests
# --------------------------------------------------------------------------- #


def _open_session(port, program_hash):
    code, body = _http("POST", port, "/vault/handshake",
                       {"program_hash": program_hash, "nonce": "n0"})
    assert code == 200
    return body["session_token"], base64.b64decode(body["session_key_b64"])


def test_get_with_session_returns_signed_response(isolated_gateway):
    port, fake_hash = isolated_gateway
    token, key = _open_session(port, fake_hash)
    request_nonce = "ffeedd"
    code, body = _http(
        "POST", port, "/vault/get",
        {"secret_key": SECRET_KEY, "nonce": request_nonce},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert code == 200
    assert body["request_nonce"] == request_nonce

    ct = base64.b64decode(body["ciphertext_b64"])
    rn = base64.b64decode(body["response_nonce_b64"])
    sig = base64.b64decode(body["hmac_b64"])

    # HMAC verifies
    expected = hmac.new(
        key, rn + ct + request_nonce.encode("utf-8"), hashlib.sha256
    ).digest()
    assert hmac.compare_digest(sig, expected)

    # Plaintext decrypts to the placeholder
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pt = AESGCM(key).decrypt(rn, ct, None).decode("utf-8")
    assert pt == SECRET_VALUE


def test_get_without_session_returns_401(isolated_gateway):
    port, _ = isolated_gateway
    code, body = _http("POST", port, "/vault/get",
                       {"secret_key": SECRET_KEY, "nonce": "x"})
    assert code == 401


def test_get_unauthorized_secret_returns_403(isolated_gateway):
    port, fake_hash = isolated_gateway
    token, _ = _open_session(port, fake_hash)
    # OTHER_SECRET is in the vault but NOT in this program's ACL
    code, body = _http(
        "POST", port, "/vault/get",
        {"secret_key": OTHER_SECRET, "nonce": "x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert code == 403


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


def test_rate_limit_returns_429_after_burst(tmp_path, monkeypatch):
    """Re-create the fixture with a tiny burst to exercise the limit."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    monkeypatch.setenv("ARGUS_GATEWAY_SKIP_LIVE_REHASH", "1")
    importlib.reload(argus_vault)
    importlib.reload(gw)

    argus_vault.vault_init(passphrase=PASSPHRASE)
    argus_vault.vault_set(SECRET_KEY, SECRET_VALUE, passphrase=PASSPHRASE)

    # Tight bucket: rate 6/min = 0.1/sec, burst=2
    fake_binary = _make_fake_binary(tmp_path, name="rl_prog.bin")
    fake_hash = gw.gateway_register_program(
        binary_path=fake_binary,
        allowed_secrets=[SECRET_KEY],
        permissions={SECRET_KEY: ["read"]},
        program_label="rl_test",
        rate_per_min=6,
        burst=2,
    )
    port = _free_port()
    gw._reset_state_for_tests()
    gw.gateway_start(host="127.0.0.1", port=port, tls=False,
                     vault_passphrase=PASSPHRASE)
    time.sleep(0.05)
    try:
        token, _ = _open_session(port, fake_hash)
        statuses = []
        for i in range(5):
            code, _ = _http(
                "POST", port, "/vault/get",
                {"secret_key": SECRET_KEY, "nonce": f"n{i}"},
                headers={"Authorization": f"Bearer {token}"},
            )
            statuses.append(code)
        # First 2 succeed (burst), then at least one 429
        assert 200 in statuses
        assert 429 in statuses
    finally:
        gw.gateway_stop()


# --------------------------------------------------------------------------- #
# Audit chain
# --------------------------------------------------------------------------- #


def test_audit_entry_written_on_request(isolated_gateway, tmp_path):
    port, fake_hash = isolated_gateway
    token, _ = _open_session(port, fake_hash)
    _http(
        "POST", port, "/vault/get",
        {"secret_key": SECRET_KEY, "nonce": "x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    audit = tmp_path / ".gateway" / "audit.jsonl"
    assert audit.exists()
    lines = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    actions = [r["action"] for r in lines]
    # register, handshake (during fixture setup), handshake (the _open_session
    # call above), and a get must all appear.
    assert "register" in actions
    assert "handshake" in actions
    assert "get" in actions


def test_audit_chain_verify_intact_returns_true(isolated_gateway):
    port, fake_hash = isolated_gateway
    token, _ = _open_session(port, fake_hash)
    _http("POST", port, "/vault/get",
          {"secret_key": SECRET_KEY, "nonce": "x"},
          headers={"Authorization": f"Bearer {token}"})
    assert gw.gateway_audit_chain_verify() is True


def test_audit_chain_verify_tampered_returns_false(isolated_gateway, tmp_path):
    port, fake_hash = isolated_gateway
    token, _ = _open_session(port, fake_hash)
    _http("POST", port, "/vault/get",
          {"secret_key": SECRET_KEY, "nonce": "x"},
          headers={"Authorization": f"Bearer {token}"})
    audit = tmp_path / ".gateway" / "audit.jsonl"
    raw = audit.read_text(encoding="utf-8").splitlines()
    # Mutate the last entry's action field
    rec = json.loads(raw[-1])
    rec["action"] = "tampered_action"
    raw[-1] = json.dumps(rec, sort_keys=True)
    audit.write_text("\n".join(raw) + "\n", encoding="utf-8")
    assert gw.gateway_audit_chain_verify() is False


# --------------------------------------------------------------------------- #
# Whitelist mgmt
# --------------------------------------------------------------------------- #


def test_register_program_stores_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    importlib.reload(argus_vault)
    importlib.reload(gw)
    fake_binary = _make_fake_binary(tmp_path, name="reg_prog.bin")
    h = gw.gateway_register_program(
        binary_path=fake_binary,
        allowed_secrets=["X"],
        program_label="hello",
    )
    assert len(h) == 64  # SHA-256 hex
    progs = gw.gateway_list_programs()
    assert any(p["hash"] == h for p in progs)
    p = next(p for p in progs if p["hash"] == h)
    assert p["label"] == "hello"
    assert p["allowed_secrets"] == ["X"]


def test_revoke_program_invalidates_session(isolated_gateway):
    port, fake_hash = isolated_gateway
    token, _ = _open_session(port, fake_hash)
    # Session works first
    code, _ = _http(
        "POST", port, "/vault/get",
        {"secret_key": SECRET_KEY, "nonce": "x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert code == 200

    # Revoke
    assert gw.gateway_revoke_program(fake_hash) is True

    # Session must now be rejected
    code, _ = _http(
        "POST", port, "/vault/get",
        {"secret_key": SECRET_KEY, "nonce": "x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert code == 401


# --------------------------------------------------------------------------- #
# TLS cert generation
# --------------------------------------------------------------------------- #


def test_tls_self_signed_cert_generated_on_first_start(tmp_path, monkeypatch):
    """First gateway_start with tls=True must drop a cert.pem + key.pem."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    importlib.reload(argus_vault)
    importlib.reload(gw)
    argus_vault.vault_init(passphrase=PASSPHRASE)
    port = _free_port()
    gw._reset_state_for_tests()
    gw.gateway_start(host="127.0.0.1", port=port, tls=True,
                     vault_passphrase=PASSPHRASE)
    try:
        cert = tmp_path / ".gateway" / "cert.pem"
        key = tmp_path / ".gateway" / "key.pem"
        assert cert.exists()
        assert key.exists()
        assert b"BEGIN CERTIFICATE" in cert.read_bytes()
        assert b"BEGIN" in key.read_bytes()  # any private key marker
    finally:
        gw.gateway_stop()


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


def test_stats_count_requests(isolated_gateway):
    port, fake_hash = isolated_gateway
    token, _ = _open_session(port, fake_hash)
    for i in range(3):
        _http(
            "POST", port, "/vault/get",
            {"secret_key": SECRET_KEY, "nonce": f"n{i}"},
            headers={"Authorization": f"Bearer {token}"},
        )
    s = gw.gateway_stats()
    assert s["requests_total"] >= 3
    assert s["uptime_s"] > 0


# --------------------------------------------------------------------------- #
# Bind safety
# --------------------------------------------------------------------------- #


def test_gateway_refuses_non_localhost(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    importlib.reload(argus_vault)
    importlib.reload(gw)
    with pytest.raises(ValueError):
        gw.gateway_start(host="0.0.0.0", port=_free_port(), tls=False)
