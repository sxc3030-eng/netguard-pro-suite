# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_vault_client.

The HTTP layer is patched via monkey-patching ``VaultClient._request``
so we can exercise the client logic (handshake caching, auto-renew,
HMAC verification, error mapping) without spinning up a real server.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_vault_client as avc  # noqa: E402

FAKE_HASH = "f" * 64
SECRET_KEY = "MY_TEST_SECRET"
SECRET_VALUE = "value_placeholder_xyz"


# --------------------------------------------------------------------------- #
# Fake server: returns scripted responses for each path.
# --------------------------------------------------------------------------- #


class _FakeServer:
    """Minimal scripted HTTP responder that records every call."""

    def __init__(self):
        self.session_token = "session-tok-placeholder-" + "0" * 32
        self.session_key = secrets.token_bytes(32)
        self.calls: list[tuple] = []
        self.script: list[dict] = []  # if non-empty, pop next response from here

    def _make_get_response(self, request_nonce: str) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        rn = secrets.token_bytes(12)
        ct = AESGCM(self.session_key).encrypt(rn, SECRET_VALUE.encode(), None)
        sig = hmac.new(
            self.session_key,
            rn + ct + request_nonce.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return {
            "status": 200,
            "body": {
                "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
                "response_nonce_b64": base64.b64encode(rn).decode("ascii"),
                "request_nonce": request_nonce,
                "hmac_b64": base64.b64encode(sig).decode("ascii"),
            },
        }

    def respond(self, method: str, path: str, body, with_auth: bool) -> dict:
        self.calls.append((method, path, body, with_auth))
        if self.script:
            return self.script.pop(0)
        if path == "/vault/handshake":
            return {
                "status": 200,
                "body": {
                    "session_token": self.session_token,
                    "session_key_b64": base64.b64encode(self.session_key).decode(),
                    "expires_in_s": 300,
                },
            }
        if path == "/vault/get":
            return self._make_get_response(body["nonce"])
        if path == "/vault/list":
            return {"status": 200, "body": {"secrets": [SECRET_KEY]}}
        if path == "/vault/store":
            return {"status": 200, "body": {"status": "ok"}}
        return {"status": 404, "body": {"error": "not found"}}


@pytest.fixture
def fake_server(monkeypatch):
    srv = _FakeServer()
    def _patched_request(self, method, path, body=None, with_auth=True):
        return srv.respond(method, path, body, with_auth)
    monkeypatch.setattr(avc.VaultClient, "_request", _patched_request)
    return srv


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_handshake_caches_session(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    assert c.handshake() is True
    assert c._session_token == fake_server.session_token
    assert c._session_key == fake_server.session_key


def test_get_calls_handshake_first(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    val = c.get(SECRET_KEY)
    assert val == SECRET_VALUE
    paths = [p for _, p, _, _ in fake_server.calls]
    assert paths[0] == "/vault/handshake"
    assert paths[1] == "/vault/get"


def test_session_renew_on_401(fake_server, monkeypatch):
    """First /vault/get gives 401, client re-handshakes and retries."""
    c = avc.VaultClient(program_hash=FAKE_HASH)
    # Pre-seed the script: handshake ok, get -> 401, handshake ok, get ok
    fake_server.script = [
        {  # initial handshake
            "status": 200,
            "body": {
                "session_token": fake_server.session_token,
                "session_key_b64": base64.b64encode(fake_server.session_key).decode(),
                "expires_in_s": 300,
            },
        },
        {"status": 401, "body": {"error": "expired"}},
        {  # re-handshake
            "status": 200,
            "body": {
                "session_token": "renewed-tok-" + "0" * 32,
                "session_key_b64": base64.b64encode(fake_server.session_key).decode(),
                "expires_in_s": 300,
            },
        },
        # The retry get — generate a valid signed response inline
        fake_server._make_get_response("__retry_nonce__"),
    ]
    # Force a deterministic nonce so the 4th scripted entry matches
    monkeypatch.setattr(avc.secrets, "token_hex", lambda n: "__retry_nonce__")

    val = c.get(SECRET_KEY)
    assert val == SECRET_VALUE
    # Second token landed in cache after auto-renew
    assert c._session_token == "renewed-tok-" + "0" * 32


def test_context_manager_clears_session(fake_server):
    with avc.VaultClient(program_hash=FAKE_HASH) as c:
        c.handshake()
        assert c._session_token is not None
    assert c._session_token is None
    assert c._session_key is None


def test_get_raises_on_permission_denied(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    fake_server.script = [
        {  # handshake
            "status": 200,
            "body": {
                "session_token": fake_server.session_token,
                "session_key_b64": base64.b64encode(fake_server.session_key).decode(),
                "expires_in_s": 300,
            },
        },
        {"status": 403, "body": {"error": "secret not in ACL"}},
    ]
    with pytest.raises(avc.VaultPermissionDenied):
        c.get("RESTRICTED_SECRET")


def test_get_raises_on_not_registered(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    fake_server.script = [
        {  # handshake fails: program not whitelisted
            "status": 403,
            "body": {"error": "program not whitelisted"},
        },
    ]
    with pytest.raises(avc.VaultNotRegistered):
        c.handshake()


def test_get_raises_on_rate_limit(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    fake_server.script = [
        {  # handshake
            "status": 200,
            "body": {
                "session_token": fake_server.session_token,
                "session_key_b64": base64.b64encode(fake_server.session_key).decode(),
                "expires_in_s": 300,
            },
        },
        {"status": 429, "body": {"error": "rate limit exceeded"}},
    ]
    with pytest.raises(avc.VaultRateLimited):
        c.get(SECRET_KEY)


def test_hmac_mismatch_raises_protocol_error(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    # Build a tampered response: valid handshake, then a get with bad HMAC
    bad_body = {
        "ciphertext_b64": base64.b64encode(b"\x00" * 16).decode(),
        "response_nonce_b64": base64.b64encode(b"\x00" * 12).decode(),
        "request_nonce": "willmatch",
        "hmac_b64": base64.b64encode(b"\x99" * 32).decode(),
    }
    fake_server.script = [
        {
            "status": 200,
            "body": {
                "session_token": fake_server.session_token,
                "session_key_b64": base64.b64encode(fake_server.session_key).decode(),
                "expires_in_s": 300,
            },
        },
        {"status": 200, "body": bad_body},
    ]
    import argus_vault_client
    # Pin the request nonce so the round-trip matches but the HMAC won't.
    real_token_hex = argus_vault_client.secrets.token_hex
    argus_vault_client.secrets.token_hex = lambda n: "willmatch"
    try:
        with pytest.raises(avc.VaultProtocolError):
            c.get(SECRET_KEY)
    finally:
        argus_vault_client.secrets.token_hex = real_token_hex


def test_list_returns_names(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    names = c.list()
    assert names == [SECRET_KEY]


def test_store_calls_endpoint(fake_server):
    c = avc.VaultClient(program_hash=FAKE_HASH)
    c.store(SECRET_KEY, "new_value_placeholder")
    # Last call was the store
    method, path, body, _ = fake_server.calls[-1]
    assert method == "POST"
    assert path == "/vault/store"
    assert body["secret_key"] == SECRET_KEY
    assert body["value"] == "new_value_placeholder"
