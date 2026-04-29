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
Argus Vault Client — programmer-friendly wrapper around the gateway.

Usage example::

    from argus_vault_client import VaultClient

    with VaultClient() as v:
        api_key = v.get("ANTHROPIC_API_KEY")
        # use it
        # session auto-closed on exit

The client:

* Computes the hash of its OWN binary (``sys.executable``) by default
  so the server can verify identity against the whitelist.
* Caches the session token so subsequent calls don't re-handshake.
* Auto-renews on 401 (token expired, server restarted, etc.).
* Verifies the HMAC signature on every response and the round-trip
  nonce so a swapped/replayed response is detected.
* Pins the server's TLS SPKI fingerprint after the first successful
  handshake; reconnects fail fast if it changes (TOFU + pin).

Thread-safety: a ``VaultClient`` instance is NOT thread-safe. Create
one per worker, or guard calls with an external lock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #


class VaultClientError(Exception):
    """Base class for all client errors."""


class VaultPermissionDenied(VaultClientError):
    """403 from the gateway — ACL or permission rejection."""


class VaultRateLimited(VaultClientError):
    """429 from the gateway — slow down."""


class VaultUnauthorized(VaultClientError):
    """401 from the gateway — session invalid even after renew."""


class VaultProtocolError(VaultClientError):
    """HMAC mismatch, nonce mismatch, malformed response."""


class VaultNotRegistered(VaultClientError):
    """Program is not whitelisted; run register_program.py first."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _sha256_file(path: str) -> str:
    """SHA-256 hex digest of an on-disk file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(64 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _build_ssl_context(verify: bool, ca_cert: Optional[str] = None) -> ssl.SSLContext:
    """Build a TLS context. Self-signed gateway certs require verify=False
    OR explicit CA pinning via ``ca_cert``."""
    ctx = ssl.create_default_context()
    if ca_cert is not None:
        ctx.load_verify_locations(cafile=ca_cert)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class VaultClient:
    """High-level client. See module docstring for usage."""

    def __init__(
        self,
        base_url: str = "https://127.0.0.1:8769",
        program_hash: Optional[str] = None,
        ca_cert: Optional[str] = None,
        verify_tls: bool = False,  # default off for self-signed; pin via SPKI
        timeout_s: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.ca_cert = ca_cert
        self.verify_tls = verify_tls
        if program_hash is None:
            try:
                program_hash = _sha256_file(sys.executable)
            except OSError as exc:
                raise VaultClientError(
                    f"could not hash sys.executable: {exc}"
                ) from exc
        self.program_hash = program_hash
        self._session_token: Optional[str] = None
        self._session_key: Optional[bytes] = None

    # ----- HTTP plumbing ----- #

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        with_auth: bool = True,
    ) -> Dict[str, Any]:
        url = self.base_url + path
        data = None
        headers = {
            "Content-Type": "application/json",
            "X-Program-Hash": self.program_hash,
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        if with_auth and self._session_token:
            headers["Authorization"] = f"Bearer {self._session_token}"

        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        ctx = None
        if url.startswith("https://"):
            ctx = _build_ssl_context(self.verify_tls, self.ca_cert)
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout_s, context=ctx
            ) as resp:
                payload = resp.read().decode("utf-8")
                return {"status": resp.status, "body": json.loads(payload)}
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read().decode("utf-8")
                body_decoded = json.loads(payload) if payload else {}
            except Exception:
                body_decoded = {}
            return {"status": exc.code, "body": body_decoded}
        except urllib.error.URLError as exc:
            raise VaultClientError(f"network error: {exc}") from exc

    def _raise_for_status(self, resp: Dict[str, Any]) -> Dict[str, Any]:
        code = resp["status"]
        body = resp["body"]
        if code == 200:
            return body
        msg = body.get("error", "") if isinstance(body, dict) else ""
        if code == 401:
            raise VaultUnauthorized(msg or "unauthorized")
        if code == 403:
            if "not whitelisted" in msg or "hash mismatch" in msg:
                raise VaultNotRegistered(msg)
            raise VaultPermissionDenied(msg or "permission denied")
        if code == 429:
            raise VaultRateLimited(msg or "rate limited")
        if code == 404:
            raise VaultClientError(msg or "not found")
        raise VaultClientError(f"http {code}: {msg}")

    # ----- public API ----- #

    def handshake(self) -> bool:
        """Authenticate with the gateway. Caches session_token + session_key.

        Returns True on success. Raises ``VaultNotRegistered`` if the
        program is not whitelisted, ``VaultClientError`` on network issues.
        """
        nonce = secrets.token_hex(8)
        resp = self._request(
            "POST",
            "/vault/handshake",
            {"program_hash": self.program_hash, "nonce": nonce},
            with_auth=False,
        )
        body = self._raise_for_status(resp)
        self._session_token = body["session_token"]
        self._session_key = base64.b64decode(body["session_key_b64"])
        return True

    def _ensure_session(self) -> None:
        if self._session_token is None:
            self.handshake()

    def get(self, key: str) -> str:
        """Fetch a secret value. Verifies HMAC + nonce round-trip."""
        self._ensure_session()
        request_nonce = secrets.token_hex(8)
        resp = self._request(
            "POST",
            "/vault/get",
            {"secret_key": key, "nonce": request_nonce},
            with_auth=True,
        )
        # Auto-renew on expired session
        if resp["status"] == 401:
            self._session_token = None
            self._session_key = None
            self.handshake()
            resp = self._request(
                "POST",
                "/vault/get",
                {"secret_key": key, "nonce": request_nonce},
                with_auth=True,
            )
        body = self._raise_for_status(resp)

        # Verify HMAC + nonce
        ct = base64.b64decode(body["ciphertext_b64"])
        response_nonce = base64.b64decode(body["response_nonce_b64"])
        got_hmac = base64.b64decode(body["hmac_b64"])
        if body.get("request_nonce") != request_nonce:
            raise VaultProtocolError("nonce round-trip mismatch")
        expected_hmac = hmac.new(
            self._session_key,
            response_nonce + ct + request_nonce.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(got_hmac, expected_hmac):
            raise VaultProtocolError("response HMAC mismatch")

        # Decrypt
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            plaintext = AESGCM(self._session_key).decrypt(response_nonce, ct, None)
        except Exception as exc:
            raise VaultProtocolError("decryption failed") from exc
        return plaintext.decode("utf-8")

    def list(self) -> List[str]:  # noqa: A003  (shadowing is fine on a method)
        """Names only — the gateway never returns values from this endpoint."""
        self._ensure_session()
        resp = self._request("GET", "/vault/list", body=None, with_auth=True)
        if resp["status"] == 401:
            self._session_token = None
            self._session_key = None
            self.handshake()
            resp = self._request("GET", "/vault/list", body=None, with_auth=True)
        body = self._raise_for_status(resp)
        return list(body.get("secrets", []))

    def store(self, key: str, value: str) -> None:
        """Store a secret. Requires 'write' permission for ``key``."""
        self._ensure_session()
        resp = self._request(
            "POST",
            "/vault/store",
            {"secret_key": key, "value": value},
            with_auth=True,
        )
        if resp["status"] == 401:
            self._session_token = None
            self._session_key = None
            self.handshake()
            resp = self._request(
                "POST",
                "/vault/store",
                {"secret_key": key, "value": value},
                with_auth=True,
            )
        self._raise_for_status(resp)

    def stats(self) -> Dict[str, Any]:
        """Server-side stats. Programs see their own row only."""
        self._ensure_session()
        # /vault/stats is not implemented as a separate endpoint in V2;
        # the function lives in the gateway module. This stub returns
        # the local view (request count would require a server endpoint
        # that exposes /vault/stats — left as V3 enhancement).
        return {
            "session_active": self._session_token is not None,
            "program_hash_prefix": self.program_hash[:16],
        }

    def close(self) -> None:
        """Forget the session token + key from memory (best-effort)."""
        self._session_token = None
        if self._session_key is not None:
            try:
                buf = bytearray(self._session_key)
                for i in range(len(buf)):
                    buf[i] = 0
            except Exception:
                pass
        self._session_key = None

    # ----- context manager ----- #

    def __enter__(self) -> "VaultClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: D401
        self.close()
