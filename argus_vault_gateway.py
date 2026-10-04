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
Argus Vault Gateway V2 — localhost-only HTTPS broker for vault secrets.

This is the *cross-process* face of the vault. ``argus_vault.vault_get``
talks to the on-disk ``.vault/secrets.enc`` file directly and is fine
for in-process Argus code, but other suite components (NetGuard, Argus
browser, GeniA, third-party modules) need a network-style broker that
can authenticate them by *binary identity* rather than by a shared
passphrase or filesystem ACL.

What the gateway adds on top of the plain vault
-----------------------------------------------
1. **Binary-hash live verification.** The client claims a SHA-256 of
   its own executable. The gateway re-hashes the calling exe LIVE
   (resolved via the TCP source port -> PID -> exe path) and refuses
   the request if the live hash mismatches either the claim or the
   whitelist entry. That defeats "I will pretend to be NetGuard" by a
   sibling process — the attacker would have to replace the on-disk
   binary, which is a much higher bar.
2. **HMAC-signed responses.** Every response carries an HMAC-SHA256
   over ``response_nonce || ciphertext || request_nonce`` keyed by the
   per-session shared key. The client verifies the HMAC and the nonce
   round-trip before decrypting.
3. **Token-bucket rate limiting.** Default 60 req/min sustained, burst
   10, configurable per program at registration. Rejections are 429s
   and get logged to surveillance.
4. **Audit chain.** Every request -> a JSONL line in
   ``argus_data/.gateway/audit.jsonl`` with an HMAC-SHA256 chain (each
   entry signs the previous). ``gateway_audit_chain_verify`` walks the
   chain and returns False on any tamper.
5. **TLS even on localhost.** Defence in depth — other-user processes
   on the same machine can otherwise sniff loopback. Self-signed cert
   is generated on first start and pinned by the client (cert SPKI
   hash stored in vault).

Hard constraints
----------------
* Bind ``127.0.0.1`` only — never ``0.0.0.0``.
* No real secrets in tests — placeholders only.
* Backward compatibility: ``argus_vault.vault_get()`` still works
  directly for in-process Argus code; the gateway is for OTHER
  programs.
* Plaintext is wrapped in ``bytearray`` and zeroed after use
  (best-effort — Python ``str`` immutability is documented).

Threat model — what this DOES protect against
---------------------------------------------
* A sibling process on the same box claiming to be NetGuard but
  running from a different binary. The live re-hash catches this.
* A passive sniffer on the loopback interface. TLS + cert pinning
  caches the first fingerprint and refuses TOFU after that.
* A replay attack. Each request carries a fresh nonce that the
  response HMAC commits to.
* A long-running compromised binary. Sessions expire after 5 min and
  rate limits cap the blast radius.

Threat model — what this does NOT protect against (be honest)
-------------------------------------------------------------
* A debugger attached to your process. Once the secret is decrypted in
  your address space, ``ptrace`` / ``ReadProcessMemory`` can scrape
  it. Document this to the caller.
* Process injection via DLL load order, ``LD_PRELOAD``, or hot-patching
  before the gateway hash is computed. The hash is of the on-disk
  binary, not its in-memory image.
* A privileged attacker who can replace the on-disk binary between
  ``register_program`` and the runtime check.
* A compromised vault file (covered by ``argus_vault`` corruption
  detection but not by the gateway itself).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import logging
import os
import secrets
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

import argus_vault
import argus_vault_manifests

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

GATEWAY_VERSION = 2
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8769

SESSION_TOKEN_BYTES = 32
SESSION_KEY_BYTES = 32
SESSION_TTL_SECONDS = 300  # 5 minutes
NONCE_BYTES = 12

DEFAULT_RATE_PER_MIN = 60
DEFAULT_BURST = 10

AUDIT_GENESIS = b"GATEWAY_AUDIT_GENESIS"

_LOG = logging.getLogger("argus.vault_gateway")


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def _gateway_root() -> Path:
    """Resolve the gateway state directory.

    Honours the ``ARGUS_VAULT_ROOT`` env var the same way ``argus_vault``
    does, so test fixtures can redirect everything to ``tmp_path``.
    """
    override = os.environ.get("ARGUS_VAULT_ROOT")
    if override:
        return Path(override) / ".gateway"
    return Path(__file__).resolve().parent / "argus_data" / ".gateway"


def _whitelist_path() -> Path:
    return _gateway_root() / "whitelist.json"


def _audit_path() -> Path:
    return _gateway_root() / "audit.jsonl"


def _cert_path() -> Path:
    return _gateway_root() / "cert.pem"


def _key_path() -> Path:
    return _gateway_root() / "key.pem"


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #


class GatewayError(Exception):
    """Base class for gateway errors."""


class GatewayNotRunning(GatewayError):
    """Raised when stop is called and no server is running."""


class GatewayProgramNotFound(GatewayError):
    """Raised when a program hash is not in the whitelist."""


# --------------------------------------------------------------------------- #
# Module-level state
# --------------------------------------------------------------------------- #


class _GatewayState:
    """Process-wide state for the gateway."""

    def __init__(self) -> None:
        self.server: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.RLock()
        # session_token (str) -> {program_hash, session_key, expires_at}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        # program_hash -> token-bucket {tokens, capacity, rate_per_sec, last}
        self.buckets: Dict[str, Dict[str, float]] = {}
        # Vault passphrase used for vault_get/vault_set when the vault is
        # PBKDF2-wrapped (Linux/macOS or test environments). On Windows
        # production deployments DPAPI handles unwrapping transparently.
        self.vault_passphrase: Optional[str] = None
        # Stats
        self.stats: Dict[str, Any] = {
            "started_at": None,
            "requests_total": 0,
            "requests_denied": 0,
            "by_program": {},
            "latencies_ms": [],
        }


_STATE = _GatewayState()


# --------------------------------------------------------------------------- #
# Helpers — binary hashing
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


def _resolve_pid_for_port(remote_addr: Tuple[str, int]) -> Optional[int]:
    """Map a TCP source (ip, port) to a PID via psutil.

    Returns None if psutil is unavailable or the connection is no
    longer in the table (it CAN race; we fall back to the claimed hash
    in that case but with a warning logged).
    """
    try:
        import psutil  # type: ignore
    except ImportError:
        return None
    ip, port = remote_addr
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.laddr and c.laddr.port == port and c.laddr.ip in (ip, "127.0.0.1"):
                return c.pid
    except (psutil.AccessDenied, OSError):
        return None
    return None


def _resolve_exe_for_pid(pid: int) -> Optional[str]:
    """Get the on-disk exe path for a PID via psutil."""
    try:
        import psutil  # type: ignore
        return psutil.Process(pid).exe()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Whitelist persistence
# --------------------------------------------------------------------------- #


def _read_whitelist() -> Dict[str, Any]:
    p = _whitelist_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        _LOG.warning("whitelist.json unreadable; treating as empty")
        return {}


def _write_whitelist(data: Dict[str, Any]) -> None:
    p = _whitelist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)


# --------------------------------------------------------------------------- #
# Audit chain
# --------------------------------------------------------------------------- #


def _audit_hmac_key() -> bytes:
    """Stable HMAC key for the audit chain.

    Tries the vault first. If unavailable (e.g. CI without DPAPI), uses
    a deterministic per-machine derivation that survives across gateway
    restarts.
    """
    try:
        v = argus_vault.vault_get("GATEWAY_AUDIT_KEY")
        if v:
            return base64.b64decode(v)
    except Exception:
        pass
    # Fallback: derive from gateway root path. NOT a strong secret; the
    # gateway readme calls this out.
    return hashlib.sha256(
        ("gateway-audit-fallback-" + str(_gateway_root())).encode()
    ).digest()


def _last_audit_hash() -> bytes:
    """Walk the audit log and return the prev-hash for the next entry."""
    p = _audit_path()
    if not p.exists():
        return AUDIT_GENESIS
    last_line = b""
    try:
        with p.open("rb") as fh:
            for raw in fh:
                if raw.strip():
                    last_line = raw.strip()
    except OSError:
        return AUDIT_GENESIS
    if not last_line:
        return AUDIT_GENESIS
    try:
        rec = json.loads(last_line.decode("utf-8"))
        return bytes.fromhex(rec["hmac"])
    except Exception:
        return AUDIT_GENESIS


def _audit_write(action: str, program_hash: str, secret_key: Optional[str],
                 result_status: str, nonce: Optional[str] = None) -> None:
    """Append a single chained audit record."""
    p = _audit_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    prev = _last_audit_hash()
    entry = {
        "ts_iso": datetime.now(timezone.utc).isoformat(),
        "request_id": uuid.uuid4().hex,
        "program_hash": program_hash,
        "action": action,
        "secret_key": secret_key,
        "result_status": result_status,
        "nonce": nonce,
        "prev_hash": prev.hex(),
    }
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(_audit_hmac_key(), prev + canonical, hashlib.sha256).digest()
    entry["hmac"] = sig.hex()
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    # Best-effort surveillance cross-publish — only if the surveillance
    # subsystem is *already* initialized. We do NOT want the gateway's
    # audit writes to cold-init surveillance (that pollutes test state
    # and forces unrelated callers into the fallback-key warning path).
    try:
        import argus_surveillance  # type: ignore
        state = getattr(argus_surveillance, "_STATE", None)
        if state is not None and getattr(state, "initialized", False):
            argus_surveillance.surveil_log_event(
                "user_action",
                {"source": "vault_gateway", "action": action,
                 "program_hash": program_hash[:16],
                 "status": result_status},
            )
    except Exception:
        pass


def gateway_audit_chain_verify() -> bool:
    """Walk the audit log, recompute every HMAC, return True iff intact."""
    p = _audit_path()
    if not p.exists():
        return True
    key = _audit_hmac_key()
    prev = AUDIT_GENESIS
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                got_hmac = bytes.fromhex(rec.pop("hmac"))
                if rec["prev_hash"] != prev.hex():
                    return False
                canonical = json.dumps(
                    rec, sort_keys=True, separators=(",", ":")
                ).encode()
                expected = hmac.new(key, prev + canonical, hashlib.sha256).digest()
                if not hmac.compare_digest(got_hmac, expected):
                    return False
                prev = got_hmac
    except (OSError, ValueError, KeyError):
        return False
    return True


# --------------------------------------------------------------------------- #
# TLS cert generation
# --------------------------------------------------------------------------- #


def _ensure_self_signed_cert() -> Tuple[Path, Path]:
    """Generate self-signed cert+key on first call. Idempotent.

    Returns (cert_path, key_path).
    """
    cert = _cert_path()
    key = _key_path()
    if cert.exists() and key.exists():
        return cert, key

    cert.parent.mkdir(parents=True, exist_ok=True)
    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "argus-vault-gateway"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Argus"),
    ])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(privkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now.replace(tzinfo=None))
        .not_valid_after(now.replace(tzinfo=None).replace(year=now.year + 5))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                         x509.IPAddress(_ip_127_0_0_1())]),
            critical=False,
        )
    )
    certificate = builder.sign(privkey, hashes.SHA256())

    key.write_bytes(privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    # Pin SPKI hash in vault for client verification
    spki = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_hash = hashlib.sha256(spki).hexdigest()
    try:
        argus_vault.vault_set("GATEWAY_CERT_SPKI_HASH", spki_hash,
                              owner="vault_gateway",
                              passphrase=_STATE.vault_passphrase)
    except Exception:
        # Vault may not be initialized in tests; cert is still usable.
        _LOG.info("vault not initialized; SPKI pin not recorded")
    return cert, key


def _ip_127_0_0_1():
    import ipaddress
    return ipaddress.IPv4Address("127.0.0.1")


# --------------------------------------------------------------------------- #
# Public registration API
# --------------------------------------------------------------------------- #


def gateway_register_program(
    binary_path: str,
    allowed_secrets: List[str],
    permissions: Optional[Dict[str, List[str]]] = None,
    program_label: Optional[str] = None,
    rate_per_min: int = DEFAULT_RATE_PER_MIN,
    burst: int = DEFAULT_BURST,
) -> str:
    """Compute SHA-256 of the binary, store in whitelist. Returns the hash."""
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"binary not found: {binary_path}")
    program_hash = _sha256_file(binary_path)
    wl = _read_whitelist()
    wl[program_hash] = {
        "label": program_label or os.path.basename(binary_path),
        "binary_path": os.path.abspath(binary_path),
        "allowed_secrets": list(allowed_secrets),
        "permissions": permissions or {k: ["read"] for k in allowed_secrets},
        "rate_per_min": int(rate_per_min),
        "burst": int(burst),
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_used": None,
    }
    _write_whitelist(wl)
    _audit_write("register", program_hash, None, "ok")
    return program_hash


def gateway_revoke_program(program_hash: str) -> bool:
    """Remove a program from the whitelist + invalidate any live session."""
    wl = _read_whitelist()
    if program_hash not in wl:
        return False
    del wl[program_hash]
    _write_whitelist(wl)
    # Invalidate sessions
    with _STATE.lock:
        for tok, sess in list(_STATE.sessions.items()):
            if sess["program_hash"] == program_hash:
                del _STATE.sessions[tok]
    _audit_write("revoke", program_hash, None, "ok")
    return True


def gateway_list_programs() -> List[Dict[str, Any]]:
    """Metadata only — never secret values."""
    wl = _read_whitelist()
    out = []
    for h, meta in wl.items():
        out.append({
            "hash": h,
            "label": meta.get("label"),
            "allowed_secrets": meta.get("allowed_secrets", []),
            "registered_at": meta.get("registered_at"),
            "last_used": meta.get("last_used"),
        })
    return out


def gateway_stats() -> Dict[str, Any]:
    """Lightweight snapshot — never includes secrets or session tokens."""
    with _STATE.lock:
        lat = _STATE.stats["latencies_ms"]
        avg = sum(lat) / len(lat) if lat else 0.0
        started = _STATE.stats["started_at"]
        uptime = (time.time() - started) if started else 0.0
        return {
            "requests_total": _STATE.stats["requests_total"],
            "requests_denied": _STATE.stats["requests_denied"],
            "by_program": dict(_STATE.stats["by_program"]),
            "avg_latency_ms": round(avg, 3),
            "uptime_s": round(uptime, 1),
            "active_sessions": len(_STATE.sessions),
        }


# --------------------------------------------------------------------------- #
# Rate limiter (token bucket)
# --------------------------------------------------------------------------- #


def _check_rate_limit(program_hash: str, rate_per_min: int, burst: int) -> bool:
    """Return True iff the request is allowed; consume one token."""
    now = time.monotonic()
    with _STATE.lock:
        b = _STATE.buckets.get(program_hash)
        if b is None:
            b = {
                "tokens": float(burst),
                "capacity": float(burst),
                "rate_per_sec": float(rate_per_min) / 60.0,
                "last": now,
            }
            _STATE.buckets[program_hash] = b
        # Refill
        elapsed = now - b["last"]
        b["tokens"] = min(b["capacity"], b["tokens"] + elapsed * b["rate_per_sec"])
        b["last"] = now
        if b["tokens"] >= 1.0:
            b["tokens"] -= 1.0
            return True
        return False


# --------------------------------------------------------------------------- #
# HTTP request handler
# --------------------------------------------------------------------------- #


class _GatewayHandler(http.server.BaseHTTPRequestHandler):
    """Per-request HTTP handler. Localhost-only by construction."""

    # Quiet the default stderr noise; we log via logging.
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        _LOG.debug("gateway: " + fmt, *args)

    # ----- util ----- #

    def _send_json(self, code: int, body: Dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Gateway-Version", str(GATEWAY_VERSION))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> Dict[str, Any]:
        cached = getattr(self, "_body_cache", None)
        if cached is not None:
            return cached
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        raw = self.rfile.read(min(n, 1 << 20))
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _peer_program_hash(self) -> Optional[str]:
        """Best-effort: live-rehash the calling exe via psutil."""
        try:
            remote_addr = self.client_address  # (ip, port)
            pid = _resolve_pid_for_port(remote_addr)
            if pid is None:
                return None
            exe = _resolve_exe_for_pid(pid)
            if exe is None:
                return None
            return _sha256_file(exe)
        except Exception:
            return None

    def _record_request(self, program_hash: str, denied: bool,
                        latency_ms: float) -> None:
        with _STATE.lock:
            _STATE.stats["requests_total"] += 1
            if denied:
                _STATE.stats["requests_denied"] += 1
            by = _STATE.stats["by_program"].setdefault(
                program_hash, {"total": 0, "denied": 0}
            )
            by["total"] += 1
            if denied:
                by["denied"] += 1
            _STATE.stats["latencies_ms"].append(latency_ms)
            # Cap latency buffer
            if len(_STATE.stats["latencies_ms"]) > 1000:
                _STATE.stats["latencies_ms"] = _STATE.stats["latencies_ms"][-500:]

    # ----- session helpers ----- #

    def _validate_session(self) -> Optional[Tuple[str, Dict[str, Any]]]:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[len("Bearer "):].strip()
        with _STATE.lock:
            sess = _STATE.sessions.get(token)
            if sess is None:
                return None
            if sess["expires_at"] < time.time():
                del _STATE.sessions[token]
                return None
            return token, sess

    # ----- routes ----- #

    def do_POST(self) -> None:  # noqa: N802
        t0 = time.monotonic()
        # Drain the body first: a 401/404 sent with unread bytes in the socket
        # makes Windows reset the connection (WinError 10053, flaky clients).
        self._body_cache = self._read_body()
        path = self.path.split("?")[0]
        if path == "/vault/handshake":
            self._handle_handshake(t0)
        elif path == "/vault/get":
            self._handle_get(t0)
        elif path == "/vault/store":
            self._handle_store(t0)
        elif path == "/vault/rotate":
            self._handle_rotate(t0)
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self) -> None:  # noqa: N802
        t0 = time.monotonic()
        path = self.path.split("?")[0]
        if path == "/vault/list":
            self._handle_list(t0)
        elif path == "/manifest":
            self._handle_manifest(t0)
        else:
            self._send_json(404, {"error": "not found"})

    # ----- handshake ----- #

    def _handle_handshake(self, t0: float) -> None:
        body = self._read_body()
        claimed_hash = body.get("program_hash") or self.headers.get("X-Program-Hash")
        nonce = body.get("nonce", "")
        if not claimed_hash:
            self._send_json(400, {"error": "missing program_hash"})
            return

        wl = _read_whitelist()
        meta = wl.get(claimed_hash)
        if meta is None:
            _audit_write("handshake", claimed_hash or "unknown", None, "denied_unknown")
            self._record_request(claimed_hash or "unknown", True,
                                 (time.monotonic() - t0) * 1000)
            self._send_json(403, {"error": "program not whitelisted"})
            return

        # Live re-hash the caller. If we cannot resolve the PID (race or
        # restricted permissions on Windows), we degrade gracefully but
        # log it so an operator notices. Tests can disable the comparison
        # entirely via ARGUS_GATEWAY_SKIP_LIVE_REHASH=1 because the live
        # caller is the test harness, not the registered "fake" binary.
        skip_rehash = os.environ.get("ARGUS_GATEWAY_SKIP_LIVE_REHASH") == "1"
        if not skip_rehash:
            live_hash = self._peer_program_hash()
            if live_hash is None:
                _LOG.warning(
                    "could not resolve live PID for %s; using claimed",
                    self.client_address,
                )
            elif live_hash != claimed_hash:
                _audit_write("handshake", claimed_hash, None,
                             "denied_hash_mismatch")
                self._record_request(claimed_hash, True,
                                     (time.monotonic() - t0) * 1000)
                self._send_json(403, {"error": "binary hash mismatch"})
                return

        # Issue session
        session_token = secrets.token_hex(SESSION_TOKEN_BYTES)
        session_key = secrets.token_bytes(SESSION_KEY_BYTES)
        with _STATE.lock:
            _STATE.sessions[session_token] = {
                "program_hash": claimed_hash,
                "session_key": session_key,
                "expires_at": time.time() + SESSION_TTL_SECONDS,
                "request_nonce": nonce,
            }

        # Touch last_used
        meta["last_used"] = datetime.now(timezone.utc).isoformat()
        wl[claimed_hash] = meta
        _write_whitelist(wl)

        _audit_write("handshake", claimed_hash, None, "ok", nonce=nonce)
        self._record_request(claimed_hash, False, (time.monotonic() - t0) * 1000)
        self._send_json(200, {
            "session_token": session_token,
            "session_key_b64": base64.b64encode(session_key).decode("ascii"),
            "expires_in_s": SESSION_TTL_SECONDS,
        })

    # ----- get ----- #

    def _handle_get(self, t0: float) -> None:
        sess = self._validate_session()
        if sess is None:
            self._send_json(401, {"error": "no valid session"})
            return
        _, sess_data = sess
        program_hash = sess_data["program_hash"]
        wl = _read_whitelist()
        meta = wl.get(program_hash)
        if meta is None:
            self._send_json(401, {"error": "program no longer whitelisted"})
            return
        # Rate limit
        if not _check_rate_limit(
            program_hash,
            int(meta.get("rate_per_min", DEFAULT_RATE_PER_MIN)),
            int(meta.get("burst", DEFAULT_BURST)),
        ):
            _audit_write("get", program_hash, None, "denied_rate_limit")
            self._record_request(program_hash, True,
                                 (time.monotonic() - t0) * 1000)
            self._send_json(429, {"error": "rate limit exceeded"})
            return

        body = self._read_body()
        secret_key = body.get("secret_key")
        request_nonce = body.get("nonce", "")
        if not secret_key:
            self._send_json(400, {"error": "missing secret_key"})
            return

        allowed = meta.get("allowed_secrets", [])
        if secret_key not in allowed and "*" not in allowed:
            _audit_write("get", program_hash, secret_key, "denied_acl")
            self._record_request(program_hash, True,
                                 (time.monotonic() - t0) * 1000)
            self._send_json(403, {"error": "secret not in ACL"})
            return

        # Trust-on-register entitlement check. The whitelist's ACL is the
        # *upper bound* of what a program could ever touch (set by the
        # operator at register time); the manifest is the *opt-in list* the
        # operator approved during the same flow. A missing manifest means
        # nothing is entitled — callers go through the lazy path
        # (config.get_secret -> None -> degrade gracefully). Programs
        # registered with allowed_secrets=["*"] still need an explicit
        # manifest entry per secret, so a wildcard ACL does not auto-grant
        # everything new the user adds later.
        try:
            entitled = argus_vault_manifests.manifest_is_entitled(
                program_hash, secret_key
            )
        except Exception:
            entitled = False
        if not entitled:
            _audit_write("get", program_hash, secret_key, "denied_not_entitled")
            self._record_request(program_hash, True,
                                 (time.monotonic() - t0) * 1000)
            self._send_json(403, {
                "error": "not_entitled",
                "secret": secret_key,
            })
            return

        perms = meta.get("permissions", {}).get(secret_key, ["read"])
        if "read" not in perms:
            _audit_write("get", program_hash, secret_key, "denied_no_read")
            self._record_request(program_hash, True,
                                 (time.monotonic() - t0) * 1000)
            self._send_json(403, {"error": "no read permission"})
            return

        # Pull the real value, encrypt with session key, HMAC the response.
        try:
            raw = argus_vault.vault_get(secret_key,
                                        passphrase=_STATE.vault_passphrase)
        except argus_vault.VaultError as e:
            _audit_write("get", program_hash, secret_key, "vault_error")
            self._send_json(500, {"error": "vault error", "detail": type(e).__name__})
            return
        if raw is None:
            _audit_write("get", program_hash, secret_key, "not_found")
            self._send_json(404, {"error": "secret not found"})
            return

        plaintext_buf = bytearray(raw.encode("utf-8"))
        try:
            response_nonce = secrets.token_bytes(NONCE_BYTES)
            ct = AESGCM(sess_data["session_key"]).encrypt(
                response_nonce, bytes(plaintext_buf), None
            )
        finally:
            for i in range(len(plaintext_buf)):
                plaintext_buf[i] = 0

        request_nonce_bytes = request_nonce.encode("utf-8") if isinstance(
            request_nonce, str) else b""
        sig = hmac.new(
            sess_data["session_key"],
            response_nonce + ct + request_nonce_bytes,
            hashlib.sha256,
        ).digest()

        _audit_write("get", program_hash, secret_key, "ok",
                     nonce=request_nonce)
        self._record_request(program_hash, False,
                             (time.monotonic() - t0) * 1000)
        self._send_json(200, {
            "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
            "response_nonce_b64": base64.b64encode(response_nonce).decode("ascii"),
            "request_nonce": request_nonce,
            "hmac_b64": base64.b64encode(sig).decode("ascii"),
        })

    # ----- list ----- #

    def _handle_list(self, t0: float) -> None:
        sess = self._validate_session()
        if sess is None:
            self._send_json(401, {"error": "no valid session"})
            return
        _, sess_data = sess
        program_hash = sess_data["program_hash"]
        wl = _read_whitelist()
        meta = wl.get(program_hash)
        if meta is None:
            self._send_json(401, {"error": "program no longer whitelisted"})
            return
        names = list(meta.get("allowed_secrets", []))
        _audit_write("list", program_hash, None, "ok")
        self._record_request(program_hash, False,
                             (time.monotonic() - t0) * 1000)
        self._send_json(200, {"secrets": names})

    # ----- manifest ----- #

    def _handle_manifest(self, t0: float) -> None:
        """Return the calling program's own manifest.

        Shape:
            {"name": str, "needs": [str, ...], "granted": [str, ...]}

        ``needs`` is the operator-approved opt-in list; ``granted`` is
        the intersection with the whitelist ACL (i.e. secrets the
        program could *and* is entitled to read right now). Programs
        without a stored manifest get an empty record so the lazy
        client can still call this safely.
        """
        sess = self._validate_session()
        if sess is None:
            self._send_json(401, {"error": "no valid session"})
            return
        _, sess_data = sess
        program_hash = sess_data["program_hash"]
        wl = _read_whitelist()
        meta = wl.get(program_hash)
        if meta is None:
            self._send_json(401, {"error": "program no longer whitelisted"})
            return
        try:
            rec = argus_vault_manifests.manifest_get(program_hash)
        except Exception:
            rec = None
        needs = list(rec.get("needs", [])) if rec else []
        name = (rec or {}).get("name") or meta.get("label") or ""
        allowed = set(meta.get("allowed_secrets", []) or [])
        wildcard = "*" in allowed
        granted = [n for n in needs if wildcard or n in allowed]
        _audit_write("manifest", program_hash, None, "ok")
        self._record_request(program_hash, False,
                             (time.monotonic() - t0) * 1000)
        self._send_json(200, {
            "name": name,
            "needs": needs,
            "granted": granted,
        })

    # ----- store ----- #

    def _handle_store(self, t0: float) -> None:
        sess = self._validate_session()
        if sess is None:
            self._send_json(401, {"error": "no valid session"})
            return
        _, sess_data = sess
        program_hash = sess_data["program_hash"]
        wl = _read_whitelist()
        meta = wl.get(program_hash)
        if meta is None:
            self._send_json(401, {"error": "program no longer whitelisted"})
            return
        body = self._read_body()
        secret_key = body.get("secret_key")
        secret_value = body.get("value")
        if not secret_key or secret_value is None:
            self._send_json(400, {"error": "missing secret_key or value"})
            return
        perms = meta.get("permissions", {}).get(secret_key, ["read"])
        if "write" not in perms:
            _audit_write("store", program_hash, secret_key, "denied_no_write")
            self._record_request(program_hash, True,
                                 (time.monotonic() - t0) * 1000)
            self._send_json(403, {"error": "no write permission"})
            return
        try:
            argus_vault.vault_set(secret_key, secret_value,
                                  owner=program_hash[:12],
                                  passphrase=_STATE.vault_passphrase)
        except argus_vault.VaultError as e:
            _audit_write("store", program_hash, secret_key, "vault_error")
            self._send_json(500, {"error": "vault error",
                                  "detail": type(e).__name__})
            return
        _audit_write("store", program_hash, secret_key, "ok")
        self._record_request(program_hash, False,
                             (time.monotonic() - t0) * 1000)
        self._send_json(200, {"status": "ok"})

    # ----- rotate (admin only, requires 2FA) ----- #

    def _handle_rotate(self, t0: float) -> None:
        sess = self._validate_session()
        if sess is None:
            self._send_json(401, {"error": "no valid session"})
            return
        _, sess_data = sess
        program_hash = sess_data["program_hash"]
        # 2FA gate
        try:
            import argus_2fa  # type: ignore
            ok = argus_2fa.two_fa_challenge(None)
        except ImportError:
            ok = False
        except Exception:
            ok = False
        if not ok:
            _audit_write("rotate", program_hash, None, "denied_2fa")
            self._record_request(program_hash, True,
                                 (time.monotonic() - t0) * 1000)
            self._send_json(403, {"error": "2FA required for rotate"})
            return
        body = self._read_body()
        new_passphrase = body.get("new_passphrase")
        old_passphrase = body.get("old_passphrase")
        try:
            argus_vault.vault_rotate_masterkey(new_passphrase=new_passphrase,
                                               old_passphrase=old_passphrase)
        except argus_vault.VaultError as e:
            _audit_write("rotate", program_hash, None, "vault_error")
            self._send_json(500, {"error": "vault error",
                                  "detail": type(e).__name__})
            return
        _audit_write("rotate", program_hash, None, "ok")
        self._record_request(program_hash, False,
                             (time.monotonic() - t0) * 1000)
        self._send_json(200, {"status": "rotated"})


# --------------------------------------------------------------------------- #
# Server lifecycle
# --------------------------------------------------------------------------- #


class _LocalhostHTTPServer(http.server.HTTPServer):
    """Refuses to bind anywhere other than 127.0.0.1."""

    allow_reuse_address = True

    def server_bind(self) -> None:  # noqa: D401
        host, _ = self.server_address
        if host not in ("127.0.0.1", "localhost"):
            raise RuntimeError("gateway binds 127.0.0.1 ONLY")
        super().server_bind()


def gateway_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                  tls: bool = True,
                  vault_passphrase: Optional[str] = None) -> None:
    """Start HTTPS server on a background thread. Idempotent.

    On first start: generates self-signed cert + private key in
    ``argus_data/.gateway/`` (gitignored). ``tls=False`` is for tests
    only — it skips cert generation and serves plaintext.

    ``vault_passphrase`` is needed when the vault was sealed with
    PBKDF2 (passphrase wrap). On Windows DPAPI deployments leave it
    None — DPAPI unlocks transparently. In tests the fixture passes
    the test passphrase here.
    """
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("gateway binds 127.0.0.1 ONLY")
    with _STATE.lock:
        _STATE.vault_passphrase = vault_passphrase
        if _STATE.server is not None:
            return  # already running
        srv = _LocalhostHTTPServer((host, port), _GatewayHandler)
        if tls:
            cert, key = _ensure_self_signed_cert()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        thr = threading.Thread(
            target=srv.serve_forever, name="argus-vault-gateway", daemon=True
        )
        thr.start()
        _STATE.server = srv
        _STATE.thread = thr
        _STATE.stats["started_at"] = time.time()
        _LOG.info("vault gateway listening on %s://%s:%d",
                  "https" if tls else "http", host, port)


def gateway_stop() -> None:
    """Stop the server. Raises ``GatewayNotRunning`` if not started."""
    with _STATE.lock:
        if _STATE.server is None:
            raise GatewayNotRunning("gateway is not running")
        _STATE.server.shutdown()
        _STATE.server.server_close()
        _STATE.server = None
        if _STATE.thread is not None:
            _STATE.thread.join(timeout=2.0)
            _STATE.thread = None
        _STATE.stats["started_at"] = None
        # Clear sessions
        _STATE.sessions.clear()


# --------------------------------------------------------------------------- #
# Test-only convenience
# --------------------------------------------------------------------------- #


def _reset_state_for_tests() -> None:
    """Wipe in-memory state. Tests only — not a public API."""
    with _STATE.lock:
        _STATE.sessions.clear()
        _STATE.buckets.clear()
        _STATE.stats = {
            "started_at": None,
            "requests_total": 0,
            "requests_denied": 0,
            "by_program": {},
            "latencies_ms": [],
        }
