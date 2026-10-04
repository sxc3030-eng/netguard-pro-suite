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
Argus <-> Mythos Tool Gateway V1 (loopback REST).

This is the action-half of the Mythos plug interface. Where the bus is
read-only fan-out, the gateway accepts commands: Mythos POSTs JSON to a
named tool, the gateway validates the params against the tool's schema,
asks the user for approval if the tool is risky, runs the handler, and
returns a structured result with an audit signature.

Wire
----
* Bind: ``http://127.0.0.1:8768`` (NEVER 0.0.0.0). Default port intentionally
  differs from the bus (8767) so the two components can be lifecycled
  independently.
* Auth: ``Authorization: Bearer <MYTHOS_BUS_TOKEN>`` on every request.
  Wrong/missing token => 401. The token comes from the same vault key
  used by the bus, so installing the cage is one-knob.
* Discovery: ``GET /tools`` returns metadata for every registered tool
  (no handlers, only name/description/schema/needs_approval). Mythos uses
  this to populate its tool list.
* Invocation: ``POST /tools/<name>`` with body ``{"params": {...}}``.
  - 200 + ``{"result": ..., "decision_id": "...", "audit_signature": "..."}``
    on success.
  - 400 + ``{"error": "schema"}`` when params don't validate.
  - 401 + ``{"error": "unauthorized"}`` on bad/missing token.
  - 403 + ``{"error": "approval_rejected"}`` if the user denies (or times
    out — default 30s).
  - 404 + ``{"error": "unknown_tool"}`` for unregistered names.
  - 500 + ``{"error": "handler_error", "detail": ...}`` on exceptions.

Audit
-----
Every invocation is logged via ``argus_surveillance.surveil_log_event``
under the ``user_action`` event type with a ``source: "mythos"`` tag. The
HMAC chain in surveillance gives tamper-evidence; the gateway just
forwards. ``params_hash`` (sha256 of canonical JSON, first 16 hex) is
recorded instead of raw params.

Approval flow
-------------
1. Tools with ``needs_approval=True`` block until the UI returns a
   bool. The UI registers a callable via ``gateway_set_approval_handler``.
2. Default timeout is ``APPROVAL_TIMEOUT_SECONDS`` (30s). Timing out
   counts as a rejection.
3. ``audit_irreversible=True`` is a stronger tier: the approval handler
   sees a flag in the params dict (``__irreversible__: True``) so the UI
   can require 2FA. Behaviour is otherwise identical to the standard
   approval gate.

Threading model
---------------
The HTTP server runs on its own background thread (``ThreadingHTTPServer``
spawns one thread per request). Tool handlers run on the request thread.
The approval handler is invoked synchronously from the request thread,
so the UI side typically uses a Qt cross-thread signal to pop a dialog
on the main thread and wait on a ``threading.Event``.

GPL v3 — see LICENSE.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

_LOG = logging.getLogger("argus.mythos.gateway")

VAULT_TOKEN_KEY = "MYTHOS_BUS_TOKEN"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8768
APPROVAL_TIMEOUT_SECONDS = 30.0
PROTOCOL_VERSION = "1.0"


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #


@dataclass
class ToolDefinition:
    """A single callable tool exposed to Mythos."""

    name: str
    description: str
    schema: Dict[str, Any]              # minimal JSON schema for params
    needs_approval: bool
    handler: Callable[[Dict[str, Any]], Any]
    audit_irreversible: bool = False


@dataclass
class _GatewayState:
    """Module-level singleton container."""

    running: bool = False
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    token: Optional[str] = None
    tools: Dict[str, ToolDefinition] = field(default_factory=dict)
    approval_handler: Optional[Callable[[str, Dict[str, Any]], bool]] = None
    approval_timeout: float = APPROVAL_TIMEOUT_SECONDS
    server: Optional[ThreadingHTTPServer] = None
    thread: Optional[threading.Thread] = None
    invocations: int = 0
    rejected: int = 0
    errors: int = 0


_STATE = _GatewayState()
_STATE_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# Token bootstrap (shared with the bus — one knob to install the cage)
# --------------------------------------------------------------------------- #


def _acquire_token() -> str:
    try:
        import argus_vault  # type: ignore
    except Exception:
        argus_vault = None  # type: ignore[assignment]

    if argus_vault is not None:
        try:
            if argus_vault.vault_exists():
                stored = argus_vault.vault_get(VAULT_TOKEN_KEY)
                if stored:
                    return stored
                fresh = secrets.token_hex(32)
                try:
                    argus_vault.vault_set(
                        VAULT_TOKEN_KEY, fresh, owner="mythos_gateway"
                    )
                    return fresh
                except Exception as exc:  # pragma: no cover - defensive
                    _LOG.warning(
                        "vault_set failed for MYTHOS_BUS_TOKEN: %s", exc
                    )
        except Exception as exc:
            _LOG.warning(
                "vault unavailable for mythos token, falling back: %s", exc
            )

    _LOG.warning(
        "argus_mythos_gateway: vault unavailable, using process-local token"
    )
    return secrets.token_hex(32)


# --------------------------------------------------------------------------- #
# Schema validation (deliberately tiny — no jsonschema dep)
# --------------------------------------------------------------------------- #


_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _validate_params(params: Any, schema: Dict[str, Any]) -> Optional[str]:
    """Return None if valid, else a human-readable error string.

    Supports a minimal subset of JSON-schema: ``type``, ``properties``,
    ``required``, and per-field ``type``. Extra params are tolerated
    unless ``additionalProperties`` is False.
    """
    if not isinstance(schema, dict):
        return "schema must be an object"
    schema_type = schema.get("type", "object")
    py_type = _TYPE_MAP.get(schema_type)
    if py_type is None:
        return f"unsupported schema type: {schema_type}"
    if not isinstance(params, py_type):
        # Special case: bool is an int subclass in Python. Treat them
        # distinctly so we don't accept True for "integer".
        if schema_type == "integer" and isinstance(params, bool):
            return "params must be integer, got boolean"
        if schema_type == "number" and isinstance(params, bool):
            return "params must be number, got boolean"
        return f"params must be {schema_type}"

    if schema_type != "object":
        return None

    properties = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    additional = schema.get("additionalProperties", True)

    for key in required:
        if key not in params:
            return f"missing required field: {key}"

    for key, value in params.items():
        if key in properties:
            sub = properties[key]
            err = _validate_params(value, sub)
            if err is not None:
                return f"{key}: {err}"
        elif additional is False:
            return f"unexpected field: {key}"
    return None


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def _params_hash(params: Dict[str, Any]) -> str:
    try:
        canonical = json.dumps(params, sort_keys=True, default=str).encode("utf-8")
    except Exception:
        canonical = repr(params).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


def _audit_invoke(
    tool_name: str,
    params: Dict[str, Any],
    decision_id: str,
    outcome: str,
) -> str:
    """Log to surveillance and return an audit signature.

    Returns sha256(decision_id || tool_name || params_hash || outcome)[:16].
    The HMAC chain is owned by surveillance; this short signature is just
    a stable handle that Mythos can reference in follow-up calls.
    """
    p_hash = _params_hash(params)
    sig_src = f"{decision_id}|{tool_name}|{p_hash}|{outcome}".encode("utf-8")
    sig = hashlib.sha256(sig_src).hexdigest()[:16]

    try:
        from argus_surveillance import surveil_log_event  # type: ignore
    except ImportError:
        return sig
    except Exception:
        return sig
    try:
        surveil_log_event("user_action", {
            "source": "mythos",
            "tool": tool_name,
            "params_hash": p_hash,
            "decision_id": decision_id,
            "outcome": outcome,
            "audit_signature": sig,
        })
    except Exception:
        # Never let surveillance failure break a tool call.
        pass
    return sig


# Bus mirror — best-effort.
def _bus_mirror(topic: str, payload: Dict[str, Any]) -> None:
    try:
        from argus_mythos_bus import bus_publish  # type: ignore
    except ImportError:
        return
    except Exception:
        return
    try:
        bus_publish(topic, payload)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Stub tool handlers (real wiring lands in argus_pyqt later)
# --------------------------------------------------------------------------- #


def _stub_handler(name: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    def _handler(params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "stubbed",
            "tool": name,
            "params": params,
            "ts_iso": datetime.now(timezone.utc).isoformat(),
        }
    return _handler


# Concrete read-only tools we can implement now without UI wiring.
def _query_history(params: Dict[str, Any]) -> Dict[str, Any]:
    n = int(params.get("limit", 50))
    n = max(1, min(n, 1000))
    try:
        from argus_surveillance import surveil_query  # type: ignore
        events = surveil_query(limit=n)
    except Exception as exc:
        return {"status": "unavailable", "error": str(exc), "events": []}
    return {"status": "ok", "events": list(events)[-n:], "count": min(len(events), n)}


def _query_arbiter_decisions(params: Dict[str, Any]) -> Dict[str, Any]:
    n = int(params.get("limit", 50))
    n = max(1, min(n, 1000))
    try:
        from argus_surveillance import surveil_query  # type: ignore
        events = surveil_query(event_type="arbiter_decision", limit=n)
    except Exception as exc:
        return {"status": "unavailable", "error": str(exc), "decisions": []}
    return {"status": "ok", "decisions": list(events)[-n:]}


def _query_stats(params: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": "ok"}
    try:
        from argus_surveillance import surveil_stats  # type: ignore
        out["surveillance"] = surveil_stats()
    except Exception:
        out["surveillance"] = None
    try:
        from argus_mythos_bus import bus_stats  # type: ignore
        out["bus"] = bus_stats()
    except Exception:
        out["bus"] = None
    out["gateway"] = {
        "invocations": _STATE.invocations,
        "rejected": _STATE.rejected,
        "errors": _STATE.errors,
        "tools_registered": len(_STATE.tools),
    }
    return out


# --------------------------------------------------------------------------- #
# Built-in tool registry
# --------------------------------------------------------------------------- #


def _builtin_tools() -> List[ToolDefinition]:
    return [
        ToolDefinition(
            name="query_history",
            description="Return recent surveillance events (read-only).",
            schema={
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
                "additionalProperties": True,
            },
            needs_approval=False,
            handler=_query_history,
        ),
        ToolDefinition(
            name="query_arbiter_decisions",
            description="Return recent arbiter decisions (read-only).",
            schema={
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
                "additionalProperties": True,
            },
            needs_approval=False,
            handler=_query_arbiter_decisions,
        ),
        ToolDefinition(
            name="query_stats",
            description="Return aggregate surveillance + bus + gateway counters.",
            schema={"type": "object", "properties": {},
                    "additionalProperties": True},
            needs_approval=False,
            handler=_query_stats,
        ),
        ToolDefinition(
            name="set_mode",
            description="Switch Argus browser mode (normal | private | vault).",
            schema={
                "type": "object",
                "properties": {"mode": {"type": "string"}},
                "required": ["mode"],
                "additionalProperties": False,
            },
            needs_approval=True,
            handler=_stub_handler("set_mode"),
        ),
        ToolDefinition(
            name="block_url",
            description="Add a URL pattern to the user blocklist.",
            schema={
                "type": "object",
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"],
                "additionalProperties": True,
            },
            needs_approval=True,
            handler=_stub_handler("block_url"),
        ),
        ToolDefinition(
            name="unblock_url",
            description="Remove a URL pattern from the user blocklist.",
            schema={
                "type": "object",
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"],
                "additionalProperties": True,
            },
            needs_approval=True,
            handler=_stub_handler("unblock_url"),
        ),
        ToolDefinition(
            name="run_arbiter",
            description="Re-run the arbiter on a context (read-only, no side effects).",
            schema={
                "type": "object",
                "properties": {"context": {"type": "object"}},
                "required": ["context"],
                "additionalProperties": True,
            },
            needs_approval=False,
            handler=_stub_handler("run_arbiter"),
        ),
        ToolDefinition(
            name="clear_history",
            description="Wipe surveillance events for a given date (irreversible).",
            schema={
                "type": "object",
                "properties": {"date": {"type": "string"}},
                "required": ["date"],
                "additionalProperties": False,
            },
            needs_approval=True,
            handler=_stub_handler("clear_history"),
            audit_irreversible=True,
        ),
        ToolDefinition(
            name="export_audit",
            description="Export surveillance events as JSONL.",
            schema={
                "type": "object",
                "properties": {"date": {"type": "string"}},
                "additionalProperties": True,
            },
            needs_approval=False,
            handler=_stub_handler("export_audit"),
        ),
        ToolDefinition(
            name="request_screenshot",
            description="Capture a screenshot of the current Argus tab.",
            schema={"type": "object", "properties": {},
                    "additionalProperties": True},
            needs_approval=True,
            handler=_stub_handler("request_screenshot"),
        ),
        ToolDefinition(
            name="notify_user",
            description="Push a non-modal toast notification in the Argus UI.",
            schema={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "level": {"type": "string"},
                },
                "required": ["message"],
                "additionalProperties": True,
            },
            needs_approval=False,
            handler=_stub_handler("notify_user"),
        ),
    ]


def _ensure_builtins_registered() -> None:
    if _STATE.tools:
        return
    for tool in _builtin_tools():
        _STATE.tools[tool.name] = tool


# --------------------------------------------------------------------------- #
# Public registration API
# --------------------------------------------------------------------------- #


def gateway_register_tool(tool: ToolDefinition) -> None:
    """Register a tool. Idempotent: re-registration overwrites."""
    if not isinstance(tool, ToolDefinition):
        raise TypeError("tool must be a ToolDefinition")
    if not tool.name or not isinstance(tool.name, str):
        raise ValueError("tool.name must be a non-empty string")
    if not callable(tool.handler):
        raise TypeError("tool.handler must be callable")
    with _STATE_LOCK:
        _STATE.tools[tool.name] = tool


def gateway_unregister_tool(name: str) -> bool:
    with _STATE_LOCK:
        return _STATE.tools.pop(name, None) is not None


def gateway_list_tools() -> List[Dict[str, Any]]:
    """Return tool metadata (no handlers). Safe to expose to Mythos."""
    _ensure_builtins_registered()
    return [
        {
            "name": t.name,
            "description": t.description,
            "schema": t.schema,
            "needs_approval": t.needs_approval,
            "audit_irreversible": t.audit_irreversible,
        }
        for t in _STATE.tools.values()
    ]


def gateway_set_approval_handler(
    handler: Callable[[str, Dict[str, Any]], bool]
) -> None:
    """The UI registers a function ``(tool_name, params) -> bool``."""
    if not callable(handler):
        raise TypeError("handler must be callable")
    _STATE.approval_handler = handler


def gateway_set_approval_timeout(seconds: float) -> None:
    """Override the default 30s approval timeout (tests use a small value)."""
    if seconds <= 0:
        raise ValueError("timeout must be positive")
    _STATE.approval_timeout = float(seconds)


# --------------------------------------------------------------------------- #
# Approval helper (synchronous, with timeout)
# --------------------------------------------------------------------------- #


def _await_approval(tool_name: str, params: Dict[str, Any],
                    irreversible: bool) -> bool:
    """Run the approval handler in a thread; reject on timeout."""
    handler = _STATE.approval_handler
    if handler is None:
        return False  # fail-closed: no UI registered, no risky calls
    payload = dict(params)
    if irreversible:
        payload["__irreversible__"] = True

    result_holder: Dict[str, Any] = {"approved": False, "done": False}
    done = threading.Event()

    def _runner() -> None:
        try:
            ok = bool(handler(tool_name, payload))
        except Exception as exc:
            _LOG.warning("approval handler raised: %s", exc)
            ok = False
        result_holder["approved"] = ok
        result_holder["done"] = True
        done.set()

    t = threading.Thread(target=_runner, name=f"approval-{tool_name}",
                         daemon=True)
    t.start()
    if not done.wait(timeout=_STATE.approval_timeout):
        return False
    return result_holder["approved"]


# --------------------------------------------------------------------------- #
# HTTP request handler
# --------------------------------------------------------------------------- #


class _Handler(BaseHTTPRequestHandler):
    server_version = "ArgusMythosGateway/1.0"
    sys_version = ""

    # Quiet the default per-request stderr line — surveillance is the audit
    # trail of record.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        _LOG.debug("%s - %s", self.address_string(), format % args)

    def _write_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _check_token(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return False
        return auth[7:].strip() == _STATE.token

    def do_GET(self) -> None:  # noqa: N802
        if not self._check_token():
            self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if self.path.rstrip("/") == "/tools":
            self._write_json(HTTPStatus.OK, {
                "protocol": PROTOCOL_VERSION,
                "tools": gateway_list_tools(),
            })
            return
        if self.path.rstrip("/") == "/health":
            self._write_json(HTTPStatus.OK, {"status": "ok",
                                             "protocol": PROTOCOL_VERSION})
            return
        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        # Drain the request body BEFORE any early error reply: answering 401/404
        # with unread bytes still in the socket makes Windows reset the connection
        # (WinError 10053 on the client, flaky tests).
        try:
            _pending = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            _pending = 0
        _prefetched = self.rfile.read(min(_pending, 1 << 20)) if _pending > 0 else b""

        if not self._check_token():
            self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return

        if not self.path.startswith("/tools/"):
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        tool_name = self.path[len("/tools/"):].strip("/")
        if not tool_name:
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        _ensure_builtins_registered()
        tool = _STATE.tools.get(tool_name)
        if tool is None:
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "unknown_tool",
                                                    "tool": tool_name})
            return

        # Body was read up front (see top of do_POST)
        raw = _prefetched
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        if not isinstance(body, dict):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_body"})
            return
        params = body.get("params", {})
        if not isinstance(params, dict):
            self._write_json(HTTPStatus.BAD_REQUEST,
                             {"error": "params_must_be_object"})
            return

        # Validate
        err = _validate_params(params, tool.schema)
        if err is not None:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "schema",
                                                      "detail": err})
            return

        decision_id = uuid.uuid4().hex

        # Approval gate
        if tool.needs_approval:
            ok = _await_approval(tool.name, params, tool.audit_irreversible)
            if not ok:
                _STATE.rejected += 1
                sig = _audit_invoke(tool.name, params, decision_id, "rejected")
                _bus_mirror("user/action", {
                    "source": "mythos",
                    "tool": tool.name,
                    "outcome": "rejected",
                    "decision_id": decision_id,
                })
                self._write_json(HTTPStatus.FORBIDDEN, {
                    "error": "approval_rejected",
                    "decision_id": decision_id,
                    "audit_signature": sig,
                })
                return

        _STATE.invocations += 1

        # Execute
        try:
            result = tool.handler(params)
        except Exception as exc:
            _STATE.errors += 1
            sig = _audit_invoke(tool.name, params, decision_id, "error")
            self._write_json(HTTPStatus.INTERNAL_SERVER_ERROR, {
                "error": "handler_error",
                "detail": str(exc),
                "decision_id": decision_id,
                "audit_signature": sig,
            })
            return

        sig = _audit_invoke(tool.name, params, decision_id, "ok")
        _bus_mirror("user/action", {
            "source": "mythos",
            "tool": tool.name,
            "outcome": "ok",
            "decision_id": decision_id,
        })
        self._write_json(HTTPStatus.OK, {
            "result": result,
            "decision_id": decision_id,
            "audit_signature": sig,
        })


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


def gateway_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Start the gateway HTTP server in a background thread. Idempotent."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("argus_mythos_gateway binds to localhost only")
    with _STATE_LOCK:
        if _STATE.running:
            return
        _STATE.token = _acquire_token()
        _STATE.host = host
        _STATE.port = port
        _ensure_builtins_registered()

        server = ThreadingHTTPServer((host, port), _Handler)
        _STATE.server = server
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.2},
            name="argus-mythos-gateway",
            daemon=True,
        )
        thread.start()
        _STATE.thread = thread
        _STATE.running = True


def gateway_stop() -> None:
    """Stop the gateway. Idempotent."""
    with _STATE_LOCK:
        if not _STATE.running:
            return
        server = _STATE.server
        thread = _STATE.thread
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        if thread is not None:
            thread.join(timeout=3.0)
        _STATE.running = False
        _STATE.server = None
        _STATE.thread = None


def gateway_get_token() -> Optional[str]:
    """Return the active bearer token (UI displays for first-run setup)."""
    return _STATE.token


def gateway_stats() -> Dict[str, Any]:
    return {
        "running": _STATE.running,
        "host": _STATE.host,
        "port": _STATE.port,
        "invocations": _STATE.invocations,
        "rejected": _STATE.rejected,
        "errors": _STATE.errors,
        "tools_registered": len(_STATE.tools),
    }


def gateway_reset_for_tests() -> None:
    """Wipe registry + counters. Test-only helper."""
    with _STATE_LOCK:
        _STATE.tools.clear()
        _STATE.approval_handler = None
        _STATE.approval_timeout = APPROVAL_TIMEOUT_SECONDS
        _STATE.invocations = 0
        _STATE.rejected = 0
        _STATE.errors = 0
