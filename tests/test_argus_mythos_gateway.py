# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_mythos_gateway.

Each test starts the gateway on a free port, drives it via stdlib
``urllib.request`` (no extra deps), and shuts it down. The approval
handler is replaced per-test to exercise the approval flow without a UI.

No real secrets — placeholder URLs / patterns only.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_mythos_gateway as gw  # noqa: E402


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _request(method: str, port: int, path: str,
             token: Optional[str] = None,
             body: Optional[Dict[str, Any]] = None,
             timeout: float = 5.0) -> Tuple[int, Dict[str, Any]]:
    """Issue an HTTP call and return (status, json_body)."""
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except Exception:
            payload = {}
        return exc.code, payload


@pytest.fixture(autouse=True)
def _isolated_gateway(tmp_path, monkeypatch):
    """Reset registry + redirect vault per test."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    if gw._STATE.running:
        gw.gateway_stop()
    gw.gateway_reset_for_tests()
    # Force the bootstrapped (empty) registry to repopulate.
    yield tmp_path
    if gw._STATE.running:
        gw.gateway_stop()
    gw.gateway_reset_for_tests()


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def test_list_tools_returns_registered():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()
    assert token and len(token) >= 32

    status, body = _request("GET", port, "/tools", token=token)
    assert status == 200
    assert body["protocol"] == "1.0"
    names = {t["name"] for t in body["tools"]}
    # Built-ins must all be present.
    for required in (
        "query_history", "query_arbiter_decisions", "query_stats",
        "set_mode", "block_url", "unblock_url", "run_arbiter",
        "clear_history", "export_audit", "request_screenshot",
        "notify_user",
    ):
        assert required in names, f"missing {required}"
    # No handler keys should leak.
    for tool in body["tools"]:
        assert "handler" not in tool


def test_health_endpoint():
    port = _free_port()
    gw.gateway_start(port=port)
    status, body = _request("GET", port, "/health",
                            token=gw.gateway_get_token())
    assert status == 200
    assert body["status"] == "ok"


# --------------------------------------------------------------------------- #
# No-approval invocation
# --------------------------------------------------------------------------- #


def test_call_tool_no_approval_returns_result():
    """Use a custom no-approval tool so we don't pay surveillance init cost.

    query_stats is great for end-to-end smoke tests but the first call
    pays a heavy surveillance/netguard import chain (~15-20s on a cold
    machine). The custom tool path is what 90% of real callers will hit.
    """
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    def _ping(params):
        return {"pong": True, "echo": params.get("x")}

    gw.gateway_register_tool(gw.ToolDefinition(
        name="ping",
        description="Test-only no-approval tool.",
        schema={"type": "object",
                "properties": {"x": {"type": "string"}},
                "additionalProperties": True},
        needs_approval=False,
        handler=_ping,
    ))

    status, body = _request("POST", port, "/tools/ping",
                            token=token, body={"params": {"x": "hi"}})
    assert status == 200, body
    assert body["result"] == {"pong": True, "echo": "hi"}
    assert "decision_id" in body and len(body["decision_id"]) == 32
    assert "audit_signature" in body and len(body["audit_signature"]) == 16


# --------------------------------------------------------------------------- #
# Approval flow
# --------------------------------------------------------------------------- #


def test_call_tool_needs_approval_calls_approval_handler():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    seen: List[Tuple[str, Dict[str, Any]]] = []

    def _approve(name: str, params: Dict[str, Any]) -> bool:
        seen.append((name, dict(params)))
        return True

    gw.gateway_set_approval_handler(_approve)

    status, body = _request(
        "POST", port, "/tools/block_url",
        token=token,
        body={"params": {"pattern": "https://placeholder.example/*"}},
    )
    assert status == 200, body
    assert seen and seen[0][0] == "block_url"
    assert seen[0][1]["pattern"] == "https://placeholder.example/*"
    # Stub handler returns status:stubbed.
    assert body["result"]["status"] == "stubbed"


def test_approval_rejected_returns_403():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    def _deny(name: str, params: Dict[str, Any]) -> bool:
        return False

    gw.gateway_set_approval_handler(_deny)

    status, body = _request(
        "POST", port, "/tools/set_mode",
        token=token,
        body={"params": {"mode": "vault"}},
    )
    assert status == 403
    assert body["error"] == "approval_rejected"
    assert "decision_id" in body
    assert "audit_signature" in body


def test_approval_timeout_rejects():
    """A handler that never returns must time out and reject."""
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()
    # Use a tiny timeout so the test runs fast.
    gw.gateway_set_approval_timeout(0.5)

    started = threading.Event()

    def _hang(name: str, params: Dict[str, Any]) -> bool:
        started.set()
        time.sleep(5.0)  # would be > timeout
        return True

    gw.gateway_set_approval_handler(_hang)

    t0 = time.monotonic()
    status, body = _request(
        "POST", port, "/tools/set_mode",
        token=token, body={"params": {"mode": "private"}},
        timeout=10.0,
    )
    elapsed = time.monotonic() - t0
    assert status == 403
    assert body["error"] == "approval_rejected"
    assert elapsed < 5.0, f"approval should have timed out fast, took {elapsed:.2f}s"
    assert started.is_set()


def test_no_approval_handler_means_reject():
    """If the UI never registered a handler, gated tools fail closed."""
    port = _free_port()
    gw.gateway_start(port=port)
    gw.gateway_set_approval_timeout(0.3)

    status, body = _request(
        "POST", port, "/tools/set_mode",
        token=gw.gateway_get_token(),
        body={"params": {"mode": "private"}},
    )
    assert status == 403
    assert body["error"] == "approval_rejected"


def test_irreversible_flag_passed_to_handler():
    """audit_irreversible=True tools must mark params with __irreversible__."""
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    seen: List[Dict[str, Any]] = []

    def _approve(name: str, params: Dict[str, Any]) -> bool:
        seen.append(dict(params))
        return True

    gw.gateway_set_approval_handler(_approve)

    _request("POST", port, "/tools/clear_history",
             token=token, body={"params": {"date": "2026-04-27"}})

    assert seen and seen[0].get("__irreversible__") is True
    assert seen[0]["date"] == "2026-04-27"


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def test_invalid_params_returns_400():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    # set_mode requires a string `mode` field.
    status, body = _request(
        "POST", port, "/tools/set_mode",
        token=token, body={"params": {"mode": 42}},
    )
    assert status == 400
    assert body["error"] == "schema"


def test_missing_required_field_returns_400():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    status, body = _request(
        "POST", port, "/tools/block_url",
        token=token, body={"params": {}},
    )
    assert status == 400
    assert body["error"] == "schema"
    assert "pattern" in body.get("detail", "")


def test_invalid_json_returns_400():
    """Send raw garbage as the body."""
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/tools/query_stats",
        data=b"not json at all {{{",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            status = resp.getcode()
            body = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = json.loads(exc.read() or b"{}")

    assert status == 400
    assert body["error"] == "invalid_json"


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #


def test_unauthorized_token_returns_401():
    port = _free_port()
    gw.gateway_start(port=port)

    status, body = _request("GET", port, "/tools",
                            token="not-the-real-token")
    assert status == 401
    assert body["error"] == "unauthorized"


def test_missing_auth_returns_401():
    port = _free_port()
    gw.gateway_start(port=port)

    status, body = _request("GET", port, "/tools", token=None)
    assert status == 401


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


def test_unknown_tool_returns_404():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    status, body = _request(
        "POST", port, "/tools/does_not_exist",
        token=token, body={"params": {}},
    )
    assert status == 404
    assert body["error"] == "unknown_tool"


def test_unknown_path_returns_404():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    status, _ = _request("GET", port, "/garbage", token=token)
    assert status == 404


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def test_audit_log_written(monkeypatch):
    """Every tool call must hit surveil_log_event."""
    captured: List[Tuple[str, Dict[str, Any]]] = []

    def _fake_log(event_type: str, data: Dict[str, Any], **kw: Any) -> str:
        captured.append((event_type, dict(data)))
        return "fake-id"

    # Inject a stub argus_surveillance module so the gateway's lazy import
    # picks up our fake.
    fake_module = type(sys)("argus_surveillance")
    fake_module.surveil_log_event = _fake_log  # type: ignore[attr-defined]
    fake_module.surveil_query = lambda **kw: []  # type: ignore[attr-defined]
    fake_module.surveil_stats = lambda: {}  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "argus_surveillance", fake_module)

    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    _request("POST", port, "/tools/query_stats",
             token=token, body={"params": {}})

    assert captured, "surveil_log_event was never called"
    assert captured[0][0] == "user_action"
    assert captured[0][1]["source"] == "mythos"
    assert captured[0][1]["tool"] == "query_stats"
    assert captured[0][1]["outcome"] == "ok"
    assert "params_hash" in captured[0][1]
    assert "decision_id" in captured[0][1]


def test_audit_logs_rejection():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()
    gw.gateway_set_approval_timeout(0.2)

    captured: List[Tuple[str, Dict[str, Any]]] = []

    import sys as _sys
    fake_module = type(_sys)("argus_surveillance")
    fake_module.surveil_log_event = lambda et, d, **kw: (  # type: ignore[attr-defined]
        captured.append((et, dict(d))) or "id"
    )
    fake_module.surveil_query = lambda **kw: []  # type: ignore[attr-defined]
    fake_module.surveil_stats = lambda: {}  # type: ignore[attr-defined]
    _sys.modules["argus_surveillance"] = fake_module
    try:
        _request("POST", port, "/tools/set_mode",
                 token=token, body={"params": {"mode": "private"}})
    finally:
        _sys.modules.pop("argus_surveillance", None)

    outcomes = [d.get("outcome") for et, d in captured]
    assert "rejected" in outcomes


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #


def test_idempotent_start_stop():
    port = _free_port()
    gw.gateway_start(port=port)
    gw.gateway_start(port=port)  # no-op
    assert gw.gateway_stats()["running"] is True
    gw.gateway_stop()
    gw.gateway_stop()  # no-op
    assert gw.gateway_stats()["running"] is False


def test_localhost_only():
    with pytest.raises(ValueError):
        gw.gateway_start(host="0.0.0.0", port=_free_port())


def test_register_and_unregister_custom_tool():
    port = _free_port()
    gw.gateway_start(port=port)
    token = gw.gateway_get_token()

    def _custom(params):
        return {"echo": params.get("msg")}

    gw.gateway_register_tool(gw.ToolDefinition(
        name="echo_test",
        description="Echo back the message",
        schema={"type": "object",
                "properties": {"msg": {"type": "string"}},
                "required": ["msg"],
                "additionalProperties": False},
        needs_approval=False,
        handler=_custom,
    ))

    status, body = _request("POST", port, "/tools/echo_test",
                            token=token, body={"params": {"msg": "hi"}})
    assert status == 200
    assert body["result"] == {"echo": "hi"}

    assert gw.gateway_unregister_tool("echo_test") is True
    assert gw.gateway_unregister_tool("echo_test") is False

    status, _ = _request("POST", port, "/tools/echo_test",
                         token=token, body={"params": {"msg": "hi"}})
    assert status == 404
