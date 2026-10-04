# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Integration tests for ``examples.mythos_sample``.

Each test starts the bus + gateway in-process on free high ports, runs a
focused slice of the sample plugin against them, and shuts the services
down. We exercise the bus and gateway through the same code paths the
sample uses (``BusSubscriber`` / ``GatewayClient``), not via subprocess —
that way pytest gets line-level failure messages and we can mock the
approval handler.

A separate end-to-end smoke test does spawn the sample as a subprocess to
prove the runnable entry point is wired. It uses a short duration override.

No real secrets — vault is redirected to ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_mythos_bus as bus  # noqa: E402
import argus_mythos_gateway as gw  # noqa: E402
import argus_vault  # noqa: E402

from examples.mythos_sample.main import (  # noqa: E402
    BusSubscriber,
    GatewayClient,
    SUBSCRIBE_TOPICS,
    verify_signature,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def bus_and_gateway(tmp_path, monkeypatch):
    """Spin up bus + gateway on free ports, yield (token, bus_port, gw_port).

    Both services read MYTHOS_BUS_TOKEN from the vault. Without a real
    vault, each one falls back to its own random token, which would make
    the gateway's auth header reject the bus's token (and vice versa).
    We initialise a per-test vault and pre-seed the shared token so the
    two services agree.
    """
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    # Pass a test passphrase so vault_init works on non-Windows (DPAPI
    # is Windows-only; PBKDF2 fallback needs an explicit passphrase).
    # The bus and the gateway read the vault WITHOUT a passphrase, so the
    # same passphrase is exported for them (headless opt-in, see argus_vault).
    monkeypatch.setenv("ARGUS_VAULT_PASSPHRASE", "test_passphrase_xyz")
    argus_vault.vault_init(passphrase="test_passphrase_xyz")
    import secrets
    shared = secrets.token_hex(32)
    argus_vault.vault_set("MYTHOS_BUS_TOKEN", shared, owner="test")

    # Reset state from prior tests in the same process.
    if bus._STATE.running:
        bus.bus_stop()
    bus._STATE = bus._BusState()
    if gw._STATE.running:
        gw.gateway_stop()
    gw.gateway_reset_for_tests()

    bus_port = _free_port()
    gw_port = _free_port()
    bus.bus_start(port=bus_port)
    gw.gateway_start(port=gw_port)

    bus_token = bus.bus_get_token()
    gw_token = gw.gateway_get_token()
    assert bus_token == gw_token == shared, (
        f"token mismatch: bus={bus_token!r} gw={gw_token!r} shared={shared!r}"
    )

    yield shared, bus_port, gw_port

    if bus._STATE.running:
        bus.bus_stop()
    if gw._STATE.running:
        gw.gateway_stop()
    gw.gateway_reset_for_tests()


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_sample_connects_to_bus(bus_and_gateway):
    """BusSubscriber should connect, receive _meta/hello, set _connected."""
    token, bus_port, _ = bus_and_gateway
    sub = BusSubscriber("127.0.0.1", bus_port, token, SUBSCRIBE_TOPICS)
    sub.start()
    try:
        assert sub.wait_connected(timeout=5.0), \
            f"connect timed out (err={sub.error!r})"
        # The hello frame is the first received event.
        assert sub.received, "no events received"
        assert sub.received[0]["topic"] == "_meta/hello"
        assert sub.received[0]["payload"]["protocol"] == "1.0"
    finally:
        sub.stop()


def test_sample_subscribes_topics(bus_and_gateway):
    """After subscription, published events on matching topics should arrive."""
    token, bus_port, _ = bus_and_gateway
    sub = BusSubscriber("127.0.0.1", bus_port, token, SUBSCRIBE_TOPICS)
    sub.start()
    try:
        assert sub.wait_connected(timeout=5.0)
        # Give the subscribe message time to register on the bus loop.
        time.sleep(0.4)
        bus.bus_publish("surveillance/event", {"tag": "from-test"})
        bus.bus_publish("arbiter/decision", {"verdict": "deny"})
        bus.bus_publish("mode/switched", {"mode": "private"})
        # And one event we should NOT receive (not in subscription list).
        bus.bus_publish("tab/opened", {"url": "should-not-arrive"})

        # Poll up to 3s for the three matching events to land.
        deadline = time.monotonic() + 3.0
        topics_seen = set()
        while time.monotonic() < deadline:
            topics_seen = {e["topic"] for e in sub.received
                           if e["topic"] != "_meta/hello"}
            if {"surveillance/event", "arbiter/decision",
                "mode/switched"} <= topics_seen:
                break
            time.sleep(0.1)

        assert "surveillance/event" in topics_seen
        assert "arbiter/decision" in topics_seen
        assert "mode/switched" in topics_seen
        assert "tab/opened" not in topics_seen, \
            "received an event we did not subscribe to"
    finally:
        sub.stop()


def test_sample_calls_query_stats_tool(bus_and_gateway):
    """GatewayClient should call query_stats and get a 200 with signed body."""
    token, _, gw_port = bus_and_gateway
    client = GatewayClient(gw_port, token)
    assert client.health(), "gateway /health not reachable"

    tools = client.list_tools()
    names = {t["name"] for t in tools.get("tools", [])}
    # All 11 builtins should be there.
    assert {"query_stats", "notify_user", "set_mode", "clear_history",
            "query_history", "query_arbiter_decisions", "block_url",
            "unblock_url", "run_arbiter", "export_audit",
            "request_screenshot"} <= names

    status, body = client.call("query_stats", {})
    assert status == 200, f"unexpected status: {status} body={body}"
    assert "result" in body
    assert "decision_id" in body
    assert "audit_signature" in body
    assert body["result"]["status"] == "ok"
    assert "gateway" in body["result"]
    # The gateway counters should reflect at least our call.
    assert body["result"]["gateway"]["tools_registered"] >= 11


def test_sample_handles_approval_timeout(bus_and_gateway, monkeypatch):
    """A tool that needs approval, with no handler, should 403 (fail-closed).

    Note: the gateway returns 403 (FORBIDDEN) on rejection or timeout —
    not 408 as one might expect. The approval helper fails-closed when
    no handler is registered, which is what the sample relies on.
    """
    token, _, gw_port = bus_and_gateway

    # Make the timeout short so this test doesn't take 30s.
    gw.gateway_set_approval_timeout(0.5)

    # Ensure no approval handler is registered.
    gw._STATE.approval_handler = None

    client = GatewayClient(gw_port, token)
    params = {"mode": "private"}
    status, body = client.call("set_mode", params, timeout=5.0)
    assert status == 403, f"expected 403, got {status}: {body}"
    assert body["error"] == "approval_rejected"
    assert "decision_id" in body
    assert "audit_signature" in body

    # Auto-approve handler -> 200.
    gw.gateway_set_approval_handler(lambda name, p: True)
    status, body = client.call("set_mode", params, timeout=5.0)
    assert status == 200, f"expected 200 with auto-approve, got {status}: {body}"
    assert body["audit_signature"]


def test_sample_verifies_hmac_response(bus_and_gateway):
    """verify_signature() must accept the gateway's actual signature."""
    token, _, gw_port = bus_and_gateway
    client = GatewayClient(gw_port, token)

    params = {"message": "verify me", "level": "info"}
    status, body = client.call("notify_user", params)
    assert status == 200, body

    # The sample's verifier should agree with the gateway.
    assert verify_signature(
        body["decision_id"], "notify_user", params, "ok",
        body["audit_signature"],
    ), "signature did not verify against gateway response"

    # Tamper detection: changing any field should invalidate the signature.
    assert not verify_signature(
        body["decision_id"], "notify_user", {"message": "tampered"},
        "ok", body["audit_signature"],
    )
    assert not verify_signature(
        body["decision_id"], "notify_user", params, "rejected",
        body["audit_signature"],
    )


def test_sample_runs_as_subprocess(bus_and_gateway, tmp_path):
    """End-to-end smoke: spawn main.py with a 2s duration; expect exit 0.

    This proves the ``python -m examples.mythos_sample.main`` entry
    point is wired and that token discovery via env var works.
    """
    token, bus_port, gw_port = bus_and_gateway
    env = os.environ.copy()
    env["MYTHOS_BUS_TOKEN"] = token
    env["MYTHOS_BUS_PORT"] = str(bus_port)
    env["MYTHOS_GATEWAY_PORT"] = str(gw_port)
    env["MYTHOS_SAMPLE_DURATION"] = "2"
    env["MYTHOS_SAMPLE_NO_COLOR"] = "1"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.run(
        [sys.executable, "-m", "examples.mythos_sample.main"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        stdin=subprocess.DEVNULL,   # an un-inheritable parent stdin raised WinError 50 on Windows
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f"sample exited {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    # Output should mention the protocol elements we documented.
    assert "Mythos Sample" in proc.stdout
    assert "tools_registered" in proc.stdout or "query_stats" in proc.stdout
    assert "approval_rejected" in proc.stdout  # set_mode + clear_history
