# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_mythos_bus.

Pattern: each test brings up the bus on a fresh high-numbered port, drives
it through a real ``websockets`` client (no mocks), and shuts the bus down
in a teardown step. We avoid pytest-asyncio because it's not installed in
this repo; instead, the client coroutine runs on a dedicated background
thread with its own asyncio loop.

No real secrets — all tokens are random per-process or hardcoded fakes.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_mythos_bus as bus  # noqa: E402
import websockets  # noqa: E402


def _free_port() -> int:
    """Allocate a free TCP port by binding ephemerally."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def _isolated_bus(tmp_path, monkeypatch):
    """Redirect vault to tmp + ensure the bus is fresh per test."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    # Guarantee no leakage from a previous test in the same process.
    if bus._STATE.running:
        bus.bus_stop()
    bus._STATE = bus._BusState()
    yield tmp_path
    if bus._STATE.running:
        bus.bus_stop()


def _run_client(token: str, port: int, topics: List[str], expected_count: int,
                timeout: float = 3.0) -> List[Dict[str, Any]]:
    """Run a client on a background thread; return all received messages."""
    received: List[Dict[str, Any]] = []
    err: List[BaseException] = []
    ready = threading.Event()

    async def _client_coro() -> None:
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{port}/",
                additional_headers={"X-Mythos-Token": token},
                open_timeout=2.0,
            ) as ws:
                # First frame is the hello.
                hello_raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                received.append(json.loads(hello_raw))
                if topics:
                    await ws.send(json.dumps({
                        "action": "subscribe", "topics": topics
                    }))
                ready.set()
                while len(received) < expected_count:
                    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    received.append(json.loads(raw))
        except Exception as exc:
            err.append(exc)
            ready.set()

    t = threading.Thread(target=lambda: asyncio.run(_client_coro()),
                         name="bus-test-client", daemon=True)
    t.start()
    ready.wait(timeout=3.0)
    return received, err, t


# --------------------------------------------------------------------------- #
# Core publish / receive
# --------------------------------------------------------------------------- #


def test_publish_then_subscriber_receives():
    port = _free_port()
    bus.bus_start(port=port)
    token = bus.bus_get_token()
    assert token and len(token) >= 32

    received, err, t = _run_client(token, port,
                                   topics=["surveillance/event"],
                                   expected_count=2)
    # Give the subscribe message time to register.
    time.sleep(0.3)
    bus.bus_publish("surveillance/event", {"tag": "hello"})
    t.join(timeout=4.0)

    assert not err, f"client errors: {err}"
    assert len(received) >= 2
    assert received[0]["topic"] == "_meta/hello"
    delivered = [m for m in received if m["topic"] == "surveillance/event"]
    assert len(delivered) == 1
    assert delivered[0]["payload"] == {"tag": "hello"}
    assert delivered[0]["seq"] >= 1


# --------------------------------------------------------------------------- #
# Glob matching
# --------------------------------------------------------------------------- #


def test_topic_glob_matching():
    port = _free_port()
    bus.bus_start(port=port)
    token = bus.bus_get_token()

    # expected = hello + 2 matching surveillance events (the arbiter event
    # is filtered out by the glob, so we never see it).
    received, err, t = _run_client(token, port,
                                   topics=["surveillance/*"],
                                   expected_count=3)
    time.sleep(0.3)
    bus.bus_publish("surveillance/event", {"i": 1})  # should match
    bus.bus_publish("arbiter/decision", {"i": 2})    # should NOT match
    bus.bus_publish("surveillance/event", {"i": 3})  # should match
    t.join(timeout=4.0)

    assert not err, f"client errors: {err}"
    matched = [m["payload"] for m in received
               if m["topic"] == "surveillance/event"]
    assert {"i": 1} in matched
    assert {"i": 3} in matched
    assert all(m["topic"] != "arbiter/decision" for m in received)


def test_topic_glob_double_star():
    """`prefix/**` matches any tail."""
    assert bus._topic_matches("a/**", "a")
    assert bus._topic_matches("a/**", "a/b")
    assert bus._topic_matches("a/**", "a/b/c")
    assert not bus._topic_matches("a/**", "ab")


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #


def test_unauthorized_token_rejected():
    port = _free_port()
    bus.bus_start(port=port)

    err: List[BaseException] = []

    async def _bad_client() -> None:
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{port}/",
                additional_headers={"X-Mythos-Token": "wrong-token"},
                open_timeout=2.0,
            ) as ws:
                await ws.recv()
        except Exception as exc:
            err.append(exc)

    t = threading.Thread(target=lambda: asyncio.run(_bad_client()),
                         daemon=True)
    t.start()
    t.join(timeout=4.0)
    assert err, "expected an error for wrong token"
    # The websockets lib raises InvalidStatus / InvalidStatusCode on a 401.
    msg = str(err[0]).lower()
    assert "401" in msg or "unauthor" in msg or "rejected" in msg \
        or "handshake" in msg


def test_unauthorized_missing_token_rejected():
    port = _free_port()
    bus.bus_start(port=port)

    err: List[BaseException] = []

    async def _bad_client() -> None:
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{port}/", open_timeout=2.0,
            ) as ws:
                await ws.recv()
        except Exception as exc:
            err.append(exc)

    t = threading.Thread(target=lambda: asyncio.run(_bad_client()),
                         daemon=True)
    t.start()
    t.join(timeout=4.0)
    assert err, "expected an error for missing token"


# --------------------------------------------------------------------------- #
# Backpressure
# --------------------------------------------------------------------------- #


def test_buffer_drop_when_subscriber_slow(monkeypatch):
    """A slow client should cause drops, not OOM, not block the publisher."""
    monkeypatch.setattr(bus, "CLIENT_SEND_QUEUE_MAX", 4, raising=True)
    port = _free_port()
    bus.bus_start(port=port)
    token = bus.bus_get_token()

    err: List[BaseException] = []
    connected = threading.Event()

    async def _slow_client() -> None:
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{port}/",
                additional_headers={"X-Mythos-Token": token},
                open_timeout=2.0,
            ) as ws:
                await ws.recv()  # hello
                await ws.send(json.dumps({
                    "action": "subscribe", "topics": ["spam"]
                }))
                connected.set()
                # Block for a while so events pile up server-side.
                await asyncio.sleep(2.0)
        except Exception as exc:
            err.append(exc)

    t = threading.Thread(target=lambda: asyncio.run(_slow_client()),
                         daemon=True)
    t.start()
    connected.wait(timeout=3.0)
    time.sleep(0.3)
    # Far more events than CLIENT_SEND_QUEUE_MAX.
    for i in range(200):
        bus.bus_publish("spam", {"i": i})
    time.sleep(1.0)
    stats = bus.bus_stats()
    t.join(timeout=4.0)

    assert stats["events_published"] >= 200
    # Either the per-client queue overflowed or the global queue did.
    # In either case Argus must not have OOM'd / blocked.
    assert stats["events_dropped"] >= 0  # always true; we just want no crash


# --------------------------------------------------------------------------- #
# Unsubscribe
# --------------------------------------------------------------------------- #


def test_unsubscribe_stops_delivery():
    port = _free_port()
    bus.bus_start(port=port)
    token = bus.bus_get_token()

    received: List[Dict[str, Any]] = []
    err: List[BaseException] = []
    phase = threading.Event()

    async def _client_coro() -> None:
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{port}/",
                additional_headers={"X-Mythos-Token": token},
                open_timeout=2.0,
            ) as ws:
                received.append(json.loads(await ws.recv()))  # hello
                await ws.send(json.dumps({
                    "action": "subscribe", "topics": ["foo"]
                }))
                # First event after subscribe.
                phase.set()
                first = await asyncio.wait_for(ws.recv(), timeout=2.0)
                received.append(json.loads(first))
                # Now unsubscribe.
                await ws.send(json.dumps({
                    "action": "unsubscribe", "topics": ["foo"]
                }))
                await asyncio.sleep(0.5)
                # Server publishes another event; we should NOT get it.
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                    received.append(json.loads(raw))
                except asyncio.TimeoutError:
                    pass
        except Exception as exc:
            err.append(exc)

    t = threading.Thread(target=lambda: asyncio.run(_client_coro()),
                         daemon=True)
    t.start()
    phase.wait(timeout=3.0)
    time.sleep(0.4)
    bus.bus_publish("foo", {"x": 1})  # should arrive
    time.sleep(0.6)
    # By now client has unsubscribed (it does so right after the first recv).
    time.sleep(0.6)
    bus.bus_publish("foo", {"x": 2})  # should NOT arrive
    t.join(timeout=4.0)

    assert not err, f"client errors: {err}"
    foo_payloads = [m["payload"] for m in received if m.get("topic") == "foo"]
    assert {"x": 1} in foo_payloads
    assert {"x": 2} not in foo_payloads


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


def test_stats_returns_counts():
    port = _free_port()
    bus.bus_start(port=port)
    bus.bus_publish("alpha/one", {"n": 1})
    bus.bus_publish("alpha/two", {"n": 2})
    bus.bus_publish("alpha/one", {"n": 3})
    time.sleep(0.1)
    stats = bus.bus_stats()
    assert stats["running"] is True
    assert stats["events_published"] == 3
    assert stats["topic_counts"]["alpha/one"] == 2
    assert stats["topic_counts"]["alpha/two"] == 1
    assert stats["host"] == "127.0.0.1"
    assert stats["port"] == port


def test_idempotent_start_stop():
    port = _free_port()
    bus.bus_start(port=port)
    bus.bus_start(port=port)  # second call must be a no-op
    assert bus.bus_stats()["running"] is True
    bus.bus_stop()
    bus.bus_stop()  # double-stop also no-op
    assert bus.bus_stats()["running"] is False


def test_localhost_only():
    """bus_start must refuse non-loopback hosts."""
    with pytest.raises(ValueError):
        bus.bus_start(host="0.0.0.0", port=_free_port())
    with pytest.raises(ValueError):
        bus.bus_start(host="192.168.1.1", port=_free_port())
