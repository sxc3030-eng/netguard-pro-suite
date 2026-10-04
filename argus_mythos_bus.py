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
Argus <-> Mythos Event Bus V1 (loopback WebSocket).

Mythos is the future AI agent ("the beast in the cage"). This module is the
event-stream half of the cage's plug interface: any meaningful Argus event
(surveillance log, arbiter decision, mode switch, tab open/close, user
action) is fanned out over a localhost-only WebSocket so a future Mythos
process can subscribe to a glob of topics.

Wire format
-----------
* Server bind: ``ws://127.0.0.1:8767`` (NEVER 0.0.0.0).
* Auth: pre-shared bearer token from the Argus vault under the key
  ``MYTHOS_BUS_TOKEN``. The token is auto-generated on first ``bus_start``
  if missing. Clients send it in the WebSocket handshake header
  ``X-Mythos-Token``. Missing or wrong token => 4401 Unauthorized close.
* Subscribe: client sends ``{"action": "subscribe",
  "topics": ["surveillance/*", "arbiter/decision"]}``. Topics use slash
  namespacing; ``*`` matches a single segment, ``**`` matches any tail.
* Unsubscribe: ``{"action": "unsubscribe", "topics": [...]}``.
* Event (server->client): ``{"topic": "...", "ts_iso": "...",
  "seq": <int>, "payload": {...}}``. ``seq`` is monotonic per server start.

Non-blocking publish
--------------------
``bus_publish`` is called from arbitrary threads (UI thread, surveillance
writer, scanner thread). It enqueues onto a bounded ``queue.Queue`` and
returns immediately. A background dispatcher running on the bus's asyncio
loop drains the queue and fans out to interested clients. If a client's
send buffer is full the event is dropped for that client and a counter is
incremented; we never block the publisher.

This module is GPL v3. See LICENSE in the repo root.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import queue
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
except ImportError:  # pragma: no cover - listed in requirements.txt
    websockets = None  # type: ignore[assignment]
    ConnectionClosed = Exception  # type: ignore[misc, assignment]

_LOG = logging.getLogger("argus.mythos.bus")

VAULT_TOKEN_KEY = "MYTHOS_BUS_TOKEN"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8767
PUBLISH_QUEUE_MAX = 4096
CLIENT_SEND_QUEUE_MAX = 256
HANDSHAKE_TOKEN_HEADER = "X-Mythos-Token"
PROTOCOL_VERSION = "1.0"


# --------------------------------------------------------------------------- #
# Token bootstrap (vault-backed, with deterministic CI fallback)
# --------------------------------------------------------------------------- #


def _acquire_token() -> str:
    """Fetch or mint the bearer token. Best-effort vault integration.

    1. Try ``argus_vault.vault_get(MYTHOS_BUS_TOKEN)``.
    2. If vault exists but entry is missing, generate 32 random bytes (hex)
       and store them.
    3. If vault is unavailable, fall back to a process-local random token
       (logged with a WARNING). This keeps the bus usable in CI.
    """
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
                        VAULT_TOKEN_KEY, fresh, owner="mythos_bus"
                    )
                    return fresh
                except Exception as exc:  # pragma: no cover - defensive
                    _LOG.warning("vault_set failed for MYTHOS_BUS_TOKEN: %s", exc)
        except Exception as exc:
            _LOG.warning("vault unavailable for mythos token, falling back: %s", exc)

    _LOG.warning(
        "argus_mythos_bus: vault unavailable, using process-local random token"
    )
    return secrets.token_hex(32)


# --------------------------------------------------------------------------- #
# Topic glob matching
# --------------------------------------------------------------------------- #


def _topic_matches(pattern: str, topic: str) -> bool:
    """Return True if ``topic`` matches glob ``pattern`` (segment-aware)."""
    if pattern == topic:
        return True
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return topic == prefix or topic.startswith(prefix + "/")
    # Standard fnmatch handles "*", "?", and "[..]" — fine for single-segment
    # cases like "surveillance/*". For multi-segment we use the "/**" rule
    # above. Reject leading slash to keep namespaces clean.
    return fnmatch.fnmatchcase(topic, pattern)


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #


class _ClientState:
    """Per-connection bookkeeping (lives on the bus loop)."""

    __slots__ = ("ws", "topics", "send_queue", "dropped", "remote")

    def __init__(self, ws: Any, remote: str) -> None:
        self.ws = ws
        self.topics: Set[str] = set()
        self.send_queue: "asyncio.Queue[str]" = asyncio.Queue(
            maxsize=CLIENT_SEND_QUEUE_MAX
        )
        self.dropped = 0
        self.remote = remote


class _BusState:
    """Module-level singleton container."""

    def __init__(self) -> None:
        self.running: bool = False
        self.host: str = DEFAULT_HOST
        self.port: int = DEFAULT_PORT
        self.token: Optional[str] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self.server: Optional[Any] = None
        self.publish_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(
            maxsize=PUBLISH_QUEUE_MAX
        )
        self.clients: Set[_ClientState] = set()
        self.events_published: int = 0
        self.events_dropped: int = 0
        self.topic_counts: Dict[str, int] = {}
        self.seq: int = 0
        self.dispatcher_task: Optional[asyncio.Task] = None
        self.start_lock = threading.Lock()


_STATE = _BusState()


# --------------------------------------------------------------------------- #
# Server-side handlers (run on the bus loop)
# --------------------------------------------------------------------------- #


def _extract_token(headers: Any) -> Optional[str]:
    """Read the bearer token from a ``websockets`` request headers object."""
    try:
        return headers.get(HANDSHAKE_TOKEN_HEADER)
    except Exception:
        try:
            for k, v in headers.raw_items():  # type: ignore[attr-defined]
                if k.lower() == HANDSHAKE_TOKEN_HEADER.lower():
                    return v
        except Exception:
            return None
    return None


async def _process_request(connection: Any, request: Any) -> Optional[Any]:
    """websockets >= 12 process_request hook: gate on the bearer token."""
    headers = getattr(request, "headers", None)
    if headers is None:
        # Older websockets used (path, headers) signature; the wrapper below
        # adapts. Reject on missing header structure.
        return connection.respond(401, "missing headers\n")
    token = _extract_token(headers)
    if not token or token != _STATE.token:
        return connection.respond(401, "unauthorized\n")
    return None


async def _client_writer(client: _ClientState) -> None:
    """Drain a single client's send queue onto the wire."""
    try:
        while True:
            msg = await client.send_queue.get()
            try:
                await client.ws.send(msg)
            except ConnectionClosed:
                return
            except Exception as exc:  # pragma: no cover - transport edge cases
                _LOG.debug("client send failed: %s", exc)
                return
    except asyncio.CancelledError:
        return


async def _handle_client(ws: Any) -> None:
    """One connection: read sub/unsub messages, deliver matching events."""
    remote = ""
    try:
        remote = ":".join(str(p) for p in ws.remote_address[:2])  # type: ignore[index]
    except Exception:
        remote = "?"

    client = _ClientState(ws, remote)
    _STATE.clients.add(client)
    writer = asyncio.create_task(_client_writer(client))

    # Greet so a freshly-connected (and authenticated) Mythos knows we're up.
    hello = {
        "topic": "_meta/hello",
        "ts_iso": datetime.now(timezone.utc).isoformat(),
        "seq": 0,
        "payload": {"protocol": PROTOCOL_VERSION},
    }
    try:
        await ws.send(json.dumps(hello))
    except Exception:
        pass

    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue
            action = msg.get("action")
            topics = msg.get("topics") or []
            if not isinstance(topics, list):
                continue
            cleaned = [t for t in topics if isinstance(t, str) and t]
            if action == "subscribe":
                client.topics.update(cleaned)
            elif action == "unsubscribe":
                for t in cleaned:
                    client.topics.discard(t)
            # Other actions are silently ignored (forward-compat).
    except ConnectionClosed:
        pass
    finally:
        writer.cancel()
        _STATE.clients.discard(client)


async def _dispatcher() -> None:
    """Drain the cross-thread publish queue onto interested clients."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            event = await loop.run_in_executor(
                None, _STATE.publish_queue.get, True, 0.5
            )
        except queue.Empty:
            continue
        except Exception:
            await asyncio.sleep(0.05)
            continue
        if event is None:
            return  # shutdown sentinel
        topic = event.get("topic", "")
        text = json.dumps(event, separators=(",", ":"))
        for client in list(_STATE.clients):
            for pat in client.topics:
                if _topic_matches(pat, topic):
                    try:
                        client.send_queue.put_nowait(text)
                    except asyncio.QueueFull:
                        client.dropped += 1
                        _STATE.events_dropped += 1
                    break


# --------------------------------------------------------------------------- #
# Loop bootstrapping (background thread)
# --------------------------------------------------------------------------- #


async def _serve(host: str, port: int) -> None:
    if websockets is None:  # pragma: no cover - covered by import-time check
        raise RuntimeError("websockets package is required for argus_mythos_bus")
    async with websockets.serve(
        _handle_client,
        host,
        port,
        process_request=_process_request,
    ) as server:
        _STATE.server = server
        _STATE.dispatcher_task = asyncio.create_task(_dispatcher())
        try:
            await asyncio.Future()  # park until cancelled
        except asyncio.CancelledError:
            pass
        finally:
            if _STATE.dispatcher_task is not None:
                _STATE.dispatcher_task.cancel()


def _thread_target(host: str, port: int, ready: threading.Event) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _STATE.loop = loop

    async def runner() -> None:
        # Mark ready once the server has bound; we don't have a hook before
        # `serve()` returns, so we flip the event after a tiny yield.
        async def flip_ready() -> None:
            await asyncio.sleep(0.05)
            ready.set()
        asyncio.create_task(flip_ready())
        await _serve(host, port)

    try:
        loop.run_until_complete(runner())
    except Exception as exc:  # pragma: no cover - surfaced in logs
        _LOG.error("mythos bus loop crashed: %s", exc)
        ready.set()
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        loop.close()


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def bus_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Start the bus in a background thread. Idempotent."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("argus_mythos_bus binds to localhost only")
    with _STATE.start_lock:
        if _STATE.running:
            return
        _STATE.token = _acquire_token()
        _STATE.host = host
        _STATE.port = port
        _STATE.events_published = 0
        _STATE.events_dropped = 0
        _STATE.topic_counts = {}
        _STATE.seq = 0
        # Drain any stale events from a previous lifecycle.
        try:
            while True:
                _STATE.publish_queue.get_nowait()
        except queue.Empty:
            pass

        ready = threading.Event()
        thread = threading.Thread(
            target=_thread_target,
            args=(host, port, ready),
            name="argus-mythos-bus",
            daemon=True,
        )
        thread.start()
        _STATE.thread = thread
        # Block briefly for the loop to come up; max 3s.
        ready.wait(timeout=3.0)
        _STATE.running = True


def bus_stop() -> None:
    """Graceful shutdown: stop accepting, drain pending events, join thread."""
    with _STATE.start_lock:
        if not _STATE.running:
            return
        loop = _STATE.loop
        # Drain by giving the dispatcher one more pass, then cancel it.
        try:
            _STATE.publish_queue.put_nowait(None)  # sentinel
        except queue.Full:
            pass
        if loop is not None and loop.is_running():
            async def _shutdown() -> None:
                if _STATE.server is not None:
                    _STATE.server.close()
                    try:
                        await _STATE.server.wait_closed()
                    except Exception:
                        pass
                # Close all clients
                for client in list(_STATE.clients):
                    try:
                        await client.ws.close()
                    except Exception:
                        pass
                if _STATE.dispatcher_task is not None:
                    _STATE.dispatcher_task.cancel()
                # Stop the parked future in _serve by cancelling all tasks.
                for t in asyncio.all_tasks(loop):
                    if t is not asyncio.current_task():
                        t.cancel()
            try:
                fut = asyncio.run_coroutine_threadsafe(_shutdown(), loop)
                fut.result(timeout=2.0)
            except Exception:
                pass
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
        thread = _STATE.thread
        if thread is not None:
            thread.join(timeout=3.0)
        _STATE.running = False
        _STATE.thread = None
        _STATE.loop = None
        _STATE.server = None
        _STATE.dispatcher_task = None
        _STATE.clients.clear()


def bus_publish(topic: str, payload: dict) -> None:
    """Publish an event. Non-blocking; drops if buffer is full."""
    if not isinstance(topic, str) or not topic:
        raise ValueError("topic must be a non-empty string")
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")
    _STATE.seq += 1
    _STATE.events_published += 1
    _STATE.topic_counts[topic] = _STATE.topic_counts.get(topic, 0) + 1
    event = {
        "topic": topic,
        "ts_iso": datetime.now(timezone.utc).isoformat(),
        "seq": _STATE.seq,
        "payload": payload,
    }
    try:
        _STATE.publish_queue.put_nowait(event)
    except queue.Full:
        _STATE.events_dropped += 1


def bus_stats() -> Dict[str, Any]:
    """Return a snapshot of bus counters."""
    return {
        "running": _STATE.running,
        "connected_clients": len(_STATE.clients),
        "events_published": _STATE.events_published,
        "events_dropped": _STATE.events_dropped,
        "topic_counts": dict(_STATE.topic_counts),
        "queue_depth": _STATE.publish_queue.qsize(),
        "host": _STATE.host,
        "port": _STATE.port,
    }


def bus_get_token() -> Optional[str]:
    """Return the active bearer token (callers display it in the UI for setup)."""
    return _STATE.token


# Convenience for tests / debugging — list configured topic namespaces.
KNOWN_TOPIC_NAMESPACES: List[str] = [
    "surveillance/event",
    "arbiter/decision",
    "mode/switched",
    "tab/opened",
    "tab/closed",
    "user/action",
    "download/intercepted",
    "error/bus",
    "error/gateway",
    "_meta/hello",
]
