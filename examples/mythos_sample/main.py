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
Mythos Sample Plugin — end-to-end demo of the Argus integration protocol.

This is the reference client that exercises both halves of the cage's plug
interface: the read-only event bus (``argus_mythos_bus``, ws://127.0.0.1:8767)
and the action gateway (``argus_mythos_gateway``, http://127.0.0.1:8768).

Usage
-----
With Argus running::

    # terminal 1
    python argus_pyqt.py

    # terminal 2
    python -m examples.mythos_sample.main

With bus + gateway only (headless, no UI)::

    # terminal 1
    python -c "from argus_mythos_bus import bus_start; \
        from argus_mythos_gateway import gateway_start; \
        bus_start(); gateway_start(); \
        import time; time.sleep(3600)"

    # terminal 2
    python -m examples.mythos_sample.main

Environment knobs
-----------------
* ``MYTHOS_BUS_TOKEN``  — bearer token. Falls back to vault lookup, then
  :py:func:`argus_mythos_bus.bus_get_token` (in-process).
* ``MYTHOS_BUS_HOST``   — default 127.0.0.1
* ``MYTHOS_BUS_PORT``   — default 8767
* ``MYTHOS_GATEWAY_PORT`` — default 8768
* ``MYTHOS_SAMPLE_DURATION`` — seconds to keep listening (default 60).
* ``MYTHOS_SAMPLE_NO_COLOR`` — set to disable ANSI colours.

Exit codes
----------
* 0 — success
* 1 — token unavailable
* 2 — bus connect failed
* 3 — gateway unreachable
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# requests is required at runtime; websockets is required for the bus loop.
try:
    import requests
except ImportError:  # pragma: no cover - listed in requirements.txt
    print("[FATAL] missing dep: pip install -r requirements.txt", file=sys.stderr)
    raise

try:
    import websockets
except ImportError:  # pragma: no cover - listed in requirements.txt
    print("[FATAL] missing dep: pip install -r requirements.txt", file=sys.stderr)
    raise


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

BUS_HOST = os.environ.get("MYTHOS_BUS_HOST", "127.0.0.1")
BUS_PORT = int(os.environ.get("MYTHOS_BUS_PORT", "8767"))
GATEWAY_PORT = int(os.environ.get("MYTHOS_GATEWAY_PORT", "8768"))
DEFAULT_DURATION = int(os.environ.get("MYTHOS_SAMPLE_DURATION", "60"))
USE_COLOR = "MYTHOS_SAMPLE_NO_COLOR" not in os.environ

# Topics the sample subscribes to. These match the namespaces declared in
# ``argus_mythos_bus.KNOWN_TOPIC_NAMESPACES``.
SUBSCRIBE_TOPICS = [
    "surveillance/event",
    "arbiter/decision",
    "mode/switched",
]

# ANSI escapes — green for ok, yellow for pending, red for error, cyan for events.
_ANSI = {
    "reset": "\033[0m",
    "bold":  "\033[1m",
    "dim":   "\033[2m",
    "red":   "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue":  "\033[34m",
    "magenta": "\033[35m",
    "cyan":  "\033[36m",
}

# Map topic prefix to colour for the event printer.
_TOPIC_COLORS = {
    "_meta/":         "dim",
    "surveillance/":  "cyan",
    "arbiter/":       "magenta",
    "mode/":          "yellow",
    "tab/":           "blue",
    "user/":          "green",
    "download/":      "yellow",
    "error/":         "red",
}


def c(text: str, color: str) -> str:
    """Wrap ``text`` in an ANSI colour if colour output is enabled."""
    if not USE_COLOR:
        return text
    code = _ANSI.get(color, "")
    return f"{code}{text}{_ANSI['reset']}" if code else text


def _topic_color(topic: str) -> str:
    for prefix, color in _TOPIC_COLORS.items():
        if topic.startswith(prefix):
            return color
    return "reset"


# --------------------------------------------------------------------------- #
# Token discovery
# --------------------------------------------------------------------------- #


def discover_token() -> Optional[str]:
    """Locate the bus/gateway bearer token.

    Resolution order:
      1. ``MYTHOS_BUS_TOKEN`` environment variable.
      2. ``argus_vault.vault_get(MYTHOS_BUS_TOKEN)`` — if the vault module
         is importable and unlocked.
      3. ``argus_mythos_bus.bus_get_token()`` — works only if the bus has
         been started in this same Python process (e.g. tests).

    Returns None if nothing is found; the caller prints an instructive
    message and exits.
    """
    env = os.environ.get("MYTHOS_BUS_TOKEN")
    if env:
        return env.strip()

    # Try the vault next — that's where Argus stores the token at runtime.
    try:
        repo_root = Path(__file__).resolve().parent.parent.parent
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        import argus_vault  # type: ignore
        if argus_vault.vault_exists():
            tok = argus_vault.vault_get("MYTHOS_BUS_TOKEN")
            if tok:
                return tok
    except Exception:
        pass

    # Last resort: the bus may already be running in this process.
    try:
        import argus_mythos_bus  # type: ignore
        return argus_mythos_bus.bus_get_token()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Audit-signature verification
# --------------------------------------------------------------------------- #


def _params_hash(params: Dict[str, Any]) -> str:
    """Mirror ``argus_mythos_gateway._params_hash`` exactly."""
    try:
        canonical = json.dumps(params, sort_keys=True, default=str).encode("utf-8")
    except Exception:
        canonical = repr(params).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


def verify_signature(decision_id: str, tool: str, params: Dict[str, Any],
                     outcome: str, signature: str) -> bool:
    """Recompute the gateway's audit signature and compare.

    The gateway uses a deterministic SHA-256 of
    ``decision_id | tool | params_hash | outcome`` truncated to 16 hex
    chars (see ``_audit_invoke`` in ``argus_mythos_gateway.py``).

    This is NOT an HMAC — there's no shared secret in the chain — so the
    "verify" really means "the gateway returned values that match the
    documented signature recipe". A real Mythos would still want to log
    the surveillance HMAC chain for tamper-evidence.
    """
    expected_src = f"{decision_id}|{tool}|{_params_hash(params)}|{outcome}"
    expected = hashlib.sha256(expected_src.encode("utf-8")).hexdigest()[:16]
    return expected == signature


# --------------------------------------------------------------------------- #
# Bus subscriber (background asyncio loop)
# --------------------------------------------------------------------------- #


class BusSubscriber:
    """Connects to the bus on a background thread and prints events."""

    def __init__(self, host: str, port: int, token: str,
                 topics: List[str]) -> None:
        self.url = f"ws://{host}:{port}/"
        self.token = token
        self.topics = topics
        self.received: List[Dict[str, Any]] = []
        self._stop = threading.Event()
        self._connected = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[BaseException] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="mythos-sample-bus", daemon=True
        )
        self._thread.start()

    def wait_connected(self, timeout: float = 5.0) -> bool:
        return self._connected.wait(timeout=timeout)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    @property
    def error(self) -> Optional[BaseException]:
        return self._error

    def _run(self) -> None:
        try:
            asyncio.run(self._loop())
        except Exception as exc:  # pragma: no cover - transport edge cases
            self._error = exc
            self._connected.set()  # unblock the foreground

    async def _loop(self) -> None:
        try:
            async with websockets.connect(
                self.url,
                additional_headers={"X-Mythos-Token": self.token},
                open_timeout=3.0,
                ping_interval=20,
                ping_timeout=10,
            ) as ws:
                # First frame is always the bus's _meta/hello greeting.
                hello_raw = await asyncio.wait_for(ws.recv(), timeout=3.0)
                hello = json.loads(hello_raw)
                self._on_event(hello)

                # Subscribe.
                await ws.send(json.dumps({
                    "action": "subscribe",
                    "topics": self.topics,
                }))
                print(c(
                    f"[bus] connected -> subscribed to {len(self.topics)} "
                    f"topics: {', '.join(self.topics)}",
                    "green"
                ))
                self._connected.set()

                while not self._stop.is_set():
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue
                    except websockets.exceptions.ConnectionClosed:
                        break
                    try:
                        evt = json.loads(raw)
                    except Exception:
                        continue
                    self._on_event(evt)
        except Exception as exc:
            self._error = exc
            self._connected.set()

    def _on_event(self, evt: Dict[str, Any]) -> None:
        self.received.append(evt)
        topic = evt.get("topic", "?")
        seq = evt.get("seq", "?")
        ts = evt.get("ts_iso", "")
        payload = evt.get("payload", {})
        # Compact inline payload preview (truncate long ones).
        try:
            payload_str = json.dumps(payload, separators=(",", ":"))
        except Exception:
            payload_str = repr(payload)
        if len(payload_str) > 120:
            payload_str = payload_str[:117] + "..."
        line = (
            f"[bus] {ts} #{seq} "
            f"{c(topic, _topic_color(topic))} {c(payload_str, 'dim')}"
        )
        print(line, flush=True)


# --------------------------------------------------------------------------- #
# Gateway tool calls
# --------------------------------------------------------------------------- #


class GatewayClient:
    """Tiny REST client for the Mythos gateway."""

    def __init__(self, port: int, token: str,
                 host: str = "127.0.0.1") -> None:
        self.base = f"http://{host}:{port}"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def list_tools(self, timeout: float = 5.0) -> Dict[str, Any]:
        # Note: gateway exposes GET /tools (NOT /tools/list).
        r = requests.get(f"{self.base}/tools",
                         headers=self.headers, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def call(self, name: str, params: Optional[Dict[str, Any]] = None,
             timeout: float = 35.0) -> Tuple[int, Dict[str, Any]]:
        """Invoke a tool. Returns (status_code, body) — does not raise."""
        body = {"params": params or {}}
        try:
            r = requests.post(f"{self.base}/tools/{name}",
                              headers=self.headers, json=body, timeout=timeout)
            return r.status_code, r.json() if r.content else {}
        except requests.exceptions.RequestException as exc:
            return 0, {"error": "transport", "detail": str(exc)}

    def health(self, timeout: float = 2.0) -> bool:
        try:
            r = requests.get(f"{self.base}/health",
                             headers=self.headers, timeout=timeout)
            return r.status_code == 200
        except requests.exceptions.RequestException:
            return False


def print_response(name: str, status: int, body: Dict[str, Any],
                   params: Optional[Dict[str, Any]] = None) -> None:
    """Pretty-print a gateway response, including signature verification."""
    if 200 <= status < 300:
        decision = body.get("decision_id", "?")
        sig = body.get("audit_signature", "?")
        result = body.get("result", body)
        verified = verify_signature(decision, name, params or {}, "ok", sig)
        tag = c("ok", "green") if verified else c("ok (sig mismatch!)", "yellow")
        print(c(
            f"[gw]  {name} -> 200 {tag}  decision={decision[:8]} sig={sig}",
            "green" if verified else "yellow"
        ))
        try:
            preview = json.dumps(result, indent=2, default=str)
        except Exception:
            preview = repr(result)
        # Indent each line so the gateway block reads as a sub-section.
        for line in preview.splitlines()[:30]:
            print(c(f"      {line}", "dim"))
        if len(preview.splitlines()) > 30:
            print(c("      ... (truncated)", "dim"))
        return

    err = body.get("error", "?")
    detail = body.get("detail", "")
    decision = body.get("decision_id", "")
    sig = body.get("audit_signature", "")
    if status == 403 and err == "approval_rejected":
        # Verify the rejection signature matches "rejected" outcome.
        verified = verify_signature(decision, name, params or {},
                                    "rejected", sig)
        tag = "verified" if verified else "sig mismatch!"
        print(c(
            f"[gw]  {name} -> 403 approval_rejected ({tag}) "
            f"decision={decision[:8]} sig={sig}",
            "yellow"
        ))
        return
    print(c(
        f"[gw]  {name} -> {status} {err}  {detail}",
        "red"
    ))


# --------------------------------------------------------------------------- #
# Main flow
# --------------------------------------------------------------------------- #


def run_demo(duration: int = DEFAULT_DURATION) -> int:
    print(c("=" * 70, "bold"))
    print(c(" Mythos Sample Plugin -- Argus Integration Protocol V1", "bold"))
    print(c("=" * 70, "bold"))
    print()

    token = discover_token()
    if not token:
        print(c(
            "[FATAL] could not locate MYTHOS_BUS_TOKEN.\n"
            "        Set it explicitly:  export MYTHOS_BUS_TOKEN=<hex>\n"
            "        Or start Argus first so the vault is populated.\n"
            "        Or run with the bus already started in this process.",
            "red"
        ))
        return 1
    print(c(f"[init] token discovered: {token[:8]}...{token[-4:]} "
            f"({len(token)} chars)", "dim"))

    # ----- 1. Bus subscriber -----
    sub = BusSubscriber(BUS_HOST, BUS_PORT, token, SUBSCRIBE_TOPICS)
    sub.start()
    if not sub.wait_connected(timeout=4.0):
        if sub.error is not None:
            print(c(f"[FATAL] bus connect failed: {sub.error!r}", "red"))
        else:
            print(c("[FATAL] bus connect timed out", "red"))
        return 2

    # ----- 2. Gateway tool calls -----
    gw = GatewayClient(GATEWAY_PORT, token)
    if not gw.health():
        print(c(
            f"[FATAL] gateway not reachable at {gw.base}. "
            f"Is argus_mythos_gateway running?",
            "red"
        ))
        sub.stop()
        return 3

    # 2a. List tools.
    print()
    print(c("--- GET /tools ----------------------------------------------------",
            "bold"))
    try:
        tools_resp = gw.list_tools()
    except Exception as exc:
        print(c(f"[FATAL] list_tools failed: {exc!r}", "red"))
        sub.stop()
        return 3
    tools = tools_resp.get("tools", [])
    print(c(
        f"[gw]  protocol={tools_resp.get('protocol', '?')}  "
        f"tools_registered={len(tools)}",
        "green"
    ))
    for t in tools:
        flag = ""
        if t.get("needs_approval"):
            flag = " [approval]"
        if t.get("audit_irreversible"):
            flag += " [irreversible]"
        print(c(f"      - {t['name']}{flag}: {t['description']}", "dim"))

    # 2b. query_stats — read-only, no approval.
    print()
    print(c("--- POST /tools/query_stats --------------------------------------",
            "bold"))
    status, body = gw.call("query_stats", {})
    print_response("query_stats", status, body, {})

    # 2c. notify_user — read-only-ish, no approval, illustrates passing args.
    print()
    print(c("--- POST /tools/notify_user --------------------------------------",
            "bold"))
    notify_params = {
        "message": "Hello from Mythos sample",
        "level": "info",
    }
    status, body = gw.call("notify_user", notify_params)
    print_response("notify_user", status, body, notify_params)

    # 2d. set_mode — needs approval. With no UI handler registered, the
    # gateway will fail-closed (the approval helper returns False without
    # waiting on a handler). We expect 403 approval_rejected.
    print()
    print(c("--- POST /tools/set_mode (approval gate) -------------------------",
            "bold"))
    set_mode_params = {"mode": "private"}
    print(c("[gw]  set_mode requires approval; with no UI registered the "
            "gateway returns 403 immediately (fail-closed).",
            "dim"))
    status, body = gw.call("set_mode", set_mode_params, timeout=35.0)
    print_response("set_mode", status, body, set_mode_params)

    # 2e. clear_history — approval + irreversible flag. Same fail-closed.
    print()
    print(c("--- POST /tools/clear_history (approval + irreversible) ----------",
            "bold"))
    clear_params = {"date": "2026-01-01"}
    status, body = gw.call("clear_history", clear_params, timeout=35.0)
    print_response("clear_history", status, body, clear_params)

    # ----- 3. Wait & collect events -----
    print()
    print(c(f"--- Listening on bus for {duration}s (Ctrl-C to stop) ---",
            "bold"))
    end = time.monotonic() + duration
    try:
        while time.monotonic() < end and not sub.error:
            # Print a heartbeat every 10s so the operator knows we're alive.
            time.sleep(min(10.0, end - time.monotonic()))
            print(c(
                f"[heartbeat] {datetime.now(timezone.utc).isoformat()}  "
                f"events_received={len(sub.received)}",
                "dim"
            ))
    except KeyboardInterrupt:
        print(c("\n[init] Ctrl-C received, exiting cleanly", "yellow"))

    # ----- 4. Shutdown summary -----
    sub.stop()
    print()
    print(c("=" * 70, "bold"))
    print(c(f" Summary: {len(sub.received)} bus events received, gateway "
            f"reached at {gw.base}", "bold"))
    print(c("=" * 70, "bold"))
    return 0


def main() -> int:
    try:
        return run_demo()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
