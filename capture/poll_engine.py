"""Polling capture engine — works without administrator and without any driver.

Reads the operating system's connection table once per second (psutil) and
emits a FlowEvent for every NEW connection. It cannot see per-connection byte
counts or individual packets; global in/out byte rates come from the network
interface counters. Used as the fallback when ETW is not available (not
elevated) so the dashboard is never empty.
"""
from __future__ import annotations

import time
from typing import Dict, Set, Tuple

from .base import ACCEPT, CONNECT, DISCONNECT, CaptureEngine, FlowEvent


def _split(addr) -> Tuple[str, int]:
    try:
        return (addr.ip, int(addr.port)) if addr else ("", 0)
    except Exception:
        try:
            return (addr[0], int(addr[1])) if addr else ("", 0)
        except Exception:
            return ("", 0)


class PollEngine(CaptureEngine):
    name = "poll"

    def __init__(self, *args, interval: float = 1.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.interval = max(0.2, float(interval))
        self._known: Dict[tuple, tuple] = {}
        self._last_io = None

    def snapshot(self):
        """Return (connections, listening_ports). Separated for unit tests."""
        import psutil
        conns = psutil.net_connections(kind="inet")
        listening: Set[int] = set()
        for c in conns:
            if getattr(c, "status", "") == "LISTEN":
                listening.add(_split(c.laddr)[1])
        return conns, listening

    def poll_once(self) -> int:
        """One polling pass. Returns the number of events emitted."""
        import socket as _socket
        conns, listening = self.snapshot()
        current: Dict[tuple, tuple] = {}
        emitted = 0
        for c in conns:
            lip, lport = _split(c.laddr)
            rip, rport = _split(c.raddr)
            if not rip or not rport:
                continue                                  # listening / unconnected socket
            proto = "TCP" if c.type == _socket.SOCK_STREAM else "UDP"
            key = (proto, lip, lport, rip, rport)
            pid = int(c.pid or 0)
            current[key] = (pid,)
            if key in self._known:
                continue
            kind = ACCEPT if lport in listening else CONNECT
            self.events_seen += 1
            emitted += 1
            self.on_flow(FlowEvent(kind=kind, proto=proto, local_ip=lip, local_port=lport,
                                   remote_ip=rip, remote_port=rport, size=0, pid=pid))
        for key, (pid,) in self._known.items():
            if key not in current:
                proto, lip, lport, rip, rport = key
                self.on_flow(FlowEvent(kind=DISCONNECT, proto=proto, local_ip=lip, local_port=lport,
                                       remote_ip=rip, remote_port=rport, size=0, pid=pid))
        self._known = current
        return emitted

    def _totals(self) -> None:
        try:
            import psutil
            io = psutil.net_io_counters()
            if self._last_io is not None:
                rx = max(0, io.bytes_recv - self._last_io.bytes_recv)
                tx = max(0, io.bytes_sent - self._last_io.bytes_sent)
                if rx or tx:
                    self.on_totals(rx, tx)
            self._last_io = io
        except Exception:
            pass

    def _run(self) -> None:
        try:
            import psutil  # noqa: F401
        except ImportError:
            self.on_error("moteur de repli: psutil manquant (pip install psutil)")
            return
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                self.poll_once()
                self._totals()
            except Exception as e:  # noqa: BLE001 — AccessDenied on some builds, keep going
                self.events_lost += 1
                if self.events_lost == 1:
                    self.on_error(f"moteur de repli: {type(e).__name__}: {e}")
            self._stop.wait(max(0.05, self.interval - (time.monotonic() - t0)))
