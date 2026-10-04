"""Common types for the capture engines."""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Callable, Optional

# kind values
SEND, RECV, CONNECT, ACCEPT, DISCONNECT = "send", "recv", "connect", "accept", "disconnect"


@dataclass(frozen=True)
class FlowEvent:
    """One unit of observed traffic, from the LOCAL machine's point of view."""
    kind: str            # send | recv | connect | accept | disconnect
    proto: str           # "TCP" | "UDP"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    size: int = 0        # bytes carried by this event (0 for connect/accept/disconnect)
    pid: int = 0

    @property
    def inbound(self) -> bool:
        """True when the remote end is the source of this observation."""
        return self.kind in (RECV, ACCEPT)


@dataclass(frozen=True)
class DnsEvent:
    name: str
    pid: int = 0
    qtype: int = 0


ENGINE_CAPABILITIES = {
    "etw":   ("flows", "bytes", "process", "dns"),
    "poll":  ("flows", "process"),
    "npcap": ("flows", "bytes", "payload", "pcap", "dns", "ja3", "ids"),
}


class CaptureEngine:
    """Base class. Subclasses call ``self.on_flow`` / ``self.on_dns`` from their own thread."""
    name = "base"

    def __init__(self,
                 on_flow: Callable[[FlowEvent], None],
                 on_dns: Optional[Callable[[DnsEvent], None]] = None,
                 on_error: Optional[Callable[[str], None]] = None,
                 on_totals: Optional[Callable[[int, int], None]] = None):
        self.on_flow = on_flow
        self.on_dns = on_dns or (lambda ev: None)
        self.on_error = on_error or (lambda msg: None)
        self.on_totals = on_totals or (lambda rx, tx: None)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.events_seen = 0
        self.events_lost = 0

    @property
    def capabilities(self) -> tuple:
        return ENGINE_CAPABILITIES.get(self.name, ())

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run_guarded, name=f"capture-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run_guarded(self) -> None:
        try:
            self._run()
        except Exception as e:  # noqa: BLE001 — report, never die silently
            self.on_error(f"moteur {self.name}: {type(e).__name__}: {e}")

    def _run(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


def select_engine_name(preference: str, *, is_windows: bool, is_admin: bool,
                       has_scapy: bool, npcap_installed: bool, store_build: bool) -> str:
    """Pick the engine. ``preference`` is CFG.capture_engine: auto | etw | poll | npcap.

    auto on Windows: ETW when elevated (nothing to install), otherwise the
    polling engine. Npcap is never chosen automatically on Windows — it is the
    opt-in "expert" engine — and never in a Store build.
    """
    pref = (preference or "auto").lower()
    env = os.environ.get("NETGUARD_CAPTURE_ENGINE", "").lower()
    if env in ("etw", "poll", "npcap"):
        pref = env
    if not is_windows:
        if pref == "poll" or not has_scapy:
            return "poll"
        return "npcap"
    if pref == "npcap":
        if store_build or not has_scapy or not npcap_installed:
            pref = "auto"
        else:
            return "npcap"
    if pref == "poll":
        return "poll"
    # etw / auto
    return "etw" if is_admin else "poll"
