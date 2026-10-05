# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Capture engines (2026-10): ETW (no driver), polling fallback, Npcap expert mode.

No live ETW session is opened here (it needs administrator): the payload
parsers are pure functions fed with bytes built exactly like the
Microsoft-Windows-Kernel-Network / DNS-Client manifests describe them.
"""

from __future__ import annotations

import socket
import struct
import sys
from types import SimpleNamespace

import pytest

import netguard
from capture import ENGINE_CAPABILITIES, DnsEvent, FlowEvent, select_engine_name
from capture import etw_engine as etw
from capture.poll_engine import PollEngine


def v4_payload(pid, size, daddr, saddr, dport, sport, extra=b"\x00" * 16):
    return (struct.pack("<II", pid, size) + socket.inet_aton(daddr) + socket.inet_aton(saddr)
            + struct.pack(">HH", dport, sport) + extra)


def v6_payload(pid, size, daddr, saddr, dport, sport):
    return (struct.pack("<II", pid, size) + socket.inet_pton(socket.AF_INET6, daddr)
            + socket.inet_pton(socket.AF_INET6, saddr) + struct.pack(">HH", dport, sport) + b"\x00" * 12)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ABI: ctypes.wintypes sizes differ elsewhere")
class TestEtwStructs:
    @pytest.mark.skipif(struct.calcsize("P") != 8, reason="x64 layout")
    def test_sizes_match_windows_sdk(self):
        assert etw.struct_sizes() == {
            "EVENT_TRACE_PROPERTIES": 120, "EVENT_HEADER": 80, "EVENT_RECORD": 112,
            "EVENT_TRACE": 88, "TRACE_LOGFILE_HEADER": 280, "EVENT_TRACE_LOGFILEW": 448,
        }

    def test_guid_roundtrip(self):
        g = etw.GUID.from_uuid(etw.KERNEL_NETWORK_GUID)
        assert g.to_uuid() == etw.KERNEL_NETWORK_GUID
        assert bytes(g) == etw.KERNEL_NETWORK_GUID.bytes_le


class TestNetworkEventParser:
    LOCAL = {"10.0.0.194", "127.0.0.1"}

    def test_tcp4_send(self):
        ev = etw.parse_network_event(10, v4_payload(4321, 1460, "93.184.216.34", "10.0.0.194", 443, 51000), self.LOCAL)
        assert ev == FlowEvent("send", "TCP", "10.0.0.194", 51000, "93.184.216.34", 443, 1460, 4321)
        assert not ev.inbound

    def test_tcp4_recv_keeps_local_endpoint(self):
        ev = etw.parse_network_event(11, v4_payload(4321, 900, "93.184.216.34", "10.0.0.194", 443, 51000), self.LOCAL)
        assert ev.kind == "recv" and ev.inbound
        assert (ev.local_ip, ev.local_port, ev.remote_ip, ev.remote_port) == ("10.0.0.194", 51000, "93.184.216.34", 443)

    def test_recv_in_wire_order_is_swapped_using_local_ips(self):
        # some builds log receive events as source=remote, destination=local
        ev = etw.parse_network_event(11, v4_payload(1, 10, "10.0.0.194", "93.184.216.34", 51000, 443), self.LOCAL)
        assert (ev.local_ip, ev.local_port, ev.remote_ip, ev.remote_port) == ("10.0.0.194", 51000, "93.184.216.34", 443)

    def test_ports_are_network_byte_order(self):
        ev = etw.parse_network_event(10, v4_payload(1, 1, "1.2.3.4", "10.0.0.194", 443, 0x1234), self.LOCAL)
        assert ev.remote_port == 443 and ev.local_port == 0x1234

    def test_connect_accept_have_no_size(self):
        c = etw.parse_network_event(12, v4_payload(7, 999, "1.2.3.4", "10.0.0.194", 22, 50001), self.LOCAL)
        a = etw.parse_network_event(15, v4_payload(7, 999, "5.6.7.8", "10.0.0.194", 40000, 3389), self.LOCAL)
        assert c.kind == "connect" and c.size == 0 and not c.inbound
        assert a.kind == "accept" and a.size == 0 and a.inbound and a.local_port == 3389

    def test_udp4_and_ipv6(self):
        u = etw.parse_network_event(42, v4_payload(9, 64, "8.8.8.8", "10.0.0.194", 53, 60000), self.LOCAL)
        assert u.proto == "UDP" and u.kind == "send" and u.remote_port == 53
        t6 = etw.parse_network_event(27, v6_payload(9, 1200, "2607:6bc0::10", "2607:fa49::1", 443, 55555), {"2607:fa49::1"})
        assert t6.proto == "TCP" and t6.kind == "recv" and t6.remote_ip == "2607:6bc0::10" and t6.local_port == 55555
        u6 = etw.parse_network_event(58, v6_payload(9, 80, "2001:4860:4860::8888", "2607:fa49::1", 53, 50000), None)
        assert u6.proto == "UDP" and u6.remote_port == 53

    def test_garbage_is_ignored(self):
        assert etw.parse_network_event(10, b"\x00" * 5) is None
        assert etw.parse_network_event(9999, v4_payload(1, 1, "1.1.1.1", "2.2.2.2", 1, 1)) is None
        assert etw.parse_network_event(26, b"\x01" * 20) is None


class TestDnsEventParser:
    def test_query_name_and_type(self):
        data = "www.example.com".encode("utf-16-le") + b"\x00\x00" + struct.pack("<I", 28) + b"\x00" * 8
        assert etw.parse_dns_event(data, pid=42) == DnsEvent("www.example.com", 42, 28)

    def test_trailing_dot_and_bad_input(self):
        assert etw.parse_dns_event("a.b.".encode("utf-16-le") + b"\x00\x00").name == "a.b"
        assert etw.parse_dns_event(b"") is None
        assert etw.parse_dns_event(b"\x00\x00") is None
        assert etw.parse_dns_event(("x" * 300).encode("utf-16-le") + b"\x00\x00") is None


class TestEngineSelection:
    K = dict(has_scapy=True, npcap_installed=True, store_build=False)

    def test_windows_auto_prefers_etw_when_admin_else_poll(self):
        assert select_engine_name("auto", is_windows=True, is_admin=True, **self.K) == "etw"
        assert select_engine_name("auto", is_windows=True, is_admin=False, **self.K) == "poll"

    def test_npcap_is_opt_in_and_never_in_store_build(self):
        assert select_engine_name("npcap", is_windows=True, is_admin=True, **self.K) == "npcap"
        assert select_engine_name("npcap", is_windows=True, is_admin=True, has_scapy=True,
                                  npcap_installed=True, store_build=True) == "etw"
        assert select_engine_name("npcap", is_windows=True, is_admin=False, has_scapy=True,
                                  npcap_installed=False, store_build=False) == "poll"

    def test_non_windows_uses_scapy_or_poll(self):
        assert select_engine_name("auto", is_windows=False, is_admin=True, **self.K) == "npcap"
        assert select_engine_name("auto", is_windows=False, is_admin=True, has_scapy=False,
                                  npcap_installed=False, store_build=False) == "poll"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("NETGUARD_CAPTURE_ENGINE", "poll")
        assert select_engine_name("auto", is_windows=True, is_admin=True, **self.K) == "poll"

    def test_capabilities(self):
        assert "payload" not in ENGINE_CAPABILITIES["etw"] and "bytes" in ENGINE_CAPABILITIES["etw"]
        assert "pcap" in ENGINE_CAPABILITIES["npcap"]
        assert "bytes" not in ENGINE_CAPABILITIES["poll"]


class TestPollEngine:
    def _conn(self, lip, lport, rip, rport, pid=10, status="ESTABLISHED", stream=True):
        return SimpleNamespace(laddr=SimpleNamespace(ip=lip, port=lport),
                               raddr=SimpleNamespace(ip=rip, port=rport) if rip else None,
                               pid=pid, status=status,
                               type=socket.SOCK_STREAM if stream else socket.SOCK_DGRAM)

    def test_new_connections_emit_once_and_direction_from_listeners(self, monkeypatch):
        seen = []
        eng = PollEngine(on_flow=seen.append)
        conns = [self._conn("10.0.0.5", 3389, None, 0, status="LISTEN"),
                 self._conn("10.0.0.5", 50000, "1.2.3.4", 443, pid=77),
                 self._conn("10.0.0.5", 3389, "5.6.7.8", 61000, pid=4)]
        monkeypatch.setattr(eng, "snapshot", lambda: (conns, {3389}))
        assert eng.poll_once() == 2
        kinds = {(e.remote_ip, e.kind, e.pid) for e in seen}
        assert kinds == {("1.2.3.4", "connect", 77), ("5.6.7.8", "accept", 4)}
        assert eng.poll_once() == 0                      # nothing new
        monkeypatch.setattr(eng, "snapshot", lambda: (conns[:2], {3389}))
        eng.poll_once()
        assert seen[-1].kind == "disconnect" and seen[-1].remote_ip == "5.6.7.8"

    def test_errors_are_reported_not_raised(self):
        errors = []
        eng = etw.EtwEngine(on_flow=lambda e: None, on_error=errors.append)
        eng._run = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        eng._run_guarded()
        assert errors and "boom" in errors[0]


class TestPipelineAdapter:
    @pytest.fixture
    def calls(self, monkeypatch):
        got = []
        monkeypatch.setattr(netguard, "process_observation",
                            lambda *a, **k: got.append((a, k)))
        monkeypatch.setattr(netguard, "_proc_label", lambda pid: f"proc ({pid})" if pid else "")
        monkeypatch.setattr(netguard, "_refresh_local_ips", lambda force=False: None)
        return got

    def test_outbound_send_maps_local_to_remote(self, calls, monkeypatch):
        monkeypatch.setattr(netguard.STATE, "capture_engine", "etw")
        netguard.analyze_flow(FlowEvent("send", "TCP", "10.0.0.5", 50000, "93.184.216.34", 443, 1460, 12))
        (a, k), = calls
        assert a == ("10.0.0.5", "93.184.216.34", 50000, 443, "HTTPS", 1460)
        assert k["is_syn"] is False and k["process_label"] == "proc (12)"

    def test_inbound_accept_is_a_connection_attempt_from_remote(self, calls, monkeypatch):
        monkeypatch.setattr(netguard.STATE, "capture_engine", "etw")
        netguard.analyze_flow(FlowEvent("accept", "TCP", "10.0.0.5", 3389, "5.6.7.8", 61000, 0, 4))
        (a, k), = calls
        assert a[:5] == ("5.6.7.8", "10.0.0.5", 61000, 3389, "RDP")
        assert k["is_syn"] is True and k["flags"] == "S"

    def test_loopback_and_disconnect_are_dropped(self, calls):
        netguard.analyze_flow(FlowEvent("send", "TCP", "127.0.0.1", 1, "127.0.0.1", 2, 5, 1))
        netguard.analyze_flow(FlowEvent("disconnect", "TCP", "10.0.0.5", 1, "1.2.3.4", 2, 0, 1))
        assert calls == []

    def test_poll_engine_mirrors_outbound_connect(self, calls, monkeypatch):
        monkeypatch.setattr(netguard.STATE, "capture_engine", "poll")
        netguard.analyze_flow(FlowEvent("connect", "TCP", "10.0.0.5", 50000, "1.2.3.4", 443, 0, 9))
        assert len(calls) == 2
        assert calls[1][0][:4] == ("1.2.3.4", "10.0.0.5", 443, 50000)


class TestPipelineWithoutPackets:
    def test_flow_observation_reaches_state_without_scapy(self, monkeypatch):
        monkeypatch.setattr(netguard, "_schedule_geo_lookup", lambda ip: None)
        monkeypatch.setattr(netguard, "process_for_packet", lambda *a: "")
        before = netguard.STATE.packets_total
        netguard.process_observation("45.33.32.156", "10.0.0.5", 443, 50000, "HTTPS", 1200,
                                     process_label="chrome.exe (1)")
        assert netguard.STATE.packets_total == before + 1
        entry = netguard.STATE.recent_packets[0]
        assert entry["src"] == "45.33.32.156" and entry["size"] == "1200B" and entry["process"] == "chrome.exe (1)"

    def test_local_public_address_is_not_external(self, monkeypatch):
        monkeypatch.setattr(netguard, "_LOCAL_IPS", {"2607:fa49:b402:a100::1"})
        assert netguard.is_private("2607:fa49:b402:a100::1") is True
        assert netguard.is_private("2607:6bc0::10") is False

    def test_recording_refused_without_pcap_capability(self, monkeypatch):
        monkeypatch.setattr(netguard.STATE, "capture_engine", "etw")
        monkeypatch.setattr(netguard.STATE, "capture_caps", ENGINE_CAPABILITIES["etw"])
        assert netguard.record_start() is False
        assert netguard.STATE.record_active is False

    def test_dns_event_triggers_blackhole_threat(self, monkeypatch):
        monkeypatch.setattr(netguard, "_refresh_local_ips", lambda force=False: None)
        monkeypatch.setattr(netguard, "_LOCAL_IPS", {"10.0.0.5"})
        monkeypatch.setattr(netguard, "dns_blackhole_check", lambda name: name == "evil.example")
        monkeypatch.setattr(netguard, "_proc_label", lambda pid: "bad.exe (5)")
        netguard._THREAT_LAST.clear()
        n = len(netguard.STATE.threats)
        netguard.analyze_dns(DnsEvent("evil.example", 5))
        assert len(netguard.STATE.threats) == n + 1
        t = netguard.STATE.threats[0]
        assert t["src_ip"] == "10.0.0.5" and "evil.example" in t["description"] and "bad.exe" in t["description"]
        netguard._THREAT_LAST.clear()
