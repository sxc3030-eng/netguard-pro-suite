# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Tests for the memory-audit fixes of 2026-09-30 (docs/AUDIT_MEMOIRE_2026-09-30.md).

Covers:
* prune_ip_tables() evicts idle IPs from every per-IP table and keeps active ones
* _schedule_geo_lookup() never spawns more than one lookup per IP and writes a
  placeholder BEFORE enqueuing (the old code spawned a thread per packet)
* _fetch_city_async() writes a negative cache entry when all providers fail
* anomaly_flush() swaps the accumulator under lock (no RuntimeError)
* pcap recording uses an int counter and rotation reopens a new file
* forensic auto-report is rate-limited per IP
* BehaviorProfile.port_counter is capped
"""

from __future__ import annotations

import os
import time
from unittest.mock import patch

import pytest

import netguard


@pytest.fixture
def seeded_ip_tables():
    """Populate every per-IP table for one idle IP and one active IP."""
    now = time.time()
    idle, active = "203.0.113.10", "198.51.100.20"
    S = netguard.STATE
    for ip, ts in ((idle, now - 7200), (active, now)):
        S.ip_last_seen[ip] = ts
        S.bytes_per_ip[ip] += 100
        S.bytes_per_ip_per_sec[ip].append((int(ts * 1000), 100))
        S.process_per_ip[ip] = "test.exe (1)"
        S.active_conns[ip].add(443)
        S._port_scan_tracker[ip].append((ts, 80))
        S._dns_tracker[ip].append(ts)
        S.ip_risk_scores[ip] = 10
        S.ip_intel[ip] = {"country": "ZZ"}
        S.ip_hit_counter[ip] = 1
        S.ip_recent_packets[ip].appendleft({"ts_ms": int(ts * 1000)})
        S.ip_first_seen_ts[ip] = ts
        netguard.ATTACK_CHAINS[ip] = [{"phase": "scan", "ts": ts, "type": "x"}]
        netguard.JA3_CACHE[ip] = {"hash": "abc", "ts": ts}
        prof = netguard.BehaviorProfile()
        prof.last_seen = ts
        netguard.IP_BEHAVIOR_PROFILES[ip] = prof
        netguard.IP_BASELINES[ip] = netguard.BaselineProfile()
        netguard._geo_city_cache[ip] = {"country": "ZZ", "city": ""}
    yield idle, active
    for ip in (idle, active):
        for d in (S.ip_last_seen, S.bytes_per_ip, S.bytes_per_ip_per_sec, S.process_per_ip,
                  S.active_conns, S._port_scan_tracker, S._dns_tracker, S.ip_risk_scores,
                  S.ip_intel, S.ip_hit_counter, S.ip_recent_packets, S.ip_first_seen_ts,
                  netguard.ATTACK_CHAINS, netguard.JA3_CACHE, netguard.IP_BEHAVIOR_PROFILES,
                  netguard.IP_BASELINES, netguard._geo_city_cache):
            d.pop(ip, None)


class TestPruneIpTables:
    def test_idle_ip_is_evicted_everywhere_and_active_kept(self, seeded_ip_tables):
        idle, active = seeded_ip_tables
        dropped = netguard.prune_ip_tables()
        assert dropped >= 1
        S = netguard.STATE
        for d in (S.ip_last_seen, S.bytes_per_ip, S.bytes_per_ip_per_sec, S.process_per_ip,
                  S.active_conns, S._port_scan_tracker, S._dns_tracker, S.ip_risk_scores,
                  S.ip_intel, S.ip_hit_counter, S.ip_recent_packets, S.ip_first_seen_ts,
                  netguard.ATTACK_CHAINS, netguard.JA3_CACHE, netguard.IP_BEHAVIOR_PROFILES,
                  netguard.IP_BASELINES):
            assert idle not in d, f"idle IP still in {d!r}"
            assert active in d, f"active IP wrongly evicted from {d!r}"

    def test_blocked_ip_keeps_hit_counter_and_intel(self, seeded_ip_tables):
        idle, _ = seeded_ip_tables
        netguard.BLOCKED_IPS.add(idle)
        try:
            netguard.prune_ip_tables()
            assert idle in netguard.STATE.ip_hit_counter
            assert idle in netguard.STATE.ip_intel
            assert idle not in netguard.STATE.bytes_per_ip
        finally:
            netguard.BLOCKED_IPS.discard(idle)

    def test_empty_tracker_keys_are_removed(self):
        S = netguard.STATE
        S._syn_flood_tracker["192.0.2.99"] = []
        netguard.ATTACK_CHAINS["192.0.2.99"] = []
        netguard.prune_ip_tables()
        assert "192.0.2.99" not in S._syn_flood_tracker
        assert "192.0.2.99" not in netguard.ATTACK_CHAINS

    def test_geo_cache_hard_cap(self, monkeypatch):
        monkeypatch.setattr(netguard, "_IP_CACHE_TTL_SEC", 10**9)  # nothing is "stale"
        cache = netguard._geo_city_cache
        before = dict(cache)
        try:
            cache.clear()
            for i in range(60_000):
                cache[f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"] = {"country": ""}
            netguard.prune_ip_tables()
            assert len(cache) <= 50_000
        finally:
            cache.clear()
            cache.update(before)


class TestGeoWorker:
    def test_schedule_writes_placeholder_and_enqueues_once(self, monkeypatch):
        ip = "192.0.2.77"
        netguard._geo_city_cache.pop(ip, None)
        queued = []
        monkeypatch.setattr(netguard._GEO_QUEUE, "put_nowait", lambda x: queued.append(x))
        monkeypatch.setattr(netguard, "_ensure_geo_worker", lambda: None)
        try:
            for _ in range(500):          # 500 packets from the same IP
                netguard._schedule_geo_lookup(ip)
            assert queued == [ip]         # exactly one lookup, not 500 threads
            entry = netguard._geo_city_cache[ip]
            assert entry["_retry_at"] > time.time()
            assert entry["city"] == ""
        finally:
            netguard._geo_city_cache.pop(ip, None)

    def test_schedule_retries_after_negative_entry_expires(self, monkeypatch):
        ip = "192.0.2.78"
        queued = []
        monkeypatch.setattr(netguard._GEO_QUEUE, "put_nowait", lambda x: queued.append(x))
        monkeypatch.setattr(netguard, "_ensure_geo_worker", lambda: None)
        netguard._geo_city_cache[ip] = {"country": "", "city": "", "_retry_at": time.time() - 1}
        try:
            netguard._schedule_geo_lookup(ip)
            assert queued == [ip]
        finally:
            netguard._geo_city_cache.pop(ip, None)

    def test_resolved_entry_is_never_rescheduled(self, monkeypatch):
        ip = "192.0.2.79"
        queued = []
        monkeypatch.setattr(netguard._GEO_QUEUE, "put_nowait", lambda x: queued.append(x))
        netguard._geo_city_cache[ip] = {"country": "CA", "city": "Montréal"}
        try:
            netguard._schedule_geo_lookup(ip)
            assert queued == []
        finally:
            netguard._geo_city_cache.pop(ip, None)

    def test_all_providers_fail_writes_negative_entry(self, monkeypatch):
        ip = "192.0.2.80"
        netguard._geo_city_cache.pop(ip, None)
        monkeypatch.setattr(netguard, "_GEO_PROVIDERS", (lambda _ip: None,))
        try:
            netguard._fetch_city_async(ip)
            entry = netguard._geo_city_cache[ip]
            assert "_retry_at" in entry and entry["_retry_at"] > time.time()
        finally:
            netguard._geo_city_cache.pop(ip, None)


class TestAnomalyFlush:
    def test_flush_swaps_accumulator_and_survives_concurrent_insert(self, monkeypatch):
        calls = []

        def fake_check(ip, *a):
            calls.append(ip)
            # Simulate the sniff thread inserting a new IP mid-iteration
            with netguard._ANOMALY_LOCK:
                netguard._anomaly_accum.setdefault("192.0.2.200", {"pkts": 1, "bytes": 1, "ports": set(), "protos": {}})

        monkeypatch.setattr(netguard, "anomaly_check_ip", fake_check)
        with netguard._ANOMALY_LOCK:
            netguard._anomaly_accum.clear()
            for i in range(5):
                netguard._anomaly_accum[f"192.0.2.{i}"] = {"pkts": 1, "bytes": 1, "ports": set(), "protos": {}}
        netguard.anomaly_flush()          # must not raise RuntimeError
        assert len(calls) == 5
        # The concurrent insert landed in the fresh accumulator, not lost
        assert "192.0.2.200" in netguard._anomaly_accum
        with netguard._ANOMALY_LOCK:
            netguard._anomaly_accum.clear()


class TestRecording:
    def test_record_counter_and_rotation_reopens_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(netguard.CFG, "record_dir", str(tmp_path))
        monkeypatch.setattr(netguard.CFG, "record_rotate_min", 0)   # rotate on first packet
        monkeypatch.setattr(netguard.CFG, "record_max_files", 10)
        assert netguard.record_start()
        first = netguard.STATE.record_file_path
        try:
            netguard.record_write_packet(b"\x00" * 60)   # triggers rotation
            assert netguard.STATE.record_active, "rotation must keep recording"
            assert netguard.STATE.record_file is not None
            assert netguard.STATE.record_count == 0        # fresh file after rotation
            monkeypatch.setattr(netguard.CFG, "record_rotate_min", 60)
            netguard.record_write_packet(b"\x00" * 60)
            netguard.record_write_packet(b"\x00" * 60)
            assert netguard.STATE.record_count == 2
            assert not hasattr(netguard.STATE, "record_packets")
            assert len([f for f in os.listdir(tmp_path) if f.endswith(".pcap")]) == 2
        finally:
            netguard.record_stop()
            assert netguard.STATE.record_file is None


class TestForensicCooldown:
    def test_second_critical_threat_within_cooldown_spawns_no_report(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(netguard.CFG, "auto_forensic_enabled", True)
        monkeypatch.setattr(netguard.CFG, "can_block", False)
        spawned = []

        class FakeThread:
            def __init__(self, *a, **kw):
                spawned.append(kw.get("target"))

            def start(self):
                pass

        ip = "192.0.2.150"
        netguard._FORENSIC_LAST.pop(ip, None)
        with patch.object(netguard.threading, "Thread", FakeThread):
            netguard.add_threat(ip, "JA3 malware", "x", "critical")
            netguard.add_threat(ip, "JA3 malware", "x", "critical")
            netguard.add_threat(ip, "JA3 malware", "x", "critical")
        forensic = [t for t in spawned if t is netguard.generate_forensic_report]
        assert len(forensic) == 1
        netguard._FORENSIC_LAST.pop(ip, None)


class TestBehaviorProfileCap:
    def test_port_counter_capped(self):
        prof = netguard.BehaviorProfile()
        for port in range(1, 5000):
            prof.update(port, "TCP", 60)
        assert len(prof.port_counter) <= 256
        assert prof.total_packets == 4999
