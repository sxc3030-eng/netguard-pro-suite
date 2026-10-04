# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Tests for the superaudit hardening of 2026-09-30 (docs/SUPERAUDIT_2026-09-30.md).

Backend (netguard.py):
* block_ip_os never auto-blocks private / whitelisted IPs, is rate-limited,
  and manual blocks bypass the rate limit
* auto_block_check ignores spoofable evidence against servers we talk to
* add_threat sanitises strings and applies a per-(ip, type) cooldown
* _safe_str strips HTML delimiters and control characters
* _validate_ip rejects non-strings (JSON ints parse as IPs)
* backup_delete / backup_create refuse path traversal
* _report_filename refuses unknown types/formats (path injection)
* update_param allowlist (no __dict__, no record_dir, no whitelist)
* backup_restore validates blocked_ips / geo_countries types
* WebSocket dispatcher survives malformed commands
"""

from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

import netguard


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


def run(coro):
    return asyncio.run(coro)


class TestSafeStr:
    def test_strips_html_and_control_chars(self):
        s = netguard._safe_str('<img src=x onerror="alert(1)">\n\x00evil\tname')
        assert "<" not in s and ">" not in s and '"' not in s
        assert "\n" not in s and "\x00" not in s
        assert "evil name" in s

    def test_caps_length_and_handles_non_str(self):
        assert len(netguard._safe_str("a" * 1000)) == netguard._NET_STR_MAX
        assert netguard._safe_str(None) == ""
        assert netguard._safe_str(123) == "123"


class TestValidateIp:
    def test_rejects_int_and_garbage(self):
        assert netguard._validate_ip(16843009) is False
        assert netguard._validate_ip("../x") is False
        assert netguard._validate_ip("1.1.1.1") is True
        assert netguard._validate_ip("2001:db8::1") is True


class TestBlockGuards:
    @pytest.fixture(autouse=True)
    def _no_os(self, monkeypatch):
        monkeypatch.setattr(netguard.CFG, "can_block", False)
        netguard._AUTO_BLOCK_WINDOW.clear()
        yield
        netguard._AUTO_BLOCK_WINDOW.clear()

    def test_auto_block_never_touches_whitelist_or_private(self):
        netguard.block_ip_os("8.8.8.8", "geo")           # whitelisted by default
        netguard.block_ip_os("192.168.1.10", "scan")     # private
        assert "8.8.8.8" not in netguard.BLOCKED_IPS
        assert "192.168.1.10" not in netguard.BLOCKED_IPS

    def test_manual_block_bypasses_guards_but_validates(self):
        netguard.block_ip_os("45.79.1.5", "manual", manual=True)
        assert "45.79.1.5" in netguard.BLOCKED_IPS
        netguard.block_ip_os("not-an-ip", "manual", manual=True)
        assert "not-an-ip" not in netguard.BLOCKED_IPS

    def test_auto_block_rate_limit(self):
        for i in range(netguard._AUTO_BLOCK_MAX_PER_MIN + 10):
            netguard.block_ip_os(f"45.33.{(i + 1) // 256}.{(i + 1) % 256}", "flood")
        blocked = [ip for ip in netguard.BLOCKED_IPS if ip.startswith("45.33.")]
        assert len(blocked) == netguard._AUTO_BLOCK_MAX_PER_MIN

    def test_auto_block_check_ignores_spoofable_evidence_against_known_server(self, monkeypatch):
        monkeypatch.setattr(netguard.CFG, "auto_block_enabled", True)
        monkeypatch.setattr(netguard.CFG, "auto_block_hits", 1)
        ip = "91.198.174.9"
        netguard.STATE.outbound_seen[ip] = time.time()       # we talk to this server
        netguard.STATE.ip_hit_counter.pop(ip, None)
        try:
            netguard.auto_block_check(ip, established=False)  # blind spoof
            assert ip not in netguard.BLOCKED_IPS
            netguard.auto_block_check(ip, established=True)   # real conversation
            assert ip in netguard.BLOCKED_IPS
        finally:
            netguard.STATE.outbound_seen.pop(ip, None)
            netguard.STATE.ip_hit_counter.pop(ip, None)

    def test_flow_established(self):
        netguard.STATE.flows[("198.51.100.1", 443, 50000)] = time.time()
        try:
            assert netguard._flow_established("198.51.100.1", 443, 50000)
            assert not netguard._flow_established("198.51.100.1", 443, 50001)
        finally:
            netguard.STATE.flows.clear()


class TestAddThreat:
    def test_sanitises_and_cooldown(self):
        netguard._THREAT_LAST.clear()
        t1 = netguard.add_threat("203.0.113.77", "DNS <b>x</b>", "Domaine=<script>alert(1)</script>", "high")
        assert "<" not in t1["type"] and "<" not in t1["description"]
        n = len(netguard.STATE.threats)
        t2 = netguard.add_threat("203.0.113.77", "DNS <b>x</b>", "autre", "high")
        assert t2 is t1                      # cooldown: same (ip, type) within 10 s
        assert len(netguard.STATE.threats) == n
        netguard._THREAT_LAST.clear()


class TestBackupPaths:
    def test_backup_delete_refuses_traversal_and_absolute(self, tmp_path, monkeypatch):
        monkeypatch.setattr(netguard, "BACKUP_DIR", str(tmp_path / "backups"))
        os.makedirs(netguard.BACKUP_DIR)
        victim = tmp_path / "netguard_settings.json"
        victim.write_text("{}")
        for bad in ("../netguard_settings.json", str(victim), "..\\netguard_settings.json", 42):
            r = netguard.backup_delete(bad)
            assert r["ok"] is False
        assert victim.exists()

    def test_backup_delete_ok_inside_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(netguard, "BACKUP_DIR", str(tmp_path))
        f = tmp_path / "netguard_backup_1.json"
        f.write_text("{}")
        assert netguard.backup_delete("netguard_backup_1.json")["ok"] is True
        assert not f.exists()

    def test_backup_create_refuses_bad_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr(netguard, "BACKUP_DIR", str(tmp_path))
        r = netguard.backup_create("C:\\Users\\x\\evil", [])
        assert r["ok"] is False
        r = netguard.backup_create("../evil", [])
        assert r["ok"] is False
        assert not (tmp_path.parent / "evil.json").exists()


class TestReportFilename:
    def test_refuses_injection(self):
        with pytest.raises(ValueError):
            netguard._report_filename("full", "json/../../../x.bat")
        with pytest.raises(ValueError):
            netguard._report_filename("../x", "json")
        p = netguard._report_filename("threats", "csv")
        assert p.name.startswith("netguard_threats_") and p.suffix == ".csv"


class TestWsCommands:
    def test_update_param_allowlist(self):
        ws = FakeWS()
        before_dir = netguard.CFG.record_dir
        run(netguard.handle_ws_command(ws, {"cmd": "update_param", "key": "__dict__", "value": {}}))
        run(netguard.handle_ws_command(ws, {"cmd": "update_param", "key": "record_dir", "value": "C:\\x"}))
        run(netguard.handle_ws_command(ws, {"cmd": "update_param", "key": "whitelist", "value": "x"}))
        assert netguard.CFG.record_dir == before_dir
        assert all(m["type"] == "param_error" for m in ws.sent)
        run(netguard.handle_ws_command(ws, {"cmd": "update_param", "key": "port_scan_threshold", "value": "7"}))
        assert ws.sent[-1]["type"] == "param_updated"
        assert netguard.CFG.port_scan_threshold == 7

    def test_bad_types_do_not_raise(self):
        ws = FakeWS()
        run(netguard.handle_ws_command(ws, {"cmd": "set_auto_block_hits", "value": "abc"}))
        assert netguard.CFG.auto_block_hits == 10
        run(netguard.handle_ws_command(ws, {"cmd": "block_ip", "ip": 16843009}))
        assert ws.sent[-1]["type"] == "error"
        run(netguard.handle_ws_command(ws, []))      # non-dict JSON
        assert ws.sent[-1]["type"] == "error"
        run(netguard.handle_ws_command(ws, {"cmd": "generate_report", "report_type": "../x", "format": "json"}))
        assert ws.sent[-1]["type"] == "report_error"

    def test_generate_forensic_requires_valid_ip(self):
        ws = FakeWS()
        run(netguard.handle_ws_command(ws, {"cmd": "generate_forensic", "ip": "../../x"}))
        assert ws.sent == []


class TestBackupRestoreValidation:
    def test_blocked_ips_string_and_bad_countries_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(netguard, "BACKUP_DIR", str(tmp_path))
        monkeypatch.setattr(netguard, "load_settings", lambda: None)
        monkeypatch.setattr(netguard, "_secure_json_write", lambda *a, **k: None)
        data = {"blocked_ips": "1.2.3.4", "geo_countries": ["fr", "<x>", 5]}
        (tmp_path / "netguard_backup_t.json").write_text(json.dumps(data), encoding="utf-8")
        netguard.BLOCKED_IPS.add("203.0.113.1")
        r = netguard.backup_restore("netguard_backup_t.json")
        assert r["ok"] is True
        assert "203.0.113.1" in netguard.BLOCKED_IPS          # string payload ignored, list untouched
        assert "1" not in netguard.BLOCKED_IPS
        assert netguard.GEO_BLOCKED_COUNTRIES == {"FR"}
        netguard.GEO_BLOCKED_COUNTRIES.clear()
