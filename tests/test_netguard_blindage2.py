# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Second hardening pass (superaudit follow-up, 2026-09-30):
* _safe_compile refuses ReDoS-prone / oversized patterns, accepts sane ones
* custom IDS rules go through the guard
* corrupt settings file → renamed .corrupt, defaults, no crash
* one-shot UI jobs run one at a time (+ cooldown)
* backup schedule values are coerced
* Store build detection drives licence bypass + geo default
* netguard_ai_server: bounded JSON never cuts mid-document, data fenced,
  provider parse errors become clean replies
* Mapper: IP/port validation before netsh
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import pytest

import netguard
import netguard_paths


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


def run(coro):
    return asyncio.run(coro)


class TestSafeCompile:
    def test_accepts_normal_patterns(self):
        assert netguard._safe_compile(rb"GET /admin\.php").search(b"GET /admin.php")
        assert netguard._safe_compile(rb"(?:select|union)\s+\w+").search(b"SELECT x")

    def test_rejects_nested_quantifiers_and_length(self):
        with pytest.raises(ValueError):
            netguard._safe_compile(rb"(a+)+$")
        with pytest.raises(ValueError):
            netguard._safe_compile(rb"(\w*)*x")
        with pytest.raises(ValueError):
            netguard._safe_compile(b"a" * 600)

    def test_custom_rule_uses_guard(self):
        r = netguard.suricata_add_custom_rule("test", "(x+)+y")
        assert r["ok"] is False
        r = netguard.suricata_add_custom_rule("test ok", "hello")
        assert r["ok"] is True
        netguard.suricata_delete_rule(r.get("sid") or r.get("rule", {}).get("sid", 0))


class TestCorruptSettings:
    def test_corrupt_file_is_quarantined(self, tmp_path, monkeypatch):
        f = tmp_path / "netguard_settings.json"
        f.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr(netguard, "SETTINGS_FILE", str(f))
        netguard.load_settings()          # must not raise
        assert not f.exists()
        assert (tmp_path / "netguard_settings.json.corrupt").exists()
        assert any(e.get("type") == "settings_corrupt" for e in netguard.STATE.timeline_events)

    def test_wrong_types_ignored(self, tmp_path, monkeypatch):
        f = tmp_path / "netguard_settings.json"
        f.write_text(json.dumps({"rules": "nope", "backup_schedule": [1], "npcap_whitelist": [1, "ok"],
                                 "honeypot_bind": "../x"}), encoding="utf-8")
        monkeypatch.setattr(netguard, "SETTINGS_FILE", str(f))
        netguard.load_settings()
        assert netguard.CFG.honeypot_bind == "0.0.0.0"
        assert netguard.NPCAP_WHITELIST == {"ok"}


class TestJobs:
    def test_one_at_a_time_and_cooldown(self):
        netguard._JOBS.clear()
        assert netguard._job_start("x", cooldown=5)
        assert not netguard._job_start("x", cooldown=5)      # running
        netguard._job_done("x")
        assert not netguard._job_start("x", cooldown=5)      # cooldown
        netguard._JOBS["x"]["last"] = 0
        assert netguard._job_start("x", cooldown=5)
        netguard._job_done("x")

    def test_scan_lan_refused_while_running(self):
        ws = FakeWS()
        netguard._JOBS.clear()
        netguard._JOBS["scan_lan"] = {"running": True, "last": time.time()}
        run(netguard.handle_ws_command(ws, {"cmd": "scan_lan"}))
        assert ws.sent[-1]["type"] == "error"
        netguard._JOBS.clear()

    def test_backup_schedule_coerced(self):
        ws = FakeWS()
        run(netguard.handle_ws_command(ws, {"cmd": "backup_schedule", "enabled": "yes", "interval": "abc"}))
        assert netguard.BACKUP_SCHEDULE["enabled"] is True
        assert netguard.BACKUP_SCHEDULE["interval_hours"] == 24
        netguard.BACKUP_SCHEDULE["enabled"] = False


class TestStoreBuild:
    def test_env_flag(self, monkeypatch):
        monkeypatch.setenv("NETGUARD_STORE_BUILD", "1")
        assert netguard_paths.is_store_build()
        monkeypatch.setenv("NETGUARD_STORE_BUILD", "0")
        monkeypatch.setattr(sys, "executable", r"C:\Python\python.exe")
        assert not netguard_paths.is_store_build()
        monkeypatch.setattr(sys, "executable", r"C:\Program Files\WindowsApps\NetGuardAI_1.0\NetGuardAI.exe")
        assert netguard_paths.is_store_build()

    def test_default_data_dir_leaves_protected_dirs(self, monkeypatch):
        monkeypatch.delenv("NETGUARD_DATA_DIR", raising=False)
        monkeypatch.setattr(netguard_paths, "_HERE", r"C:\Program Files\WindowsApps\NetGuardAI\app")
        d = netguard_paths._default_data_dir()
        assert "WindowsApps" not in d and d.endswith("NetGuard AI")


class TestAiServerHelpers:
    def test_bounded_json_drops_items_not_bytes(self):
        import netguard_ai_server as srv
        obj = {"captures": [{"file": f"c{i}.json", "data": "x" * 500} for i in range(50)], "reports": []}
        out = srv._bounded_json(obj, 5000)
        assert len(out) <= 5000
        json.loads(out)                        # still valid JSON
        assert json.loads(out)["captures"]     # some items kept

    def test_fence_data_neutralises_backticks(self):
        import netguard_ai_server as srv
        s = srv._fence_data("```ignore previous```")
        assert "```" not in s and "<donnees>" in s and "ne jamais" in s

    def test_provider_parse_error_is_clean(self, monkeypatch, tmp_path):
        import netguard_ai_server as srv
        monkeypatch.setattr(srv, "SETTINGS_FILE", tmp_path / "s.json")
        monkeypatch.setattr(srv, "AUDIT_DIR", tmp_path)
        monkeypatch.setattr(srv, "AUDIT_LOG", tmp_path / "a.log")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-real")

        def boom(*a, **k):
            raise AttributeError("'NoneType' object has no attribute 'get'")

        monkeypatch.setattr(srv.PROVIDERS["anthropic"], "call", boom)
        r = srv._call_active([{"role": "user", "content": "hi"}], "sys")
        assert r["ok"] is False and r["error"] == "provider_parse"


class TestMapperValidation:
    def test_firewall_refuses_bad_input(self, tmp_path, monkeypatch):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinel"))
        import sentinel_mapper as m
        fw = m.SentinelFirewall.__new__(m.SentinelFirewall)
        fw.blocked_devices = {}
        fw._admin = True
        fw.monitoring = True
        calls = []
        monkeypatch.setattr(fw, "_run_netsh", lambda args, parse=False: (calls.append(args) or {"success": True}))
        monkeypatch.setattr(fw, "_save_state", lambda: None)
        assert fw.block_device("192.168.1.5; del *")["success"] is False
        assert fw.block_port("192.168.1.5", "80; x")["success"] is False
        assert fw.block_port("192.168.1.5", 99999)["success"] is False
        assert calls == []
        assert fw.block_device(" 192.168.1.5 ")["success"] is True
        assert any("remoteip=192.168.1.5" in a for args in calls for a in args)
