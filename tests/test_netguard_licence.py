# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Trial end and licence activation (2026-10-05).

Before: after 30 days the programme computed "expired" and restricted nothing;
deleting netguard_license.json or post-dating it handed out a new trial.
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import license_manager as lm
import netguard


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


def run(coro):
    return asyncio.run(coro)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@pytest.fixture
def licence_env(tmp_path, monkeypatch):
    """Isolated licence file, activation registry and signing key."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(lm, "LICENSE_FILE", str(tmp_path / "netguard_license.json"))
    monkeypatch.setattr(lm, "ACTIVATIONS_DIR", str(tmp_path))
    monkeypatch.setattr(lm, "ACTIVATIONS_FILE", str(tmp_path / ".activations.json"))
    monkeypatch.setattr(lm, "LICENSE_PUBLIC_KEY_B64", base64.b64encode(pub).decode())
    anchor = {"v": ""}
    monkeypatch.setattr(lm, "_trial_anchor_read", lambda: anchor["v"])
    monkeypatch.setattr(lm, "_trial_anchor_write", lambda iso: anchor.__setitem__("v", iso))
    monkeypatch.setattr(netguard, "_LICENSE_SKIP", False)
    monkeypatch.setattr(netguard, "_LICENSE_REFRESHED", 0.0)

    def mint(**extra):
        payload = {"tier": "pro", "plan": "starter", "max_seats": 1, "license_id": str(uuid.uuid4()),
                   "customer_email": "client@example.com",
                   "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        payload.update(extra)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return f"NGPRO-{b64url(body)}-{b64url(priv.sign(body))}"

    def set_trial(days_ago):
        start = (datetime.now() - timedelta(days=days_ago)).isoformat()
        (tmp_path / "netguard_license.json").write_text(json.dumps({"trial_start": start, "tier": "trial"}))
        netguard._LICENSE_REFRESHED = 0.0
        netguard.LICENSE.clear()
        netguard.LICENSE.update(lm.init_license())

    yield SimpleNS(tmp=tmp_path, mint=mint, set_trial=set_trial, anchor=anchor)
    netguard.LICENSE.clear()
    netguard.LICENSE.update({"tier": "trial", "trial": True, "trial_days_left": 30, "expired": False})
    netguard._LICENSE_REFRESHED = 1e18      # no refresh for the following tests


class SimpleNS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class TestTrialClock:
    def test_first_launch_starts_30_days_and_writes_anchor(self, licence_env):
        st = lm.init_license()
        assert st["trial"] and st["trial_days_left"] == 30 and not st["expired"]
        assert licence_env.anchor["v"]

    def test_day_31_is_expired(self, licence_env):
        licence_env.set_trial(31)
        st = lm.init_license()
        assert st["expired"] and st["tier"] == "free" and st["trial_days_left"] == 0

    def test_future_dated_file_is_not_a_long_trial(self, licence_env):
        licence_env.set_trial(-400)
        st = lm.init_license()
        assert st["expired"], "une date dans le futur donnait 430 jours d'essai"

    def test_deleting_the_file_does_not_restart_the_trial(self, licence_env):
        licence_env.anchor["v"] = (datetime.now() - timedelta(days=45)).isoformat()
        st = lm.init_license()                       # no licence file at all
        assert st["expired"]
        assert (licence_env.tmp / "netguard_license.json").exists()   # restored from the marker

    def test_days_left_never_exceeds_30(self, licence_env):
        licence_env.set_trial(0)
        assert lm.init_license()["trial_days_left"] <= 30


class TestGate:
    def test_trial_running_nothing_is_locked(self, licence_env, monkeypatch):
        monkeypatch.setattr(netguard.CFG, "can_block", False)
        licence_env.set_trial(3)
        assert netguard.license_locked() is False
        ws = FakeWS()
        run(netguard.handle_ws_command(ws, {"cmd": "block_ip", "ip": "45.33.32.10", "reason": "x"}))
        assert ws.sent[-1]["type"] == "ip_blocked"

    def test_after_trial_blocking_needs_a_licence_but_unblocking_does_not(self, licence_env, monkeypatch):
        monkeypatch.setattr(netguard.CFG, "can_block", False)
        netguard.BLOCKED_IPS.add("45.33.32.11")
        licence_env.set_trial(40)
        assert netguard.license_locked() is True
        ws = FakeWS()
        run(netguard.handle_ws_command(ws, {"cmd": "block_ip", "ip": "45.33.32.12"}))
        assert ws.sent[-1]["type"] == "license_required" and ws.sent[-1]["purchase_url"]
        assert "45.33.32.12" not in netguard.BLOCKED_IPS
        run(netguard.handle_ws_command(ws, {"cmd": "unblock_ip", "ip": "45.33.32.11"}))
        assert ws.sent[-1]["type"] == "ip_unblocked"
        run(netguard.handle_ws_command(ws, {"cmd": "set_geo_countries", "countries": ["RU"]}))
        assert ws.sent[-1]["type"] == "license_required"
        run(netguard.handle_ws_command(ws, {"cmd": "get_blocked_ips"}))
        assert ws.sent[-1]["type"] == "blocked_ips"            # monitoring stays available

    def test_automatic_blocking_stops_after_trial(self, licence_env, monkeypatch):
        monkeypatch.setattr(netguard.CFG, "can_block", False)
        netguard._AUTO_BLOCK_WINDOW.clear()
        licence_env.set_trial(40)
        netguard.block_ip_os("45.33.32.20", "scan")
        assert "45.33.32.20" not in netguard.BLOCKED_IPS
        netguard.block_ip_os("45.33.32.21", "manuel", manual=True)   # internal manual path is not the gate
        assert "45.33.32.21" in netguard.BLOCKED_IPS

    def test_state_exposes_lock_and_purchase_url(self, licence_env):
        licence_env.set_trial(40)
        s = netguard.build_state_message()
        assert s["license_locked"] is True and s["license_expired"] is True
        assert s["purchase_url"].startswith("https://")


class TestActivation:
    def test_valid_key_unlocks(self, licence_env, monkeypatch):
        monkeypatch.setattr(netguard.CFG, "can_block", False)
        licence_env.set_trial(40)
        ws = FakeWS()
        run(netguard.handle_ws_command(ws, {"cmd": "license_activate", "key": licence_env.mint()}))
        assert ws.sent[-1] == {**ws.sent[-1], "type": "license_activated", "ok": True}
        assert netguard.license_locked() is False
        run(netguard.handle_ws_command(ws, {"cmd": "block_ip", "ip": "45.33.32.30"}))
        assert ws.sent[-1]["type"] == "ip_blocked"

    def test_forged_and_malformed_keys_are_refused(self, licence_env):
        licence_env.set_trial(40)
        ws = FakeWS()
        good = licence_env.mint()
        forged = good[:-5] + ("AAAAA" if not good.endswith("AAAAA") else "BBBBB")
        for bad in (forged, "NGPRO-abc", "", 123, "x" * 5000):
            run(netguard.handle_ws_command(ws, {"cmd": "license_activate", "key": bad}))
            assert ws.sent[-1]["type"] == "license_activated" and ws.sent[-1]["ok"] is False
        assert netguard.license_locked() is True

    def test_expired_key_is_refused(self, licence_env):
        licence_env.set_trial(40)
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        ws = FakeWS()
        run(netguard.handle_ws_command(ws, {"cmd": "license_activate", "key": licence_env.mint(expires_at=past)}))
        assert ws.sent[-1]["ok"] is False


class TestAiServerGate:
    def test_assistant_returns_402_after_trial(self, licence_env, monkeypatch):
        import netguard_ai_server as srv
        licence_env.set_trial(40)
        srv._LICENSE_CACHE["ts"] = 0.0
        locked, url = srv._license_locked()
        assert locked is True and url.startswith("https://")
        (licence_env.tmp / "netguard_license.json").unlink()
        licence_env.anchor["v"] = ""
        srv._LICENSE_CACHE["ts"] = 0.0
        assert srv._license_locked()[0] is False            # fresh trial → open
        srv._LICENSE_CACHE["ts"] = 0.0
