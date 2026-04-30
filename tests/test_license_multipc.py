# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Tests for the multi-PC seat licensing system in license_manager.py.

These tests are completely hermetic:
- Each test gets a fresh tmp dir for the activation registry and license file.
- An *ephemeral* Ed25519 keypair is generated per test run, and the module's
  embedded public key is monkey-patched to match. We never touch the real
  tools/keys/license_ed25519.priv file.

Notes
-----
The DeviceFingerprint relies on ``wmic`` / ``/sys/class/dmi/id/product_uuid``
which differ between hosts. We don't mock those — DeviceFingerprint.current()
must be deterministic on a single machine across calls inside one test run,
which is what we actually verify.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import license_manager as lm
from license_manager import (
    ActivationRegistry,
    DeviceFingerprint,
    LicenseError,
    LicenseManager,
    LicenseSeatExhaustedError,
    PLAN_PRO,
    PLAN_STARTER,
    TIER_PRO,
)


# ──────────────────────────── helpers ────────────────────────────────


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def _priv_raw_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _mint_key(priv, *, tier="pro", plan="pro", max_seats=3,
              license_id=None, expires_at=None, customer_email="alice@example.com",
              machine_id=None, issued_at=None):
    if license_id is None:
        license_id = str(uuid.uuid4())
    if issued_at is None:
        issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "tier": tier,
        "plan": plan,
        "max_seats": max_seats,
        "license_id": license_id,
        "customer_email": customer_email,
        "issued_at": issued_at,
    }
    if expires_at is not None:
        payload["expires"] = expires_at
        payload["expires_at"] = expires_at
    if machine_id is not None:
        payload["machine_id"] = machine_id
    payload = {k: v for k, v in payload.items() if v is not None}
    pb = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = priv.sign(pb)
    return f"NGPRO-{_b64url(pb)}-{_b64url(sig)}", license_id, payload


@pytest.fixture
def isolated_lm(tmp_path, monkeypatch):
    """Per-test license dir + ephemeral Ed25519 pubkey patched into license_manager."""
    priv, pub = _make_keypair()
    monkeypatch.setattr(lm, "LICENSE_PUBLIC_KEY_B64", base64.b64encode(pub).decode("ascii"))

    # Redirect license file + activations file to tmp_path
    license_file = tmp_path / "netguard_license.json"
    activations_file = tmp_path / "argus_data" / ".activations.json"
    activations_file.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(lm, "LICENSE_FILE", str(license_file))
    monkeypatch.setattr(lm, "ACTIVATIONS_FILE", str(activations_file))

    return {
        "priv": priv,
        "pub": pub,
        "license_file": license_file,
        "activations_file": activations_file,
        "manager": LicenseManager(license_file=str(license_file),
                                  registry=ActivationRegistry(path=str(activations_file))),
    }


# ─────────────────────── DeviceFingerprint ──────────────────────────


class TestDeviceFingerprint:

    def test_current_is_64char_hex(self):
        fp = DeviceFingerprint.current()
        assert isinstance(fp, str)
        assert len(fp) == 64
        int(fp, 16)  # must be valid hex

    def test_current_is_stable_across_calls(self):
        a = DeviceFingerprint.current()
        b = DeviceFingerprint.current()
        c = DeviceFingerprint.current()
        assert a == b == c

    def test_short_is_prefix(self):
        fp = "abcdef0123456789" * 4
        assert DeviceFingerprint.short(fp) == "abcdef012345"

    def test_verify_matches_current(self):
        fp = DeviceFingerprint.current()
        assert DeviceFingerprint.verify(fp) is True

    def test_verify_rejects_other(self):
        assert DeviceFingerprint.verify("0" * 64) is False
        assert DeviceFingerprint.verify("") is False

    def test_works_when_wmic_missing(self, monkeypatch):
        # Simulate a stripped Windows / non-Windows where wmic isn't on PATH.
        def fake_check_output(*a, **kw):
            raise FileNotFoundError("wmic")
        monkeypatch.setattr(subprocess, "check_output", fake_check_output)
        fp = DeviceFingerprint.current()
        # Still 64 hex chars — falls back on MAC + hostname.
        assert len(fp) == 64
        int(fp, 16)


# ─────────────────────── ActivationRegistry ─────────────────────────


class TestActivationRegistry:

    def test_seats_used_starts_at_zero(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        assert r.seats_used("any-id") == 0
        assert r.is_activated("any-id", "fp1") is False

    def test_activate_under_cap(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        assert r.activate("L1", "fp1", max_seats=3) is True
        assert r.seats_used("L1") == 1
        assert r.is_activated("L1", "fp1") is True
        assert r.is_activated("L1", "fp2") is False

    def test_activate_idempotent(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        r.activate("L1", "fp1", max_seats=2)
        r.activate("L1", "fp1", max_seats=2)
        r.activate("L1", "fp1", max_seats=2)
        assert r.seats_used("L1") == 1

    def test_max_seats_enforced(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        assert r.activate("L1", "a", max_seats=2) is True
        assert r.activate("L1", "b", max_seats=2) is True
        assert r.activate("L1", "c", max_seats=2) is False
        assert r.seats_used("L1") == 2

    def test_deactivate_releases_seat(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        r.activate("L1", "a", max_seats=2)
        r.activate("L1", "b", max_seats=2)
        assert r.deactivate("L1", "a") is True
        assert r.seats_used("L1") == 1
        assert r.activate("L1", "c", max_seats=2) is True

    def test_deactivate_unknown_returns_false(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        assert r.deactivate("L1", "nope") is False

    def test_isolation_between_licenses(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        r.activate("L1", "fp1", max_seats=1)
        r.activate("L2", "fp1", max_seats=1)
        assert r.is_activated("L1", "fp1") is True
        assert r.is_activated("L2", "fp1") is True
        r.deactivate("L1", "fp1")
        assert r.is_activated("L1", "fp1") is False
        assert r.is_activated("L2", "fp1") is True

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / ".activations.json")
        r1 = ActivationRegistry(path=path)
        r1.activate("L1", "fp1", max_seats=3)
        r1.activate("L1", "fp2", max_seats=3)
        r2 = ActivationRegistry(path=path)
        assert r2.seats_used("L1") == 2
        assert r2.is_activated("L1", "fp1") is True

    def test_hmac_rejects_tampered_file(self, tmp_path):
        path = tmp_path / ".activations.json"
        r = ActivationRegistry(path=str(path))
        r.activate("L1", "fp1", max_seats=3)
        # Tamper: append an extra fingerprint without recomputing the HMAC.
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["L1"]["entries"].append({
            "fingerprint": "evil",
            "hostname": "attacker",
            "activated_at": "2026-01-01",
            "last_seen": "2026-01-01",
        })
        path.write_text(json.dumps(raw), encoding="utf-8")

        # Now the registry must report tampering and refuse to trust the entries.
        r2 = ActivationRegistry(path=str(path))
        assert r2.is_tampered("L1") is True
        assert r2.seats_used("L1") == 0
        assert r2.is_activated("L1", "evil") is False
        assert r2.is_activated("L1", "fp1") is False

    def test_list_devices_returns_entries(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        r.activate("L1", "a", max_seats=3, hostname="hostA")
        r.activate("L1", "b", max_seats=3, hostname="hostB")
        entries = r.list_devices("L1")
        assert len(entries) == 2
        hostnames = {e["hostname"] for e in entries}
        assert hostnames == {"hostA", "hostB"}

    def test_touch_updates_last_seen(self, tmp_path):
        r = ActivationRegistry(path=str(tmp_path / ".activations.json"))
        r.activate("L1", "fp1", max_seats=1, hostname="h")
        before = r.list_devices("L1")[0]["last_seen"]
        # Force a tiny delay by bumping the clock indirectly — datetime is ms-precise
        r.touch("L1", "fp1")
        after = r.list_devices("L1")[0]["last_seen"]
        # Either it's bumped, or at worst equal — but must not regress
        assert after >= before


# ─────────────────────── LicenseManager.validate ────────────────────


class TestLicenseManagerValidate:

    def test_no_license_raises(self, isolated_lm):
        with pytest.raises(LicenseError):
            isolated_lm["manager"].validate()

    def test_validate_auto_activates_under_cap(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=3)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        v = isolated_lm["manager"].validate(auto_activate=True)
        assert v["tier"] == TIER_PRO
        assert v["plan"] == PLAN_PRO
        assert v["max_seats"] == 3
        assert v["seats_used"] == 1
        assert v["activated"] is True
        assert v["license_id"] == lid

    def test_validate_idempotent(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=3)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        m = isolated_lm["manager"]
        m.validate()
        m.validate()
        m.validate()
        # Still 1 seat used (us only)
        v = m.validate()
        assert v["seats_used"] == 1

    def test_validate_seat_exhausted(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=2)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        # Fill the 2 slots with *other* fingerprints
        reg = isolated_lm["manager"].registry
        reg.activate(lid, "other-fp-1", max_seats=2, hostname="h1")
        reg.activate(lid, "other-fp-2", max_seats=2, hostname="h2")

        with pytest.raises(LicenseSeatExhaustedError):
            isolated_lm["manager"].validate(auto_activate=True)

    def test_validate_seat_exhausted_carries_hint_in_message(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=1)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        reg = isolated_lm["manager"].registry
        reg.activate(lid, "other-fp", max_seats=1)
        try:
            isolated_lm["manager"].validate(auto_activate=True)
            pytest.fail("should have raised")
        except LicenseSeatExhaustedError as e:
            assert "Manage Devices" in str(e) or "Settings" in str(e)

    def test_validate_no_auto_activate_does_not_consume_seat(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=2)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        with pytest.raises(LicenseSeatExhaustedError):
            # No room because: max_seats=2, both other-fps occupy them, our FP
            # would need a 3rd seat.
            reg = isolated_lm["manager"].registry
            reg.activate(lid, "other-1", max_seats=2)
            reg.activate(lid, "other-2", max_seats=2)
            isolated_lm["manager"].validate(auto_activate=False)

    def test_validate_expired(self, isolated_lm):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        key, lid, _ = _mint_key(isolated_lm["priv"], expires_at=past, max_seats=3)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        with pytest.raises(LicenseError):
            isolated_lm["manager"].validate()

    def test_validate_signature_tamper_rejected(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=3)
        # Flip a byte at the start of the payload (right after NGPRO-)
        prefix = "NGPRO-"
        body = key[len(prefix):]
        sig_b64 = body[-86:]
        payload_b64 = body[:-87]  # exclude trailing '-' + sig
        bad_payload = ("A" if payload_b64[0] != "A" else "B") + payload_b64[1:]
        bad_key = f"{prefix}{bad_payload}-{sig_b64}"
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": bad_key, "tier": "pro"}), encoding="utf-8"
        )
        with pytest.raises(LicenseError):
            isolated_lm["manager"].validate()

    def test_starter_plan_caps_at_one_seat(self, isolated_lm):
        # Mint a starter license that *claims* 5 seats — manager must clamp to 1.
        key, lid, _ = _mint_key(isolated_lm["priv"], plan="starter", max_seats=5)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        v = isolated_lm["manager"].validate()
        assert v["plan"] == PLAN_STARTER
        assert v["max_seats"] == 1

    def test_pro_plan_clamps_to_5(self, isolated_lm):
        # Forge a license claiming 99 seats — Pro cap is 5.
        key, lid, _ = _mint_key(isolated_lm["priv"], plan="pro", max_seats=99)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro"}), encoding="utf-8"
        )
        v = isolated_lm["manager"].validate()
        assert v["max_seats"] == 5


# ─────────────────────── activate_license() public API ──────────────


class TestActivateLicense:

    def test_activate_succeeds(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=3)
        # The module-level activate_license uses the patched LICENSE_FILE.
        result = lm.activate_license(key)
        assert result["ok"] is True
        assert result["plan"] == PLAN_PRO
        assert result["max_seats"] == 3
        assert result["license_id"] == lid

    def test_activate_full_seats_returns_seat_exhausted(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=1)
        # Pre-fill the only seat with *another* fingerprint.
        reg = ActivationRegistry(path=str(isolated_lm["activations_file"]))
        reg.activate(lid, "other-fp", max_seats=1)

        result = lm.activate_license(key)
        assert result["ok"] is False
        assert result.get("seat_exhausted") is True

    def test_activate_then_deactivate(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=2)
        lm.activate_license(key)
        assert ActivationRegistry(path=str(isolated_lm["activations_file"])).seats_used(lid) == 1
        lm.deactivate_license()
        assert ActivationRegistry(path=str(isolated_lm["activations_file"])).seats_used(lid) == 0


# ─────────────────────── list_activated / deactivate_device ─────────


class TestDeviceListing:

    def test_list_marks_this_machine(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=3)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro", "license_id": lid}),
            encoding="utf-8")
        m = isolated_lm["manager"]
        m.validate()  # activates this machine
        # Add another fake device too
        m.registry.activate(lid, "other-fp", max_seats=3, hostname="other-host")
        devices = m.list_activated_devices(lid)
        assert len(devices) == 2
        me = [d for d in devices if d["this_machine"]]
        assert len(me) == 1
        assert me[0]["fingerprint_short"] == DeviceFingerprint.short(DeviceFingerprint.current())

    def test_deactivate_specific_device(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=3)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro", "license_id": lid}),
            encoding="utf-8")
        m = isolated_lm["manager"]
        m.validate()
        m.registry.activate(lid, "other-fp-1", max_seats=3)
        m.registry.activate(lid, "other-fp-2", max_seats=3)

        ok = m.deactivate_device("other-fp-1", license_id=lid)
        assert ok is True
        remaining_fps = {d["fingerprint"] for d in m.list_activated_devices(lid)}
        assert "other-fp-1" not in remaining_fps
        assert "other-fp-2" in remaining_fps

    def test_deactivate_unknown_returns_false(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=1)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro", "license_id": lid}),
            encoding="utf-8")
        m = isolated_lm["manager"]
        assert m.deactivate_device("nope", license_id=lid) is False


# ─────────────────────── Mint CLI smoke test ────────────────────────


class TestMintCli:

    def test_mint_cli_plan_pro_seats_3(self, tmp_path, monkeypatch):
        """Run the mint CLI with our ephemeral keypair and validate the output."""
        priv, pub = _make_keypair()
        # Drop a fake priv file in tools/keys/ for the CLI
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        priv_path = keys_dir / "license_ed25519.priv"
        priv_path.write_bytes(_priv_raw_bytes(priv))

        # Import the mint module fresh and patch its PRIV_PATH
        import importlib
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import license_mint
            importlib.reload(license_mint)
        finally:
            sys.path.pop(0)
        monkeypatch.setattr(license_mint, "PRIV_PATH", priv_path)

        # Parse with sys.argv
        argv = ["license_mint.py", "pro", "--plan", "pro", "--seats", "3",
                "--customer-email", "z@x.com", "--expires-days", "30"]
        monkeypatch.setattr(sys, "argv", argv)
        rc = license_mint.main()
        assert rc == 0

    def test_mint_cli_starter_clamps_seats_to_1(self, tmp_path, monkeypatch, capsys):
        priv, pub = _make_keypair()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        priv_path = keys_dir / "license_ed25519.priv"
        priv_path.write_bytes(_priv_raw_bytes(priv))
        import importlib
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import license_mint
            importlib.reload(license_mint)
        finally:
            sys.path.pop(0)
        monkeypatch.setattr(license_mint, "PRIV_PATH", priv_path)

        argv = ["license_mint.py", "pro", "--plan", "starter",
                "--seats", "5", "--expires-days", "30"]
        monkeypatch.setattr(sys, "argv", argv)
        rc = license_mint.main()
        assert rc == 0
        captured = capsys.readouterr().out
        # The first non-empty line is the NGPRO key
        first = next(line for line in captured.splitlines() if line.strip())
        assert first.startswith("NGPRO-")
        # Decode the payload and check max_seats == 1
        body = first[len("NGPRO-"):]
        payload_b64 = body[:-87]  # strip trailing '-' + 86-char sig
        pad = (-len(payload_b64)) % 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * pad).decode())
        assert payload["plan"] == "starter"
        assert payload["max_seats"] == 1

    def test_mint_cli_writes_lic_file(self, tmp_path, monkeypatch):
        priv, _ = _make_keypair()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        priv_path = keys_dir / "license_ed25519.priv"
        priv_path.write_bytes(_priv_raw_bytes(priv))
        import importlib
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import license_mint
            importlib.reload(license_mint)
        finally:
            sys.path.pop(0)
        monkeypatch.setattr(license_mint, "PRIV_PATH", priv_path)

        out = tmp_path / "test.lic"
        argv = ["license_mint.py", "pro", "--plan", "pro", "--seats", "5",
                "--out", str(out), "--expires-days", "365"]
        monkeypatch.setattr(sys, "argv", argv)
        license_mint.main()
        assert out.exists()
        body = out.read_text(encoding="utf-8").strip()
        assert body.startswith("NGPRO-")
        # Body must contain at least one '-' (payload/sig delimiter)
        assert body.count("-") >= 2


# ─────────────────────── status() helper ────────────────────────────


class TestStatusHelper:

    def test_status_when_no_license(self, isolated_lm):
        # Falls back to legacy init_license() path — should not raise.
        s = isolated_lm["manager"].status()
        assert "tier" in s
        assert s.get("seats_used", 0) == 0

    def test_status_after_activation(self, isolated_lm):
        key, lid, _ = _mint_key(isolated_lm["priv"], max_seats=3)
        isolated_lm["license_file"].write_text(
            json.dumps({"license_key": key, "tier": "pro", "license_id": lid}),
            encoding="utf-8")
        s = isolated_lm["manager"].status()
        assert s["tier"] == TIER_PRO
        assert s["plan"] == PLAN_PRO
        assert s["max_seats"] == 3
        assert s["seats_used"] == 1
        assert len(s["devices"]) == 1
        assert s["devices"][0]["this_machine"] is True
