# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Critical-path tests for ``netguard.py``.

This is the foundation suite — 20 tests across five concern areas:
  1. IP validation       (_validate_ip)
  2. Password hashing    (_hash_password / iam_verify_password)
  3. Atomic JSON writes  (_secure_json_write)
  4. Threat detection    (auto_block_check / detect_port_scan /
                          detect_brute_force / detect_syn_flood)
  5. Traceroute          (_traceroute)

Constraints honoured
--------------------
* No network calls — every external probe is mocked.
* No admin rights required — ``CFG.can_block`` is forced to False so
  ``block_ip_os`` never invokes ``netsh`` or ``iptables``.
* No real secrets — placeholder strings only.
* Module state is snapshotted and restored by the autouse fixture in
  ``conftest.py``.

Notes on function-name divergence
---------------------------------
The audit listed ``_verify_password`` but the actual function in
netguard.py is called ``iam_verify_password``. We use the real name
and document the mapping below.
"""

from __future__ import annotations

import json
import os
import time
from unittest.mock import patch

import pytest

import netguard

# --------------------------------------------------------------------------- #
# Test constants — never use real secrets here
# --------------------------------------------------------------------------- #
PASSWORD_PLACEHOLDER = "test_password_not_a_real_secret"
WRONG_PASSWORD = "test_wrong_password"
TEST_VALUE = "test_value"


@pytest.fixture(autouse=True)
def _no_real_firewall(monkeypatch):
    """Prevent every test in this file from touching the real firewall
    or making outbound network calls during threat-handling paths.

    ``add_threat`` calls ``get_country`` / ``_compute_risk_score`` /
    ``dispatch_alert`` / ``correlate_attack_phase`` — any of which may
    reach out to webhooks, GeoIP APIs, or threat-intel feeds. Stubbing
    them keeps the tests hermetic.
    """
    monkeypatch.setattr(netguard.CFG, "can_block", False, raising=False)
    monkeypatch.setattr(netguard, "get_country", lambda ip: "",
                        raising=False)
    monkeypatch.setattr(netguard, "_compute_risk_score", lambda ip: 0,
                        raising=False)
    monkeypatch.setattr(netguard, "dispatch_alert", lambda *a, **kw: None,
                        raising=False)
    monkeypatch.setattr(netguard, "correlate_attack_phase",
                        lambda *a, **kw: None, raising=False)


# =========================================================================== #
# 1. _validate_ip
# =========================================================================== #


class TestValidateIp:
    """``netguard._validate_ip`` wraps ipaddress.ip_address with logging."""

    def test_valid_ipv4(self):
        assert netguard._validate_ip("8.8.8.8") is True
        assert netguard._validate_ip("192.168.1.1") is True
        assert netguard._validate_ip("0.0.0.0") is True

    def test_valid_ipv6(self):
        assert netguard._validate_ip("::1") is True
        assert netguard._validate_ip("2001:4860:4860::8888") is True
        assert netguard._validate_ip("fe80::1") is True

    def test_invalid_string_rejected(self):
        # Anti-injection: shell metachars, SQL, hostnames must all fail
        assert netguard._validate_ip("not_an_ip") is False
        assert netguard._validate_ip("8.8.8.8; rm -rf /") is False
        assert netguard._validate_ip("' OR 1=1 --") is False
        assert netguard._validate_ip("999.999.999.999") is False
        assert netguard._validate_ip("") is False

    def test_loopback_handling(self):
        # _validate_ip accepts loopback (it's a valid IP);
        # the caller decides whether loopback should be blocked.
        assert netguard._validate_ip("127.0.0.1") is True
        assert netguard._validate_ip("::1") is True

    def test_private_range_handling(self):
        # Private IPs are valid for parsing; classification lives in is_private().
        assert netguard._validate_ip("10.0.0.1") is True
        assert netguard._validate_ip("172.16.0.1") is True
        assert netguard._validate_ip("192.168.1.1") is True
        # And is_private actually classifies them as private
        assert netguard.is_private("10.0.0.1") is True
        assert netguard.is_private("8.8.8.8") is False


# =========================================================================== #
# 2. _hash_password / iam_verify_password
# =========================================================================== #
# NOTE on naming: audit asked for "_verify_password" but the actual symbol
# in netguard.py is ``iam_verify_password``. Same semantics, different name.


class TestPasswordHashing:

    def test_password_hash_roundtrip(self):
        h = netguard._hash_password(PASSWORD_PLACEHOLDER)
        # Format check: scrypt$<salt-hex>$<hash-hex>
        assert h.startswith("scrypt$")
        parts = h.split("$")
        assert len(parts) == 3
        # Roundtrip must verify
        assert netguard.iam_verify_password(PASSWORD_PLACEHOLDER, h) is True

    def test_wrong_password_rejected(self):
        h = netguard._hash_password(PASSWORD_PLACEHOLDER)
        assert netguard.iam_verify_password(WRONG_PASSWORD, h) is False
        # Empty password also rejected
        assert netguard.iam_verify_password("", h) is False
        # Empty stored hash also rejected
        assert netguard.iam_verify_password(PASSWORD_PLACEHOLDER, "") is False

    def test_hash_uses_salt(self):
        # Same input, two calls -> two different hashes (random salt).
        h1 = netguard._hash_password(PASSWORD_PLACEHOLDER)
        h2 = netguard._hash_password(PASSWORD_PLACEHOLDER)
        assert h1 != h2
        # Both still verify
        assert netguard.iam_verify_password(PASSWORD_PLACEHOLDER, h1) is True
        assert netguard.iam_verify_password(PASSWORD_PLACEHOLDER, h2) is True

    @pytest.mark.slow
    def test_hash_resistant_to_timing_attack(self):
        """``iam_verify_password`` uses ``secrets.compare_digest`` which is
        constant-time. We don't try to detect a single bit of leakage —
        that needs thousands of samples. Instead we assert the two paths
        (correct vs wrong) take roughly the same order of magnitude.
        """
        h = netguard._hash_password(PASSWORD_PLACEHOLDER)

        # Warm up scrypt (first call has KDF init overhead)
        netguard.iam_verify_password(PASSWORD_PLACEHOLDER, h)

        N = 5
        t_correct = 0.0
        t_wrong = 0.0
        for _ in range(N):
            t0 = time.perf_counter()
            netguard.iam_verify_password(PASSWORD_PLACEHOLDER, h)
            t_correct += time.perf_counter() - t0

            t0 = time.perf_counter()
            netguard.iam_verify_password(WRONG_PASSWORD, h)
            t_wrong += time.perf_counter() - t0

        # scrypt dominates both paths so they should be within 10x.
        # (A naive == comparison would short-circuit and make wrong
        # passwords ~100-1000x faster.)
        ratio = max(t_correct, t_wrong) / max(min(t_correct, t_wrong), 1e-9)
        assert ratio < 10.0, (
            f"Suspicious timing skew (correct={t_correct:.4f}s, "
            f"wrong={t_wrong:.4f}s, ratio={ratio:.2f})"
        )


# =========================================================================== #
# 3. _secure_json_write
# =========================================================================== #


class TestSecureJsonWrite:

    def test_atomic_write_does_not_corrupt_on_kill(self, tmp_path):
        """If ``json.dump`` raises mid-write, the original file must
        still be intact and no partial temp file should remain.

        We simulate a *recoverable* failure (regular Exception) — that's
        the path ``_secure_json_write``'s ``except Exception`` clause
        cleans up. A SIGKILL would obviously bypass any Python cleanup
        anyway, so testing that path adds no real signal.
        """
        target = tmp_path / "settings.json"
        original = {"keep": "me"}
        netguard._secure_json_write(str(target), original)
        assert json.loads(target.read_text(encoding="utf-8")) == original

        # Inject a failure halfway through json.dump.
        def boom(data, fp, *a, **kw):
            fp.write('{"partial": ')
            raise RuntimeError("simulated mid-write failure")

        with patch.object(json, "dump", side_effect=boom):
            with pytest.raises(RuntimeError):
                netguard._secure_json_write(str(target), {"new": "data"})

        # Original file untouched (atomicity guarantee)
        assert json.loads(target.read_text(encoding="utf-8")) == original
        # No leftover temp file in parent dir
        leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".tmp_")]
        assert leftovers == [], f"Temp files leaked: {leftovers}"

    def test_unicode_json_roundtrip(self, tmp_path):
        target = tmp_path / "i18n.json"
        data = {
            "fr": "Le réseau est sécurisé",
            "ja": "ネットワークは安全です",
            "emoji_excluded_per_house_style": "ok",
            "rtl": "الشبكة آمنة",
        }
        netguard._secure_json_write(str(target), data)
        # File should be valid UTF-8 and roundtrip exactly.
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded == data

    def test_overwrites_existing_file_safely(self, tmp_path):
        target = tmp_path / "rules.json"
        netguard._secure_json_write(str(target), {"v": 1})
        netguard._secure_json_write(str(target), {"v": 2})
        netguard._secure_json_write(str(target), {"v": 3})
        assert json.loads(target.read_text(encoding="utf-8")) == {"v": 3}
        # Single file in dir, no temp leftovers.
        files = sorted(p.name for p in tmp_path.iterdir())
        assert files == ["rules.json"]


# =========================================================================== #
# 4. Threat detection
# =========================================================================== #
# auto_block_check is the simple "10 hits -> block" path.
# detect_port_scan / detect_brute_force / detect_syn_flood are the
# specific signature detectors. We test the actual thresholds from CFG.


class TestThreatDetection:

    # IPs on 185.199.108.0/22 (GitHub Pages) — public, not in the
    # default whitelist, and ``ipaddress.ip_address(...).is_private``
    # returns False for them. (TEST-NET-3 / 203.0.113.0/24 won't work
    # because Python's stdlib classifies it as ``is_private == True``.)
    def _ext_ip(self, last_octet: int = 5) -> str:
        return f"185.199.108.{last_octet}"

    def test_port_scan_triggers_block(self):
        """detect_port_scan returns a non-None reason once 15 unique
        ports hit within the 10 s window (CFG.port_scan_threshold)."""
        ip = self._ext_ip(11)
        threshold = netguard.CFG.port_scan_threshold  # 15
        reason = None
        for port in range(1000, 1000 + threshold):
            reason = netguard.detect_port_scan(ip, port)
        # On the threshold-th unique port the detector must fire.
        assert reason is not None
        assert "ports" in reason.lower() or "scan" in reason.lower()

    def test_brute_force_triggers_block(self):
        """detect_brute_force fires after CFG.brute_force_threshold (8)
        SYNs hitting a sensitive port (22/3389/5900/23)."""
        ip = self._ext_ip(12)
        sensitive_port = 22  # SSH
        reason = None
        for _ in range(netguard.CFG.brute_force_threshold):
            reason = netguard.detect_brute_force(ip, sensitive_port, is_syn=True)
        assert reason is not None
        assert "brute" in reason.lower()

    def test_syn_flood_triggers_block(self):
        """detect_syn_flood fires after CFG.syn_flood_threshold (200)
        SYN packets in syn_flood_window (5 s)."""
        ip = self._ext_ip(13)
        reason = None
        for _ in range(netguard.CFG.syn_flood_threshold):
            reason = netguard.detect_syn_flood(ip, is_syn=True)
        assert reason is not None
        assert "syn" in reason.lower() or "flood" in reason.lower()

    def test_whitelist_skipped(self, monkeypatch):
        """auto_block_check must NOT block a whitelisted IP no matter
        how many hits it racks up."""
        # 8.8.8.0/24 is in the default whitelist.
        ip = "8.8.8.8"
        assert netguard.is_whitelisted(ip) is True

        # Drive way past the auto_block_hits threshold.
        for _ in range(netguard.CFG.auto_block_hits * 5):
            netguard.auto_block_check(ip)

        assert ip not in netguard.BLOCKED_IPS

    def test_threshold_below_does_not_block(self):
        """One short of every threshold => no detection."""
        ip = self._ext_ip(14)

        # Port scan: 14 unique ports (threshold is 15)
        last = None
        for port in range(2000, 2000 + netguard.CFG.port_scan_threshold - 1):
            last = netguard.detect_port_scan(ip, port)
        assert last is None

        # Brute force: 7 SYNs (threshold is 8)
        ip2 = self._ext_ip(15)
        last_bf = None
        for _ in range(netguard.CFG.brute_force_threshold - 1):
            last_bf = netguard.detect_brute_force(ip2, 22, is_syn=True)
        assert last_bf is None

        # SYN flood: 199 SYNs (threshold is 200)
        ip3 = self._ext_ip(16)
        last_sf = None
        for _ in range(netguard.CFG.syn_flood_threshold - 1):
            last_sf = netguard.detect_syn_flood(ip3, is_syn=True)
        assert last_sf is None

    def test_auto_block_check_blocks_after_threshold(self, monkeypatch):
        """auto_block_check on a non-private, non-whitelisted IP should
        end up in BLOCKED_IPS once ``CFG.auto_block_hits`` is reached.
        Real firewall calls are short-circuited by the autouse fixture
        (``CFG.can_block = False``)."""
        ip = self._ext_ip(17)
        assert ip not in netguard.BLOCKED_IPS

        for _ in range(netguard.CFG.auto_block_hits):
            netguard.auto_block_check(ip)

        assert ip in netguard.BLOCKED_IPS


# =========================================================================== #
# 5. _traceroute
# =========================================================================== #


class TestTraceroute:

    def test_traceroute_returns_hop_list(self, monkeypatch):
        """When scapy.sr returns a fake answer, _traceroute must shape
        it into ``{ok: True, target, hops: [...]}``."""
        if not netguard.HAS_SCAPY:
            pytest.skip("scapy not installed in this environment")

        # 185.199.108.50 is public (GitHub Pages range); see
        # TestThreatDetection._ext_ip for why we don't use TEST-NET.
        target = "185.199.108.50"

        # Fake scapy.sr that returns one answered hop = the target.
        class _FakeSent:
            def __init__(self, ttl):
                self.ttl = ttl
                self.hlim = ttl
                self.sent_time = 1.0

        class _FakeRecv:
            def __init__(self, src):
                self.src = src
                self.time = 1.05

        def fake_sr(probes, timeout=3, verbose=0):
            ans = [(_FakeSent(1), _FakeRecv(target))]
            return ans, []

        # Patch in scapy.all so the inner ``from scapy.all import sr`` resolves to ours.
        import scapy.all as _scapy_all
        monkeypatch.setattr(_scapy_all, "sr", fake_sr, raising=False)

        # Avoid hitting the geo-lookup chain.
        monkeypatch.setattr(netguard, "_fetch_city_async", lambda ip: None,
                            raising=False)

        result = netguard._traceroute(target, max_hops=5)
        assert result["ok"] is True
        assert result["target"] == target
        assert isinstance(result["hops"], list)
        assert len(result["hops"]) >= 1
        assert result["hops"][0]["ip"] == target
        assert result["hops"][0]["is_target"] is True

    def test_traceroute_handles_timeout(self, mock_npcap_unavailable):
        """When scapy isn't available we should get a clean error dict
        instead of a crash. ``mock_npcap_unavailable`` flips
        ``netguard.HAS_SCAPY`` to False."""
        result = netguard._traceroute("8.8.8.8", max_hops=5)
        assert result["ok"] is False
        assert "error" in result
        assert "scapy" in result["error"].lower()

    def test_traceroute_rejects_invalid_ip(self):
        """Defensive: bogus input shouldn't reach scapy at all."""
        result = netguard._traceroute("not.an.ip.address")
        assert result["ok"] is False
        assert "invalid" in result["error"].lower()

    def test_traceroute_rejects_private_target(self):
        """Tracerouting RFC1918 from a public-facing tool is meaningless;
        ``_traceroute`` short-circuits on private IPs."""
        result = netguard._traceroute("10.0.0.1")
        assert result["ok"] is False
        assert "private" in result["error"].lower()
