# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Shared pytest fixtures for the NetGuard test suite.

Conventions
-----------
* No real secrets in this file — placeholders only.
* Tests must NOT touch the real ``argus_data/`` or ``netguard.log``;
  fixtures redirect every write into a per-test ``tmp_path``.
* Tests must NOT require Npcap/scapy or admin rights; the
  ``mock_npcap_unavailable`` fixture toggles ``HAS_SCAPY=False``.
* Module-level state in ``netguard`` is process-wide, so per-test
  cleanup (``clean_blocked_ips``) is mandatory and autouse.
"""

from __future__ import annotations

import sys
from collections import defaultdict, deque
from pathlib import Path
from unittest.mock import MagicMock

# ─────────────────────────────────────────────────────────────────────────────
# Pre-mock scapy at module level — MUST run before any `import netguard`.
#
# Why: netguard.py does `from scapy.all import sniff, IP, TCP, ...` at top
# level. On Windows with Npcap in admin-only mode, importing scapy actually
# loads Packet.dll which triggers a UAC prompt. Tests don't need real packet
# capture, so we install MagicMock for every scapy submodule before pytest
# discovers any test.
#
# Tests that need to opt-out and use real scapy can do so explicitly via
# pytest.MonkeyPatch by deleting these mocks before importing netguard.
# ─────────────────────────────────────────────────────────────────────────────
_SCAPY_MODULES = (
    "scapy", "scapy.all", "scapy.layers", "scapy.layers.inet",
    "scapy.layers.inet6", "scapy.layers.dns", "scapy.layers.l2",
    "scapy.arch", "scapy.arch.windows", "scapy.config", "scapy.sendrecv",
)
for _mod in _SCAPY_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock(name=_mod)

# QtWebEngine (argus_pyqt) requires AA_ShareOpenGLContexts BEFORE any QApplication is
# created; pytest-qt / earlier test modules may create one first. Set it once here.
try:
    from PyQt6.QtCore import QCoreApplication as _QCA, Qt as _Qt
    _QCA.setAttribute(_Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
except Exception:
    pass

import pytest

# Make sibling netguard.py importable for every test in this directory.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------------- #
# tmp_data_dir — redirects argus_data/ writes via env var
# --------------------------------------------------------------------------- #


@pytest.fixture
def tmp_data_dir(tmp_path, monkeypatch):
    """Redirect argus_data/ writes (and ARGUS_VAULT_ROOT) to tmp_path.

    Mirrors the test_argus_vault.py pattern: any module that respects
    ``ARGUS_VAULT_ROOT`` will land in tmp_path. We also chdir so that
    relative paths like ``netguard.log`` or ``argus_data/`` end up here.
    """
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    monkeypatch.setenv("NETGUARD_DATA_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --------------------------------------------------------------------------- #
# mock_npcap_unavailable — pretend scapy isn't installed
# --------------------------------------------------------------------------- #


@pytest.fixture
def mock_npcap_unavailable(monkeypatch):
    """Force netguard.HAS_SCAPY = False so traceroute / sniffer paths
    take the no-scapy branch instead of trying to send real probes.

    netguard.py already wraps `from scapy.all import ...` in try/except
    and exposes HAS_SCAPY as a module flag, so flipping it is enough.
    """
    import netguard
    monkeypatch.setattr(netguard, "HAS_SCAPY", False, raising=False)
    return netguard


# --------------------------------------------------------------------------- #
# sample_packets — fake scapy Packet-like objects
# --------------------------------------------------------------------------- #


class _FakeLayer:
    """Minimal stand-in for a scapy layer with attribute access."""

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class _FakePacket:
    """Duck-typed scapy.Packet — supports ``haslayer`` and indexing."""

    def __init__(self, layers):
        self._layers = layers  # dict: name -> _FakeLayer

    def haslayer(self, layer):
        # scapy passes either the class or its __name__; we accept both.
        name = getattr(layer, "__name__", layer)
        return name in self._layers

    def __getitem__(self, layer):
        name = getattr(layer, "__name__", layer)
        return self._layers[name]


@pytest.fixture
def sample_packets():
    """Return a small set of fake packets covering TCP/UDP/ICMP/DNS."""
    return [
        _FakePacket({
            "IP":  _FakeLayer(src="203.0.113.10", dst="10.0.0.1"),
            "TCP": _FakeLayer(sport=44321, dport=443, flags=0x02),  # SYN
        }),
        _FakePacket({
            "IP":  _FakeLayer(src="198.51.100.7", dst="10.0.0.1"),
            "UDP": _FakeLayer(sport=53, dport=12345),
        }),
        _FakePacket({
            "IP":   _FakeLayer(src="192.0.2.5", dst="10.0.0.1"),
            "ICMP": _FakeLayer(type=8, code=0),
        }),
    ]


# --------------------------------------------------------------------------- #
# clean_blocked_ips — autouse cleanup of module state between tests
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def clean_blocked_ips():
    """Reset any IP block / detection state between tests.

    netguard's STATE/BLOCKED_IPS/RULES are module globals — without this
    fixture, ordering between tests would matter. We snapshot before and
    restore after so the test process leaves no firewall residue.
    """
    try:
        import netguard
    except Exception:
        # If the module fails to import, individual tests will skip/fail
        # — nothing to clean here.
        yield
        return

    # Snapshot
    blocked_before = set(getattr(netguard, "BLOCKED_IPS", set()))
    rules_before = {
        k: dict(v) for k, v in getattr(netguard, "RULES", {}).items()
    }

    yield

    # Restore BLOCKED_IPS
    if hasattr(netguard, "BLOCKED_IPS"):
        netguard.BLOCKED_IPS.clear()
        netguard.BLOCKED_IPS.update(blocked_before)

    # Restore per-IP trackers (re-init the defaultdicts)
    state = getattr(netguard, "STATE", None)
    if state is not None:
        for attr in (
            "_port_scan_tracker",
            "_brute_force_tracker",
            "_syn_flood_tracker",
            "_dns_tracker",
        ):
            if hasattr(state, attr):
                setattr(state, attr, defaultdict(list))
        if hasattr(state, "ip_hit_counter"):
            state.ip_hit_counter = defaultdict(int)
        if hasattr(state, "threats"):
            state.threats = deque(maxlen=100)

    # Restore RULES
    if hasattr(netguard, "RULES"):
        for k, v in rules_before.items():
            netguard.RULES[k] = v


# ─────────────────────────────────────────────────────────────────────────────
# QtWebEngine teardown: once argus_pyqt (QtWebEngine) has been imported, the
# interpreter segfaults at exit ("Release of profile requested but WebEnginePage
# still not deleted") AFTER every test passed — CI then reports exit code 139.
# Exit with pytest's real status as soon as the session is finished.
# ─────────────────────────────────────────────────────────────────────────────
def pytest_sessionfinish(session, exitstatus):
    session.config._ng_exitstatus = int(exitstatus)


@pytest.hookimpl(trylast=True)
def pytest_unconfigure(config):
    import os as _os
    if "PyQt6.QtWebEngineWidgets" in sys.modules or "PyQt6.QtWebEngineCore" in sys.modules:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            _os._exit(getattr(config, "_ng_exitstatus", 0))
