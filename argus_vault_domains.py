# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""
argus_vault_domains — known banking / payment / crypto / gov-tax / wallet
domain registry.

Argus uses this module to detect when a tab is navigating to a sensitive
financial or identity surface. When a match is found, Argus prompts the
user "Open in Coffre Mode?" so that authentication, downloads, and
clipboard activity all run under a hardened profile.

Public API
----------
* ``is_vault_domain(url)`` -> ``Optional[VaultMatch]``
* ``all_institutions()`` -> ``list[VaultMatch]``
* ``add_user_institution(name, category, domain)`` -> ``None``
* ``remove_user_institution(domain)`` -> ``bool``

Hard constraints
----------------
* Every domain entry is a publicly known brand — no leaked / private data.
* User-added entries persist to ``argus_data/vault_domains_user.json``,
  which is gitignored at the repo root.
* No network I/O. This module is a pure lookup table.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional
from urllib.parse import urlparse


# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #


class VaultMatch(NamedTuple):
    """A single (institution, category, domain) registry entry."""

    institution_name: str  # e.g., "RBC Royal Bank"
    category: str          # "bank" | "payment" | "crypto" | "gov_tax" | "wallet" | "broker"
    matched_domain: str    # the specific domain that matched


VALID_CATEGORIES = frozenset(
    {"bank", "payment", "crypto", "gov_tax", "wallet", "broker"}
)


# --------------------------------------------------------------------------- #
# Pre-loaded list — public brand names only
# --------------------------------------------------------------------------- #


def _b(name: str, *domains: str) -> List[VaultMatch]:
    return [VaultMatch(name, "bank", d) for d in domains]


def _p(name: str, *domains: str) -> List[VaultMatch]:
    return [VaultMatch(name, "payment", d) for d in domains]


def _c(name: str, *domains: str) -> List[VaultMatch]:
    return [VaultMatch(name, "crypto", d) for d in domains]


def _g(name: str, *domains: str) -> List[VaultMatch]:
    return [VaultMatch(name, "gov_tax", d) for d in domains]


def _w(name: str, *domains: str) -> List[VaultMatch]:
    return [VaultMatch(name, "wallet", d) for d in domains]


def _br(name: str, *domains: str) -> List[VaultMatch]:
    return [VaultMatch(name, "broker", d) for d in domains]


KNOWN_VAULT_DOMAINS: Dict[str, List[VaultMatch]] = {
    "bank": (
        _b("TD Canada Trust", "td.com", "tdcanadatrust.com", "tdbank.com", "easyweb.td.com")
        + _b("RBC Royal Bank", "rbcroyalbank.com", "rbc.com", "rbcbank.com")
        + _b("BMO", "bmo.com", "bmoharris.com", "bmoonlinebanking.com")
        + _b("Scotiabank", "scotiabank.com", "scotiaonline.com")
        + _b("CIBC", "cibc.com", "cibconline.cibc.com")
        + _b("Desjardins", "desjardins.com", "accesweb.desjardins.com")
        + _b("Tangerine", "tangerine.ca")
        + _b("EQ Bank", "eqbank.ca")
        + _b("Chase", "chase.com", "chasebank.com")
        + _b("Bank of America", "bankofamerica.com", "bofa.com")
        + _b("Wells Fargo", "wellsfargo.com")
        + _b("Citi", "citi.com", "citibank.com")
        + _b("HSBC", "hsbc.com", "hsbc.ca")
        + _b("American Express", "americanexpress.com")
        + _b("Barclays", "barclays.com", "barclays.co.uk")
    ),
    "payment": (
        _p("PayPal", "paypal.com", "paypal.me")
        + _p("Stripe", "stripe.com", "dashboard.stripe.com")
        + _p("Square", "squareup.com", "cash.app")
        + _p("Interac", "interac.ca")
    ),
    "broker": (
        _br("Wealthsimple", "wealthsimple.com")
        + _br("Questrade", "questrade.com")
        + _br("Robinhood", "robinhood.com")
        + _br("Fidelity", "fidelity.com")
    ),
    "crypto": (
        _c("Coinbase", "coinbase.com")
        + _c("Kraken", "kraken.com")
        + _c("Binance", "binance.com", "binance.us")
        + _c("Ledger", "ledger.com")
        + _c("Trezor", "trezor.io")
    ),
    "wallet": (
        _w("Apple Wallet", "pay.apple.com")
        + _w("Google Pay", "pay.google.com")
    ),
    "gov_tax": (
        _g("CRA My Account", "canada.ca")
        + _g("Revenu Québec", "revenuquebec.ca")
        + _g("IRS", "irs.gov")
    ),
}


# --------------------------------------------------------------------------- #
# User-extension persistence
# --------------------------------------------------------------------------- #


def _user_file() -> Path:
    """Resolve the user-extension JSON path.

    Honours ``ARGUS_VAULT_ROOT`` so tests can redirect via tmp_path.
    Otherwise falls back to ``argus_data/vault_domains_user.json``
    next to this module.
    """
    override = os.environ.get("ARGUS_VAULT_ROOT")
    if override:
        return Path(override) / "vault_domains_user.json"
    return Path(__file__).resolve().parent / "argus_data" / "vault_domains_user.json"


def _load_user_entries() -> List[VaultMatch]:
    path = _user_file()
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, list):
        return []
    out: List[VaultMatch] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("institution_name")
        cat = entry.get("category")
        dom = entry.get("matched_domain")
        if not (isinstance(name, str) and isinstance(cat, str)
                and isinstance(dom, str)):
            continue
        if cat not in VALID_CATEGORIES:
            continue
        out.append(VaultMatch(name, cat, dom.lower()))
    return out


def _save_user_entries(entries: List[VaultMatch]) -> None:
    path = _user_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    serialised = [
        {
            "institution_name": e.institution_name,
            "category": e.category,
            "matched_domain": e.matched_domain,
        }
        for e in entries
    ]
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(serialised, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# URL parsing
# --------------------------------------------------------------------------- #


def _extract_host(url: str) -> Optional[str]:
    """Return the lowercase hostname from an arbitrary URL/host string."""
    if not isinstance(url, str) or not url:
        return None
    candidate = url.strip()
    # urlparse needs a scheme to populate netloc reliably.
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    host = parsed.hostname  # already lowercases per RFC3986
    if not host:
        return None
    return host.lower().rstrip(".")


def _host_matches_domain(host: str, domain: str) -> bool:
    """True if host equals domain or is a subdomain of it.

    Examples
    --------
    >>> _host_matches_domain("td.com", "td.com")
    True
    >>> _host_matches_domain("easyweb.td.com", "td.com")
    True
    >>> _host_matches_domain("nottd.com", "td.com")
    False
    """
    if not host or not domain:
        return False
    h = host.lower().rstrip(".")
    d = domain.lower().rstrip(".")
    if h == d:
        return True
    return h.endswith("." + d)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def is_vault_domain(url: str) -> Optional[VaultMatch]:
    """Return a VaultMatch if ``url``'s host is a known vault domain.

    Subdomain matches count (e.g., ``easyweb.td.com`` -> TD Canada Trust).
    The URL may include scheme, path, query, fragment — only the host is
    inspected. Returns ``None`` if no match.
    """
    host = _extract_host(url)
    if host is None:
        return None

    # User entries take precedence so the user can override / extend.
    for entry in _load_user_entries():
        if _host_matches_domain(host, entry.matched_domain):
            return entry

    for entries in KNOWN_VAULT_DOMAINS.values():
        for entry in entries:
            if _host_matches_domain(host, entry.matched_domain):
                return entry
    return None


def all_institutions() -> List[VaultMatch]:
    """Return every entry (built-in + user-added) flat, for Settings UI."""
    out: List[VaultMatch] = []
    for entries in KNOWN_VAULT_DOMAINS.values():
        out.extend(entries)
    out.extend(_load_user_entries())
    return out


def add_user_institution(name: str, category: str, domain: str) -> None:
    """Persist a user-defined entry to the gitignored user JSON file.

    Validates inputs and de-duplicates by ``matched_domain`` (case-insensitive).
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("institution_name must be a non-empty string")
    if category not in VALID_CATEGORIES:
        raise ValueError(
            f"category must be one of {sorted(VALID_CATEGORIES)}, got {category!r}"
        )
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")

    norm_domain = domain.strip().lower().rstrip(".")
    entries = _load_user_entries()
    # Replace any existing entry with the same domain.
    entries = [e for e in entries if e.matched_domain != norm_domain]
    entries.append(VaultMatch(name.strip(), category, norm_domain))
    _save_user_entries(entries)


def remove_user_institution(domain: str) -> bool:
    """Remove the user-added entry for ``domain``. Returns True iff removed."""
    if not isinstance(domain, str):
        return False
    norm = domain.strip().lower().rstrip(".")
    if not norm:
        return False
    entries = _load_user_entries()
    new_entries = [e for e in entries if e.matched_domain != norm]
    if len(new_entries) == len(entries):
        return False
    _save_user_entries(new_entries)
    return True
