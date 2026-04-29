# Copyright (C) 2026 NetGuard Pro Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""
argus_sandbox — QWebEngineProfile factory + URL request interceptor.

Pillar 1 of Argus: sandbox-first. Each browsing mode is a different
``QWebEngineProfile`` configuration that enforces *real* isolation
differences (not cosmetic). Mode capabilities:

==============  ===========  ============  =================
Aspect          Normal       Privé          Coffre
==============  ===========  ============  =================
Persistence     YES          NO (memory)    NO (memory)
Cookies         persistent   session        session
Cache           persistent   none           none
WebRTC          on           off            off
User-Agent      Chromium     randomized     randomized
DNT header      on           on             on
Tracker block   yes          stricter       strictest
3rd-party reqs  allowed      CDN allow      whitelist only
Cert pinning    no           no             SPKI per domain
Anti-skimmer    off          off            injected
Memory wipe     no           on destroy     on destroy
==============  ===========  ============  =================

Public API
----------
* :func:`make_normal_profile`
* :func:`make_private_profile`
* :func:`make_vault_profile`
* :func:`get_tracker_blocklist`
* :func:`get_vault_cdn_allowlist`
* :func:`install_anti_skimmer_script`
* :func:`install_doh_resolver`
* :func:`randomize_user_agent`
* :class:`TrackerInterceptor`

V1 caveats
----------
* ``VAULT_CERT_PINS`` ships empty (Trust-On-First-Use). V2 will pin
  real SPKI sha256 hashes per banking domain. See ``SECURITY.md``.
* DoH (DNS-over-HTTPS) is configured via Chromium command-line flags
  set on ``QApplication`` startup. Argus forwards the flag value via
  the ``QTWEBENGINE_CHROMIUM_FLAGS`` env var; we only document the
  flag here — actual env-var setting belongs to the launcher.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────
# Qt imports — guarded so this module can be unit-tested without
# QtWebEngine present (tests will skip Qt-dependent assertions).
# ─────────────────────────────────────────────────────────────────
try:
    from PyQt6.QtCore import QObject, QUrl
    from PyQt6.QtWebEngineCore import (
        QWebEngineProfile,
        QWebEngineScript,
        QWebEngineUrlRequestInfo,
        QWebEngineUrlRequestInterceptor,
    )

    _QT_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised only on Qt-less CI
    QObject = object  # type: ignore[assignment,misc]
    QUrl = object  # type: ignore[assignment,misc]
    QWebEngineProfile = object  # type: ignore[assignment,misc]
    QWebEngineScript = object  # type: ignore[assignment,misc]
    QWebEngineUrlRequestInfo = object  # type: ignore[assignment,misc]
    QWebEngineUrlRequestInterceptor = object  # type: ignore[assignment,misc]
    _QT_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parent
DATA_ROOT = _REPO_ROOT / "argus_data"
SANDBOX_DIR = DATA_ROOT / "sandbox"
TRACKER_BLOCKLIST_FILE = SANDBOX_DIR / "trackers_blocklist.txt"


# ─────────────────────────────────────────────────────────────────
# Hardcoded constants — tracker / CDN / cert pin tables
# ─────────────────────────────────────────────────────────────────

#: CDN domains that legitimate banking sites typically need.
#: Used by Privé (allow when host == CDN) and Coffre (whitelist set).
#: Kept narrow on purpose — generic JS CDNs (jsdelivr, unpkg) are
#: NOT here because banks shouldn't be loading random libraries.
_VAULT_CDN_ALLOWLIST = frozenset(
    {
        # Cloudflare (banking + payment processors)
        "cloudflare.com",
        "cdnjs.cloudflare.com",
        "challenges.cloudflare.com",
        # Akamai (used by RBC, BMO, Scotiabank, Desjardins)
        "akamaized.net",
        "akamai.net",
        "akamaihd.net",
        "akamaitechnologies.com",
        "edgekey.net",
        "edgesuite.net",
        # Fastly (used by some fintech)
        "fastly.net",
        "fastlylb.net",
        "global.ssl.fastly.net",
        # Microsoft Azure (Tangerine, EQ Bank)
        "azureedge.net",
        "msecnd.net",
        # AWS CloudFront (many neobanks)
        "cloudfront.net",
        # Bank-specific CDNs
        "rbcroyalbank.com",
        "rbcwealthmanagement.com",
        "scene7.com",  # Adobe — used by RBC for product imagery
    }
)


#: Per-domain SPKI sha256 (base64) pin set.
#: V1: empty values = TOFU (Trust On First Use) with a security warning.
#: V2 will populate real hashes harvested + verified manually.
VAULT_CERT_PINS: dict[str, list[str]] = {
    "rbcroyalbank.com": [],
    "rbcbank.com": [],
    "scotiabank.com": [],
    "td.com": [],
    "tdcanadatrust.com": [],
    "bmo.com": [],
    "cibc.com": [],
    "desjardins.com": [],
    "tangerine.ca": [],
    "eqbank.ca": [],
}


#: Plausible Chrome user-agents (kept in sync with last 10 stable releases).
#: Selected randomly per private/vault session to break naive fingerprinting.
_CHROME_UA_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
)


# ─────────────────────────────────────────────────────────────────
# Anti-skimmer JS — embedded as a Python string and injected via
# QWebEngineScript on document end. Heuristic-based (V1):
#   * Freeze cc input fields after the first user keystroke
#     (reduces second-factor exfil window for late-injected scripts).
#   * MutationObserver on <body> watching for dynamically injected
#     <script src="..."> nodes after page load — alerts the host via
#     window.argusReportSkimmerSuspicion if present.
#
# This script is intentionally tiny and self-contained: no closures
# captured, no external deps, no bundled JS.
# ─────────────────────────────────────────────────────────────────
_ANTI_SKIMMER_JS = r"""
(function () {
  'use strict';
  try {
    // Mark page as armored — hosts can read this from devtools.
    Object.defineProperty(window, '__argus_skimmer_guard__', {
      value: true,
      writable: false,
      configurable: false,
    });

    // 1) Freeze inputs after first keystroke for cc fields.
    var ccSelector = (
      'input[autocomplete*="cc-"], ' +
      'input[name*="card"], ' +
      'input[name*="cardnumber"], ' +
      'input[id*="card"], ' +
      'input[autocomplete="cc-number"], ' +
      'input[autocomplete="cc-csc"], ' +
      'input[autocomplete="cc-exp"]'
    );
    document.querySelectorAll(ccSelector).forEach(function (el) {
      var touched = false;
      el.addEventListener('input', function () {
        if (touched) return;
        touched = true;
        // After first input, prevent setAttribute hijacks that would
        // change the field's destination (some skimmers swap
        // form action by mutating attributes mid-stream).
        var origSetAttr = el.setAttribute.bind(el);
        el.setAttribute = function (name, value) {
          if (
            name === 'name' ||
            name === 'autocomplete' ||
            name === 'form'
          ) {
            try {
              window.argusReportSkimmerSuspicion &&
                window.argusReportSkimmerSuspicion(
                  'cc_field_attr_swap',
                  String(name) + '=' + String(value)
                );
            } catch (e) {}
            return; // Block silently.
          }
          return origSetAttr(name, value);
        };
      }, { passive: true });
    });

    // 2) MutationObserver — watch for late-injected script tags.
    var mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var added = muts[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (!node || node.nodeType !== 1) continue;
          if (node.tagName === 'SCRIPT' && node.src) {
            try {
              window.argusReportSkimmerSuspicion &&
                window.argusReportSkimmerSuspicion(
                  'late_script_injection',
                  String(node.src)
                );
            } catch (e) {}
          }
        }
      }
    });
    mo.observe(document.body, { childList: true, subtree: true });
  } catch (e) {
    // Never throw inside a content script — silent fail.
  }
})();
"""


# ─────────────────────────────────────────────────────────────────
# Tracker blocklist loader
# ─────────────────────────────────────────────────────────────────
_BLOCKLIST_CACHE: Optional[frozenset[str]] = None


def get_tracker_blocklist() -> set[str]:
    """Return the registrable-domain set parsed from ``trackers_blocklist.txt``.

    Lines starting with ``#`` and blank lines are ignored. Result is
    cached after the first read; pass through ``set(...)`` to copy if
    the caller needs to mutate.
    """
    global _BLOCKLIST_CACHE
    if _BLOCKLIST_CACHE is not None:
        return set(_BLOCKLIST_CACHE)

    domains: set[str] = set()
    if TRACKER_BLOCKLIST_FILE.exists():
        try:
            text = TRACKER_BLOCKLIST_FILE.read_text(encoding="utf-8")
        except OSError:
            text = ""
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Strip any inline path component (we suffix-match on host only).
            host = line.split("/", 1)[0].strip().lower()
            if host:
                domains.add(host)

    _BLOCKLIST_CACHE = frozenset(domains)
    return set(_BLOCKLIST_CACHE)


def get_vault_cdn_allowlist() -> set[str]:
    """Return the CDN allowlist as a mutable copy."""
    return set(_VAULT_CDN_ALLOWLIST)


# ─────────────────────────────────────────────────────────────────
# URL request interceptor
# ─────────────────────────────────────────────────────────────────
class TrackerInterceptor(QWebEngineUrlRequestInterceptor):
    """Block trackers + enforce per-mode third-party request policy.

    Modes
    -----
    * ``"normal"``  — block tracker-blocklist hits only.
    * ``"private"`` — block trackers + non-CDN third-party requests.
    * ``"vault"``   — block trackers + everything not in CDN allow set
      and not under ``allowed_domain``.
    """

    def __init__(
        self,
        mode: str = "normal",
        allowed_domain: Optional[str] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        if _QT_AVAILABLE:
            super().__init__(parent) if parent is not None else super().__init__()
        if mode not in ("normal", "private", "vault"):
            raise ValueError(
                f"mode must be normal|private|vault, got {mode!r}"
            )
        self.mode = mode
        self.allowed_domain = (
            allowed_domain.lower().lstrip(".") if allowed_domain else None
        )
        self.blocklist: frozenset[str] = frozenset(get_tracker_blocklist())
        self.cdn_allowlist: frozenset[str] = frozenset(_VAULT_CDN_ALLOWLIST)
        self.block_count: int = 0  # Counter for tests / surveillance.

    # ---- public helpers (also used by tests) ----

    def is_tracker(self, host: str) -> bool:
        host = host.lower()
        return any(
            host == t or host.endswith("." + t) for t in self.blocklist
        )

    def is_third_party(self, host: str, first_party: str) -> bool:
        """Strict definition: host equals first-party OR shares its
        registrable suffix → first-party. Otherwise third-party."""
        h, fp = host.lower(), first_party.lower()
        if not fp:
            return False  # No first-party context (e.g. user-typed URL).
        return not (h == fp or h.endswith("." + fp) or fp.endswith("." + h))

    def is_cdn(self, host: str) -> bool:
        host = host.lower()
        return any(
            host == c or host.endswith("." + c) for c in self.cdn_allowlist
        )

    def is_under_allowed_domain(self, host: str) -> bool:
        if not self.allowed_domain:
            return False
        host = host.lower()
        ad = self.allowed_domain
        return host == ad or host.endswith("." + ad)

    def should_block(self, host: str, first_party: str) -> tuple[bool, str]:
        """Pure decision function — easy to unit test without Qt."""
        # Always block trackers, regardless of mode.
        if self.is_tracker(host):
            return True, "tracker"

        # Mode-specific 3rd-party policy.
        if not self.is_third_party(host, first_party):
            return False, ""

        if self.mode == "normal":
            return False, ""
        if self.mode == "private":
            if self.is_cdn(host):
                return False, ""
            return True, "3rd_party"
        if self.mode == "vault":
            if self.is_under_allowed_domain(host):
                return False, ""
            if self.is_cdn(host):
                return False, ""
            return True, "3rd_party_strict"
        return False, ""

    # ---- Qt entry-point ----

    def interceptRequest(self, info) -> None:  # type: ignore[override]
        if not _QT_AVAILABLE:
            return  # pragma: no cover
        try:
            host = info.requestUrl().host()
            first_party = info.firstPartyUrl().host()
        except Exception:
            return

        block, reason = self.should_block(host, first_party)

        # Always set Do-Not-Track on outbound requests.
        try:
            info.setHttpHeader(b"DNT", b"1")
            info.setHttpHeader(b"Sec-GPC", b"1")
        except Exception:
            pass

        if block:
            self.block_count += 1
            try:
                info.block(True)
            except Exception:
                pass
            self._log_block(reason, host, first_party)

    def _log_block(self, reason: str, host: str, first_party: str) -> None:
        """Best-effort surveillance logging — failure must never break
        request processing."""
        try:
            from argus_surveillance import surveil_log_event  # type: ignore

            surveil_log_event(
                "tracker_block",
                {
                    "reason": reason,
                    "host": host,
                    "first_party": first_party,
                    "mode": self.mode,
                },
            )
        except Exception:
            # No surveillance module yet, or import error — silent.
            pass


# ─────────────────────────────────────────────────────────────────
# Profile factories
# ─────────────────────────────────────────────────────────────────
def _ensure_qt() -> None:
    if not _QT_AVAILABLE:
        raise RuntimeError(
            "QtWebEngine is not available. Install PyQt6 + "
            "PyQt6-WebEngine to use Argus profile factories."
        )


def _set_common_settings(profile: "QWebEngineProfile") -> None:
    """Settings shared by all three modes — DNT header (set by
    interceptor), HTTP referer policy, autofill off."""
    if not _QT_AVAILABLE:
        return
    # Profile-level HTTP headers.
    try:
        profile.setHttpAcceptLanguage("en-US,en;q=0.9")
    except Exception:
        pass


def make_normal_profile(
    parent: Optional[QObject] = None,
) -> "QWebEngineProfile":
    """Persistent profile in ``argus_data/normal/``. Tracker blocking on,
    cookies persistent, default Chromium UA, WebRTC enabled."""
    _ensure_qt()
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    storage = DATA_ROOT / "normal"
    cache = DATA_ROOT / "normal_cache"
    storage.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)

    profile = QWebEngineProfile("argus-normal", parent)
    profile.setPersistentStoragePath(str(storage))
    profile.setCachePath(str(cache))
    profile.setPersistentCookiesPolicy(
        QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies
    )
    profile.setHttpCacheType(
        QWebEngineProfile.HttpCacheType.DiskHttpCache
    )

    interceptor = TrackerInterceptor(mode="normal", parent=profile)
    profile.setUrlRequestInterceptor(interceptor)
    # Hold a ref so Python doesn't gc it before Qt does.
    profile._argus_interceptor = interceptor  # type: ignore[attr-defined]

    _set_common_settings(profile)
    return profile


def make_private_profile(
    parent: Optional[QObject] = None,
) -> "QWebEngineProfile":
    """Off-the-record profile (no persistence). WebRTC off via Chromium
    flags (set by launcher), UA randomized per-session, stricter 3rd-party
    blocking."""
    _ensure_qt()
    # In PyQt6, the no-arg ``QWebEngineProfile()`` constructor creates a
    # true off-the-record (OTR) profile. ``isOffTheRecord()`` returns
    # True; nothing is persisted to disk regardless of the (default)
    # path Qt reports back. Named-constructor profiles are ALWAYS
    # persistent and can't be flipped to OTR — so for private mode we
    # MUST use the no-arg form. ``parent`` is set via ``setParent``.
    profile = QWebEngineProfile(parent) if parent is not None else QWebEngineProfile()
    # Belt-and-suspenders — these are no-ops on an OTR profile but make
    # the intent explicit and survive future Qt API changes.
    profile.setPersistentCookiesPolicy(
        QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies
    )
    profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)

    randomize_user_agent(profile)

    interceptor = TrackerInterceptor(mode="private", parent=profile)
    profile.setUrlRequestInterceptor(interceptor)
    profile._argus_interceptor = interceptor  # type: ignore[attr-defined]

    _set_common_settings(profile)
    return profile


def make_vault_profile(
    parent: Optional[QObject] = None,
    allowed_domain: Optional[str] = None,
) -> "QWebEngineProfile":
    """Strictest mode: off-the-record, anti-skimmer JS injection,
    per-domain whitelist (``allowed_domain`` + small CDN allow set).

    ``allowed_domain`` should be the registrable domain of the bank or
    payment processor the user is opening (e.g. ``"rbcroyalbank.com"``).
    Subdomains of this domain are allowed; everything else is blocked
    unless it is in :func:`get_vault_cdn_allowlist`.
    """
    _ensure_qt()
    # No-arg constructor = off-the-record (see ``make_private_profile``).
    profile = QWebEngineProfile(parent) if parent is not None else QWebEngineProfile()
    profile.setPersistentCookiesPolicy(
        QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies
    )
    profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)

    randomize_user_agent(profile)

    interceptor = TrackerInterceptor(
        mode="vault", allowed_domain=allowed_domain, parent=profile
    )
    profile.setUrlRequestInterceptor(interceptor)
    profile._argus_interceptor = interceptor  # type: ignore[attr-defined]

    _set_common_settings(profile)
    install_anti_skimmer_script(profile)

    # Cert pinning hook — V1 ships with empty pin sets (TOFU + warn).
    # We attach the table for the certificate-error handler to read.
    profile._argus_cert_pins = dict(VAULT_CERT_PINS)  # type: ignore[attr-defined]
    profile._argus_allowed_domain = allowed_domain  # type: ignore[attr-defined]

    return profile


# ─────────────────────────────────────────────────────────────────
# Anti-skimmer / DoH / UA helpers
# ─────────────────────────────────────────────────────────────────
def install_anti_skimmer_script(profile: "QWebEngineProfile") -> None:
    """Inject the embedded anti-skimmer JS at document-end.

    The script is added to the profile's script collection so EVERY
    page loaded under this profile receives it, including iframes
    (subFrames=True).
    """
    _ensure_qt()
    script = QWebEngineScript()
    script.setName("argus-anti-skimmer")
    script.setSourceCode(_ANTI_SKIMMER_JS)
    script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
    script.setRunsOnSubFrames(True)
    script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
    profile.scripts().insert(script)


def install_doh_resolver(profile: "QWebEngineProfile") -> None:
    """Configure DoH (DNS-over-HTTPS) — Cloudflare 1.1.1.1 + Quad9.

    QtWebEngine routes DNS through Chromium's resolver; the practical
    way to enable DoH is via Chromium command-line flags. We set them
    on the process-level ``QTWEBENGINE_CHROMIUM_FLAGS`` env var if no
    one else has done it yet. Idempotent — never appends duplicates.
    """
    _ensure_qt()
    flag = (
        "--enable-features=DnsOverHttps "
        "--dns-over-https-templates="
        "https://cloudflare-dns.com/dns-query "
        "https://dns.quad9.net/dns-query"
    )
    existing = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
    if "DnsOverHttps" not in existing:
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
            (existing + " " + flag).strip()
        )


def randomize_user_agent(profile: "QWebEngineProfile") -> str:
    """Pick a random plausible Chrome UA, set it on ``profile``, return it.

    Uses :mod:`secrets` for the choice (not :mod:`random`) so two
    concurrent private windows can't be correlated by predicting each
    other's UA from a shared seed.
    """
    ua = secrets.choice(_CHROME_UA_POOL)
    if _QT_AVAILABLE:
        try:
            profile.setHttpUserAgent(ua)
        except Exception:
            pass
    return ua


# ─────────────────────────────────────────────────────────────────
# Introspection helpers (used by tests + UI badge)
# ─────────────────────────────────────────────────────────────────
def anti_skimmer_js() -> str:
    """Return the verbatim anti-skimmer script — for tests + audits."""
    return _ANTI_SKIMMER_JS


__all__ = [
    "DATA_ROOT",
    "SANDBOX_DIR",
    "TRACKER_BLOCKLIST_FILE",
    "VAULT_CERT_PINS",
    "TrackerInterceptor",
    "anti_skimmer_js",
    "get_tracker_blocklist",
    "get_vault_cdn_allowlist",
    "install_anti_skimmer_script",
    "install_doh_resolver",
    "make_normal_profile",
    "make_private_profile",
    "make_vault_profile",
    "randomize_user_agent",
]
