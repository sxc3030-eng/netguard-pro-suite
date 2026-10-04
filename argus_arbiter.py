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
Argus Arbiter — Claude-powered risk decision gateway.

Third pillar of Argus alongside the sandbox (argus_pyqt browser) and
surveillance (argus_surveillance event log). When the user is about to
do something risky -- download an executable, submit a credit card to a
domain that looks like ``paypa1.com``, paste a password into a non-HTTPS
form -- the arbiter scores the action heuristically and, if the score
crosses the configured threshold, asks Claude for a verdict.

Design goals
------------
* Fast path. Most actions never touch the network: the heuristic catches
  obviously safe and obviously bad cases immediately. Only the grey zone
  goes to Claude.
* BYOK. The Anthropic API key resolves through ``config.get_secret``,
  meaning vault first, ``.env`` second, OS env third. Tests use
  ``"sk-ant-test-fake"`` and mock the HTTP layer; we never hit the wire.
* Safe defaults. If anything goes wrong (timeout, malformed JSON,
  missing key, network error) the arbiter falls back to a heuristic-only
  verdict and never raises into the calling UI thread.
* Observability. Every decision -- claude or heuristic, allow or block,
  cached or fresh -- is logged via ``surveil_log_event`` if available.

Public API
----------
    arbiter_init(threshold="balanced") -> None
    arbiter_decide(action_type, context, mode="normal") -> Decision
    arbiter_decide_async(action_type, context, callback, mode="normal") -> None
    arbiter_clear_cache() -> int
    arbiter_stats() -> dict

The ``Decision`` dataclass is the canonical return type and includes the
``decision_id`` audit cross-reference.

Threshold tiers
---------------
``lax`` 0.85, ``balanced`` 0.60, ``strict`` 0.35, ``paranoid`` 0.15. In
``vault`` mode the active tier drops one notch (e.g. balanced -> strict)
because vault sessions handle the user's most sensitive credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional


# --------------------------------------------------------------------------- #
# Type aliases (Python 3.9+ Literal)
# --------------------------------------------------------------------------- #

ActionType = Literal[
    "download",
    "form_submit",
    "auth_submit",
    "navigation",
    "executable_run",
    "vault_mode_entry",
    "external_link",
]
Verdict = Literal["allow", "warn", "block"]
Threshold = Literal["lax", "balanced", "strict", "paranoid"]


# --------------------------------------------------------------------------- #
# Decision dataclass
# --------------------------------------------------------------------------- #


@dataclass
class Decision:
    """Outcome of one arbiter call.

    ``confidence`` is whatever the verdict source (heuristic or Claude)
    produced; for heuristic-only decisions it tracks the raw risk score
    transformed into a confidence-in-the-verdict number.
    ``decision_id`` is a UUID4 hex prefix so audit logs can cross-ref a
    decision back to a UI action without exposing PII.
    """

    verdict: Verdict
    reason: str
    confidence: float
    used_claude: bool
    cached: bool
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

_THRESHOLDS: dict[str, float] = {
    "lax": 0.85,       # almost never asks Claude
    "balanced": 0.60,  # default
    "strict": 0.35,
    "paranoid": 0.15,  # asks Claude on almost every risky action
}

# Tier order used when ``mode="vault"`` shifts one step stricter.
_TIER_ORDER: list[str] = ["lax", "balanced", "strict", "paranoid"]

# Default endpoint + model. Model is overridable via env so users can
# pin a specific Haiku revision without a code change.
_API_URL = "https://api.anthropic.com/v1/messages"
_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_API_VERSION = "2023-06-01"
_REQUEST_TIMEOUT_SEC = 3.0
_CACHE_TTL_SEC = 300
_CACHE_MAX_ENTRIES = 1000

_SYSTEM_PROMPT = (
    "You are Argus, a cybersecurity arbiter. Given a user action and "
    "context, return JSON: {verdict: 'allow'|'warn'|'block', reason: "
    "'short explanation in user's language', confidence: 0.0-1.0}. Be "
    "conservative for downloads of executables and submissions to "
    "typosquat domains. Do NOT block legitimate banking actions."
)

# A tiny set of "high-value" brands typosquatters tend to imitate.
# Real implementations should pull this list from a TI feed; we keep
# enough entries to be useful for testing without bloating the file.
_HIGH_VALUE_BRANDS: tuple[str, ...] = (
    "paypal", "amazon", "google", "microsoft", "apple",
    "facebook", "instagram", "twitter", "github", "gitlab",
    "netflix", "linkedin", "dropbox", "slack", "discord",
    "bankofamerica", "chase", "wellsfargo", "citibank", "rbc",
    "bmo", "scotiabank", "td", "desjardins",
)

# Treat these TLDs as common-enough that "domain not in alexa-top-1000"
# isn't quite as strong a signal -- still bumps risk, just less.
_COMMON_TLDS: frozenset[str] = frozenset({"com", "net", "org", "io", "co"})

_RISKY_DOWNLOAD_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".msi", ".bat", ".ps1", ".cmd", ".scr", ".vbs", ".js",
    ".jar", ".apk", ".dmg", ".pkg",
})

# A handful of widely-installed apps -- typo-of-app heuristic compares
# the candidate filename stem to these.
_COMMON_APPS: tuple[str, ...] = (
    "chrome", "firefox", "edge", "safari", "zoom", "teams", "slack",
    "discord", "spotify", "vlc", "notepad", "winrar", "7zip",
    "putty", "filezilla", "anydesk", "teamviewer",
)


# --------------------------------------------------------------------------- #
# Module state (configured by arbiter_init)
# --------------------------------------------------------------------------- #


class _State:
    """All mutable arbiter state in one container.

    Kept on a singleton instance so arbiter_init can swap fields without
    leaking partial state between calls. A lock guards cache + stats so
    arbiter_decide_async can safely run on a worker thread.
    """

    def __init__(self) -> None:
        self.threshold_name: str = "balanced"
        self.threshold_value: float = _THRESHOLDS["balanced"]
        # cache key -> (Decision, expires_at_monotonic)
        self.cache: "OrderedDict[tuple[str, str], tuple[Decision, float]]" = (
            OrderedDict()
        )
        self.lock = threading.Lock()
        # Stats counters
        self.total_decisions: int = 0
        self.by_verdict: dict[str, int] = {"allow": 0, "warn": 0, "block": 0}
        self.claude_calls: int = 0
        self.cache_hits: int = 0
        self.total_latency_ms: float = 0.0


_S = _State()


# --------------------------------------------------------------------------- #
# Test seams
# --------------------------------------------------------------------------- #
#
# These are module-level so unittest.mock.patch can swap them in tests
# without us having to take a mocking framework dependency. They default
# to the real wall clock and the real urllib opener.


def _now() -> float:
    """Monotonic clock for cache TTL. Override in tests via patch."""
    return time.monotonic()


def _http_post(url: str, headers: dict[str, str], body: bytes,
               timeout: float) -> tuple[int, bytes]:
    """Minimal HTTP POST so we don't pull ``requests`` into the BYOK path.

    Returns ``(status_code, response_body_bytes)``. Raises whatever
    urllib raises on transport failure; the caller catches everything.
    """
    req = urllib.request.Request(url=url, data=body, headers=headers,
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read()


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def arbiter_init(threshold: Threshold = "balanced") -> None:
    """Configure the arbiter risk threshold.

    Reading the API key here is intentional: we want the BYOK story to
    be obvious in logs ("Arbiter initialised with no API key") rather
    than surfacing as a mystery 401 on first decision. The actual key
    isn't cached on the state object -- ``config.get_secret`` is fast
    and we re-resolve on every Claude call so a key added mid-session
    starts working immediately.
    """
    if threshold not in _THRESHOLDS:
        raise ValueError(
            f"unknown threshold {threshold!r}; expected one of "
            f"{list(_THRESHOLDS)}"
        )
    with _S.lock:
        _S.threshold_name = threshold
        _S.threshold_value = _THRESHOLDS[threshold]
        # Reset per-init counters so stats reflect the active session.
        _S.cache.clear()
        _S.total_decisions = 0
        _S.by_verdict = {"allow": 0, "warn": 0, "block": 0}
        _S.claude_calls = 0
        _S.cache_hits = 0
        _S.total_latency_ms = 0.0

    # Touch the secrets API so missing-key is observable up front.
    # Failure here is non-fatal -- the arbiter still works in
    # heuristic-only mode.
    try:
        from config import get_secret  # local import, lazy
        _ = get_secret("ANTHROPIC_API_KEY")
    except Exception:
        pass


def arbiter_decide(
    action_type: ActionType,
    context: dict,
    mode: str = "normal",
) -> Decision:
    """Return a verdict for ``action_type`` with the given ``context``.

    Synchronous: blocks up to ~3s if Claude is consulted. Errors caught
    and turned into safe-default verdicts; never raises into the caller.
    """
    started = time.perf_counter()
    try:
        decision = _decide_impl(action_type, context, mode)
    except Exception as exc:  # pragma: no cover - defensive
        # Last-resort safety net. We never let an exception escape into
        # the UI thread; instead we fall back to a generic warn so the
        # user sees something rather than a crashed action.
        decision = Decision(
            verdict="warn",
            reason=f"Arbiter internal error: {type(exc).__name__}",
            confidence=0.5,
            used_claude=False,
            cached=False,
        )

    latency_ms = (time.perf_counter() - started) * 1000.0
    with _S.lock:
        _S.total_decisions += 1
        _S.by_verdict[decision.verdict] = (
            _S.by_verdict.get(decision.verdict, 0) + 1
        )
        _S.total_latency_ms += latency_ms

    _surveil_log(action_type, context, decision)
    return decision


def arbiter_decide_async(
    action_type: ActionType,
    context: dict,
    callback: Callable[[Decision], None],
    mode: str = "normal",
) -> None:
    """Non-blocking variant. ``callback`` runs on a daemon worker thread.

    The callback is invoked exactly once. We swallow callback exceptions
    so a buggy UI handler can't crash the worker thread.
    """

    def _worker() -> None:
        decision = arbiter_decide(action_type, context, mode=mode)
        try:
            callback(decision)
        except Exception:  # pragma: no cover - defensive
            pass

    t = threading.Thread(target=_worker, name="arbiter-decide", daemon=True)
    t.start()


def arbiter_clear_cache() -> int:
    """Drop every cached decision. Returns the number of entries cleared."""
    with _S.lock:
        n = len(_S.cache)
        _S.cache.clear()
    return n


def arbiter_stats() -> dict:
    """Snapshot of arbiter counters for diagnostics / settings UI."""
    with _S.lock:
        total = _S.total_decisions
        cache_hit_rate = (_S.cache_hits / total) if total else 0.0
        avg_latency = (_S.total_latency_ms / total) if total else 0.0
        return {
            "total_decisions": total,
            "by_verdict": dict(_S.by_verdict),
            "claude_calls": _S.claude_calls,
            "cache_hit_rate": round(cache_hit_rate, 4),
            "avg_latency_ms": round(avg_latency, 2),
        }


# --------------------------------------------------------------------------- #
# Core decision pipeline
# --------------------------------------------------------------------------- #


def _decide_impl(action_type: str, context: dict, mode: str) -> Decision:
    """Heuristic -> cache -> Claude -> verdict, in that order."""
    # 1. Score
    score = _heuristic_score(action_type, context)

    # 2. Pick effective threshold (vault mode tightens by one tier)
    threshold = _effective_threshold(mode)

    # 3. Below threshold -> auto-allow, no API call
    if score < threshold:
        return Decision(
            verdict="allow",
            reason=f"Heuristic risk {score:.2f} below threshold {threshold:.2f}",
            confidence=max(0.0, 1.0 - score),
            used_claude=False,
            cached=False,
        )

    # 4. Cache lookup (skip Claude if we've seen this exact context)
    cache_key = _cache_key(action_type, context)
    cached = _cache_get(cache_key)
    if cached is not None:
        # Return a fresh Decision with cached=True; keep verdict/reason.
        return Decision(
            verdict=cached.verdict,
            reason=cached.reason,
            confidence=cached.confidence,
            used_claude=cached.used_claude,
            cached=True,
            decision_id=uuid.uuid4().hex[:12],
        )

    # 5. Ask Claude (or fall back to heuristic if no key / transport fails)
    decision = _ask_claude(action_type, context, score)
    _cache_put(cache_key, decision)
    return decision


def _effective_threshold(mode: str) -> float:
    """Vault mode shifts the active tier one notch stricter."""
    base_name = _S.threshold_name
    if mode == "vault":
        idx = _TIER_ORDER.index(base_name)
        # max idx in the list is the strictest -> can't go further.
        bumped = _TIER_ORDER[min(idx + 1, len(_TIER_ORDER) - 1)]
        return _THRESHOLDS[bumped]
    return _THRESHOLDS[base_name]


# --------------------------------------------------------------------------- #
# Heuristic scoring
# --------------------------------------------------------------------------- #


def _heuristic_score(action_type: str, context: dict) -> float:
    """Cheap, deterministic risk estimate in [0.0, 1.0].

    The scores are additive contributions; the sum is clamped to 1.0.
    Every term has a comment explaining *why* it matters because future
    maintainers will tweak these without context otherwise.
    """
    score = 0.0
    ctx = context or {}

    if action_type == "download":
        url = str(ctx.get("url", ""))
        filename = str(ctx.get("filename", "")).lower()
        size = ctx.get("size_bytes")
        domain = _domain_of(url) or str(ctx.get("domain", ""))

        # Executables ARE the typical malware vector. +0.3 baseline.
        if any(filename.endswith(ext) for ext in _RISKY_DOWNLOAD_EXTENSIONS):
            score += 0.3

        # Unknown / non-mainstream domain -> +0.2. We approximate
        # "alexa top 1000" by checking the brand list and TLD.
        if domain and not _is_well_known_domain(domain):
            score += 0.2

        # Filename like "chr0me_setup.exe" -- typo of a common app.
        # Also catches "chr0me-installer", "chrome_v2", etc. by checking
        # each word-ish chunk separately.
        stem = filename.rsplit(".", 1)[0]
        chunks = [c for c in stem.replace("-", "_").split("_") if c]
        if any(_is_typosquat_of_any(chunk, _COMMON_APPS) for chunk in chunks):
            score += 0.3

        # < 10 KB executable is almost always a stub / dropper.
        if isinstance(size, (int, float)) and size > 0 and size < 10_240:
            score += 0.2

    elif action_type in ("form_submit", "auth_submit"):
        action_url = str(ctx.get("action_url", ""))
        page_url = str(ctx.get("page_url", ""))
        has_password = bool(ctx.get("has_password_field", False))
        scheme = (ctx.get("scheme") or _scheme_of(page_url) or "").lower()
        dom_action = _domain_of(action_url)
        dom_page = _domain_of(page_url)

        # Password over plain HTTP -> +0.4. Blatant.
        if has_password and scheme not in ("https", ""):
            score += 0.4

        # Form posts off-domain. Legitimate cross-site posts exist
        # (Stripe, OAuth) but they're a minority and worth a Claude check.
        if dom_action and dom_page and dom_action != dom_page:
            score += 0.3

        # Domain is a typo of a high-value brand.
        if dom_page and _is_typosquat_of_any(_brand_of(dom_page),
                                             _HIGH_VALUE_BRANDS):
            score += 0.5

    elif action_type == "navigation":
        url = str(ctx.get("url", ""))
        domain = _domain_of(url) or str(ctx.get("domain", ""))
        whois_age_days = ctx.get("whois_age_days")

        # Brand typosquat in URL bar -> high.
        if domain and _is_typosquat_of_any(_brand_of(domain),
                                           _HIGH_VALUE_BRANDS):
            score += 0.4

        # Punycode / IDN homograph (Cyrillic а vs Latin a, etc.).
        if domain and _looks_like_idn_homograph(domain):
            score += 0.3

        # Very young domain. Skipped silently if WHOIS unavailable.
        if isinstance(whois_age_days, (int, float)) and 0 <= whois_age_days < 30:
            score += 0.2

    elif action_type == "vault_mode_entry":
        # We always want Claude to confirm before unlocking the vault,
        # because vault unlock is exactly what malware would target.
        score += 0.5

    elif action_type == "executable_run":
        path = str(ctx.get("path", "")).lower()
        signed = ctx.get("signed")
        if any(path.endswith(ext) for ext in _RISKY_DOWNLOAD_EXTENSIONS):
            score += 0.4
        if signed is False:
            score += 0.3

    elif action_type == "external_link":
        url = str(ctx.get("url", ""))
        from_email = bool(ctx.get("from_email", False))
        domain = _domain_of(url)
        # Email-borne links are the #1 phishing vector.
        if from_email:
            score += 0.3
        if domain and _is_typosquat_of_any(_brand_of(domain),
                                           _HIGH_VALUE_BRANDS):
            score += 0.4

    return min(1.0, score)


# --------------------------------------------------------------------------- #
# String / domain helpers
# --------------------------------------------------------------------------- #


def _domain_of(url: str) -> str:
    """Cheap host extraction without pulling urllib.parse for one job."""
    if not url:
        return ""
    s = url.strip()
    # Strip scheme
    if "://" in s:
        s = s.split("://", 1)[1]
    # Strip path / query / fragment
    for sep in ("/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    # Strip user@, port
    if "@" in s:
        s = s.split("@", 1)[1]
    if ":" in s:
        s = s.split(":", 1)[0]
    return s.lower()


def _scheme_of(url: str) -> str:
    if not url or "://" not in url:
        return ""
    return url.split("://", 1)[0].lower()


def _brand_of(domain: str) -> str:
    """Pull the registrable label out of a domain.

    "secure.paypa1.com" -> "paypa1". Good enough for typosquat checks
    without dragging in tldextract / the public suffix list.
    """
    if not domain:
        return ""
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _is_well_known_domain(domain: str) -> bool:
    """Approximate ``in alexa-top-1000`` cheaply."""
    brand = _brand_of(domain)
    if brand in _HIGH_VALUE_BRANDS:
        return True
    # Bare ``something.com`` registered for ages? Hard to tell offline,
    # so treat any common-TLD domain as moderately trusted to avoid
    # false positives on "weird-but-real" domains like "stackoverflow".
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    return tld in _COMMON_TLDS and len(brand) >= 6


def _looks_like_idn_homograph(domain: str) -> bool:
    """Detect mixed-script or Cyrillic-look-alike characters.

    The cheap version: any non-ASCII letter triggers it. We don't try
    to be clever with confusable maps because the false-positive cost
    of nudging the user to slow down is low and Claude will sort the
    rest out.
    """
    if domain.startswith("xn--"):
        return True
    for ch in domain:
        if ch.isalpha() and ord(ch) > 127:
            return True
    return False


def _levenshtein(a: str, b: str, cutoff: int = 2) -> int:
    """Edit distance with early-exit when distance > cutoff.

    Cutoff lets us bail out cheaply for very different strings -- we
    only care whether the distance is <=2 for typosquat detection.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cutoff:
        return cutoff + 1
    # Standard dynamic-programming row-rolling version.
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            row_min = min(row_min, cur[j])
        if row_min > cutoff:
            return cutoff + 1
        prev = cur
    return prev[-1]


def _is_typosquat_of_any(candidate: str, brands: tuple[str, ...]) -> bool:
    """True if ``candidate`` is within Levenshtein <=2 of any brand
    *and* not equal to it.

    Equality means "you typed paypal.com correctly" -- not a typosquat.
    """
    if not candidate:
        return False
    c = candidate.lower()
    for brand in brands:
        if c == brand:
            return False
        if _levenshtein(c, brand, cutoff=2) <= 2:
            return True
    return False


# --------------------------------------------------------------------------- #
# Cache (FIFO with TTL, capped at _CACHE_MAX_ENTRIES)
# --------------------------------------------------------------------------- #


def _cache_key(action_type: str, context: dict) -> tuple[str, str]:
    """``(action_type, sha256(context_json)[:16])``.

    Sorting keys makes the hash stable against dict-ordering noise;
    json.dumps with default=str handles things like ints/bools/None.
    """
    serialised = json.dumps(context, sort_keys=True, default=str)
    digest = hashlib.sha256(serialised.encode("utf-8")).hexdigest()[:16]
    return (action_type, digest)


def _cache_get(key: tuple[str, str]) -> Optional[Decision]:
    with _S.lock:
        entry = _S.cache.get(key)
        if entry is None:
            return None
        decision, expires_at = entry
        if _now() >= expires_at:
            # Expired -- evict and miss.
            _S.cache.pop(key, None)
            return None
        # Move to end (LRU-ish bump on hit, helps liveliness).
        _S.cache.move_to_end(key)
        _S.cache_hits += 1
        return decision


def _cache_put(key: tuple[str, str], decision: Decision) -> None:
    with _S.lock:
        _S.cache[key] = (decision, _now() + _CACHE_TTL_SEC)
        # FIFO eviction once we hit capacity. OrderedDict pops oldest
        # when ``last=False``.
        while len(_S.cache) > _CACHE_MAX_ENTRIES:
            _S.cache.popitem(last=False)


# --------------------------------------------------------------------------- #
# Claude API call
# --------------------------------------------------------------------------- #


def _ask_claude(action_type: str, context: dict, score: float) -> Decision:
    """Round-trip to Claude, with safe fallbacks for every failure path.

    Falls back to:
      * heuristic-only ``warn`` if the API key is missing
      * heuristic-only ``warn`` on transport timeout / network error
      * ``warn`` with "unparseable" reason on malformed JSON
    """
    api_key = _resolve_api_key()
    if not api_key:
        # BYOK fallback: no key -> heuristic-only verdict. Above
        # threshold means the score warranted a check; without Claude
        # we conservatively warn rather than allow.
        return Decision(
            verdict="warn",
            reason=(
                f"Heuristic risk {score:.2f} but ANTHROPIC_API_KEY not "
                f"configured; user should verify"
            ),
            confidence=score,
            used_claude=False,
            cached=False,
        )

    model = os.environ.get("ARGUS_ARBITER_MODEL", _DEFAULT_MODEL)
    body = json.dumps({
        "model": model,
        "max_tokens": 200,
        "system": _SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": json.dumps({
                "action_type": action_type,
                "context": context,
                "heuristic_score": round(score, 3),
            }),
        }],
    }).encode("utf-8")

    headers = {
        "x-api-key": api_key,
        "anthropic-version": _API_VERSION,
        "content-type": "application/json",
    }

    with _S.lock:
        _S.claude_calls += 1

    try:
        status, raw = _http_post(_API_URL, headers, body, _REQUEST_TIMEOUT_SEC)
    except (urllib.error.URLError, TimeoutError, OSError):
        return Decision(
            verdict="warn",
            reason=(
                f"Heuristic risk {score:.2f}; Claude unreachable, "
                f"user should verify"
            ),
            confidence=score,
            used_claude=False,
            cached=False,
        )
    except Exception:
        # Belt and suspenders: anything weird (SSL, DNS, etc.) -> warn.
        return Decision(
            verdict="warn",
            reason=f"Heuristic risk {score:.2f}; Claude error, user should verify",
            confidence=score,
            used_claude=False,
            cached=False,
        )

    if status != 200:
        return Decision(
            verdict="warn",
            reason=(
                f"Claude API returned HTTP {status}; falling back to "
                f"heuristic verdict (risk {score:.2f})"
            ),
            confidence=score,
            used_claude=False,
            cached=False,
        )

    return _parse_claude_response(raw, score)


def _resolve_api_key() -> Optional[str]:
    """Look up the Anthropic key via the suite's secrets resolver.

    Falls back to a direct env-var read if config.py is missing (e.g.
    in a stripped-down build), so the arbiter can still function.
    """
    try:
        from config import get_secret  # local import keeps GUI startup fast
        key = get_secret("ANTHROPIC_API_KEY")
        if key:
            return key
    except Exception:
        pass
    return os.environ.get("ANTHROPIC_API_KEY") or None


def _parse_claude_response(raw: bytes, score: float) -> Decision:
    """Pull ``{verdict, reason, confidence}`` out of Claude's reply.

    Claude wraps the assistant text in ``content[0].text``. We then try
    to JSON-parse that text. On any malformation we fall back to warn,
    not allow -- "I couldn't parse the verdict" is closer to "danger"
    than to "safe".
    """
    try:
        envelope = json.loads(raw.decode("utf-8"))
        # Standard messages-API shape.
        chunks = envelope.get("content", [])
        text = ""
        for c in chunks:
            if isinstance(c, dict) and c.get("type") == "text":
                text = c.get("text", "")
                break
        if not text and chunks:
            # Some shims return content as a plain string list.
            first = chunks[0]
            if isinstance(first, str):
                text = first
            elif isinstance(first, dict):
                text = first.get("text", "")

        # Some models prefix the JSON with prose ("Here is the verdict:"
        # ...). Strip until the first ``{`` to be permissive.
        brace_idx = text.find("{")
        if brace_idx > 0:
            text = text[brace_idx:]

        payload = json.loads(text)
    except Exception:
        return Decision(
            verdict="warn",
            reason="Claude response unparseable; user should verify",
            confidence=score,
            used_claude=True,
            cached=False,
        )

    verdict = payload.get("verdict")
    if verdict not in ("allow", "warn", "block"):
        return Decision(
            verdict="warn",
            reason="Claude returned invalid verdict; user should verify",
            confidence=score,
            used_claude=True,
            cached=False,
        )

    reason = str(payload.get("reason") or "")[:300]  # cap to keep logs sane
    try:
        confidence = float(payload.get("confidence", score))
    except (TypeError, ValueError):
        confidence = score
    confidence = max(0.0, min(1.0, confidence))

    return Decision(
        verdict=verdict,
        reason=reason or f"Claude verdict ({verdict})",
        confidence=confidence,
        used_claude=True,
        cached=False,
    )


# --------------------------------------------------------------------------- #
# Surveillance hook
# --------------------------------------------------------------------------- #


def _surveil_log(action_type: str, context: dict, decision: Decision) -> None:
    """Best-effort hand-off to argus_surveillance. Optional dependency."""
    try:
        from argus_surveillance import surveil_log_event  # type: ignore
    except ImportError:
        return
    except Exception:
        return

    try:
        # Only the context hash leaves the arbiter -- the full context
        # might contain credentials or PII the surveillance log
        # shouldn't store.
        digest = hashlib.sha256(
            json.dumps(context, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        surveil_log_event("arbiter_decision", {
            "action_type": action_type,
            "verdict": decision.verdict,
            "reason": decision.reason,
            "confidence": decision.confidence,
            "used_claude": decision.used_claude,
            "context_hash": digest,
            "decision_id": decision.decision_id,
        })
    except Exception:
        # Surveillance must never break a decision.
        pass
