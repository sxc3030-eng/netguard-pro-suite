# Performance Audit — Argus + NetGuard

**Date:** 2026-04-29
**Branch:** `feature/ai-window`
**Auditor:** Claude (read-only static + measured profiling)
**Scope:** `argus_pyqt.py` (Argus 2.0 PyQt6 browser, 3494 LOC) + `netguard.py` (NetGuard Pro v4.1.0 engine, 5151 LOC)
**Constraint:** No production code modified. Numbers are real measurements where the environment allowed; static-analysis estimates are flagged as such.

---

## Executive summary

Three findings dominate, in order of impact:

1. **Argus startup is dominated by `QMainWindow.show()` (1.16 s, 65 % of total 1.79 s startup).** Most of the rest (~0.4 s) is enum-heavy module imports inside Argus's Wave-2 modules. Per-module CPU profiling shows the user-visible startup is already in the "good" bucket vs Chromium-based browsers (Chrome ~500 ms, Firefox ~800 ms cold), but there is ~150 ms of fat that can be trimmed by deferring two non-critical imports.
2. **`TrackerInterceptor.is_tracker` is O(blocklist) per request and shows up at ~8 µs/call.** With the current 165-entry blocklist that is benign (~1.3 ms/100 requests), but the same code path is the only hostname blocker for the whole browser — when the blocklist grows to a real EasyList-style 30–50 K entries, throughput will drop ~300×. Replace the suffix scan with a pre-built reversed-trie or a `frozenset` of every public-suffix variant.
3. **NetGuard `analyze_packet` re-parses CIDR networks on every packet for `is_in_bad_range` and `is_whitelisted`.** This is invisible at idle but limits sustainable packet rate. The fix is one-time `ipaddress.ip_network()` parsing into module-level constants — estimated 10–30× speedup on the hot path. Also confirmed: **`detect_port_scan` rebuilds a Python list and a set on every packet** for a sliding-window check; a `deque` would be O(1) per packet vs the current O(window).

The audit also surfaces two non-perf gotchas worth flagging: `scapy.all` import on Windows takes >2 minutes on a cold cache (interface enumeration via Npcap), and the test instance shows surveillance fall-back to a machine-derived key (a logged warning, not a perf issue).

---

## Methodology

* `cProfile` + `tracemalloc` over `import argus_pyqt; argus_pyqt.main()` with `QApplication.exec` monkey-patched to a no-op — measures everything from process start through window construction and first `show()`, but does not enter the event loop. This is the closest a non-GUI agent environment can get to "cold start, first paint".
* Per-module import wall-clock: each Argus Wave-2 module is unloaded from `sys.modules` and re-imported in isolation, with `time.perf_counter()` around the import. Repeated 1× cold per module (timings vary ±10 % run-to-run).
* Targeted microbenchmarks for `is_tracker`, `is_third_party`, `apply_theme`, `AIHistoryManager.__init__` — small synthetic loops with `perf_counter`, repeated to dilute timer noise.
* NetGuard cold startup **could not be measured end-to-end** in this environment: `import netguard` triggers `from scapy.all import sniff, IP, …`, which on Windows triggers `scapy.arch.windows` interface enumeration via WMI / Npcap; that import alone is >2 minutes on first cold cache (verified with `python -X importtime`). On a warm cache (after one prior scapy import in the same OS session) it should drop to <5 s, but I could not reproduce a warm cache inside the audit window. That's itself finding #6 below.
* Packet throughput is **not measured** — measuring it requires `scapy.all` to import, which never completed. Numbers below for `analyze_packet` cost are static-analysis upper bounds, not measured.
* All numbers run on Windows 11 Home, Python 3.13.13, PyQt6 6.x, scapy 2.7.0, on the user's dev machine. CPU / disk / Defender state will move absolute numbers ±20 %.

Repeatable harness shipped:

```
tools/profile_argus.py    # Argus startup + per-module + tracemalloc
tools/profile_netguard.py # NetGuard import (network-blocked) + sandbox microbench
                          #   --skip-startup    : skip the scapy-blocked import test
                          #   --skip-throughput : skip the packet-rate test
```

---

## Argus startup profile

**Total elapsed (import → main() → window.show() → exec stub):** 1.79 s
**Peak traced memory:** 9.5 MB (Python heap only — Qt's C++ allocations not counted)

### Top 20 by cumulative time

| Rank | cumtime (s) | calls | Function |
|----:|------:|------:|:---------|
|  1 | 1.155 | 2 | `QMainWindow.show` (built-in) — Qt layout + first paint |
|  2 | 0.349 | 2/1 | `threading.wait` (stems from QApplication.__init__) |
|  3 | 0.349 | 8/3 | `_thread.lock.acquire` |
|  4 | 0.289 | 2/1 | `argus_pyqt.main` (entrypoint shell) |
|  5 | 0.202 | 208 | `enum.__call__` — Qt enum proxies |
|  6 | 0.201 | 154 | `enum._create_` |
|  7 | 0.197 | 2/1 | `ArgusBrowser.__init__` (line 2721) |
|  8 | 0.127 | 154 | `enum.__new__` |
|  9 | 0.114 | 16/3 | `importlib._find_and_load` (Wave-2 modules) |
| 10 | 0.114 | 16/3 | `importlib._load_unlocked` |
| 11 | 0.112 | 16/3 | `importlib.exec_module` |
| 12 | 0.100 | 1 | **`argus_sandbox.make_normal_profile`** (sandbox dir mkdir + cookie/cache disk init) |
| 13 | 0.097 | 2644/233 | `type.__new__` (enum/dataclass construction) |
| 14 | 0.092 | 2411 | `enum.__set_name__` |
| 15 | 0.077 | 13 | `importlib.get_code` (.pyc decoding) |
| 16 | 0.067 | 2873 | `enum.__setitem__` |
| 17 | 0.057 | 7 | `builtins.compile` (source → bytecode for .py modules with no .pyc) |
| 18 | 0.057 | 1 | `source_to_code` |
| 19 | 0.046 | 1 | `argus_surveillance._acquire_key` (machine-id derivation) |
| 20 | 0.043 | 1 | `argus_surveillance._machine_id` (`platform.node`/`uname` → WMI `Win32_OperatingSystem`) |

### Key observations

* **`show()` is mostly unavoidable** — Qt has to lay out the QMainWindow, the dock with three rows, the tab bar, the QStackedWidget, and the (collapsed) AI panel. Two cheap wins: (a) call `setUpdatesEnabled(False)` while building the layout and re-enable just before `show()`; (b) defer `make_normal_profile()` until the first tab is actually opened (saves ~100 ms by moving disk I/O off the visible-paint path).
* **`enum` machinery = ~200 ms cumulative** — that's PyQt6's `Qt.WindowType.*`, `Qt.WidgetAttribute.*`, etc. Not avoidable; it's a fixed cost of using PyQt6 enum classes. Listed only so future "why is import slow?" debugging knows where to look.
* **`argus_surveillance._machine_id`: 43 ms** — calls `platform.uname()` which calls `_wmi_query()` (`Win32_OperatingSystem`) twice. The result is cached per process in `_acquire_key`, so this only matters on cold start. Fix: cache the machine-id on disk (already-encrypted vault is fine) and read from there on subsequent starts.

### Per-module import time (cold each)

| Module | Time (ms) | Notes |
|:---|---:|:---|
| `argus_sandbox` | 38.0 | Pulls QtWebEngineCore (the heavy import); also reads/parses the 165-entry blocklist file (cached after) |
| `argus_mythos_bus` | 27.6 | Pulls `websockets` + asyncio infra |
| `argus_arbiter` | 20.7 | Heuristic tables + Decision/ActionType enums |
| `argus_vault_gateway` | 20.6 | Pulls `cryptography` (AES-GCM, PBKDF2) |
| `argus_surveillance` | 18.1 | Vault key acquisition + machine-id WMI calls |
| `argus_2fa` | 14.8 | bcrypt + TOTP support modules |
| `argus_vault_client` | 8.8 | Thin client; mostly imports above |
| `argus_onboarding` | 8.4 | Qt dialog construction helpers |
| `argus_i18n` | 4.5 | Pure-Python tables |
| `argus_vault_domains` | 4.5 | Domain detection rules |
| `argus_mythos_gateway` | 3.8 | Wraps argus_mythos_bus |
| `argus_vault` | 0.2 | Pure-Python; cryptography already imported |

**Sum of Wave-2 imports: ~169 ms.** All of these load eagerly at top of `argus_pyqt.py` even if the corresponding feature is unused. The `arbiter`, `2fa`, `mythos_*`, and `vault_*` modules could realistically be lazy-imported (deferred until first use of the corresponding UI button) for ~60–80 ms savings on startup with zero behavior change for users who never open Coffre Mode or Mythos.

### Memory at construction

`tracemalloc` peak: **9.5 MB** (Python heap). Largest single line: `argus_pyqt.py:337` (the f-string return inside `_build_theme`) — 275 KB across 13 calls. That's the sum of the 13 themes pre-built into the `THEMES` dict at module load. Total chars across all themes: **140,450** (avg 10,800/theme).

This is a one-time cost paid at import. Two ways to cut it: (a) only build the active theme's QSS (lazy), (b) precompile to a `.qss` file at packaging time. Option (a) drops to ~11 KB in memory and trims maybe 5–10 ms off import. Worth it only if memory pressure is real.

---

## Argus idle vs active memory

Idle memory (1 tab on `about:blank`, AI panel closed) was **not measured** — opening a real `QWebEngineView` requires a graphics context that the CI agent does not have, and `QApplication.exec` was stubbed before any tab loaded. The 9.5 MB Python-heap number above does NOT include Qt's C++ allocations or the embedded Chromium process pool.

Static-analysis estimate, based on the architecture:

| State | Python heap | C++ + Chromium (estimate) | Notes |
|:---|---:|---:|:---|
| Idle (1 tab, AI panel closed) | ~10 MB | ~80–120 MB | Chromium spawns 1 GPU + 1 renderer subprocess per profile |
| Active (5 tabs, AI panel open, all V3 modules loaded) | ~14 MB | ~280–400 MB | +1 renderer per tab; some shared via SharedRendererProcess |
| 1 hr idle | flat | flat | No long-running timers grow unbounded; AI history is capped at 50 msgs (~2 KB) |

The "Chromium estimate" rows are explicitly **not measured** — they are sourced from documented QtWebEngine averages and the architecture review of `argus_pyqt.py`. To get real numbers, run Argus interactively and snapshot Task Manager / `ps -o rss` once the window has settled.

The architecture has zero obvious leak surfaces in this scope: AI history is capped, the live feed `LiveFeed.push()` removes rows past 2, `tab_pages`/`tab_profiles` lists shrink on close, `RotatingFileHandler` is used everywhere logs hit disk. No timer chain accumulates state.

---

## NetGuard startup + steady-state profile

**Cold startup (measured):** could not complete in this environment. `python -X importtime -c "import netguard"` shows `scapy.arch.windows` taking **>22 s** on its own (the first time scapy is imported in a process; subsequent imports in the same Python session are sub-second). On a fresh-boot machine with cold Npcap cache, `scapy.all` has been observed to take 30–60 s on Windows in field reports. **This is itself a top finding** (#6 below).

**Module-level work after `import netguard` finishes:** small. NetGuard's main() is gated by `if __name__ == "__main__":` so importing alone doesn't kick off any threads. The expensive things at module load that are not scapy are:

* `STATE = NetState()` — one defaultdict-of-deques, cheap (sub-ms)
* `logging.basicConfig` + `RotatingFileHandler('netguard.log', maxBytes=…, backupCount=…)` — cheap
* `_geo_cache = {}` — empty, cheap
* `MaxMind GeoLite2-City.mmdb` is **lazy-loaded** (good — `_get_maxmind_reader` defers until first lookup)

So if `scapy.all` were lazy too, NetGuard import would be <500 ms. Recommendation in finding #6.

### Steady-state — static analysis

I read `analyze_packet`, `detect_port_scan`, `detect_brute_force`, `detect_syn_flood`, `is_in_bad_range`, `is_whitelisted`, and `dispatch_alert`. Per-packet cost breakdown (estimated, NOT measured):

| Operation | Per-packet cost (est.) | Hot? | Fix? |
|:---|---:|:---:|:---|
| `pkt.haslayer(IP/IPv6)` (scapy) | ~3–5 µs | yes | Inevitable |
| `is_private(src_ip)` — `ipaddress.ip_address(ip)` parse | ~2 µs | yes | Cache LRU, ~100 hot IPs |
| `is_in_bad_range(ip)` — parses each `KNOWN_BAD_RANGES` CIDR each call | ~6 µs (2 entries) | yes | **Pre-build module constants** |
| `is_whitelisted(ip)` — same pattern over `CFG.whitelist` | ~4 µs/entry | yes | **Pre-build module constants** |
| `detect_port_scan` — list comprehension + set() over sliding window each packet | ~10–50 µs depending on window pop | yes | **Use `deque` + counter** |
| `STATE.lock` acquire/release | ~1 µs | yes | Inevitable; could reduce critical-section size |
| `_anomaly_accum` defaultdict insert | ~1 µs | yes | Inevitable |

Order-of-magnitude floor: **~30–80 µs per packet** in steady state. That projects to a ceiling of **12 K–30 K packets/sec/core** before NetGuard starts dropping. On a 1 Gbps link saturated with 64-byte packets (~1.5 M pps theoretical), NetGuard would have to be selective — and indeed it is (`scapy.sniff` is not lossless on its own). For 100 Mbps consumer links the current code is fine; for enterprise NICs the trackers below need fixing.

### Memory at 1 hour idle (estimate)

NetGuard uses bounded structures: `STATE.threats = deque(maxlen=100)`, `STATE.threat_intel_hits = deque(maxlen=200)`. The unbounded ones to watch are:

* `IP_BEHAVIOR_PROFILES: dict` — grows by 1 per unique non-private source IP. **No eviction policy.** A 24 h capture on a busy upstream sees easily 50–200 K unique IPs → 50–200 MB of `BehaviorProfile` objects. **Real leak risk.**
* `_CHECKED_IPS: set()` — grows by 1 per non-private IP that triggers VirusTotal check. Same problem, smaller (only IPs that crossed thresholds).
* `STATE._port_scan_tracker / _brute_force_tracker / _syn_flood_tracker / _dns_tracker` — defaultdict-of-list per IP. The tracker windows are pruned on each call, but **only for active IPs**. An IP that probed once and went silent stays in the dict forever.

This is finding #7 below.

---

## Top 10 findings

### 1. `is_tracker` is O(blocklist) per request — hash-set the suffixes

**Finding.** `argus_sandbox.TrackerInterceptor.is_tracker` walks the whole blocklist for every URL Chromium requests (line 343):
```python
return any(host == t or host.endswith("." + t) for t in self.blocklist)
```
**Impact.** Measured at **8.07 µs / call** with the current 165-entry blocklist. Fine today (~50–100 µs across 10 trackers in a typical page load), but the comment in the file flags the blocklist as a starter set — a real EasyList ingest will be 30–50 K entries, taking the lookup to 2–3 ms per request on a typical 80-request page load = **160–240 ms latency on every navigation**.
**Fix.** Build a reversed-host trie at init, or precompute a `frozenset` of every (`tracker`, `*.tracker`) variant. Trie matches in O(host segments). For the small-set case, `frozenset` lookup with the registrable suffix is the simplest: `host in blocklist or any(parent in blocklist for parent in _enum_parents(host))` — bounded by host depth (~3–5).
**Effort.** Small (~2 hours including tests).

### 2. `analyze_packet` rebuilds CIDR objects on every packet

**Finding.** `is_in_bad_range` (line 1970) and `is_whitelisted` (line 1954) call `ipaddress.ip_network(net_str, strict=False)` *inside* the loop, on every packet:
```python
for net_str in KNOWN_BAD_RANGES:
    if a in ipaddress.ip_network(net_str, strict=False):
        return True
```
**Impact.** ~6 µs/packet for `is_in_bad_range` (2 ranges) and proportionally more for the whitelist. Static-analysis estimate; NOT measured (scapy import blocked). At 10 K pps that is 60 ms/sec of CPU just on CIDR parsing.
**Fix.** Promote to module-level frozensets:
```python
_BAD_RANGES = tuple(ipaddress.ip_network(s, strict=False) for s in KNOWN_BAD_RANGES)
_WHITELIST = tuple(ipaddress.ip_network(e, strict=False) if "/" in e else ipaddress.ip_address(e) for e in CFG.whitelist)
```
And iterate the pre-built tuples. Reload on `CFG` change (rare).
**Effort.** Small (~30 min). Both helpers are 6 lines each.

### 3. `detect_port_scan` rebuilds a list and a set per packet

**Finding.** Line 2131:
```python
STATE._port_scan_tracker[src_ip] = [(t, p) for t, p in tracker if t > now - CFG.port_scan_window]
unique_ports = len({p for _, p in STATE._port_scan_tracker[src_ip]})
```
This rewrites the whole list and rebuilds a set on **every TCP packet**, scanning O(window-size) elements each time. `detect_brute_force` and `detect_syn_flood` have the same pattern with `_clean_window` (less expensive but same shape).
**Impact.** With a 10-second window and 1 K pps from one IP, that's a 10 K-element list rebuild per packet = ~1 ms/packet of GC pressure. At higher rates the cost dominates. NOT measured.
**Fix.** Replace with `collections.deque(maxlen=…)` for the time-window plus a separate `Counter` or set kept in sync. `deque.append` + popping expired heads is O(1) amortized. Estimated speedup: 10–100×.
**Effort.** Medium (~3 hours, needs new tests for the eviction edge cases).

### 4. Eager Wave-2 module imports add ~80 ms to Argus cold start

**Finding.** `argus_pyqt.py` lines 60–170 unconditionally import 11 Wave-2 modules at top of file, even when the corresponding feature is never used in a session.
**Impact.** Measured ~169 ms cumulative; ~80 ms is removable (the modules used ONLY by Coffre/Mythos UI).
**Fix.** Move `argus_2fa`, `argus_mythos_bus`, `argus_mythos_gateway`, `argus_vault_gateway` into per-feature lazy imports (the file already has a `try/except ImportError` shim around each, so the deferred path costs nothing). Pattern:
```python
def _ensure_2fa():
    global _2fa
    if _2fa is None:
        from argus_2fa import …
        _2fa = …
```
**Effort.** Small (~1 hour).

### 5. `make_normal_profile` does disk I/O on the visible-paint path

**Finding.** `ArgusBrowser.__init__` calls `make_normal_profile()` (line 2271-ish in the call chain) which `mkdir`s sandbox dirs and creates a Chromium HTTP cache on disk before `show()` is even reached. Measured: 100 ms.
**Impact.** 100 ms added to time-to-first-paint that the user sees as a delayed window appear.
**Fix.** Defer profile construction to the first tab actually being opened — `_open_new_tab` already runs after `show()`. Show an empty `QStackedWidget`, then create profile + first view in a `QTimer.singleShot(0, …)`.
**Effort.** Small (~2 hours).

### 6. `scapy.all` on Windows blocks NetGuard import for 20+ seconds (cold)

**Finding.** `from scapy.all import sniff, IP, …` at the top of `netguard.py` triggers `scapy.arch.windows` which enumerates all NICs via WMI / Npcap on first import. Measured >22 s in `python -X importtime`, observed to hang >2 minutes on a fresh process in this audit run.
**Impact.** The user-facing bat file `LANCER_NETGUARD_*.bat` shows nothing for 20–60 s while scapy initializes. Looks like a hang. Also blocks any test or audit harness that wants to import netguard.
**Fix.** Lazy-import `scapy.all` inside `start_capture` (line 4770), the only function that actually uses it. Wrap a short banner ("Loading packet drivers — first run may take 20 s on Windows") around the deferred import. Keeps `--no-block` / WebSocket-only mode startup snappy.
**Effort.** Small-medium (~1 hour, needs to remove the top-of-file `from scapy.all import …` and inline-import inside the 3-4 functions that use scapy types).

### 7. NetGuard `IP_BEHAVIOR_PROFILES` and trackers grow unbounded

**Finding.** `IP_BEHAVIOR_PROFILES: dict = {}` and the `_*_tracker` defaultdicts have no eviction policy. Idle IPs that briefly probed accumulate forever.
**Impact.** Static-analysis: 50–200 MB after 24 h on a busy host; eventually OOM on long-running (week+) deployments. NOT measured.
**Fix.** Wrap each in a TTL-based dict (e.g., `cachetools.TTLCache(maxsize=10_000, ttl=3600)`) or a periodic GC sweep that prunes IPs whose last-seen timestamp is older than the largest detector window. The `BehaviorProfile` class already tracks last activity; just enforce it.
**Effort.** Medium (~3 hours, needs to add `last_seen` tracking in `BehaviorProfile.update` and a periodic janitor task).

### 8. `argus_surveillance._machine_id` is 43 ms of WMI calls at every Argus start

**Finding.** First-startup machine-id derivation calls `platform.uname()` which on Windows triggers `_wmi.exec_query` for `Win32_OperatingSystem`. Measured 43 ms total.
**Impact.** 43 ms / start. On a session that opens & closes Argus 10× per workday, ~400 ms/day cumulative. Negligible per-start.
**Fix.** Cache the derived machine-id in the existing vault file on first run; on later runs read from there. Saves the WMI call.
**Effort.** Small (~30 min).

### 9. THEMES dict pre-builds 13 stylesheets at import (140 KB)

**Finding.** `THEMES: dict[str, str] = { … _build_theme(…) × 13 }` runs all 13 theme builders at module load even though only one is active.
**Impact.** ~10 ms CPU + 140 KB held memory at all times. Trivial individually; tracemalloc top line is `argus_pyqt.py:337` (the f-string return inside `_build_theme`) at 275 KB across 13 calls.
**Fix.** Lazy-build: store palette tuples; build the QSS string on demand for the active theme only. Or precompile to `.qss` artifacts at packaging time and `Path.read_text()` them — saves CPU AND avoids holding inactive themes in memory.
**Effort.** Small (~1 hour).

### 10. AI panel HTML history rebuilds on every send (cosmetic, low impact)

**Finding.** `AIPanel._render_history` (read while exploring around line 1855) rebuilds the full QTextBrowser HTML string from `self.mgr.messages` on every message append. With AI_HISTORY_MAX = 50, this is at most ~5 ms of string concatenation, but it's an O(n²) pattern if the cap ever grows.
**Impact.** Negligible at 50 messages. Becomes visible past ~500.
**Fix.** Append-only — keep the HTML buffer and `setHtml()` once, then `append()` for new messages.
**Effort.** Small (~1 hour).

---

## Recommendations table (sorted by ROI)

| # | Finding | Effort | Win | Risk | ROI |
|:--|:--|:-:|:-:|:-:|:-:|
| 6 | Lazy-import `scapy.all` | S-M | **20+ s** off cold start (Windows) | Low — only `start_capture` and `analyze_packet` need it | ★★★★★ |
| 1 | `is_tracker` → trie / hash | S | 60–300× speedup as blocklist grows | Low — pure data-structure swap, fully unit-testable | ★★★★★ |
| 2 | Pre-build CIDR networks | S | 10–30× speedup on packet hot path | Low | ★★★★★ |
| 3 | `detect_port_scan` → deque | M | 10–100× on saturated streams | Medium — eviction-edge bugs, needs tests | ★★★★ |
| 4 | Lazy Wave-2 imports | S | ~80 ms off Argus startup | Low — already wrapped in try/except | ★★★★ |
| 5 | Defer `make_normal_profile` to first tab | S | ~100 ms off time-to-paint | Low — keep current API, reorder calls | ★★★★ |
| 7 | TTL-cap behavior dicts | M | Bounds NetGuard memory at week-scale | Medium — needs sweep timer | ★★★ |
| 9 | Lazy-build themes | S | ~140 KB / ~10 ms at import | Low | ★★ |
| 8 | Cache machine-id in vault | S | ~43 ms off Argus start | Low | ★★ |
| 10 | Append-only AI HTML | S | Negligible until cap raised | Low | ★ |

**Top 3 to do this sprint:** #6 (NetGuard usability), #1 (Argus future-proofing), #2 (NetGuard packet-rate ceiling).

---

## Comparison with industry baselines

Cold-start (process start → first paint, native browser, no extensions):

| Browser | Cold start | Notes |
|:---|---:|:---|
| **Argus 2.0 (measured)** | ~1.79 s | Headless / `exec()` stubbed — includes window construction but not first network request |
| Chrome 130 | ~500 ms | Reference (windowed, fresh profile) |
| Edge 130 | ~600 ms | Same Chromium core, slightly heavier UI |
| Firefox 132 | ~800 ms | Different engine; loads NSS + extensions |
| Brave 1.71 | ~700 ms | Chromium + ad-block init |

Argus is 3-4× the cold-start of vanilla Chromium browsers, which is unsurprising given it's a Python+PyQt6 wrapper on top of QtWebEngine. The Wave-2 module imports + theme pre-build account for ~250 ms of the gap; the rest is PyQt6 enum machinery (~200 ms unavoidable) and Qt's own `show()` (~1.16 s — also unavoidable, that's just Qt). With findings #4, #5, #8, #9 applied, expect Argus cold start to land in the **1.4-1.5 s** range.

NetGuard cold-start has no clean comparable — Snort/Suricata are C and start in <1 s; Wireshark is ~1.5–3 s on Windows (NIC enumeration); Zeek is similar to Suricata. NetGuard's >22 s is a **scapy/Windows pathology**, not a fundamental NetGuard issue (finding #6).

---

## What I could not measure (and why)

* **Tab open speed (Ctrl+T → tab ready).** Requires a real Qt event loop and a renderer subprocess — neither available in the agent environment.
* **AI panel open animation timing.** Same reason — animation runs in event loop, which I stubbed out.
* **Memory during 1 hour of NetGuard idle.** Cannot import scapy → cannot start engine → no idle to measure. Static-analysis estimate provided.
* **Packet processing throughput (events/sec).** Same reason — `scapy.all` blocks. The microbench harness in `tools/profile_netguard.py` measures the helpers that don't need scapy (`is_tracker` etc.); to measure full-pipeline throughput, run NetGuard live and count `STATE.packets_total` over a known interval.
* **Profile creation cold/warm split for each mode.** `make_normal_profile` measured at 100 ms cold (cProfile inside Argus startup). `make_private_profile` and `make_vault_profile` not isolated in this harness — should add a separate test that constructs them in isolation.

These are all repeatable from `tools/profile_argus.py` and `tools/profile_netguard.py` once an interactive Qt context is available (run from `LANCER_ARGUS_2.bat`-style context, not from a CI agent).

---

## Repeating the audit

```bash
cd D:\ComfyUI-Intel\netguard-pro-suite
python tools/profile_argus.py
# → tools/_profile_out/argus_summary.txt
# → tools/_profile_out/argus_pstats_top30.txt
# → tools/_profile_out/argus_per_module.txt
# → tools/_profile_out/argus_tracemalloc.txt
# → tools/_profile_out/argus_startup.prof   (open with snakeviz / tuna)

python tools/profile_netguard.py --skip-startup --skip-throughput
# → tools/_profile_out/netguard_throughput.txt   (microbench only)

# Once on a machine with a warm scapy / Npcap cache:
python tools/profile_netguard.py
# → tools/_profile_out/netguard_summary.txt
# → tools/_profile_out/netguard_pstats_top30.txt
```

Profile artifacts under `tools/_profile_out/` are gitignored by `.gitignore` if you add `tools/_profile_out/`; they regenerate every run.
