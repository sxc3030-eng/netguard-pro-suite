# NetGuard Trim Report — 2026-04-30

Surgical refactor of `netguard.py` to drop ~1500 lines of overkill features that bloated the surface area without delivering value to the target market (pros / freelances / particuliers — see `audit_netguard_2026-04-28.md`). Plus a new rogue Npcap consumer detector (Task B).

## Files touched

- `D:\ComfyUI-Intel\netguard-pro-suite\netguard.py`
- `D:\ComfyUI-Intel\netguard-pro-suite\netguard_dashboard.html`
- `D:\ComfyUI-Intel\netguard-pro-suite\netguard_settings.json`

`tests/test_netguard.py` — no test edits required (the IAM-prefixed login helpers `_hash_password` / `iam_verify_password` were kept, since the actual login flow uses them).

## Task A — Trim summary

| Module | Status | Backend lines | Dashboard panel | Settings keys |
|---|---|---:|---|---|
| Vulnerability scanner | REMOVED | -163 | tab + nav + JS handlers + funcs | n/a |
| Incident tracking | REMOVED | -53 | tab + nav + JS handlers + funcs | `incidents` |
| Training & awareness | REMOVED | -119 | tab + nav + JS handlers + funcs | `training_scores` |
| NAC (network access control) | REMOVED | -27 | tab + nav + JS handlers + funcs | `nac_approved`, `nac_denied`, `nac_policy` |
| IAM user management | REMOVED | -127 | tab + nav + JS handlers + funcs | `iam_users` |
| WG server lifecycle | REMOVED | -350 | start/stop button, peer-mgmt UI | (kept client config keys) |
| **Subtotal trim** | | **~-839** | | |

### What was kept on the IAM side
- `_hash_password()` and `iam_verify_password()` are kept (~50 lines). They're the password hashing primitives used by the **login flow** (`netguard_login.html` + `netguard_users.json`), not user-management features. Test suite (`tests/test_netguard.py::TestPasswordHashing`) depends on them — kept name `iam_verify_password` for backwards compat.

### What was kept on the WG side (display-only)
- `_wg_generate_peer_config(name)` — generates a *sample* client `.conf` with placeholders for keys (~25 lines). User-actionable client-config display only.
- WS handlers `wg_get_config` and `wg_set_config` survive.
- Settings keys `wg_enabled`, `wg_listen_port`, `wg_address`, `wg_dns`, `wg_endpoint`, `wg_interface` survive.
- Removed: `wg_start`, `wg_stop`, `wg_get_status`, `wg_add_peer`, `wg_remove_peer`, `_wg_init_server`, `_wg_load_peers`, `_wg_save_peers`, `_wg_genkey`, `_wg_cmd`, `_wireguard_cmd`, `_wg_find_binary`, `_wg_genpsk_python`, `_wg_genkey_python`, `_wg_generate_server_config`, plus `WG_SERVER_PRIVKEY/PUBKEY`.

## Task B — Rogue Npcap Consumer Detector (added)

New code in `netguard.py` (~190 lines):
- `NPCAP_WHITELIST: set` — user-configurable absolute exe paths (loaded from settings).
- `_npcap_self_paths()` — auto-whitelist netguard.py + python.exe + sys.argv[0].
- `_npcap_process_uses_npcap(proc)` — checks `psutil.Process.memory_maps()` for `Packet.dll` / `wpcap.dll`.
- `_npcap_is_whitelisted(exe_path)` — combines self + user whitelist.
- `detect_npcap_uac_spammers()` — single-scan tracker. Per-exe sliding window (5 min). Tracks unique PIDs over time; if > 3 short-lived restarts of the same exe in window AND not whitelisted, kills via `proc.kill()` and logs `[NPCAP] Rogue Npcap consumer:` at CRITICAL.
- `npcap_get_consumers()` — JSON-safe snapshot for `/api/npcap_consumers`.
- `_npcap_detector_loop()` — daemon thread, runs every 30 s.
- Wired into both startup paths (`main_async` + `main_webview`).
- WS endpoint: `cmd: "npcap_consumers"` returns JSON list.
- State JSON now includes `"npcap_consumers": npcap_get_consumers()` so dashboard renders without an extra request.
- Settings key added: `npcap_whitelist: []` (loaded into `NPCAP_WHITELIST`).

Dashboard side (`netguard_dashboard.html`):
- New mini-panel in the Activité système / dashboard grid: title `Activité système`, body `dash-npcap-list`, count badge `dash-npcap-count`. JS function `renderNpcapConsumers(consumers)` reads from state. Each row shows the exe basename + status flag (`trusted` / number of launches / `ROGUE`).

## Verification

| Check | Result |
|---|---|
| `python -m py_compile netguard.py` | OK |
| `import netguard` (full module load) | OK, all expected symbols present, all trimmed symbols removed |
| `pytest tests/test_netguard.py` | 22 / 22 pass |
| `pytest tests/` (full suite) | 354 pass, 1 fail + 6 errors — **all 7 are pre-existing in `test_argus_mythos_gateway` + `test_mythos_sample`, confirmed unrelated to this trim** (verified with `git stash` baseline run) |

## Net delta

- `netguard.py`: 5154 → 4366 lines (**-788**, includes +190 for npcap detector and +25 for wg client config helper, so raw trim ≈ -1003)
- `netguard_dashboard.html`: 6928 → 6354 lines (**-574**)
- `netguard_settings.json`: 90 → 80 lines (**-10**, removed 7 dormant keys, added 1 npcap_whitelist key)

Total project line delta from `git diff --stat`: **+305 / -1715 = -1410 net lines**.

## Blockers

None. Module imports cleanly, full test suite passes (modulo the unrelated pre-existing Mythos flakiness).

## Notes

- The 6 pre-existing `test_mythos_sample.py` errors are caused by `argus_vault` not being available in the test fixture path. Not introduced by this trim.
- The 1 pre-existing `test_argus_mythos_gateway::test_register_and_unregister_custom_tool` failure is order-sensitive: passes when run in isolation, fails only inside the full suite run. Also pre-existing.
- `NetGuardAPI` (pywebview JS bridge class) had no methods specific to the trimmed modules, so no cleanup needed there.
- `wg_post_up` / `wg_post_down` / `wg_config_dir` Config fields kept (harmless dataclass defaults; no longer referenced).
