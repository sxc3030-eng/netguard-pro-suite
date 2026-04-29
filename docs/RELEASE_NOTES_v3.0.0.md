# Argus / NetGuard Pro Suite — v3.0.0 Release Notes

**Release date:** 2026-04-29
**Tag:** `v3.0.0`
**License:** GPL v3 — repository is now public.

---

## TL;DR

V2 was a browser shell with three coloured borders and an honest
admission that the modes were cosmetic. V3 makes those modes real,
encrypts every secret the suite touches, and ships the wire protocol
that a future Mythos agent plugs into.

If you only read three bullets:

- **Modes are real now.** `Privé` and `Coffre` actually isolate
  cookies, storage, and per-mode profiles. `Coffre` injects an
  anti-skimmer script. Banking domains get an auto-vault prompt.
- **Your API keys are no longer scattered in `.env` files.** The
  encrypted vault is the canonical home — AES-256-GCM, DPAPI on
  Windows, PBKDF2-600k elsewhere. A REST gateway brokers them to
  whitelisted programs, identified by live binary hash.
- **Mythos is plug-ready.** `argus_mythos_bus` (events) and
  `argus_mythos_gateway` (actions) are live. The protocol is
  versioned and documented. A reference plugin in
  `examples/mythos_sample/` proves the loop closes.

---

## What's actually new

### Real Privé / Coffre modes (was cosmetic in V2)

The V2 audit called this out as security theater. We agreed. V3 ships
the real thing in `argus_sandbox.py`:

- Per-mode persistent profile path under
  `argus_data/profiles/{normal,private,vault}/`.
- Cookie + localStorage isolation across modes.
- Third-party cookies blocked in `Privé`.
- Anti-skimmer JS injection in `Coffre`.
- Mode switch reloads the affected tabs into the new profile.

> The form-submit arbiter in V3 is **advisory** — it scores in real
> time and shows a banner, but does not synchronously block submit.
> Sync gating ships in V4.

### Claude as decision arbiter (BYOK)

`argus_arbiter.py` runs a fast heuristic on every form-submit and
suspicious navigation. If the heuristic is uncertain, it asks Claude
(your key, your account — Bring Your Own Key) and uses the answer.
Four configurable thresholds: `block`, `warn`, `verify-with-AI`,
`allow`. Every decision lands in the surveillance HMAC chain so you
can audit what it did, when, and why.

### The vault, end to end

V2 stored API keys in a `.env` file at repo root. That worked, but
"works" is not "safe":

- `argus_vault.py` — AES-256-GCM at rest, fresh nonce per secret.
  Master key wrapped with Windows DPAPI on Windows, PBKDF2-HMAC-SHA256
  at 600 000 iterations elsewhere. Vault file gitignored.
- `argus_vault_gateway.py` — localhost HTTPS service that brokers
  secrets to other programs in the suite (NetGuard, GeniA, third-party
  modules). Authenticates callers by **live SHA-256 of the requesting
  binary**, HMAC-signs every response, rate-limits with a token
  bucket. No filesystem ACL gymnastics, no shared passphrase.
- `tools/migrate_to_vault.py` — one-shot migrator for users who had
  keys in scattered `.env` / `*.json` files. Runs `--dry-run` first,
  then `--yes` when you're happy.
- A **Settings -> API Keys** tab with `Show / Save / Migrate from .env`
  buttons, plus a **Settings -> Vault** tab for browsing what's stored.

### Mythos plug interface

V3 doesn't ship Mythos. V3 ships the **cage Mythos plugs into**.

- `argus_mythos_bus.py` — read-only WebSocket fan-out on
  `ws://127.0.0.1:8767`. Every Argus event (page load, mode switch,
  arbiter verdict, surveillance entry) is published.
- `argus_mythos_gateway.py` — REST tool gateway on
  `http://127.0.0.1:8768`. Mythos posts action requests, Argus
  executes them, every call is audited.
- `docs/MYTHOS_PROTOCOL.md` — the versioned wire contract.
- `examples/mythos_sample/` — a reference client that subscribes to
  the bus, calls a tool, and validates the audit chain.

### 12 themes

Plus 6 community-favourite palettes for the people who already
preset their entire stack. `Cyber Dark`, `Pro Dark`, `Light Pro`,
`Hacker Green`, `Bank Vault`, `Pastel`, `Tokyo Night`,
`Catppuccin Mocha`, `Dracula`, `Solarized Dark`, `Gruvbox Dark`,
`Nord`. Live preview, no restart.

### Hieratic Cipher iconography

The branding swung hard. `branding/argus/` ships v1 (sigil + 12
satellite eyes + dodecagon — the "100 eyes of Argus" wired into a
medieval-grimoire grid) and v2 (a shield-silhouette refresh for
Windows ICO). Splash + about + dock badges all use the same
language.

### First-run onboarding

Pick a theme, set the vault passphrase (or accept DPAPI),
optionally enable 2FA for `Coffre`, paste your Anthropic /
OpenAI / Gemini keys. One screen, four steps, done. Source in
`argus_onboarding.py`.

### NetGuard core, while you're here

Wave 1 also lifted the core dashboard:

- Per-packet app identification + per-IP bandwidth tracking
  (Process column in the packets table, Top Bandwidth panel).
- `NetGuard Mode Fantôme` tray launcher for silent background
  protection.
- MaxMind GeoLite2 as the primary GeoIP provider with `tools/geoip_update.py`
  for licence-key updates.
- 3-axis map noise filters, multi-hop traceroute on the world map,
  per-IP ring buffer (chatty IPs no longer starve quiet ones).
- `RotatingFileHandler` (5 MB x 3) so a 30-day session doesn't fill
  your disk.

---

## What's still on the roadmap (and we say so)

- **Sync form-submit gating.** V3's arbiter warns; V4's blocks
  through `QWebChannel`.
- **Pre-pinned SPKI hashes** for banking domains. V3 is TOFU.
- **Authenticode signing.** Documented in `docs/AUTHENTICODE.md`,
  not yet executed. Until then the unsigned-binary SmartScreen
  warning is real and we're not going to pretend otherwise.
- **MSIX + Microsoft Store resubmission.** Documented but not yet
  packaged. Required to clear the 2026-04-03 policy 10.2.9
  rejection.
- **Mythos itself.** V3 ships the protocol, not the agent.
- **`docs/PERFORMANCE.md` + `docs/PRIVACY.md`.** Scheduled for V3.1.

`SECURITY.md` is the one place that lists every gap in plain
English — read it, especially if you're considering trusting
`Coffre` mode for high-stakes banking sessions.

---

## How to upgrade from V2

See [`docs/MIGRATION_v2_to_v3.md`](MIGRATION_v2_to_v3.md). Short
version: backup `argus_data/`, `git pull`, `pip install
-r requirements.txt -r requirements-dev.txt`, run
`python tools/migrate_to_vault.py --dry-run` then `--yes`, walk
through the onboarding wizard.

## How to install fresh

See the top-level [`README.md`](../README.md). It covers the three
secret-sources priority chain (vault > `.env` > OS env), the trust
model, and the launchers. Windows users: `LANCER_ARGUS_2.bat` is
the entry point. Linux / macOS: `python argus_pyqt.py`.

---

## Build + CI

The bundle is built with PyInstaller in **one-folder** mode (one-file
breaks `QtWebEngineProcess.exe` — see `docs/BUILD.md` for the
explanation). CI on every push runs the test matrix
(Ubuntu + Windows; Python 3.10 / 3.11 / 3.12), `bandit`, and
`pip-audit`. The build workflow uploads `Argus-portable.zip`. Signing
is a deliberate manual step.

## Tests

226 collected pytest tests across 14 modules. The CI matrix runs
them on three Python versions and two OSes per push.

## Thanks

To everyone who reviewed the V2 build and called the cosmetic-modes
issue what it was. V3 exists because we listened.

---

> Distributed under the GNU General Public License v3.0 — see
> `LICENSE`. Report security issues via a private
> [GitHub Security Advisory](https://github.com/sxc3030-eng/netguard-pro-suite/security/advisories/new).
