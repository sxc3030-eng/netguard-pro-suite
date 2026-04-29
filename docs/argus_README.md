# Argus

> **Voit tout, absolument tout — Sees everything, absolutely everything.**

<p align="center">
  <img src="../branding/argus/argus_wordmark.png" alt="Argus wordmark" width="640" />
</p>

<p align="center">
  <em>The privacy-first cybersecurity workbench browser.</em><br/>
  Sandbox-first &middot; surveillance-first &middot; AI-native &middot; GPL v3.
</p>

---

## What is Argus?

Argus is the dedicated browser of the **NetGuard Pro Suite**. It pairs a real
Chromium engine (PyQt6 + QtWebEngine) with a built-in cyber-forensic surface:
every request, every download, every script execution is logged to a tamper-
evident HMAC chain you can audit later. A local AI arbiter (Claude or any
BYOK provider) classifies traffic in flight; a vault keeps your secrets
encrypted at rest; and a Mythos plug-port lets a future autonomous agent read
the cage without ever speaking past it.

The browser is named after **Argus Panoptes**, the hundred-eyed giant of
Greek myth who never slept and watched what others would harm. Each tab is
one of his eyes.

---

## Three pillars

| Pillar | Module | Key features |
|---|---|---|
| **Sandbox** — strong isolation | `argus_sandbox` | Per-tab profile dirs, mode-scoped cookies/storage, opt-in download quarantine (V2), no shared state between Normal / Privé / Coffre |
| **Surveillance** — see what happened | `argus_surveillance` | HMAC-SHA256 audit chain over every event, JSONL log under `argus_data/`, replay-resistant timestamps, chain-verify CLI |
| **Arbitrage** — AI in the loop, BYOK | `argus_arbiter` | Pluggable provider (Anthropic / OpenAI / Gemini / local Ollama), verdicts: `allow` / `warn` / `block`, confidence + reason recorded, decisions auditable |

The three layers are independent — turn off the arbiter and surveillance
still records; pull the surveillance backend and the sandbox still isolates;
disable the sandbox (e.g. for legacy embeds) and you keep audit + arbitrage.

---

## Modes

Argus exposes three operating modes selectable from the top URL strip. **Be
honest with what each one actually does today versus what is on the
roadmap** — see [SECURITY.md](../SECURITY.md) for the full breakdown.

| Mode | What is implemented in V1 | What is roadmap |
|---|---|---|
| **Normal** | Default Chromium policies, full surveillance, AI arbiter live, persistent profile | (already complete) |
| **Privé** | Cosmetic blue-tinted chrome, separate profile dir, *cookies still cleared on close per Chromium incognito*, audit log still recorded under `private/` namespace | V3: stricter TLS, third-party-script blocking, per-mode session memory wipe |
| **Coffre** (Vault) | Cosmetic gold-tinted chrome, **vault-only** domain whitelist enforced (`argus_vault_domains.py`), AI arbiter required-pass, 2FA on tab open | Pro: MFA-on-resume, hardened cipher suite, per-form keystroke fence |

> **Honesty notice.** Mode Privé and Mode Coffre **do not** today guarantee
> stronger isolation than Chromium incognito + a profile-dir swap. The
> badge changes the colour and the surveillance namespace, that is all
> until V3 ships strict mode hardening. Treat them as workflow modes, not
> security boundaries.

---

## Mythos integration

Argus is also the **cage** for an upcoming autonomous agent named Mythos.
Two surfaces are already live and tested:

- **Mythos Bus** (`ws://127.0.0.1:8767`) — read-only event fan-out so the
  agent can subscribe to `surveillance/event`, `arbiter/decision`,
  `mode/switched`, `tab/opened`, `download/intercepted`, etc.
- **Tool Gateway** (`http://127.0.0.1:8768`) — REST endpoints for the
  agent to *request* actions (`block_url`, `set_mode`, `clear_history`,
  …) with mandatory user-approval gates and HMAC-anchored audit
  signatures on every call.

Both surfaces are loopback-only and bearer-token protected (token stored in
the vault, auto-generated on first start). Full wire spec:
[docs/MYTHOS_PROTOCOL.md](MYTHOS_PROTOCOL.md).

---

## Vault — secrets that stay yours

Argus carries an in-process secrets vault (`argus_vault.py`) plus a
network-style cross-process broker (`argus_vault_gateway.py`).

- **V1 in-process.** AES-256-GCM with a fresh nonce per secret. Master key
  wrapped with Windows DPAPI on Windows, PBKDF2-HMAC-SHA256 (600 000
  iterations) elsewhere. Vault file lives in `argus_data/.vault/secrets.enc`
  and is `.gitignore`'d.
- **V2 secure REST gateway.** Localhost-only HTTPS service that brokers
  secrets to *whitelisted programs* with **live binary-hash verification**
  (the gateway re-hashes the calling exe at every request), HMAC-signed
  responses, replay-resistant nonces, token-bucket rate limiting, and an
  HMAC chain over the audit log.

Full reference: [docs/VAULT_GATEWAY.md](VAULT_GATEWAY.md).

---

## Quick start

```bash
git clone https://github.com/sxc3030-eng/netguard-pro-suite.git
cd netguard-pro-suite

# install dependencies
pip install -r requirements.txt

# launch Argus
python argus_pyqt.py
# or on Windows, double-click LANCER_ARGUS_2.bat
```

On first launch the **onboarding wizard** (`argus_onboarding.py`) guides you
through:

1. Picking a default mode (Normal / Privé / Coffre).
2. Optionally configuring AI provider keys (skipped is fine — the AI side
   panel just stays disabled).
3. Optionally enabling the surveillance HMAC chain (recommended; minimal
   overhead).
4. Optionally starting the Mythos bus + gateway (off by default until you
   have an agent to plug in).

---

## API keys — three ways to provide them

Argus reads provider keys (Anthropic, OpenAI, Gemini, threat-intel feeds) in
this priority order:

1. **Argus Vault UI** — open Argus, go to **Settings -> API Keys**. Keys
   are encrypted at rest with AES-256-GCM, master-key-wrapped by DPAPI
   (Windows) or PBKDF2 elsewhere.
2. **`.env` file** at repo root — see [`.env.example`](../.env.example) for
   the full variable list (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
   `GOOGLE_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, …). The
   file is `.gitignore`'d; keys never leave your machine.
3. **OS environment variables** — set `ANTHROPIC_API_KEY=…` in your shell
   profile or system settings.

A missing key degrades the dependent feature gracefully — the AI side panel
disables itself with a tooltip rather than crashing the browser.

---

## Build — desktop app

Source-run is fully supported. To produce a single-file `.exe`:

```bash
# Windows
.\build_windows.bat
```

This wraps PyInstaller with the right entry point, icon set
(`branding/argus/argus_normal.ico` and friends), and a hidden-import list.
The full step-by-step including code-signing is in
[`docs/AUTHENTICODE.md`](AUTHENTICODE.md).

---

## Troubleshooting

**Argus opens to a blank page.**
PyQt6's QtWebEngine occasionally fails to initialise on first run if the
GPU process cannot start. Try `python argus_pyqt.py --disable-gpu` once.
The setting persists.

**`ImportError: PyQt6.QtWebEngineWidgets`.**
The standalone `PyQt6` package does not include WebEngine. Install
`PyQt6-WebEngine` explicitly:

```bash
pip install PyQt6-WebEngine
```

**Vault gateway refuses my program.**
The gateway re-hashes your binary live and rejects unknown SHA-256s. Run
`python tools/register_program.py /path/to/your/binary` once to whitelist
it. The session is invalidated whenever the binary on disk changes — this
is intentional.

**Mythos bus says `401 Unauthorized`.**
The bearer token lives in the vault under `MYTHOS_BUS_TOKEN`. Read it from
**Settings -> Advanced -> Mythos** and configure your client with it.

**Mode Coffre keeps me from opening a domain.**
That is the point: Mode Coffre enforces the whitelist in
`argus_vault_domains.py`. Add your bank's domain there, restart the tab.

---

## What V1 does NOT have yet

We track gaps in [SECURITY.md](../SECURITY.md), but here is the short list
so nobody is surprised:

- **Code Sandbox tab.** Roadmap V2 — a tab that runs a JS REPL inside a
  worker with no network and no DOM, for analysing pasted scripts.
- **Reader mode.** Roadmap V2 — Mozilla-Readability-style reflow.
- **Download sandbox.** Files land in your `Downloads/` folder with no
  pre-execution scan today. Roadmap V3.
- **Certificate pinning.** Argus trusts whatever your OS root store
  trusts. Roadmap V3.
- **MS Store distribution.** Argus is currently distributed via GitHub
  releases only. Microsoft Store / MSIX repackage is on the **NetGuard
  Pro Store** roadmap.
- **Real Mode Privé / Coffre hardening.** See modes table above.
- **Anti-skimmer / anti-keylogger.** Out of scope V1.

---

## Screenshots

> Screenshots TBD. The PyQt6 chrome ships in three skins matching the
> mode: blue (Normal), deep blue (Privé), gold (Coffre). The wordmark
> above is the master logo; per-mode icons live under
> `branding/argus/argus_normal.ico`, `argus_private.ico`, `argus_vault.ico`.

---

## Architecture in one diagram

```
+--------------------------------------------------------------+
|                       Argus (PyQt6)                          |
|                                                              |
|  +-----------+   +------------------+   +-----------------+  |
|  |  Chrome   |-->|  argus_sandbox   |-->|  Per-mode dir   |  |
|  |  (tabs)   |   |  per-mode dir    |   |  cookies/cache  |  |
|  +-----+-----+   +---------+--------+   +-----------------+  |
|        |                   |                                 |
|        v                   v                                 |
|  +-----------+   +------------------+   +-----------------+  |
|  |  Arbiter  |<->|   argus_vault    |<->|   .vault/.enc   |  |
|  |  (Claude) |   |  AES-256-GCM     |   |   DPAPI/PBKDF2  |  |
|  +-----+-----+   +---------+--------+   +-----------------+  |
|        |                   |                                 |
|        v                   |                                 |
|  +------------------+      |                                 |
|  | argus_surveil-   |<-----+                                 |
|  | lance HMAC chain |--------> argus_data/surveillance.jsonl |
|  +------------------+                                        |
|        |                                                     |
|        v                                                     |
|  +------------------+   +------------------+                 |
|  |  Mythos Bus 8767 |   | Mythos GW 8768   | (loopback only) |
|  +--------+---------+   +-------+----------+                 |
+--------------------------------------------------------------+
           ^                      ^
           |                      |
           +----- Mythos (future agent, semi-trusted) ---------+
```

---

## License

GPL v3.0 or later. See [`LICENSE`](../LICENSE) for the full text. All
artwork under `branding/argus/` is also GPL v3 and is hand-composed from
geometric primitives — no AI image generation, no training-data provenance
risk for downstream forks.

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](../CONTRIBUTING.md)
for branch naming, the pre-PR checklist, the DCO sign-off requirement,
and the coding-style notes. The Argus side of the codebase prefers small
PRs (one module + tests) over feature-megablocks.

## Security disclosure

Please report vulnerabilities through a private GitHub Security Advisory
on the [`netguard-pro-suite`](https://github.com/sxc3030-eng/netguard-pro-suite/security/advisories/new)
repository. SLA, scope, and bounty (none yet) are documented in
[`SECURITY.md`](../SECURITY.md).

---

<p align="center"><em>Voit tout, absolument tout.</em></p>
