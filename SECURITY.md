# Security Policy

This document covers responsible disclosure for the NetGuard AI Suite
(NetGuard, Argus, Sentinel, CleanGuard, MailShield, VPNGuard, FIM,
Honeypot, Strikeback, Recorder) and our threat model in plain English.

We hold ourselves to one rule: **honesty about what is implemented**.
This file states explicitly what the suite does *not* protect against
yet, so users can make informed decisions.

---

## Reporting a vulnerability

- **Preferred channel:** open a private
  [GitHub Security Advisory](https://github.com/sxc3030-eng/netguard-pro-suite/security/advisories/new)
  on this repository.
- **Email fallback:** if Security Advisories are unavailable, contact
  the maintainer through the email listed on the
  [GitHub profile](https://github.com/sxc3030-eng) (commit author of
  the most recent release tag).
- **Response SLA:** we acknowledge new reports within **7 calendar
  days**. A patch ETA follows within 14 days for High / Critical
  issues.
- **Bounty:** there is **no monetary bounty** in V1. Reporters are
  credited by name (or pseudonym, your choice) in `CHANGELOG.md` and
  in the published advisory.
- **Coordinated disclosure:** please give us 30 days from
  acknowledgement before public disclosure unless the vulnerability is
  already being exploited in the wild.

---

## Threat model — what we DO protect against

The current code-base implements the following defences. Each one has
real code behind it and is exercised by the test suite.

- **Backend hardening (NetGuard core)**
  - Per-IP and per-route rate limiting on the WebSocket dashboard.
  - Atomic file writes (write-temp-then-rename) for `netguard_*.json`
    state files to prevent corruption on power loss.
  - Salted password hashes (bcrypt-equivalent KDF) for the dashboard
    login, never plaintext.
  - Cryptographically random session tokens with HttpOnly + Secure
    flags when served over TLS.

- **Encrypted secret storage (`argus_vault.py`)**
  - AES-256-GCM with a fresh nonce per secret.
  - Master key wrapped with Windows DPAPI on Windows; PBKDF2-HMAC-SHA256
    at 600 000 iterations elsewhere.
  - Vault file (`argus_data/.vault/secrets.enc`) is in `.gitignore`.

- **Network monitoring with auto-block**
  - Configurable thresholds for port scan, brute-force, SYN flood,
    DNS tunneling.
  - Per-IP whitelist (`netguard_settings.json`).
  - OS-level blocking via `netsh` (Windows) and `iptables` (Linux);
    rules survive process restarts.

- **File integrity monitoring (FIM module)**
  - HMAC-SHA256 chain over snapshot manifests so an attacker who
    compromises the FIM history cannot silently rewrite past entries.
  - Salt rotated per snapshot.

- **Defensive coding posture**
  - User-supplied paths are normalised and bounded inside
    `argus_data/` before any disk write.
  - Subprocess calls use argument lists (no `shell=True`) so user
    input cannot inject arbitrary commands.

---

## Threat model — what we DO NOT protect against (yet)

We are deliberately explicit about gaps so nobody trusts a feature
beyond what it actually does.

- **Mode Privé / Mode Coffre are cosmetic in V1.**
  In Argus V1 the mode badge changes only the window border colour. It
  does **not** enforce strict TLS, does **not** block third-party
  scripts, does **not** isolate sessions per mode, and does **not**
  wipe memory on close. Real isolation lands in V3 — tracked as an
  open roadmap item. **Do not log into a high-stakes banking
  session in V1 expecting Coffre mode to harden the connection beyond
  what your default Chromium policies already do.**

- **No download sandboxing.** Files downloaded through the embedded
  Chromium land directly in the user's `Downloads/` folder with no
  pre-execution scanning or quarantine.

- **No certificate pinning.** Argus accepts any TLS certificate that
  the system trust store accepts. A malicious root CA installed on the
  host (e.g. by enterprise MITM) is not detected.

- **No anti-skimmer or anti-keylogger.** Argus does not detect
  card-skimming JavaScript, fake form overlays, or kernel-level
  keyloggers running on the host.

- **No protection against a compromised host.** If the OS is already
  rooted, the suite cannot defend against it. Argus Vault relies on
  DPAPI / a user-supplied passphrase; an attacker with the user's
  active session can decrypt vault contents the same way the user can.

- **No anti-debugging / anti-tampering on the suite itself.** The
  Python source is shipped readable; `argus_pyqt.exe` (when
  PyInstaller-bundled) is not yet packed or obfuscated.

- **AI providers are external trust boundaries.** When the user
  configures an Anthropic / OpenAI / Gemini key, prompts and pasted
  content are sent to those providers. We do not redact PII or
  secrets before sending. Treat the AI side panel like any third-party
  cloud service.

---

## Trust boundaries

Local-only (data never leaves your machine):
- Network capture and analysis (`netguard.py`).
- Vault contents (`argus_data/.vault/`).
- Browser sessions, cookies, localStorage (`argus_data/profiles/`).
- File integrity snapshots (`fim/`).

External calls (data leaves the machine when used):
- AI side panel — sends prompt + selected context to the configured
  provider (Anthropic / OpenAI / Gemini).
- GeoIP lookups — uses a local MaxMind DB by default; falls back to
  the configured online resolver only if explicitly opted in.
- Threat-intel feeds — only contacted when the user enables an
  IP / domain reputation source in settings.

---

## Cryptography choices

| Use case | Algorithm | Parameters | Rationale |
|---|---|---|---|
| Secret storage at rest | AES-256-GCM | 96-bit nonce, fresh per secret | Authenticated; rules out malleability |
| Master-key wrapping (non-Windows) | PBKDF2-HMAC-SHA256 | 600 000 iterations, 16-byte salt | OWASP 2024 recommendation |
| Master-key wrapping (Windows) | DPAPI (`CryptProtectData`) | `CRYPTPROTECT_UI_FORBIDDEN` | Bound to user account; resists offline attacks |
| FIM chain | HMAC-SHA256 | 32-byte rotating salt | Cheap, well-vetted, no asymmetric key needed |
| Session tokens | `secrets.token_urlsafe(32)` | 256-bit entropy | Pure CSPRNG, no rolling |
| TLS | System default (Chromium) | TLS 1.2+ | Delegated to Chromium for the browser scope |

All algorithm choices are conservative defaults, not vendor lock-in.

---

## Dependency hygiene

- `pip-audit` is run in CI on each push and surfaces known CVEs in
  third-party packages.
- `bandit` is run in CI for static analysis on the Python source
  (medium-severity threshold).
- A failing pip-audit / bandit result blocks merge to `main` for
  High / Critical severity.
- We pin direct dependencies in `requirements.txt`. Indirect pins
  live in lockfiles where applicable.

---

## Out of scope

- Cryptographic protocols designed by us — there are none. Every
  primitive comes from a vetted library (`cryptography`,
  `pycryptodome`, OS DPAPI).
- Patching upstream vulnerabilities in PyQt6, Chromium, Scapy,
  etc. — we update version pins when patches ship; we do not fork
  upstream.
- Physical-attack scenarios (cold boot, evil maid).

---

> Copyright © 2026 NetGuard AI Suite contributors
> This file is part of the suite and is licensed under the
> GNU General Public License v3.0. See `LICENSE` for the full text.
