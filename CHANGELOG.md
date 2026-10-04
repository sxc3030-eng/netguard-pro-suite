# Changelog

All notable changes to Argus / NetGuard Pro Suite will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 2026-10-04 — Moteur de capture ETW : plus besoin de Npcap (branche `moteur-etw`)

- Nouveau paquet `capture/` : moteur **ETW** (intégré à Windows, aucun pilote, flux + octets + processus + DNS en temps réel), moteur de repli **poll** (sans administrateur), et Npcap en « mode expert » optionnel.
- `process_observation` : pipeline de détection indépendant de scapy ; `analyze_packet` n'est plus qu'un adaptateur.
- Les adresses de la machine ne sont plus traitées comme externes (IPv6 global, IP publique sans NAT).
- La localisation affichée est celle de l'extrémité distante, y compris pour le trafic sortant.
- scapy déplacé dans `requirements-expert.txt` ; pastille du moteur actif dans le tableau de bord ; `docs/MOTEUR_CAPTURE.md`.

### 2026-09-30 — NetGuard AI : audit mémoire + superaudit (branche `netguard-ai`)

**Renommage** : « NetGuard Pro » devient **NetGuard AI** partout (exécutable `NetGuardAI.exe`, tâche planifiée, titres). Les règles de pare-feu gardent le préfixe `NetGuard_*`.

**Mémoire** (`docs/AUDIT_MEMOIRE_2026-09-30.md`) : éviction périodique de toutes les tables indexées par IP, un seul worker de géolocalisation (plus de thread par paquet), verrou sur l'accumulateur d'anomalies, compteur pcap, rotation réelle des captures et des journaux IA, purge de la carte.

**Sécurité** (`docs/SUPERAUDIT_2026-09-30.md`) : garde liste blanche + limite de débit sur les blocages automatiques, table de flux anti-usurpation, assainissement de toutes les chaînes réseau (XSS stocké), confinement des chemins (backups, rapports, forensique), liste blanche `update_param`, serveur IA authentifié par jeton avec liste blanche de fichiers et signature d'approbation des outils, échappement HTML dans tous les tableaux de bord, SRI sur les CDN.

**Store** : dossier de données inscriptible (`%LOCALAPPDATA%\NetGuard AI`), détection admin/Npcap exposée dans l'interface, arrêt propre, `--remove-firewall-rules` à la désinstallation, `--demo` accepté, tueur Npcap en opt-in, `geo_online_enabled`, politique de confidentialité (`PRIVACY_POLICY_NETGUARD_AI.md`) et licences tierces (`THIRD_PARTY_LICENSES.md`).

**Dépôt** : fichiers sensibles (`netguard_users.json`, `netguard_license.json`, `netguard_settings.json`) et copies obsolètes (`captures/`, `reports/`, `backups/`, `netguard_v160.py`) retirés du suivi ; `netguard_settings.json.example` fourni.

**Deuxième passe** : build Store détecté (licence gérée par le Store, pas d'essai ni de sièges, géolocalisation en ligne désactivée par défaut, pas de mise à jour GitHub), manifeste et script MSIX (`packaging/`), dialogues Npcap/WebView2 au premier lancement, Mapper complet avec pare-feu par appareil et validation des entrées, CSP sur toutes les pages, garde ReDoS sur les règles IDS, ACL propriétaire sur les fichiers secrets, planificateur de sauvegardes, travaux UI un à la fois, réglages corrompus mis en quarantaine.

## [3.0.0] — 2026-04-29

The first release where the Argus modes (`Normal` / `Privé` / `Coffre`) are
real instead of cosmetic, the secret store is fully encrypted and brokered
across processes, and the suite ships the protocol Mythos plugs into.

### Added

#### Argus Vault — encrypted secret storage
- `argus_vault.py` — in-process AES-256-GCM secret store. Master key
  wrapped with Windows DPAPI on Windows; PBKDF2-HMAC-SHA256 (600 000
  iterations, OWASP 2024) elsewhere. Vault file lives in
  `argus_data/.vault/secrets.enc` (gitignored).
- `argus_vault_gateway.py` — V2 cross-process broker. Localhost-only
  HTTPS service on `https://127.0.0.1:8769`. Authenticates callers by
  **live SHA-256 of the requesting binary** (defends against process
  spoofing), HMAC-signs every response, and rate-limits with a token
  bucket (`--rate-per-min`, `--burst`). Self-signed cert generated on
  first start and SPKI-pinned in the vault.
- `argus_vault_client.py` — thin client used by other suite programs.
- `tools/register_program.py` — registers a binary with the gateway:
  hash + label + permitted secrets + permissions (`read` / `write`).
- `tools/migrate_to_vault.py` — CLI migrator for users who had keys in
  scattered `.env` / `*.json` files. Flags: `--dry-run`, `--yes`,
  `--backup-only`.

#### The 3 Argus pillars
- **Sandbox** (`argus_sandbox.py`) — real `Privé` and `Coffre` modes:
  per-mode persistent profile path, cookie / localStorage isolation,
  third-party cookies blocked in `Privé`, anti-skimmer JS injection in
  `Coffre`. Replaces the cosmetic V2 badge.
- **Surveillance** (`argus_surveillance.py`) — forensic ring buffer.
  Each event AES-GCM-encrypted, chained with HMAC-SHA256 so an attacker
  who compromises the log cannot silently rewrite history. Salt rotates
  per snapshot.
- **Arbitrage Claude** (`argus_arbiter.py`) — heuristic-first scoring
  with optional Claude API fallback (BYOK). Four configurable
  thresholds (`block` / `warn` / `verify-with-AI` / `allow`). Logs
  every decision into the surveillance HMAC chain.

#### Auto-Vault, 2FA, onboarding
- `argus_vault_domains.py` — 52-domain allowlist of banks and payment
  providers. When the user navigates there, a banner offers to switch
  to `Coffre` mode automatically.
- `argus_2fa.py` — TOTP gate (RFC 6238 via `pyotp`) for entering
  `Coffre` mode. Recovery codes stored as bcrypt hashes.
- `argus_onboarding.py` — first-run wizard: pick theme, configure
  vault, set up 2FA, drop in API keys.
- `argus_i18n.py` — runtime FR / EN / ES switcher; ~140 strings.

#### Mythos plug interface
- `argus_mythos_bus.py` — read-only WebSocket fan-out for Argus events
  (`ws://127.0.0.1:8767`). Token-gated.
- `argus_mythos_gateway.py` — REST tool gateway for action requests
  from a Mythos instance (`http://127.0.0.1:8768`). Every call is
  audited into the surveillance chain.
- `docs/MYTHOS_PROTOCOL.md` — versioned wire contract, handshake,
  event schemas, error codes.
- `examples/mythos_sample/` — reference client that exercises both
  halves of the interface end to end.

#### UI, themes, polish
- `argus_pyqt.py` rewritten and expanded: 1176 lines (V2) -> 3567
  lines (V3) — Settings dialog with `API Keys` and `Vault` tabs, mode
  toggle moved into the dock, AI side panel (`Ctrl+J`) with persistent
  conversation history (last 50 messages, `argus_data/ai_history.json`,
  gitignored), download sandbox under
  `argus_data/downloads_sandbox/` (never the user's `Downloads/`),
  print (`Ctrl+P`), splash screen, About dialog.
- 12 themes: `Cyber Dark`, `Pro Dark`, `Light Pro`, `Hacker Green`,
  `Bank Vault`, `Pastel`, `Tokyo Night`, `Catppuccin Mocha`, `Dracula`,
  `Solarized Dark`, `Gruvbox Dark`, `Nord`.
- Hieratic Cipher iconography: `branding/argus/` ships v1 (sigil + 12
  satellite eyes + dodecagon) and v2 (shield-silhouette refresh).

#### Infrastructure
- `requirements.txt` + `requirements-dev.txt` — direct deps pinned
  with `>=` floors.
- `.github/workflows/test.yml` — pytest matrix (Ubuntu + Windows;
  Python 3.10 / 3.11 / 3.12).
- `.github/workflows/security.yml` — `bandit` + `pip-audit` on every
  push and PR.
- `.github/workflows/build.yml` — PyInstaller one-folder bundle on
  push to `main` / tag `v*`, uploads `Argus-portable.zip` artifact.
- `build/Argus.spec` — PyInstaller spec (one-folder, QtWebEngine
  helper collected, excludes for unused Qt modules).
- `tools/build_argus.bat` / `.sh` — build wrappers that wipe scratch
  dirs, run the spec, copy `README.md`/`LICENSE`/`SECURITY.md` into
  the dist, then zip / tar.
- 226 pytest tests across 14 modules — `test_argus_2fa`,
  `test_argus_arbiter`, `test_argus_i18n`, `test_argus_mythos_bus`,
  `test_argus_mythos_gateway`, `test_argus_sandbox`,
  `test_argus_surveillance`, `test_argus_vault`,
  `test_argus_vault_client`, `test_argus_vault_domains`,
  `test_argus_vault_gateway`, `test_migrate_to_vault`,
  `test_mythos_sample`, `test_netguard`.

#### Public-repo docs
- `SECURITY.md` — threat model with explicit "what we DO" and
  "what we DO NOT protect against yet" sections + crypto choices
  table.
- `CONTRIBUTING.md` — branch naming, DCO sign-off, pre-PR checklist.
- `docs/AUTHENTICODE.md` — code-signing options (Trusted Signing,
  OV cert, EV cert), MSIX repackaging for Microsoft Store
  resubmission after the 2026-04-03 policy 10.2.9 rejection.
- `docs/MYTHOS_PROTOCOL.md` — Argus <-> Mythos plug interface
  specification.
- `docs/VAULT_GATEWAY.md` — vault gateway architecture, registration
  flow, client API.
- `docs/BUILD.md` — PyInstaller build guide (one-folder rationale,
  troubleshooting, CI behaviour).

#### NetGuard core (Wave 1)
- Per-packet app identification + per-IP bandwidth tracking.
- Process column in the live packets table; "Top Bandwidth" panel.
- `NetGuard Mode Fantôme` — silent background tray protection
  (`LANCER_NETGUARD_GHOST.bat`).
- `MaxMind GeoLite2` as primary GeoIP provider with `ipapi.co` /
  `ip-api.com` fallback chain and `tools/geoip_update.py` updater
  (HTTP Basic Auth).
- 3-axis map noise filters (threshold / trusted / time window),
  multi-hop traceroute on the world map, per-IP ring buffer that
  guarantees equal airtime so chatty IPs no longer starve quiet ones,
  "Tout voir" reset link, overlay panels anchored inside the map area.

### Changed
- `argus_pyqt.py`: V2 1176 lines -> V3 3567 lines (all new wiring).
- `netguard.py` logging: `FileHandler` -> `RotatingFileHandler`
  (5 MB x 3) so long-running sessions do not fill the disk.
- `argus_data/` gitignore restructured: ignore everything by default,
  re-include only `argus_data/sandbox/trackers_blocklist.txt`.
- `README.md` adds an Argus section, Setup (vault / `.env` / env-var
  priority), Trust Model link, CI status badges.
- Repository is now public + GPL v3 (was private during V1 / V2).

### Removed
- `argus.py` (V1 `pywebview` wrapper) — superseded by `argus_pyqt.py`.
- `LANCER_ARGUS.bat` (V1 launcher) — replaced by `LANCER_ARGUS_2.bat`.

### Security
- Vault gateway re-hashes the requesting binary live on every request
  (defends against the "hash-on-register, swap-on-disk" attack).
- Anti-skimmer JS injection runs only inside `Coffre` mode.
- Audit chain HMAC verification is exposed as a CLI flag for both
  the surveillance log and the gateway access log.
- `pip-audit` and `bandit` (medium-severity threshold) run in CI on
  every push and PR. High / Critical findings block merge to `main`.
- Subprocess calls use argument lists (no `shell=True`) throughout.

### Honest gaps (carried into V4)
- The arbiter is **advisory only** in V3 — it scores and warns but
  does not synchronously block a form submit. V4 will ship
  `QWebChannel`-driven sync gating that pauses navigation until the
  verdict returns.
- Vault gateway certificate pins are **TOFU** in V3 — the SPKI hash
  recorded on first contact is trusted thereafter. V4 will ship
  pre-pinned SPKI hashes for known banking domains.
- The bundle is **not Authenticode-signed** — instructions and the
  recommended Trusted Signing flow live in `docs/AUTHENTICODE.md`.
- **No Microsoft Store distribution yet** — MSIX repackaging is
  documented in `docs/AUTHENTICODE.md §6` but not yet executed.
- `examples/mythos_sample/` proves the protocol works end to end;
  the actual Mythos AI agent is future work and out of scope for
  this release.
- `docs/PERFORMANCE.md` and `docs/PRIVACY.md` are scheduled for V3.1
  alongside the first signed release.

## [2.x] — 2026-04-26 to 2026-04-28

Pre-V3 PyQt6 history, summarised. See `git log` for the full set of
commits between `df2e387` and `16013c6`.

- `df2e387` — first real PyQt6 + QtWebEngine browser shell, replacing
  the V1 `pywebview` wrapper.
- `af62a30` — multi-tab, dynamic favorites, persistent sessions,
  inline NetGuard launcher button.
- `2261da9` — mode toggle relocated from the floating top-center into
  the dock row 3 (UI cleanup).
- `df77fb7` — Settings dialog skeleton, top URL strip, page-load
  spinner.
- `038a7f9` — `NetGuard Mode Fantôme` tray launcher.
- `673723d` — `conftest.py` pre-mocks `scapy` to break the UAC loop
  on Windows test runs.

## [1.0] — 2026-04-27

- `e8588da` — initial `pywebview` wrapper. All 11 modules with
  invisible auth via `?ng_token=` URL injection. Deprecated and
  removed in `3.0.0`; kept here for archaeology.
