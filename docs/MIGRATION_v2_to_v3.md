# Migration Guide — Argus V2 -> V3

This guide is for users who already had V2 (the PyQt6 build,
introduced at commit `df2e387`) installed and working, and who are
upgrading to **v3.0.0** released 2026-04-29.

If you're installing fresh, skip this and read the top-level
[`README.md`](../README.md) instead.

---

## At a glance

| Step | Time | Why |
|---|---|---|
| 1. Back up `argus_data/` | 30 s | Insurance |
| 2. `git pull origin main` | 10 s | Get the V3 code |
| 3. `pip install -r requirements.txt -r requirements-dev.txt` | 1–3 min | New deps (`pyotp`, `bcrypt`, etc.) |
| 4. Migrate secrets to vault | 1 min | One-shot CLI |
| 5. First launch + onboarding wizard | 2 min | Theme, vault, 2FA, keys |
| 6. (Optional) set up TOTP for `Coffre` | 1 min | Required only if you want 2FA |
| 7. Smoke test | 5 min | Verify the upgrade |

---

## 1. Back up `argus_data/`

V3's vault, profile sandboxes, and AI history all live under
`argus_data/`. The migrator is non-destructive but it's good practice:

```bash
# Windows (PowerShell)
Copy-Item -Recurse argus_data argus_data.bak.v2

# Linux / macOS
cp -r argus_data argus_data.bak.v2
```

## 2. Pull V3

```bash
git fetch origin
git checkout main
git pull origin main
```

You should now see `argus_vault.py`, `argus_arbiter.py`,
`argus_mythos_bus.py`, etc. in the repo root — those are V3 modules.

## 3. Install / refresh dependencies

V3 adds `pyotp`, `bcrypt`, and some test-only packages:

```bash
pip install -r requirements.txt -r requirements-dev.txt
```

Verify the install ran cleanly:

```bash
python -c "import argus_vault, argus_arbiter, argus_mythos_bus; print('ok')"
```

## 4. Migrate scattered secrets into the vault

If your V2 install has API keys in `.env`, `netguard_ai_settings.json`,
or any other config file, run the migrator. It's idempotent and
non-destructive.

```bash
# Preview first — touches nothing on disk:
python tools/migrate_to_vault.py --dry-run

# When you're happy with the plan:
python tools/migrate_to_vault.py --yes
```

Flags:
- `--dry-run` — show what would happen, don't write.
- `--yes` — auto-confirm every prompt.
- `--backup-only` — just back up the originals without migrating in.

After the run, your keys live in `argus_data/.vault/secrets.enc`.
The original files are renamed `*.bak.v2` rather than deleted, so you
can roll back if something is wrong.

## 5. First launch — onboarding wizard

```bash
python argus_pyqt.py
# or on Windows:
LANCER_ARGUS_2.bat
```

The first-run wizard (`argus_onboarding.py`) walks through:

1. **Theme** — pick from 12 (default `Cyber Dark`).
2. **Vault** — accept DPAPI on Windows, or set a passphrase.
3. **2FA** — optional; only required if you plan to use `Coffre`
   mode.
4. **API keys** — paste any keys the migrator didn't pick up.

If you've already run the migrator, the keys step will show your
existing values pre-filled.

## 6. (Optional) Set up TOTP for `Coffre`

If you want 2FA on `Coffre` mode entry:

1. Open Argus.
2. **Settings -> Vault -> Set up TOTP**.
3. Scan the QR with your authenticator app (Aegis, Google
   Authenticator, 1Password, etc.).
4. Save the recovery codes shown — they're stored as bcrypt hashes,
   so you can't recover them later.

You can skip this step entirely and `Coffre` will still work; the
TOTP gate is opt-in.

## 7. (Optional) Enter / update API keys

**Settings -> API Keys** has `Show / Save / Migrate from .env`
buttons. Use this if you got a new key after the migrator ran.

## 8. Smoke test

A quick checklist to confirm V3 is working:

- [ ] Argus opens without console errors.
- [ ] Mode toggle in the dock cycles `Normal -> Privé -> Coffre` and
      reloads the active tab into the new profile.
- [ ] Visiting a banking domain (e.g. your bank's URL) shows the
      auto-vault banner.
- [ ] **Settings -> Vault** lists at least one key.
- [ ] AI side panel (`Ctrl+J`) opens, accepts a question, returns
      an answer.
- [ ] `python -m examples.mythos_sample.main` connects to the bus
      and gateway.
- [ ] `pytest tests/ -q` reports the suite green (~226 tests).

If any of these fail, see the troubleshooting section in
`docs/BUILD.md`. If the failure looks like a bug, open an issue
against the repo with the smoke-test step that broke.

---

## Breaking changes

These are the only behaviours that may surprise a V2 user.

### `argus.py` is gone

The V1 `pywebview` wrapper (`argus.py`) was removed. The entry point
is now **`argus_pyqt.py`** unconditionally. The launcher
`LANCER_ARGUS.bat` was replaced by `LANCER_ARGUS_2.bat`.

If you have desktop shortcuts pointing at `argus.py` /
`LANCER_ARGUS.bat`, recreate them with the new targets.

### Modes now require a profile rebuild

V2 modes were cosmetic. V3 modes are real per-mode persistent
profiles. The first time you switch modes after upgrading, the new
profile is built from scratch — you may need to re-log into a site
in `Privé` / `Coffre` even if you were logged in there in V2.

This is by design. The whole point of the upgrade is that the modes
no longer share state.

### Settings file format changed

V2's `argus_settings.json` schema is a strict subset of V3's. On
first launch V3 reads the old file, fills in the missing V3 keys
with defaults, and writes back the V3-formatted file. The old file
is preserved as `argus_settings.json.bak.v2` for one launch in case
you want to roll back.

### `.env` is no longer the recommended secret source

V3 reads secrets in this priority order:

1. **Argus Vault** (encrypted, brokered).
2. `.env` at repo root (if vault read returns empty).
3. OS environment variables (final fallback).

V2 users with a populated `.env` will keep working unchanged —
the vault is preferred but `.env` is still honoured. Once you've
run the migrator, you can delete `.env` (or leave it; it's
gitignored either way).

### `argus_data/` gitignore is stricter

V3 ignores everything under `argus_data/` by default and
re-includes only `argus_data/sandbox/trackers_blocklist.txt`. If
you had committed anything else under `argus_data/` (you shouldn't
have), `git status` will now show it as untracked — that's
correct.

---

## Rolling back to V2

If V3 doesn't work for you and you need to roll back temporarily:

```bash
git checkout v2.0.0  # or whatever V2 tag you came from
mv argus_data argus_data.v3
mv argus_data.bak.v2 argus_data
python argus_pyqt.py
```

Please open an issue describing what went wrong before rolling
back permanently — V3 is a meaningful security upgrade and we'd
rather fix the breaker than lose a user.

---

## Getting help

- **Bugs / breakage** — open a GitHub issue with the smoke-test
  step that failed and the relevant log lines.
- **Security findings** — use a private
  [GitHub Security Advisory](https://github.com/sxc3030-eng/netguard-pro-suite/security/advisories/new).
- **Feature requests** — open a discussion, not an issue.
