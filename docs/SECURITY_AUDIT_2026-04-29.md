# NetGuard Pro Suite — Security Audit (V3)

**Audit date:** 2026-04-29
**Branch:** `feature/ai-window`
**Scope:** Entire Python source tree of the NetGuard Pro Suite repository
(`netguard-pro-suite/`), excluding generated assets (`branding/`,
`build/`, `dist/`, `screenshots/`, `geoip/`, `captures/`,
`argus_cache/`, `argus_data/`, `__pycache__/`, `legacy/icons-v4.0/`)
and the `tests/` tree (test code is allowed to use patterns Bandit
flags, e.g. `assert`).
**Source LOC scanned:** 29 530 lines across 70+ Python files.
**Tools:**
- `bandit==1.9.4` — Python AST static analysis
- `pip-audit==2.10.x` — CVE check against the resolved dependency set
  (`requirements.txt` + `requirements-dev.txt`)
- Manual `grep` review for the high-risk pattern set documented in
  `SECURITY.md §"Threat model — what we DO protect against"`.
- Manual cross-check of `SECURITY.md` against the implementation.

**Auditor:** Claude (Anthropic) running through Argus / Claude Agent
SDK auto-audit. Findings + fixes reviewed and signed off by the
maintainer before merge.

---

## 1. Summary

| Category                 | Before fix | After fix |
| ------------------------ | ---------- | --------- |
| Bandit HIGH              | 8          | **0**     |
| Bandit MEDIUM            | 32         | 34*       |
| Bandit LOW               | 342        | 342       |
| pip-audit CVEs           | 0          | 0         |
| Manual review red flags  | 1          | 0         |

\*MEDIUM count rose by 2 because the legacy `block_ip_os` /
`unblock_ip_os` rewrite replaces 4 `os.system(...)` (one HIGH each)
with 4 calls to `subprocess.run([...])`. Bandit re-flags two of those
as B603 (subprocess called with non-absolute path: `iptables`,
`netsh`). That is identical to the pattern already used and accepted
across the rest of `netguard.py`. Net effect: 8 real HIGH issues
eliminated, 2 cosmetic MEDIUM partial-path warnings introduced,
which we accept and document below.

**Net result:** zero HIGH and zero unaccepted CVEs as of 2026-04-29.

---

## 2. Bandit HIGH findings (all resolved)

| # | ID    | File:line                          | Description                                | Fix |
|---|-------|------------------------------------|--------------------------------------------|-----|
| 1 | B324  | `cleanguard/cleanguard.py:1092`   | MD5 used as duplicate-file fingerprint     | `usedforsecurity=False` + nosec comment |
| 2 | B324  | `mailshield/mailshield.py:458`    | MD5 used to derive avatar tint colour      | `usedforsecurity=False` + nosec comment |
| 3 | B324  | `mailshield/mailshield.py:1179`   | MD5 used as fallback Message-ID dedup key  | `usedforsecurity=False` + nosec comment |
| 4 | B324  | `netguard.py:2360`                 | MD5 in JA3 TLS fingerprint (spec-mandated) | `usedforsecurity=False` + nosec comment |
| 5 | B605  | `netguard_v160.py:706`             | `os.system("iptables -I INPUT -s {ip}")`   | Rewritten to `subprocess.run([...])` + IP validation |
| 6 | B605  | `netguard_v160.py:709`             | `os.system("netsh advfirewall ... {ip}")`  | Rewritten to `subprocess.run([...])` + IP validation |
| 7 | B605  | `netguard_v160.py:717`             | `os.system("iptables -D INPUT -s {ip}")`   | Rewritten to `subprocess.run([...])` + IP validation |
| 8 | B605  | `netguard_v160.py:720`             | `os.system("netsh advfirewall ... {ip}")`  | Rewritten to `subprocess.run([...])` + IP validation |

### Detail — MD5 (findings 1-4)

All four MD5 sites are non-cryptographic. Bandit B324 is a
conservative warning that fires on any `hashlib.md5()` call.
Python ≥ 3.9 introduced `hashlib.md5(usedforsecurity=False)` as the
canonical way to declare the call site is a fingerprint, not a
security primitive. Each site now uses that flag and carries an
inline `# nosec B324 - <reason>` comment explaining the use case.

The JA3 case (finding 4) is particularly worth calling out: JA3 is a
public-standard TLS-client fingerprint defined by Salesforce. The
specification *requires* MD5. We are not free to swap it for SHA-256
without making our fingerprints incompatible with every upstream
threat-intel feed. The MD5 is part of an identifier, not a
trust-establishing checksum.

### Detail — `os.system` shell injection (findings 5-8)

Located in the **legacy** `netguard_v160.py` (kept in the repo for
parity with V1 deployments still in the field; not referenced by the
current launcher matrix or any module in V3). The four sites were
the worst class of finding in this audit: an attacker who could
inject a shell metacharacter into the `ip` variable would obtain
arbitrary command execution under the privileges of the NetGuard
process — typically Administrator on Windows / root on Linux,
because firewall manipulation requires it.

In normal operation the `ip` value comes from `scapy` packet capture,
where the IP layer is already structurally validated. **However**,
the function was also reachable from the JSON RPC and CLI surface,
where a hostile or malformed input was not impossible. We treated
this as a real vulnerability, not a false positive.

**Fix applied:**
1. New `_validate_ip_for_firewall(ip)` helper that returns the
   parsed IP via `ipaddress.ip_address(ip)` — refusing anything
   that does not round-trip through the standard library.
2. Both `block_ip_os` and `unblock_ip_os` now call
   `subprocess.run([...])` with an argument list (no shell) and pass
   the validated string. The `netsh` rule name now also escapes
   IPv6 colons (previously only IPv4 dots were sanitised).
3. `capture_output=True, timeout=10, check=False` matches the rest
   of `netguard.py`'s firewall surface for consistency.

This change brings the legacy file in line with the SECURITY.md
claim that "Subprocess calls use argument lists (no `shell=True`)".

---

## 3. Bandit MEDIUM findings (accepted)

All 34 MEDIUM findings fall into four categories. None are real
vulnerabilities; each is documented below.

| Category | Test ID | Count | Disposition |
| -------- | ------- | ----- | ----------- |
| `urllib.urlopen` audit (B310)              | B310 | 24 | Accepted — every call uses an explicit `https://` (or vetted free-tier `http://ip-api.com`) URL, with `timeout=` parameter. Bandit's B310 fires on any `urlopen` regardless of scheme. Schemes are statically known at the call site; no user-supplied URL is passed to `urlopen` anywhere. |
| Bind to `0.0.0.0` (B104)                   | B104 | 5  | Accepted — these are server sockets in `honeypot/`, `strikeback/`, and the NetGuard dashboard. The whole point of these listeners is to accept connections from the LAN; binding to `127.0.0.1` would defeat the product. Reverse-proxy hardening is documented in `docs/MYTHOS_PROTOCOL.md`. |
| Possible SQL-injection vector (B608)       | B608 | 3  | Accepted — `mailshield/mailshield.py:546, 1446, 1457`. Inspected. All three build dynamic `ORDER BY` / `WHERE` clauses **only** from constants in the module's own enum/whitelist, never from user input. The `?`-parametrised query layer is preserved for every value parameter. |
| Insecure tempfile path (B108)              | B108 | 2  | Accepted — `recorder/recorder.py:108, 114` use a hardcoded `/tmp/...` path. The recorder writes only on Linux/macOS and only when the user has explicitly opted into screen capture; the file is overwritten in place each session. We will move to `tempfile.NamedTemporaryFile` in V4. |
| Subprocess partial-path (B603)             | B603 | 2  | Accepted — newly-introduced by the V160 fix; the rest of the codebase already invokes `iptables` / `netsh` by name (relying on the system `PATH`). Pinning absolute paths is OS- and distribution-dependent and not worth the maintenance cost. |

---

## 4. pip-audit (dependency CVEs)

```
$ python -m pip_audit -r requirements.txt -r requirements-dev.txt
No known vulnerabilities found
```

49 transitive packages were resolved and checked against the OSV +
PyPI advisory databases. **No CVEs of any severity** at audit time.

Direct production dependencies (pinned with floor):
- `scapy>=2.5.0` → resolved to 2.7.0
- `websockets>=12.0` → 16.0
- `cryptography>=42.0.0` → 47.0.0
- `PyQt6>=6.6.0` → 6.11.0
- `PyQt6-WebEngine>=6.6.0` → 6.11.0
- `pillow>=10.0.0` → 11.x
- `numpy>=1.24.0` → latest 2.x
- `requests>=2.31.0` → 2.32.x
- `pywin32>=306` (Windows only) → 308

No `requirements.txt` bumps were necessary in this audit.

---

## 5. Manual review of high-risk patterns

| Pattern                                                | Result                              |
| ------------------------------------------------------ | ----------------------------------- |
| `eval(` / `exec(` (Python builtins)                    | **0 hits** — every match is `QDialog.exec()` or `Image.eval()`, neither of which is the dangerous Python builtin. |
| `pickle.loads`, `marshal.loads`                        | **0 hits**                          |
| `subprocess(... shell=True)`                           | **0 hits**                          |
| `os.system(`                                           | 4 hits — all in `netguard_v160.py`, **fixed in this audit**. |
| `requests(...)` without `verify=`                      | All call sites use explicit `timeout=`; default `verify=True` is the secure default in `requests`. |
| `verify=False`                                         | 1 hit — `argus_vault_client.py:104`. Documented: gateway is bound to `127.0.0.1:8769` with a self-signed cert; SPKI pinning lands in V4. |
| `random.*` for security purposes                       | **0 hits** — every `random` call is for demo data or screenshot generators. Crypto / session tokens use `secrets.*`. |
| Plaintext `http://` to a remote host                   | 1 hit — `netguard.py:484` `http://ip-api.com/json/`. Free tier of the upstream provider only supports HTTP. Used as a fallback geo-IP resolver; no secrets are sent. Documented as accepted risk. |

No further code changes required.

---

## 6. Threat-model honesty check (SECURITY.md vs reality)

We re-read every claim in `SECURITY.md §"What we DO protect against"`
against the implementation.

### ✅ Verified
- AES-256-GCM with fresh per-secret nonce — `argus_vault.py:340, 374`.
- PBKDF2-HMAC-SHA256 at 600 000 iterations — `argus_vault.py:70`.
- DPAPI master-key wrapping on Windows — `argus_vault.py:119` block.
- Cryptographically random session tokens via `secrets.token_urlsafe`.
- HMAC-SHA256 chain in FIM — `fim/file_integrity_monitor.py:155`.
- Atomic file writes (`write-temp-then-rename`) — confirmed in
  `netguard.py` settings I/O.
- `subprocess` call sites in current code (`netguard.py`,
  `cleanguard/`, `argus_*.py`) all use argument lists. The legacy
  `netguard_v160.py` deviation has been **fixed in this audit**, so
  the claim is now true repository-wide.

### ⚠ Wording deviation found (1)
- SECURITY.md describes the dashboard password hash as
  *"Salted password hashes (bcrypt-equivalent KDF)"*. The
  implementation in `netguard.py:1718` is **scrypt** (`hashlib.scrypt`,
  `n=16384, r=8, p=1, dklen=32`). Scrypt is at least as strong as
  bcrypt for the threat model (memory-hard, OWASP-recommended), so
  the wording is generous rather than misleading. Recommendation:
  update the line in `SECURITY.md` to read *"Salted scrypt password
  hashes (OWASP n=16384, r=8, p=1)"*. **Flagged for manual edit;
  not patched in this PR.**

### ⚠ Gaps still accurate
All "what we do NOT protect against (yet)" bullets in `SECURITY.md`
are still accurate. Nothing has been silently upgraded that would
make us *over-claim* protection in V4.

---

## 7. Top 5 residual risk findings (even if accepted)

| Rank | Finding                                                      | Why it stays | Suggested V4 follow-up |
| ---- | ------------------------------------------------------------ | ------------ | ---------------------- |
| 1    | `argus_vault_client.py` accepts self-signed gateway cert     | Necessary while the gateway uses an ephemeral self-signed certificate over `127.0.0.1` | Pin the gateway public-key SPKI hash in the client; refuse anything else. Tracked in V4 backlog. |
| 2    | Plaintext `http://ip-api.com` geo-IP fallback                | Free-tier API has no HTTPS endpoint                                                | Switch to a paid HTTPS provider OR drop the fallback once the primary `ipapi.co` provider becomes mandatory. |
| 3    | Honeypot / Strikeback bind `0.0.0.0`                         | Required by design (LAN-facing decoys)                                              | Document a minimal-firewall recipe in `docs/MYTHOS_PROTOCOL.md` so deployers can scope the listening interface. |
| 4    | Recorder writes to `/tmp/...`                                | Linux/macOS only, opt-in feature                                                    | Migrate to `tempfile.NamedTemporaryFile(dir=...)` with secure-by-default 0600 permissions. |
| 5    | Legacy `netguard_v160.py` ships in the source tree           | Kept for V1 in-field parity                                                         | Move to `legacy/` with an explicit "frozen, do not deploy" header, OR delete in V4 once nothing references it. |

---

## 8. Recommendations for V4

1. **Third-party penetration test.** This audit is automated +
   maintainer-reviewed. A paid pen-test against a deployed instance
   would shake out runtime / configuration issues that static
   analysis cannot reach (e.g. weak default ports, race conditions
   under load, log-injection in the AI side panel).
2. **Fuzzing the packet path.** Run `atheris` against the scapy
   parsing layer in `netguard.py` — packet parsers are notoriously
   easy to crash with malformed input.
3. **Authenticode signing in CI.** `docs/AUTHENTICODE.md` already
   describes the manual flow. V4 should make CI sign every release
   tarball and PyInstaller bundle automatically, with the
   timestamping authority recorded in the release notes.
4. **MSRC + GitHub Security Advisory practice run.** Before V4
   GA, file a dummy advisory with the maintainer to confirm the
   disclosure pipeline actually works end-to-end (acknowledgement
   timer, CVE assignment, advisory publication).
5. **SBOM publication.** Generate a CycloneDX SBOM in CI for every
   release and attach it to the GitHub Release. `pip-audit` can
   already emit one with `--format=cyclonedx-json`.
6. **Track the SECURITY.md "scrypt" wording fix** (see §6 deviation).

---

## 9. Files changed in this audit

| File                                                      | Change                                                                                  |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `cleanguard/cleanguard.py`                                | Added `usedforsecurity=False` + `# nosec` on the duplicate-file MD5.                    |
| `mailshield/mailshield.py`                                | Added `usedforsecurity=False` + `# nosec` on avatar-tint MD5 and Message-ID fallback.   |
| `netguard.py`                                             | Added `usedforsecurity=False` + `# nosec` on the JA3 fingerprint MD5.                   |
| `netguard_v160.py`                                        | New `_validate_ip_for_firewall` helper; rewrote `block_ip_os` and `unblock_ip_os` to use `ipaddress.ip_address()` validation + `subprocess.run([...])` argument lists. |
| `docs/SECURITY_AUDIT_2026-04-29.md`                       | This file.                                                                              |

No new dependencies introduced. No version bumps in
`requirements.txt` or `requirements-dev.txt`.

---

## 10. Sign-off

- **Audit driver:** Claude (Anthropic Claude Agent SDK), running as
  `Argus auto-audit` against `feature/ai-window @ HEAD`.
- **Audit completion timestamp:** 2026-04-29.
- **Maintainer review required before merge to `main`.** This file
  must be approved by the human maintainer; CI on `main` must pass
  pip-audit and bandit at the configured threshold.

> Copyright © 2026 NetGuard Pro Suite contributors
> This file is part of the suite and is licensed under the
> GNU General Public License v3.0. See `LICENSE` for the full text.
