# Secret Vault — Triple-Encryption Spec

**Status:** draft v1
**Owner:** sxc3030-eng
**Date:** 2026-04-30
**Module:** `secret_vault.py`
**Tests:** `tests/test_secret_vault.py`

This document specifies the Secret Vault module that backs the NetGuard / Argus
/ FORGE suite. It is the secure store for API keys (Anthropic, OpenAI, Google),
service tokens, and any other long-lived credential the suite holds on disk —
including credentials touched by the Mythos cage (sandboxed AI agent runtime).

The existing `argus_vault.py` is a single-layer DPAPI-or-PBKDF2 V1 store.
`secret_vault.py` is its triple-encryption successor and is what new code must
target. The two coexist; migration is described in §10.

---

## 1. Threat model

We assume an attacker can have one or more of the following positions:

| # | Attacker position                                 | Defended by |
|---|---------------------------------------------------|-------------|
| A | Another local Windows user on the same machine    | Layer 1 — DPAPI (CurrentUser scope) |
| B | Offline disk image / cold boot / stolen laptop    | Layer 2 — Windows Credential Manager (key never lives on disk in plaintext) |
| C | Live SYSTEM-level RCE on the user's session       | Layer 3 — Argon2id-derived KEK from a master password the attacker does not know |
| D | Arbitrary code in the same user/process           | Out of scope — same trust boundary as the vault process |
| E | Compromised cryptography / argon2-cffi build      | Out of scope — supply chain |
| F | Hardware key extraction / TPM bypass              | Out of scope — best-effort only |

A secret is only revealed if **all three** layers are defeated:

1. Bypass DPAPI (requires running code as the same Windows user).
2. Read the per-vault wrapping key out of Windows Credential Manager (requires
   either same user session, or an unlocked DPAPI master key).
3. Guess or extract the master password (Argon2id memory-hard, ≥ 64 MiB cost).

The vault never stores the master password and never derives anything that
allows offline brute-force without all three layers being physically present.

### Non-goals

* We do **not** defend against malware running inside the same Python process
  (it can call `vault.get()` after unlock).
* We do **not** defend against keyloggers capturing the master password as
  the user types it. The caller is responsible for input hygiene.
* We do **not** provide forward secrecy across vault snapshots — an old
  snapshot decrypted with the old master password remains readable.

---

## 2. Three-layer architecture

```
                 ┌────────────────────────────────────────────────────┐
                 │ User-supplied master password (never persisted)    │
                 └────────────────────────────────────────────────────┘
                              │
                              ▼  Argon2id  (salt from header, m=64MiB,t=3,p=4)
                 ┌────────────────────────────────────────────────────┐
                 │ KEK_master  (32 bytes)            [Layer 3]        │
                 └────────────────────────────────────────────────────┘
                              │
                              ▼  AES-GCM unwrap
                 ┌────────────────────────────────────────────────────┐
                 │ KEK_wrap   (32 bytes)             stored: ciphered │
                 └────────────────────────────────────────────────────┘
                              │
                              ▼  XOR with keyring-stored secret
                 ┌────────────────────────────────────────────────────┐
                 │ KEK_unwrap (32 bytes) = KEK_wrap XOR keyring_blind │
                 │ keyring_blind lives in Windows Credential Manager  │
                 │ under service "NetGuardSecretVault"  [Layer 2]     │
                 └────────────────────────────────────────────────────┘
                              │
                              ▼  AES-GCM unwrap
                 ┌────────────────────────────────────────────────────┐
                 │ DEK         (32 bytes per-vault data key)          │
                 │ DEK is wrapped on disk by DPAPI(CurrentUser)       │
                 │ — DPAPI ciphertext stored in vault header          │
                 │ [Layer 1]                                          │
                 └────────────────────────────────────────────────────┘
                              │
                              ▼  AES-GCM with per-secret nonce
                 ┌────────────────────────────────────────────────────┐
                 │ Plaintext secret bytes                             │
                 └────────────────────────────────────────────────────┘
```

### Why three layers compose multiplicatively

* **Lose only the master password** → attacker still needs DPAPI (same user)
  AND the keyring blind (live session).
* **Lose only DPAPI** (e.g. attacker is the user but doesn't know the password)
  → they get the wrapped DEK ciphertext but cannot derive `KEK_master`.
* **Lose only the keyring entry** (rare, requires API-level Vault access) →
  they cannot compute `KEK_unwrap` so cannot unwrap the DEK.
* **Disk theft** → no DPAPI master key (different machine), no keyring entry
  (offline), and no master password. All three barriers stand.

---

## 3. Key derivation chain

Notation: `KDF(...)` is Argon2id; `WRAP(K, P)` is AES-GCM(K) over plaintext P
with a fresh 12-byte nonce, returning `nonce || ciphertext || tag`.

```
salt_master   ← random 16 bytes (vault header, written once at vault_init)
salt_keyring  ← random 16 bytes (vault header, written once at vault_init)

KEK_master    = Argon2id(password=master, salt=salt_master,
                         m_cost=65536, t_cost=3, p=4, hash_len=32)

keyring_blind ← random 32 bytes  (generated at vault_init,
                                  stored in Windows Credential Manager
                                  under service="NetGuardSecretVault",
                                  username=vault_id)

KEK_wrap_blob = WRAP(KEK_master, KEK_wrap)               ← stored in header
                                                           (KEK_wrap is random 32 B)

KEK_unwrap    = KEK_wrap XOR keyring_blind               ← computed in-RAM only

DEK           = random 32 bytes (data encryption key, per-vault)
DEK_wrap_blob = WRAP(KEK_unwrap, DEK)                    ← stored in header
DEK_dpapi_blob= DPAPI_protect(DEK_wrap_blob, scope=CurrentUser)
                                                          ← stored in header
                                                           (this is the on-disk
                                                            "outer" of the DEK)

Per secret:
  nonce_i     ← random 12 bytes
  ct_i        = WRAP(DEK, plaintext)
              = nonce_i || AES-GCM(DEK, nonce_i, plaintext, AAD=name_i)

The AAD ties each ciphertext to its name, so swapping records detected.
```

`KEK_master`, `KEK_wrap`, `KEK_unwrap`, and `DEK` are only ever held in RAM
inside `bytearray`s and zeroized on `lock()` (best effort — see §6).

---

## 4. File format

Single binary file at `<vault_root>/secret_vault.bin`. Vault root resolution,
in order:

1. `SECRET_VAULT_ROOT` env var (used by tests with `tmp_path`).
2. `argus_data/.secret_vault/` next to the module (production default).

The file is JSON-encoded UTF-8 for readability — all binary fields are
base64. Layout:

```json
{
  "magic":            "NGSV",
  "version":          1,
  "vault_id":         "<uuid4>",
  "created_at":       "2026-04-30T17:00:00Z",
  "salt_master_b64":  "<16 bytes>",
  "salt_keyring_b64": "<16 bytes>",
  "argon2_params": {
    "type":    "id",
    "m_cost":  65536,
    "t_cost":  3,
    "p":       4,
    "hash_len":32
  },
  "kek_wrap_blob_b64":  "<nonce||ct||tag>",
  "dek_dpapi_blob_b64": "<DPAPI(WRAP(KEK_unwrap, DEK))>",
  "dek_dpapi_available":true,
  "secrets": {
    "<name>": {
      "ct_b64":     "<nonce||ct||tag>",
      "created_at": "...",
      "updated_at": "...",
      "metadata":   {"caller": "argus_pyqt", "tags": ["api-key"]}
    }
  },
  "audit": [
    {"ts":"...", "op":"set",   "name":"anthropic_key", "caller":"...", "ok":true},
    {"ts":"...", "op":"get",   "name":"anthropic_key", "caller":"...", "ok":true}
  ]
}
```

Notes:
* `dek_dpapi_available` is `false` on non-Windows / fallback paths — the
  blob then holds the unprotected (but still keyring+argon2-wrapped) DEK.
  Layer 1 is degraded; Layers 2 and 3 still apply.
* `secrets` is a flat dict keyed by name. Names match `[A-Za-z0-9_.-]{1,128}`.
* `audit` is append-only and bounded to 5000 entries (oldest evicted).

---

## 5. Public API

```python
class SecretVault:
    def __init__(
        self,
        vault_root: Optional[Path] = None,
        idle_timeout_minutes: int = 15,
    ): ...

    # Lifecycle
    def exists(self) -> bool: ...
    def init(self, master: str) -> None: ...
    def unlock(self, master: str) -> None: ...
    def lock(self) -> None: ...
    def is_unlocked(self) -> bool: ...

    # CRUD
    def set(self, name: str, secret: str,
            metadata: Optional[Dict[str, Any]] = None) -> None: ...
    def get(self, name: str) -> Optional[str]: ...
    def list(self) -> List[Dict[str, Any]]: ...        # metadata only
    def delete(self, name: str) -> bool: ...

    # Master rotation
    def change_master(self, old: str, new: str) -> None: ...

    # Audit
    def audit_log(self) -> List[Dict[str, Any]]: ...

    # Migration
    def migrate_from_settings_json(
        self,
        path: Path,
        master: str,
    ) -> int: ...
```

Errors raised:

| Exception                       | When                                              |
|---------------------------------|---------------------------------------------------|
| `VaultNotInitializedError`      | `unlock()`/`set()` etc. before `init()`           |
| `VaultAlreadyInitializedError`  | `init()` on existing vault                        |
| `VaultLockedError`              | mutating call while locked                        |
| `VaultBadMasterError`           | wrong master password (GCM tag mismatch)          |
| `VaultCorruptedError`           | tamper detected in any blob (GCM tag mismatch)    |
| `VaultDependencyMissingError`   | argon2-cffi / pywin32 / keyring not installed     |
| `VaultBackendUnavailableError`  | keyring backend cannot store (no Vault on box)    |

Error messages are deliberately generic — they never reveal which name was
attacked, what master prefix was tried, or how big any blob was.

---

## 6. Failure modes & recovery

| Failure                                       | Effect                          | Recovery                              |
|-----------------------------------------------|---------------------------------|---------------------------------------|
| Wrong master password                         | `VaultBadMasterError`           | Retry; no lockout (caller can rate-limit) |
| Tampered ciphertext (any blob)                | `VaultCorruptedError`           | Restore from `secret_vault.bin.bak`; the module writes a `.bak` on every successful save |
| Keyring entry deleted                         | `VaultBackendUnavailableError` on unlock | Restore from backup OR re-init vault; existing secrets are unrecoverable without keyring blind |
| DPAPI fails (different Windows user / restored profile) | Layer 1 degrades; vault still opens with master + keyring | Re-`init()` to regenerate fresh DPAPI wrap |
| `argon2-cffi` missing                         | `VaultDependencyMissingError`   | `pip install argon2-cffi` |
| `keyring` missing                             | `VaultDependencyMissingError`   | `pip install keyring` |
| `pywin32` missing on Windows                  | Layer 1 silently degrades to "no DPAPI"; logged warning | `pip install pywin32` |
| Concurrent process holds the file             | Atomic rename via temp file fails | Caller retries; we use `os.replace()` which is atomic on Windows |
| Idle timeout                                  | Vault auto-locks; next `get()` raises `VaultLockedError` | Re-call `unlock(master)` |

### Best-effort zeroization

Python `str` is immutable, so master password + plaintext secrets are stored
in `bytearray` from input forward. On `lock()` we zero every `bytearray`
attribute holding key material. We acknowledge this is **best-effort only**
on CPython — the GC and string interning may have copies we cannot reach.
This is documented in the module docstring.

---

## 7. Audit log

Every public mutating or read call writes one record:

```json
{"ts": "2026-04-30T17:00:00.123Z",
 "op": "get",
 "name": "anthropic_key",
 "caller": "<frame[1].f_globals['__name__']>",
 "ok": true,
 "error_class": null}
```

* Append-only (no entry is ever modified).
* Bounded to `_AUDIT_MAX = 5000` records — oldest dropped on overflow.
* The audit log is itself part of the encrypted file, so reading it requires
  unlock (which logs an `op:unlock` entry).
* **Plaintext secrets are NEVER written to the audit log.** Names are.

---

## 8. Auto-lock

`SecretVault(idle_timeout_minutes=15)` sets a soft idle timer. On every
public call we update `self._last_activity`. On every public call we also
check `now - self._last_activity > timeout` and call `lock()` first if
exceeded. There is no background thread — the timeout is enforced lazily on
the next access.

`idle_timeout_minutes=0` disables auto-lock.

---

## 9. Concurrency

* Only one writer at a time. We take a process-local `threading.RLock` around
  every public API call.
* Cross-process writes use `os.replace(tmp, final)` (atomic on Windows
  NTFS / Linux) so a crash mid-write cannot leave a half-written file.
* We do **not** support multi-host / shared filesystem. The keyring blind is
  per-machine, so the file is per-machine by design.

---

## 10. Migration from `netguard_ai_settings.json`

`netguard_ai_settings.json` today stores API keys in plaintext. The module
exposes:

```python
SecretVault.migrate_from_settings_json(path, master) -> int
```

Behaviour:

1. Load the JSON file.
2. For each `providers.<provider>.api_key` whose value is non-empty and not
   a placeholder (`"sk-ant-REPLACE-ME"`, etc.), call
   `vault.set(f"{provider}_api_key", value)`.
3. After successful migration, rewrite the JSON file with `api_key` removed
   and a sentinel `"api_key_in_vault": true` added.
4. The original file is backed up to `<path>.pre-vault.bak`.
5. Return count of secrets migrated.

This is idempotent — re-running on an already-migrated file is a no-op (zero
returned, no backup written).

---

## 11. Test surface (what `tests/test_secret_vault.py` proves)

* `set()` / `get()` round-trip preserves bytes exactly.
* Wrong master raises `VaultBadMasterError` cleanly without panic.
* Flipping a single byte in any ciphertext blob raises `VaultCorruptedError`
  on the next read (GCM tag mismatch).
* `lock()` clears the in-memory KEK; `get()` after lock raises
  `VaultLockedError`; `unlock()` recovers.
* `change_master(old, new)` re-encrypts every secret; the vault opens with
  `new` and refuses `old`.
* Auto-lock fires after the idle window.
* Migration from a synthetic `netguard_ai_settings.json` populates the vault
  and rewrites the file safely.
* Mocked dependencies: tests run with `argon2-cffi`, `keyring`, and
  `pywin32` mocked when absent so the suite passes on a minimal box.

---

## 12. Out of scope (V2+)

* HMAC-signed audit log (tamper-evident even from someone who can decrypt).
* Threshold sharing (Shamir) of the master password.
* TPM-bound keyring entry instead of Windows Vault.
* GUI for unlock / change-master flows (that lives in `argus_pyqt.py`).
* Cross-machine sync (would require dropping the keyring layer or replacing
  it with a remote KMS).
