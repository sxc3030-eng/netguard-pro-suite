# NetGuard Pro — License Activation Protocol

**Version**: 1.0 (multi-PC seats, Ed25519-signed license + HMAC-signed local registry)
**Last updated**: 2026-04-30
**Status**: Local activation **shipped**. Cloud activation server **not yet built** (design only).

---

## 1. Overview

A NetGuard Pro license is bound to:
- A **`license_id`** (UUIDv4) generated at mint time.
- A **`max_seats`** count (1 for Starter, 1..5 for Pro).
- A **list of activated device fingerprints** stored locally in
  `argus_data/.activations.json` and HMAC-signed.

Activation today is **fully local**: the user pastes the `.lic` content into the
app or drops the file in the install dir. The app:
1. Verifies the Ed25519 signature on the license payload (public key embedded).
2. Verifies expiry.
3. Looks up `license_id` in the local activation registry.
4. Adds the current device fingerprint **if** seats are available, **else**
   raises `LicenseSeatExhaustedError`.

Cloud activation is sketched below for a future v2.

---

## 2. Trust model

- **Ed25519 keypair**: private key lives ONLY on the licence-issuing server
  (or on Simon's laptop until the server exists). Public key is embedded in
  `license_manager.py`.
- **License payload (signed)**: `tier`, `plan`, `max_seats`, `license_id`,
  `customer_email`, `issued_at`, `expires_at`. Tampering breaks the signature.
- **Activation registry HMAC**: SHA-256 HMAC over the entries list, key derived
  from the `license_id` itself (`HMAC(label, license_id)`). Only an attacker
  with the license_id can append a seat — but then they already have the
  license, so the threat model collapses to "user shares license with
  themselves on more than `max_seats` PCs", which is what the seat cap exists
  to prevent.

What this protocol **does NOT** defend against:
- A motivated attacker reverse-engineering the binary, NOPing the seat check.
  (We accept that — same posture as Sublime, JetBrains, etc.)
- A user copying `argus_data/.activations.json` along with the license to a
  new PC. The fingerprint inside the registry won't match the new PC's
  hardware, so the license will refuse to validate — but if the user *also*
  rewrites the registry to add the new fingerprint, they need to recompute
  the HMAC, which requires the `license_id`. Doable, but raises the bar.

---

## 3. Data structures

### 3.1 License payload (signed by Ed25519)

```json
{
  "tier": "pro",
  "plan": "pro",
  "max_seats": 5,
  "license_id": "550e8400-e29b-41d4-a716-446655440000",
  "customer_email": "simon@example.com",
  "issued_at": "2026-04-30T15:00:00Z",
  "expires_at": "2027-04-30T15:00:00Z"
}
```

### 3.2 License key (delivered to user)

```
NGPRO-<base64url(payload_json)>-<base64url(ed25519_sig)>
```

Embedded in a single-line `.lic` file.

### 3.3 Local activation registry (`argus_data/.activations.json`)

```json
{
  "550e8400-e29b-41d4-a716-446655440000": {
    "entries": [
      {
        "fingerprint": "<sha256-hex>",
        "hostname": "simon-laptop",
        "activated_at": "2026-04-30T15:01:00Z",
        "last_seen":    "2026-04-30T15:01:00Z"
      }
    ],
    "hmac": "<sha256-hex>"
  }
}
```

`hmac` = `HMAC-SHA256(K, canonical_json(entries))` where
`K = HMAC-SHA256(b"NetGuard-ActivationRegistry-v1", license_id_utf8)`.

---

## 4. Local activation flow (shipped today)

```
┌──────────┐                ┌──────────────┐               ┌──────────────┐
│   User   │                │ NetGuard.exe │               │ argus_data/  │
└────┬─────┘                └──────┬───────┘               │.activations  │
     │  drop simon.lic into        │                       │   .json      │
     │  install dir                │                       └──────┬───────┘
     │ ──────────────────────────► │                              │
     │                             │   Verify Ed25519 sig         │
     │                             │   Read license_id, max_seats │
     │                             │                              │
     │                             │   Read entries[license_id] ─►│
     │                             │ ◄──────────────────────────  │
     │                             │   Verify HMAC                │
     │                             │   Compute current FP         │
     │                             │                              │
     │                             │   if FP in entries: pass     │
     │                             │   elif len < max_seats:      │
     │                             │     append, re-HMAC, save ─► │
     │                             │   else:                      │
     │                             │     raise SeatExhausted      │
     │                             │                              │
     │   show dashboard            │                              │
     │ ◄────────────────────────── │                              │
```

---

## 5. Cloud activation flow (FUTURE — design only)

When the activation server exists, the flow becomes:

```
┌──────────┐    Stripe    ┌──────────────┐               ┌──────────────┐
│ Customer │   webhook    │  /webhook    │               │  /api/v1/    │
│ (browser)│ ────────────►│  Stripe      │               │  license/    │
└────┬─────┘              └──────┬───────┘               └──────┬───────┘
     │                           │                              │
     │  1. Pay on netguard.io    │                              │
     │ ──────────────────────────│                              │
     │                           │  2. Mint license (Ed25519)   │
     │                           │     Store in DB:             │
     │                           │       license_id, plan,      │
     │                           │       max_seats, expires_at, │
     │                           │       devices=[]             │
     │                           │                              │
     │  3. Email simon.lic       │                              │
     │ ◄─────────────────────────│                              │
     │                           │                              │
     │  4. Drop into NetGuard    │                              │
     │     (installer)           │                              │
     │     ─ POST /activate ───────────────────────────────────►│
     │       { license_id, fingerprint, hostname }              │
     │                                                          │
     │                                              5. Check    │
     │                                                 device   │
     │                                                 list,    │
     │                                                 if room  │
     │                                                 append,  │
     │                                                 return   │
     │                                                 200 +    │
     │                                                 updated  │
     │                                                 device   │
     │                                                 list     │
     │     ◄────────────────────────────────────────────────────│
     │  6. Write registry locally (HMAC-signed)                 │
```

### 5.1 Endpoints (proposed)

| Method | Path                              | Body                                           | Response                                       |
|--------|-----------------------------------|------------------------------------------------|------------------------------------------------|
| POST   | `/api/v1/license/activate`        | `{license_id, fingerprint, hostname}`          | `{ok, devices:[...], seats_used, max_seats}`   |
| POST   | `/api/v1/license/deactivate`      | `{license_id, fingerprint}`                    | `{ok, devices:[...]}`                          |
| GET    | `/api/v1/license/{license_id}`    | (auth: bearer signed by license)               | `{plan, max_seats, devices, expires_at}`       |
| POST   | `/webhook/stripe`                 | (Stripe checkout.session.completed)            | mints license, emails `.lic`                   |

### 5.2 Trust delta vs local-only

With a server, the registry is authoritative — local registry is a cache.
Server-side check is impossible to bypass without breaking the network
isolation, which raises the bar significantly. Recommended for v2.

---

## 6. Mint command examples

```bash
# 5-seat Pro license, 1 year, with .lic output:
python tools/license_mint.py pro \
    --plan pro \
    --seats 5 \
    --customer-email simon@example.com \
    --expires-days 365 \
    --out simon.lic

# 1-seat Starter:
python tools/license_mint.py pro \
    --plan starter \
    --seats 1 \
    --customer-email user@x.com \
    --expires-days 365

# Legacy single-PC (no plan), perpetual:
python tools/license_mint.py pro
```

---

## 7. TODOs for real-server activation

1. **Stripe webhook**: catch `checkout.session.completed`, mint a license,
   email the `.lic` file.
2. **Database schema**: `licenses(license_id, plan, max_seats, expires_at,
   customer_email, devices_json)`.
3. **Endpoints** as above; sign responses with the same Ed25519 key for
   replay protection.
4. **Re-signing**: when a device is added/removed, re-mint the license with
   the updated `devices` list embedded so the local registry can sync.
5. **Offline grace**: client should accept the local registry for N days
   after last successful server check (e.g. 14 days) so users without
   internet aren't locked out.

Until then, local activation is *good enough* to ship the +15$/mo pricing —
we trust users not to share licenses across orgs, and tampering requires
breaking Ed25519 + HMAC.
