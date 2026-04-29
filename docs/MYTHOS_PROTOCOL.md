# MYTHOS_PROTOCOL.md — Argus <-> Mythos Plug Interface

**Version:** 1.0
**Status:** Draft (V1, plug-ready). Argus implements both halves; Mythos
itself is not yet built.
**Repo:** `netguard-pro-suite` (GPL v3, public)

---

## 1. Goals + Non-goals

### Goals

* Define a stable, **versioned** wire contract so any future Mythos build
  can plug into a running Argus and read its events / drive its actions.
* Keep Argus's running surface area minimal: a single shared bearer token,
  two localhost ports, no kernel hooks, no IPC magic.
* Provide a complete **audit trail** for everything Mythos does — every
  action lands in the surveillance HMAC chain.
* Be useful even before Mythos exists: the same interface is callable from
  test harnesses, CLI tools, or a humans-only debugging proxy.

### Non-goals

* Defining how Mythos thinks. The protocol shapes the cage, not the beast.
* Cross-host / multi-tenant deployments. Localhost only in V1.
* Streaming binary payloads (e.g. raw video). Audit-friendly JSON only.
* Hot-pluggable schema upgrades during a single connection. New fields
  may appear (additive); breaking changes bump the major version.

---

## 2. Architecture

```
+-----------------------------+      +-------------------------------+
|        Argus (cage)         |      |        Mythos (beast)         |
|                             |      |                               |
| +------------------------+  |      |  +-------------------------+  |
| |  Surveillance HMAC log |  |      |  |   Reasoning loop        |  |
| |  Arbiter (Claude)      |  |      |  |   Tool selection        |  |
| |  Browser tabs / modes  |  |      |  |   Memory                |  |
| +-----------+------------+  |      |  +-----------+-------------+  |
|             |               |      |              |                |
|             v               |      |              ^                |
| +------------------------+  |  WS  |  +-------------------------+  |
| |   Mythos Bus (8767)    |<-+------+->|   Bus subscriber        |  |
| |   pub/sub over JSON    |  |      |  +-------------------------+  |
| +------------------------+  |      |              |                |
|                             |      |              v                |
| +------------------------+  | HTTP |  +-------------------------+  |
| |  Mythos Gateway (8768) |<-+------+--|   Tool caller           |  |
| |  REST tool endpoints   |  |      |  +-------------------------+  |
| +-----------+------------+  |      |                               |
|             |               |      +-------------------------------+
|             v               |
|   surveil_log_event()       |
|   (HMAC chain anchored)     |
+-----------------------------+
```

* **Bus** (port `8767`, WebSocket): Argus -> Mythos read-only fan-out.
* **Gateway** (port `8768`, HTTP): Mythos -> Argus action requests.
* **Token** (`MYTHOS_BUS_TOKEN` in the Argus vault): one shared secret
  for both surfaces. Auto-generated on first start.

---

## 3. WebSocket Bus Protocol

### 3.1 Handshake

* URL: `ws://127.0.0.1:8767/`
* Required header: `X-Mythos-Token: <hex token>`
* Server rejects with HTTP `401 Unauthorized` if the token is missing or
  wrong. No retry incentive: the token is loopback-only and only the
  local user account can read it from the vault.

### 3.2 Hello

Immediately after the WebSocket upgrades, the server pushes:

```json
{"topic": "_meta/hello", "ts_iso": "...", "seq": 0,
 "payload": {"protocol": "1.0"}}
```

This lets Mythos detect a server-protocol mismatch before it ships any
subscriptions.

### 3.3 Subscribe / Unsubscribe (client -> server)

```json
{"action": "subscribe", "topics": ["surveillance/*", "arbiter/decision"]}
{"action": "unsubscribe", "topics": ["surveillance/*"]}
```

Topic glob rules:

* `*` matches a single segment (`surveillance/*` matches
  `surveillance/event` but not `surveillance/event/inner`).
* `**` (only as a trailing suffix `prefix/**`) matches any tail.
* Exact strings always match themselves.

### 3.4 Event (server -> client)

```json
{
  "topic": "surveillance/event",
  "ts_iso": "2026-04-28T18:42:13.901234+00:00",
  "seq": 4711,
  "payload": { ... topic-specific shape ... }
}
```

* `seq` is monotonic per server start. A drop in `seq` means Argus
  restarted (clients should not assume continuity across restarts).
* `payload` is topic-defined; see the topic catalog below.

### 3.5 Backpressure

Each client has a 256-message in-memory queue. If Mythos cannot keep up,
the queue fills and *additional events are dropped* with a counter
incremented in `bus_stats().events_dropped`. The bus never blocks the
publisher. This is by design: Mythos is supposed to be best-effort.

---

## 4. Tool Gateway Protocol

### 4.1 Auth

Every request must carry `Authorization: Bearer <MYTHOS_BUS_TOKEN>`. A
missing or wrong token returns HTTP `401`.

### 4.2 Discovery

```
GET /tools
```

Response:

```json
{
  "protocol": "1.0",
  "tools": [
    {"name": "query_history",
     "description": "Return recent surveillance events (read-only).",
     "schema": { "type": "object", "properties": {"limit": {"type": "integer"}} },
     "needs_approval": false,
     "audit_irreversible": false},
    ...
  ]
}
```

### 4.3 Invocation

```
POST /tools/<name>
Content-Type: application/json
Authorization: Bearer <token>

{"params": { ... }}
```

Success:

```json
{"result": { ... handler-defined ... },
 "decision_id": "9f2c... (uuid hex)",
 "audit_signature": "8d2f1c0e... (16 hex)"}
```

### 4.4 Error codes

| HTTP | `error`               | When                                               |
|------|-----------------------|----------------------------------------------------|
| 400  | `invalid_json`        | Body not JSON                                      |
| 400  | `invalid_body`        | Body is not an object                              |
| 400  | `params_must_be_object` | `params` is not an object                        |
| 400  | `schema`              | Params fail validation (`detail` field has reason) |
| 401  | `unauthorized`        | Bad/missing bearer token                           |
| 403  | `approval_rejected`   | User denied (or 30s timeout)                       |
| 404  | `not_found` / `unknown_tool` | Path not handled / tool name not registered |
| 500  | `handler_error`       | Tool handler raised; `detail` carries str(exc)     |

### 4.5 Approval flow

For tools with `needs_approval: true`, the gateway calls
`approval_handler(tool_name, params)` and blocks (synchronously, in the
request thread) for up to `APPROVAL_TIMEOUT_SECONDS` (default 30s). If
the handler returns False, raises, or times out, the call is rejected
with HTTP 403 and the rejection is still audit-logged.

For `audit_irreversible: true` tools, the params dict passed to the
handler additionally contains `"__irreversible__": true`. The Argus UI
can use this flag to require a 2FA step before approving.

### 4.6 Audit signature

```
audit_signature = sha256(decision_id || tool_name || params_hash || outcome)[:16]
```

Where `params_hash` is sha256 of canonical JSON (sort_keys=True). This
short hash is a stable handle Mythos can quote in follow-up calls (e.g.
"undo the action with audit_signature 8d2f1c0e"). The full HMAC chain
of record lives in surveillance.

---

## 5. Topic Catalog

| Topic                  | Direction | Payload (illustrative)                                 |
|------------------------|-----------|--------------------------------------------------------|
| `_meta/hello`          | S->C      | `{"protocol": "1.0"}`                                  |
| `surveillance/event`   | S->C      | mirror of every `surveil_log_event` (type, ts, data)   |
| `arbiter/decision`     | S->C      | `{verdict, reason, confidence, used_claude, ...}`      |
| `mode/switched`        | S->C      | `{from: "normal", to: "private", ts_iso}`              |
| `tab/opened`           | S->C      | `{tab_id, url, mode}`                                  |
| `tab/closed`           | S->C      | `{tab_id}`                                             |
| `user/action`          | S->C      | `{source, tool, outcome, decision_id}`                 |
| `download/intercepted` | S->C      | `{url, sha256, mime, size, verdict}`                   |
| `error/bus`            | S->C      | `{message, traceback}`                                 |
| `error/gateway`        | S->C      | `{message, traceback}`                                 |

V1.x may *append* fields to any payload. Mythos must tolerate unknown
extra keys (forward-compat). Removing or renaming a field is a major-
version bump.

---

## 6. Tool Catalog (V1)

| Tool                       | Approval | Description                                  |
|----------------------------|----------|----------------------------------------------|
| `query_history`            | no       | Last N surveillance events                   |
| `query_arbiter_decisions`  | no       | Last N arbiter decisions                     |
| `query_stats`              | no       | Aggregate counters (surveillance + bus + gw) |
| `set_mode`                 | yes      | Switch normal/private/vault                  |
| `block_url`                | yes      | Add URL pattern to user blocklist            |
| `unblock_url`              | yes      | Remove URL pattern from user blocklist       |
| `run_arbiter`              | no       | Re-run arbiter on a context (read-only)      |
| `clear_history`            | yes (irreversible) | Wipe surveillance for a date       |
| `export_audit`             | no       | Export surveillance JSONL                    |
| `request_screenshot`       | yes      | Screenshot of current tab                    |
| `notify_user`              | no       | Push a non-modal toast in Argus              |

V1 stub handlers return `{status: "stubbed", ...}`. They will be wired
to real Argus internals in a follow-up patch — Mythos does not need to
know which tools are stubs vs. real, only their schema and
`needs_approval`.

---

## 7. Auth + Session Lifecycle

* **Token bootstrap.** First call to `bus_start()` or `gateway_start()`
  reads `MYTHOS_BUS_TOKEN` from the Argus vault. If absent, a new
  256-bit hex token is generated and stored.
* **Token rotation.** `vault_set("MYTHOS_BUS_TOKEN", new_value)` followed
  by a bus/gateway restart. There is no in-protocol rotation message.
* **Session lifetime.** WS connections survive as long as both sides
  stay healthy. The HTTP gateway is connectionless (Keep-Alive is fine
  but not required). Either side may disconnect at any time.
* **Multiple subscribers.** The bus supports multiple concurrent
  WebSocket clients (e.g. Mythos + a debug subscriber). Each gets its
  own queue and independent backpressure.

---

## 8. Backwards Compatibility Policy

* **Versioning:** semver in the `protocol` field (`1.0`, `1.1`, `2.0`).
* **Additive changes (V1.x):** new topics, new tools, new optional
  payload fields. Mythos clients must ignore unknown topics and
  unknown fields.
* **Breaking changes (V2.0):** removing/renaming a field, changing an
  error code, changing auth scheme. Argus serves the old version on
  the legacy port and the new version on a fresh port for one full
  release window.
* **Deprecation:** when Argus is about to drop a topic in vNext, the
  topic's payload gains a `"deprecated_at": "2026-XX-XX"` field one
  release ahead.

---

## 9. Security Threat Model

### Trust assumptions

* **Argus is trusted.** It runs as the user, owns the vault, owns the
  surveillance HMAC chain.
* **Mythos is semi-trusted.** Mythos can read everything and can
  *request* any action. The user (via the approval handler) is the
  final authority on side-effecting tools.
* **Network is untrusted.** Both surfaces are loopback-only. We
  refuse to bind to any address other than `127.0.0.1`, `localhost`,
  or `::1`.

### Threats in scope

| Threat                                | Mitigation                                       |
|---------------------------------------|--------------------------------------------------|
| Untrusted local app probes the bus    | Bearer token from vault (DPAPI-protected)        |
| Mythos requests irreversible action   | Approval gate + `__irreversible__` flag for 2FA  |
| Mythos floods the bus with subscribes | Per-client queue cap, drop counter               |
| Replay of an old approval             | Each call has fresh `decision_id`, audit chain   |
| Tampering with the audit log          | Surveillance HMAC chain detects byte-mutation    |
| Mythos prompt injection via webpage   | Out of scope: arbiter handles content sanitation |

### Threats out of scope (V1)

* Mythos itself being compromised (we trust it semi by definition).
* Network attackers — there is no network surface.
* Side-channel timing attacks against the bearer token comparison.

---

## 10. Sample Interactions

### 10.1 Subscribe and read

```text
client -> server (WS handshake)
  GET / HTTP/1.1
  Upgrade: websocket
  X-Mythos-Token: 9f8a...

server -> client
  {"topic": "_meta/hello", "ts_iso": "...", "seq": 0,
   "payload": {"protocol": "1.0"}}

client -> server
  {"action": "subscribe", "topics": ["arbiter/decision"]}

server -> client (when an arbiter decision happens)
  {"topic": "arbiter/decision",
   "ts_iso": "2026-04-28T18:42:13.901234+00:00",
   "seq": 42,
   "payload": {"verdict": "allow", "confidence": 0.81,
               "used_claude": true, "decision_id": "ab12..."}}
```

### 10.2 Read-only tool

```text
client:
  POST /tools/query_history
  Authorization: Bearer 9f8a...
  Content-Type: application/json

  {"params": {"limit": 5}}

server:
  HTTP/1.1 200 OK
  {"result": {"status": "ok",
              "events": [...5 events...],
              "count": 5},
   "decision_id": "c91d4e...",
   "audit_signature": "8d2f1c0e..."}
```

### 10.3 Approval-gated tool, user accepts

```text
client:
  POST /tools/block_url
  Authorization: Bearer 9f8a...

  {"params": {"pattern": "https://evil.example/*"}}

(Argus pops a confirmation dialog; user clicks Approve.)

server:
  HTTP/1.1 200 OK
  {"result": {"status": "stubbed", "tool": "block_url", ...},
   "decision_id": "...", "audit_signature": "..."}
```

### 10.4 Approval-gated tool, user denies (or 30s timeout)

```text
client:
  POST /tools/clear_history
  Authorization: Bearer 9f8a...

  {"params": {"date": "2026-04-27"}}

(Argus pops a 2FA dialog because audit_irreversible=true; user denies.)

server:
  HTTP/1.1 403 Forbidden
  {"error": "approval_rejected",
   "decision_id": "...",
   "audit_signature": "..."}
```

---

## 11. Reference Implementation

* `argus_mythos_bus.py` — WebSocket fan-out, vault-backed token, glob
  topic matching, bounded per-client queues.
* `argus_mythos_gateway.py` — HTTP REST, schema validation, approval
  flow with timeout, audit forwarding to surveillance.
* `tests/test_argus_mythos_bus.py`, `tests/test_argus_mythos_gateway.py`
  — pytest-only (no asyncio fixture dep) using subprocess-style real
  WebSocket / HTTP clients.

---

## 12. Footer

This protocol document is part of the NetGuard / Argus / GeniA / Vinom
suite and is licensed under the GNU General Public License v3 or later.
See `<https://www.gnu.org/licenses/>` for the full text.

Copyright (C) 2026 sxc3030-eng.
