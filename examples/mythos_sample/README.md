# Mythos Sample Plugin

A reference client demonstrating end-to-end use of the Argus integration
protocol V1 — the same protocol the future Mythos AI agent will speak.

It connects to:

- **Event bus** (`argus_mythos_bus`, `ws://127.0.0.1:8767`) — read-only
  fan-out of surveillance / arbiter / mode events.
- **Tool gateway** (`argus_mythos_gateway`, `http://127.0.0.1:8768`) —
  REST endpoint that runs registered tools, with approval gates and
  audit-signed responses.

If you are building a Mythos plugin (or any external automation that
wants to observe and act on Argus events), start here.

---

## What this demonstrates

| Step | Behaviour |
|------|-----------|
| Token discovery   | env var → vault → in-process bus singleton |
| WebSocket auth    | `X-Mythos-Token` handshake header |
| Subscription      | `{"action":"subscribe","topics":[...]}` |
| Event printing    | colour-coded, timestamped, payload-truncated lines |
| Tool discovery    | `GET /tools` (note: `/tools`, **not** `/tools/list`) |
| Read-only call    | `query_stats` (no approval) |
| Side-effect call  | `notify_user` (no approval, illustrates params) |
| Approval gate     | `set_mode` returns 403 when no UI handler is registered |
| Irreversible gate | `clear_history` flagged with `audit_irreversible` |
| Audit verification| recompute `sha256(decision_id\|tool\|params_hash\|outcome)` |

---

## Requirements

```
pip install -r requirements.txt
```

| Package | License | Why |
|---|---|---|
| `websockets >=12,<17` | BSD-3-Clause | bus client |
| `requests >=2.31,<3` | Apache 2.0 | gateway HTTP calls |

Both are GPL-compatible.

---

## How to run

### Option A: with full Argus

```bash
# terminal 1
python argus_pyqt.py

# terminal 2
python -m examples.mythos_sample.main
```

### Option B: bus + gateway only (headless)

```python
# terminal 1 — minimal cage harness
from argus_mythos_bus import bus_start
from argus_mythos_gateway import gateway_start
bus_start()
gateway_start()
import time; time.sleep(3600)
```

```bash
# terminal 2
python -m examples.mythos_sample.main
```

### Token resolution

The sample looks for `MYTHOS_BUS_TOKEN` in this order:

1. Environment variable `MYTHOS_BUS_TOKEN`
2. `argus_vault.vault_get("MYTHOS_BUS_TOKEN")`
3. `argus_mythos_bus.bus_get_token()` (only works in-process)

If none of those produce a token, the sample exits 1 with an instructive
message.

### Knobs

| Variable | Default | Purpose |
|---|---|---|
| `MYTHOS_BUS_HOST` | `127.0.0.1` | bus host |
| `MYTHOS_BUS_PORT` | `8767` | bus port |
| `MYTHOS_GATEWAY_PORT` | `8768` | gateway port |
| `MYTHOS_SAMPLE_DURATION` | `60` | seconds to listen |
| `MYTHOS_SAMPLE_NO_COLOR` | unset | disable ANSI colours |

---

## Expected output

See [`sample_session.txt`](sample_session.txt) for a captured run. Highlights:

- `_meta/hello` greeting from the bus
- 11 registered tools listed with `[approval]` / `[irreversible]` flags
- `query_stats` returns 200 with verified signature
- `notify_user` returns 200 with verified signature
- `set_mode` and `clear_history` both return 403 `approval_rejected`
  with verified rejection signatures (no UI handler registered =
  fail-closed)
- Bus events stream in interleaved with the gateway calls

---

## Code walkthrough

### `BusSubscriber`

A small class that runs an `asyncio` loop on a daemon thread. The
foreground stays synchronous so tool-call code reads top-to-bottom. The
loop:

1. Connects with `additional_headers={"X-Mythos-Token": token}`.
2. Reads the mandatory `_meta/hello` first frame.
3. Sends a `{"action":"subscribe","topics":[...]}` message.
4. Spins on `ws.recv()` with a 1s timeout, dispatching each frame to
   `_on_event` for printing.
5. Stops cleanly on `_stop.set()`.

### `GatewayClient`

A two-method REST wrapper:

- `list_tools()` → `GET /tools`
- `call(name, params)` → `POST /tools/{name}` with body
  `{"params": {...}}`

Auth is `Authorization: Bearer <token>`.

### `verify_signature()`

The gateway returns
`audit_signature = sha256(decision_id | tool | params_hash | outcome)[:16]`.
The sample re-derives the same hash from data it already has and
compares. This is **not** an HMAC — there is no shared secret in the
chain. The real tamper-evidence lives in the surveillance HMAC log
(`argus_surveillance`), which the gateway forwards to but the sample
never touches. Treat `verify_signature` as a "did the gateway return
data consistent with its documented contract" check.

### Approval handling

The sample does **not** register an approval handler. With no handler:

- A tool with `needs_approval=True` triggers
  `argus_mythos_gateway._await_approval`, which returns `False`
  immediately (fail-closed).
- The gateway returns 403 `approval_rejected` with a `decision_id` and
  signature whose outcome is `"rejected"`.

A real Mythos plugin would instead register a handler via
`gateway_set_approval_handler(fn)` that prompts the operator. The
contract is `(tool_name: str, params: dict) -> bool`, with
`params["__irreversible__"] = True` injected for irreversible tools so
the UI can require 2FA.

---

## Extension points for a real Mythos

1. **State machine.** Persist `decision_id` → outcome correlations and
   only re-prompt when state changes.
2. **Decision rules.** Pre-filter events on the bus side before calling
   tools (e.g. only react to `arbiter/decision` with
   `verdict == "deny"`).
3. **Multi-tool sequences.** Chain calls: `query_arbiter_decisions` →
   pick a target → `block_url` (with approval) → `notify_user`.
4. **Surveillance correlation.** Cross-reference each gateway call's
   `decision_id` with the surveillance HMAC chain to prove tamper-free
   audit trails.
5. **Backpressure.** The bus drops on a per-client buffer overflow.
   Add an LRU on the client side and watch `dropped` in `bus_stats`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `[FATAL] could not locate MYTHOS_BUS_TOKEN` | Argus not running, vault locked | export the token explicitly |
| `[FATAL] bus connect failed: 401` | wrong token | re-read the vault |
| `[FATAL] gateway not reachable` | gateway not started, port mismatch | check `gateway_start` ran, set `MYTHOS_GATEWAY_PORT` |
| `set_mode` returns 200 unexpectedly | a UI approval handler is registered AND auto-approves | inspect `gateway_set_approval_handler` in the host process |
| Tokens differ between bus and gateway | vault not initialised, each fell back to its own random token | `argus_vault.vault_init()` before `bus_start` / `gateway_start` |

---

## License

GPL v3 — see `../../LICENSE`.
