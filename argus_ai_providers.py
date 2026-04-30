# Copyright (C) 2026 NetGuard Pro Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""
Argus AI side panel — direct BYOK (bring-your-own-key) providers.

This module is the in-process counterpart to ``netguard_ai_server.py``. It
lets the Argus AI panel call Claude / OpenAI / Gemini directly using the
user's own API keys, without depending on the local HTTP backend.

Why a separate module?
----------------------
``argus_pyqt.py`` already weighs ~5500 lines. Keeping the provider plumbing
(urllib HTTP, SSE parsing, settings JSON I/O) here means:

* It can be unit-tested in isolation with mocked urllib (no Qt needed).
* If the user never enters API keys, the import is dormant and the legacy
  ``netguard_ai_server.py`` flow keeps working unchanged.
* Other Argus code (e.g. reader-mode summariser) can reuse the providers
  without pulling in QtWidgets.

Design notes
------------
* Streaming: Anthropic and OpenAI both speak SSE. We parse on a background
  thread (the AI worker is already on a thread) and emit text deltas via
  the ``on_chunk`` callback. Gemini's ``streamGenerateContent`` returns
  newline-delimited JSON arrays which is fiddlier to parse correctly under
  network jitter; we ship Gemini in blocking mode for now and surface that
  via ``Provider.supports_streaming``.

* Storage: ``argus_data/ai_settings.json`` is plain JSON. The Argus
  Secret Vault is a separate sibling task — when it lands, we'll hook
  ``load_settings`` / ``save_settings`` to pull from the vault first and
  fall back to plain JSON. Until then keys land on disk in cleartext, so
  the file is gitignored via the existing argus_data/ rule.

* Errors: providers never raise inside ``call``. They return a dict
  ``{"ok": bool, "reply": str, "error": str | None, "tokens_*": int}``
  to mirror the contract used by ``netguard_ai_server.py`` so the UI
  doesn't have to special-case the source.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Optional


# ── Settings I/O ─────────────────────────────────────────────────────────

DEFAULT_SETTINGS_PATH = Path(__file__).resolve().parent / "argus_data" / "ai_settings.json"
DEFAULT_VAULT_ROOT = Path(__file__).resolve().parent / "argus_data" / "vault"


# ── Secret Vault hookup ──────────────────────────────────────────────────
# The vault is loaded lazily so the import of this module stays cheap and
# tests that don't touch vault behaviour aren't forced to install
# argon2-cffi / pywin32 / keyring. ``_VAULT_AVAILABLE`` reflects whether
# ``secret_vault`` could be imported AND its required runtime deps are
# present (argon2-cffi + keyring). The vault module itself uses
# soft-imports so it loads even when those deps are missing — checking
# the module-level ``_HAS_ARGON2`` / ``_HAS_KEYRING`` flags is what tells
# us unlocking can actually succeed. Without both, the dialog falls back
# to plaintext mode with a banner instead of popping a master-password
# prompt that would just fail.
try:
    import secret_vault as _secret_vault_mod  # noqa: F401
    _VAULT_AVAILABLE = bool(
        getattr(_secret_vault_mod, "_HAS_ARGON2", False)
        and getattr(_secret_vault_mod, "_HAS_KEYRING", False)
    )
except Exception:
    _secret_vault_mod = None  # type: ignore[assignment]
    _VAULT_AVAILABLE = False

_vault_singleton: Optional[Any] = None
_vault_lock = threading.Lock()


def _vault_name(provider: str) -> str:
    """Vault key name convention: ``argus.<provider>.api_key``.

    The vault enforces ``[A-Za-z0-9_.\\-]{1,128}`` for names; ``argus``
    namespaces the entry so a future GeniA / FORGE module can co-exist in
    the same vault file without colliding.
    """
    return f"argus.{provider}.api_key"


def get_vault() -> Optional[Any]:
    """Return the lazy process-wide ``SecretVault`` instance.

    Returns ``None`` when the vault module is unimportable so callers can
    branch into the degraded plaintext path. The vault root is always
    ``argus_data/vault/`` unless overridden via ``SECRET_VAULT_ROOT``
    (which the vault module honours natively).
    """
    global _vault_singleton
    if not _VAULT_AVAILABLE or _secret_vault_mod is None:
        return None
    with _vault_lock:
        if _vault_singleton is None:
            try:
                _vault_singleton = _secret_vault_mod.SecretVault(
                    vault_root=DEFAULT_VAULT_ROOT,
                )
            except Exception:
                # Construction failure (e.g. argon2 missing under strict
                # check) — surface as "no vault" so the dialog degrades.
                return None
        return _vault_singleton


def _reset_vault_singleton() -> None:
    """Drop the cached vault — used by tests that swap roots between cases."""
    global _vault_singleton
    with _vault_lock:
        if _vault_singleton is not None:
            try:
                _vault_singleton.lock()
            except Exception:
                pass
        _vault_singleton = None


def vault_initialized() -> bool:
    """True iff a vault file already exists. Does not unlock."""
    v = get_vault()
    if v is None:
        return False
    try:
        return bool(v.exists())
    except Exception:
        return False


def is_vault_unlocked() -> bool:
    """True iff the vault is currently unlocked (in this process)."""
    v = get_vault()
    if v is None:
        return False
    try:
        return bool(v.is_unlocked())
    except Exception:
        return False


def unlock_vault(master: str) -> bool:
    """Try to unlock the vault. Returns False on bad master / missing
    deps / corrupted file. Never raises — the caller surfaces a UI error.
    """
    v = get_vault()
    if v is None:
        return False
    try:
        if not v.exists():
            return False
        v.unlock(master)
        return True
    except Exception:
        return False


def init_vault(master: str) -> bool:
    """Create a new vault under the configured root. Returns True on
    success. Raises nothing — the dialog inspects ``vault_initialized()``
    and shows a clear error if False is returned.
    """
    v = get_vault()
    if v is None:
        return False
    try:
        v.init(master)
        return True
    except Exception:
        return False


def lock_vault() -> None:
    """Force-lock the vault. Idempotent."""
    v = get_vault()
    if v is None:
        return
    try:
        v.lock()
    except Exception:
        pass


def secret_exists(name: str) -> bool:
    """True iff a secret with this vault-name exists. Requires unlock."""
    v = get_vault()
    if v is None or not is_vault_unlocked():
        return False
    try:
        for entry in v.list():
            if entry.get("name") == name:
                return True
    except Exception:
        return False
    return False


def get_secret(name: str) -> Optional[str]:
    """Return the secret named ``name`` from the vault, or ``None`` if
    the vault is missing / locked / the entry doesn't exist.

    Never raises so a temporary backend hiccup just degrades to "no key
    configured" rather than crashing the AI panel.
    """
    v = get_vault()
    if v is None:
        return None
    try:
        if not v.is_unlocked():
            return None
        return v.get(name)
    except Exception:
        return None


def set_secret(name: str, value: str) -> bool:
    """Persist ``value`` under ``name`` in the vault. Returns True on
    success. Caller must have already unlocked.
    """
    v = get_vault()
    if v is None:
        return False
    try:
        if not v.is_unlocked():
            return False
        v.set(name, value, metadata={"source": "argus.ai_settings"})
        return True
    except Exception:
        return False


def get_provider_key(provider: str) -> Optional[str]:
    """Lookup the per-provider API key for ``provider``.

    Resolution order:

    1. Environment variable (env wins so headless / CI setups keep working).
    2. Vault entry ``argus.<provider>.api_key`` (when unlocked).
    3. Plaintext key persisted in ``ai_settings.json`` under
       ``providers[provider].api_key``. This branch is the fallback for
       boxes with no vault deps — once the vault is initialized the
       migration moves the keys out and this branch returns None.
    """
    prov = PROVIDERS.get(provider)
    if prov is not None:
        for env in prov.env_keys:
            v = os.environ.get(env)
            if v and v.strip():
                return v.strip()
    s = get_secret(_vault_name(provider))
    if isinstance(s, str) and s.strip():
        return s.strip()
    settings = load_settings()
    plain = (
        ((settings.get("providers") or {}).get(provider) or {})
        .get("api_key")
    )
    return plain.strip() if isinstance(plain, str) and plain.strip() else None


def save_provider_key(provider: str, key: str) -> bool:
    """Persist ``key`` for ``provider`` into the vault. Returns False if
    the vault isn't available or unlocked — the dialog will fall back to
    plaintext storage and show a warning banner in that case.
    """
    return set_secret(_vault_name(provider), key)


def migrate_ai_settings_to_vault(path: Optional[Path] = None) -> int:
    """Move plaintext API keys out of ``ai_settings.json`` and into the
    vault. Returns the number of keys migrated.

    Idempotent. Safe to call on every dialog open. Requires the vault to
    be unlocked already; returns 0 otherwise so the caller doesn't block
    the UI on missed unlocks.

    The original JSON file is rewritten with a backup at
    ``<path>.pre-vault.bak`` (only on first migration) and the
    ``api_key`` field is replaced with ``"api_key_in_vault": true``.
    """
    if not is_vault_unlocked():
        return 0
    p = Path(path) if path else DEFAULT_SETTINGS_PATH
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    providers = data.get("providers", {}) if isinstance(data, dict) else {}
    if not isinstance(providers, dict):
        return 0

    placeholders = {
        "sk-ant-REPLACE-ME",
        "sk-REPLACE-ME",
        "AIza-REPLACE-ME",
        "",
    }
    migrated = 0
    for prov_name, prov_cfg in list(providers.items()):
        if not isinstance(prov_cfg, dict):
            continue
        key = prov_cfg.get("api_key", "")
        if prov_cfg.get("api_key_in_vault") is True and not key:
            continue
        if not isinstance(key, str) or key.strip() == "" or key in placeholders:
            continue
        if save_provider_key(prov_name, key.strip()):
            prov_cfg.pop("api_key", None)
            prov_cfg["api_key_in_vault"] = True
            migrated += 1

    if migrated > 0:
        backup = p.with_suffix(p.suffix + ".pre-vault.bak")
        try:
            if not backup.exists():
                backup.write_bytes(p.read_bytes())
        except OSError:
            pass
        try:
            p.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass
    return migrated


def load_settings(path: Optional[Path] = None) -> dict:
    """Load the AI settings JSON. Returns ``{}`` when the file is missing
    or unreadable — the caller checks individual fields.

    Schema::

        {
          "provider": "anthropic" | "openai" | "google",
          "providers": {
            "anthropic": {"api_key": "...", "model": "claude-sonnet-4-6"},
            "openai":    {"api_key": "...", "model": "gpt-4o"},
            "google":    {"api_key": "...", "model": "gemini-2.0-flash"}
          }
        }
    """
    p = Path(path) if path else DEFAULT_SETTINGS_PATH
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(data: dict, path: Optional[Path] = None) -> None:
    """Persist the settings JSON. Creates the parent directory if needed
    and silently swallows OSError so a read-only disk doesn't crash the UI.
    """
    p = Path(path) if path else DEFAULT_SETTINGS_PATH
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass


def has_any_api_key(settings: Optional[dict] = None) -> bool:
    """True iff at least one provider has a non-empty API key configured.

    This is what the AI panel uses to decide between direct-BYOK and the
    legacy ``netguard_ai_server.py`` HTTP backend. Environment variables
    (``ANTHROPIC_API_KEY`` etc.) also count as "configured" so existing
    headless setups keep working. After the vault hookup the vault is
    also consulted (if unlocked) so a freshly-migrated install isn't
    forced back through the legacy server when its keys live in the
    vault and not in the JSON.
    """
    s = settings if settings is not None else load_settings()
    for env_keys in (
        ("ANTHROPIC_API_KEY",),
        ("OPENAI_API_KEY",),
        ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    ):
        for k in env_keys:
            if os.environ.get(k):
                return True
    providers = s.get("providers", {}) or {}
    for prov_name, prov in providers.items():
        if isinstance(prov, dict):
            key = prov.get("api_key")
            if isinstance(key, str) and key.strip():
                return True
            # Even if the JSON only has a "api_key_in_vault: true"
            # marker, count that as "configured" so the panel uses
            # direct-BYOK when the vault is currently unlocked.
            if prov.get("api_key_in_vault") is True and is_vault_unlocked():
                if secret_exists(_vault_name(prov_name)):
                    return True
    return False


# ── Provider base class ──────────────────────────────────────────────────

DEFAULT_MAX_TOKENS = 1024


class ArgusProvider(ABC):
    """Direct-BYOK provider. Subclasses implement ``call`` (blocking) and
    optionally ``call_stream`` (streaming). The contract mirrors
    ``netguard_ai_server.py``'s ``Provider`` so callers can swap freely.
    """

    name: str = ""
    label: str = ""
    default_model: str = ""
    models: list[str] = []
    env_keys: list[str] = []
    supports_streaming: bool = False

    @abstractmethod
    def call(self, messages: list[dict], system: str, model: str,
             api_key: str, timeout: int = 120) -> dict:
        ...

    def call_stream(self, messages: list[dict], system: str, model: str,
                    api_key: str, on_chunk: Callable[[str], None],
                    timeout: int = 120) -> dict:
        """Default fallback: emit the whole reply as a single chunk after
        a blocking ``call``. Subclasses with real SSE override this.
        """
        result = self.call(messages, system, model, api_key, timeout=timeout)
        if result.get("ok") and result.get("reply"):
            try:
                on_chunk(result["reply"])
            except Exception:
                pass
        return result

    # Resolution helpers ----------------------------------------------------

    def get_api_key(self, settings: dict) -> Optional[str]:
        """Resolve API key: env var → settings JSON → vault.

        Order matters: env vars win for headless / CI use. Settings JSON
        comes next for backward compatibility with installs that haven't
        migrated to the vault yet. The vault is consulted last so a
        locked vault (or missing vault deps) silently falls through to
        the JSON path. The env-var path matches netguard_ai_server.py so
        the same keys work in both contexts.
        """
        for env in self.env_keys:
            v = os.environ.get(env)
            if v and v.strip():
                return v.strip()
        prov = (settings.get("providers") or {}).get(self.name) or {}
        k = prov.get("api_key")
        if isinstance(k, str) and k.strip():
            return k.strip()
        # Vault fallback (unlocked + has entry).
        secret = get_secret(_vault_name(self.name))
        if isinstance(secret, str) and secret.strip():
            return secret.strip()
        return None

    def get_model(self, settings: dict) -> str:
        prov = (settings.get("providers") or {}).get(self.name) or {}
        m = prov.get("model")
        return m if isinstance(m, str) and m.strip() else self.default_model


# ── HTTP helpers ─────────────────────────────────────────────────────────

def _http_post(url: str, headers: dict, body: dict, timeout: int = 120) -> tuple[int, str]:
    """Blocking POST returning ``(status, raw_text)``. Hands network errors
    back as a non-2xx so callers don't need to ``try``/``except`` urllib."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, str(e)


def _http_post_stream(url: str, headers: dict, body: dict,
                      timeout: int = 120):
    """Yield raw SSE lines (already stripped of trailing newline). The
    caller does the SSE event reassembly because the format differs
    slightly between Anthropic and OpenAI.

    Yields ``("status", code)`` first when status >= 400 to let the caller
    surface an HTTP error without buffering the whole body.
    """
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        yield ("status", e.code)
        try:
            yield ("body", e.read().decode("utf-8", errors="replace"))
        except Exception:
            pass
        return
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        yield ("error", str(e))
        return
    if resp.status >= 400:
        yield ("status", resp.status)
        return
    try:
        for raw in resp:
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            yield ("line", line)
    finally:
        try:
            resp.close()
        except Exception:
            pass


# ── Anthropic / Claude ───────────────────────────────────────────────────

class AnthropicProvider(ArgusProvider):
    name = "anthropic"
    label = "Claude"
    default_model = "claude-sonnet-4-6"
    models = [
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
    ]
    env_keys = ["ANTHROPIC_API_KEY"]
    supports_streaming = True
    endpoint = "https://api.anthropic.com/v1/messages"
    api_version = "2023-06-01"

    def _headers(self, api_key: str) -> dict:
        return {
            "x-api-key": api_key,
            "anthropic-version": self.api_version,
            "content-type": "application/json",
        }

    def _body(self, messages: list[dict], system: str, model: str,
              stream: bool) -> dict:
        body: dict = {
            "model": model,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "messages": messages,
        }
        if system:
            body["system"] = system
        if stream:
            body["stream"] = True
        return body

    def call(self, messages, system, model, api_key, timeout=120):
        body = self._body(messages, system, model, stream=False)
        status, raw = _http_post(self.endpoint, self._headers(api_key),
                                  body, timeout=timeout)
        if status == 0:
            return {"ok": False, "error": "network", "reply": raw,
                    "provider": self.name}
        if status >= 400:
            return {"ok": False, "error": f"http_{status}", "reply": raw,
                    "provider": self.name}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad_json", "reply": raw,
                    "provider": self.name}
        text_parts = [b.get("text", "") for b in parsed.get("content", [])
                       if b.get("type") == "text"]
        usage = parsed.get("usage", {})
        return {
            "ok": True,
            "reply": "\n".join(t for t in text_parts if t),
            "tokens_in": usage.get("input_tokens", 0),
            "tokens_out": usage.get("output_tokens", 0),
            "model": parsed.get("model", model),
            "provider": self.name,
        }

    def call_stream(self, messages, system, model, api_key, on_chunk,
                    timeout=120):
        """Anthropic SSE format::

            event: content_block_delta
            data: {"type":"content_block_delta",
                   "delta":{"type":"text_delta","text":"hello"}}

        We collect chunks via ``on_chunk(delta)`` and accumulate the full
        reply for the final ``done`` payload. Errors during the stream
        return early with a partial reply marked ``ok=True`` so the user
        still sees what they got before the connection died.
        """
        body = self._body(messages, system, model, stream=True)
        full_text: list[str] = []
        tokens_in = 0
        tokens_out = 0
        for kind, payload in _http_post_stream(self.endpoint,
                                                self._headers(api_key),
                                                body, timeout=timeout):
            if kind == "status":
                return {"ok": False, "error": f"http_{payload}",
                        "reply": "", "provider": self.name}
            if kind == "error":
                return {"ok": False, "error": "network",
                        "reply": str(payload), "provider": self.name}
            if kind == "body":
                return {"ok": False, "error": "http_error",
                        "reply": str(payload), "provider": self.name}
            line = payload  # SSE line
            if not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if not data_str or data_str == "[DONE]":
                continue
            try:
                evt = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            etype = evt.get("type")
            if etype == "content_block_delta":
                delta = evt.get("delta") or {}
                if delta.get("type") == "text_delta":
                    text = delta.get("text", "")
                    if text:
                        full_text.append(text)
                        try:
                            on_chunk(text)
                        except Exception:
                            pass
            elif etype == "message_delta":
                usage = evt.get("usage") or {}
                tokens_out = usage.get("output_tokens", tokens_out)
            elif etype == "message_start":
                msg = evt.get("message") or {}
                usage = msg.get("usage") or {}
                tokens_in = usage.get("input_tokens", tokens_in)
        return {
            "ok": True,
            "reply": "".join(full_text),
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "model": model,
            "provider": self.name,
        }


# ── OpenAI / GPT ─────────────────────────────────────────────────────────

class OpenAIProvider(ArgusProvider):
    name = "openai"
    label = "GPT"
    default_model = "gpt-4o"
    models = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1-preview"]
    env_keys = ["OPENAI_API_KEY"]
    supports_streaming = True
    endpoint = "https://api.openai.com/v1/chat/completions"

    def _headers(self, api_key: str) -> dict:
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def _body(self, messages: list[dict], system: str, model: str,
              stream: bool) -> dict:
        msgs: list[dict] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)
        body: dict = {
            "model": model,
            "messages": msgs,
            "max_tokens": DEFAULT_MAX_TOKENS,
        }
        if stream:
            body["stream"] = True
            body["stream_options"] = {"include_usage": True}
        return body

    def call(self, messages, system, model, api_key, timeout=120):
        body = self._body(messages, system, model, stream=False)
        status, raw = _http_post(self.endpoint, self._headers(api_key),
                                  body, timeout=timeout)
        if status == 0:
            return {"ok": False, "error": "network", "reply": raw,
                    "provider": self.name}
        if status >= 400:
            return {"ok": False, "error": f"http_{status}", "reply": raw,
                    "provider": self.name}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad_json", "reply": raw,
                    "provider": self.name}
        choices = parsed.get("choices") or []
        text = ""
        if choices:
            text = (choices[0].get("message") or {}).get("content", "") or ""
        usage = parsed.get("usage") or {}
        return {
            "ok": True,
            "reply": text,
            "tokens_in": usage.get("prompt_tokens", 0),
            "tokens_out": usage.get("completion_tokens", 0),
            "model": parsed.get("model", model),
            "provider": self.name,
        }

    def call_stream(self, messages, system, model, api_key, on_chunk,
                    timeout=120):
        """OpenAI SSE: each ``data: {...}`` line carries one chat completion
        chunk with ``choices[0].delta.content``. The terminator is
        ``data: [DONE]``. ``stream_options.include_usage`` makes the final
        chunk before [DONE] contain ``usage``."""
        body = self._body(messages, system, model, stream=True)
        full_text: list[str] = []
        tokens_in = 0
        tokens_out = 0
        for kind, payload in _http_post_stream(self.endpoint,
                                                self._headers(api_key),
                                                body, timeout=timeout):
            if kind == "status":
                return {"ok": False, "error": f"http_{payload}",
                        "reply": "", "provider": self.name}
            if kind == "error":
                return {"ok": False, "error": "network",
                        "reply": str(payload), "provider": self.name}
            if kind == "body":
                return {"ok": False, "error": "http_error",
                        "reply": str(payload), "provider": self.name}
            line = payload
            if not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if not data_str or data_str == "[DONE]":
                continue
            try:
                evt = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            choices = evt.get("choices") or []
            if choices:
                delta = choices[0].get("delta") or {}
                text = delta.get("content")
                if isinstance(text, str) and text:
                    full_text.append(text)
                    try:
                        on_chunk(text)
                    except Exception:
                        pass
            usage = evt.get("usage")
            if isinstance(usage, dict):
                tokens_in = usage.get("prompt_tokens", tokens_in)
                tokens_out = usage.get("completion_tokens", tokens_out)
        return {
            "ok": True,
            "reply": "".join(full_text),
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "model": model,
            "provider": self.name,
        }


# ── Google / Gemini ──────────────────────────────────────────────────────

class GoogleProvider(ArgusProvider):
    name = "google"
    label = "Gemini"
    default_model = "gemini-2.0-flash"
    models = [
        "gemini-2.0-flash",
        "gemini-2.0-pro",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
    ]
    env_keys = ["GOOGLE_API_KEY", "GEMINI_API_KEY"]
    # Gemini's streamGenerateContent emits a JSON array streamed as
    # newline-delimited objects which is fragile under reverse proxies.
    # Ship blocking only for now; ``call_stream`` falls back to the base
    # implementation (one big chunk).
    supports_streaming = False

    def _endpoint(self, model: str, api_key: str) -> str:
        return (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={urllib.parse.quote(api_key)}"
        )

    def call(self, messages, system, model, api_key, timeout=120):
        contents = []
        for m in messages:
            role = "user" if m.get("role") == "user" else "model"
            contents.append({"role": role,
                             "parts": [{"text": m.get("content", "")}]})
        body: dict = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": DEFAULT_MAX_TOKENS},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        status, raw = _http_post(self._endpoint(model, api_key),
                                  {"Content-Type": "application/json"},
                                  body, timeout=timeout)
        if status == 0:
            return {"ok": False, "error": "network", "reply": raw,
                    "provider": self.name}
        if status >= 400:
            return {"ok": False, "error": f"http_{status}", "reply": raw,
                    "provider": self.name}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad_json", "reply": raw,
                    "provider": self.name}
        cands = parsed.get("candidates") or []
        text = ""
        if cands:
            parts = (cands[0].get("content") or {}).get("parts") or []
            text = "".join(p.get("text", "") for p in parts)
        usage = parsed.get("usageMetadata") or {}
        return {
            "ok": True,
            "reply": text,
            "tokens_in": usage.get("promptTokenCount", 0),
            "tokens_out": usage.get("candidatesTokenCount", 0),
            "model": model,
            "provider": self.name,
        }


# ── Registry ─────────────────────────────────────────────────────────────

PROVIDERS: dict[str, ArgusProvider] = {
    "anthropic": AnthropicProvider(),
    "openai":    OpenAIProvider(),
    "google":    GoogleProvider(),
}


def get_provider(name: str) -> ArgusProvider:
    """Return the provider for ``name`` or fall back to Anthropic.

    Used by the AI worker to pick which provider serves the next message
    based on the value persisted in ``argus_data/ai_settings.json``.
    """
    return PROVIDERS.get(name) or PROVIDERS["anthropic"]


def active_provider(settings: Optional[dict] = None) -> ArgusProvider:
    s = settings if settings is not None else load_settings()
    return get_provider(s.get("provider", "anthropic"))


# ── Slash-command parsing ────────────────────────────────────────────────

KNOWN_SLASH_COMMANDS = ("/url", "/selection", "/screenshot")


def parse_slash_commands(text: str) -> tuple[list[str], str]:
    """Strip leading slash commands from a user message.

    Returns ``(commands, residual)`` where ``commands`` is the ordered list
    of recognized commands found at the start of the message (one per
    leading whitespace-separated token) and ``residual`` is the rest of
    the message with those tokens removed.

    Only commands at the *start* of the message are extracted. A command
    elsewhere in the message body is left in place — users can still type
    "what does /url mean" without triggering injection.

    Examples
    --------
    >>> parse_slash_commands("/url summarize this")
    (['/url'], 'summarize this')
    >>> parse_slash_commands("/url /selection compare")
    (['/url', '/selection'], 'compare')
    >>> parse_slash_commands("hello /url world")
    ([], 'hello /url world')
    >>> parse_slash_commands("/unknown /url x")
    ([], '/unknown /url x')
    """
    cmds: list[str] = []
    residual = text.lstrip()
    while True:
        # Peek at the first whitespace-separated token.
        sp = residual.split(None, 1)
        if not sp:
            break
        first = sp[0]
        if first in KNOWN_SLASH_COMMANDS:
            cmds.append(first)
            residual = sp[1].lstrip() if len(sp) == 2 else ""
        else:
            break
    return cmds, residual
