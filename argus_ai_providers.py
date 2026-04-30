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
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional


# ── Settings I/O ─────────────────────────────────────────────────────────

DEFAULT_SETTINGS_PATH = Path(__file__).resolve().parent / "argus_data" / "ai_settings.json"


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
    headless setups keep working.
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
    for prov in providers.values():
        if isinstance(prov, dict):
            key = prov.get("api_key")
            if isinstance(key, str) and key.strip():
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
        """Resolve API key: env var first, then settings JSON. The env-var
        path matches netguard_ai_server.py so the same keys work in both
        contexts."""
        for env in self.env_keys:
            v = os.environ.get(env)
            if v and v.strip():
                return v.strip()
        prov = (settings.get("providers") or {}).get(self.name) or {}
        k = prov.get("api_key")
        return k.strip() if isinstance(k, str) and k.strip() else None

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
