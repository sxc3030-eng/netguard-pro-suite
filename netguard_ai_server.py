"""NetGuard Pro — AI window backend.

Local HTTP server that bridges the AI window (netguard_ai.html) to the
Anthropic Claude API. Built around a pluggable capability registry so
future Mythos workloads (analyse / fix / certify) can be added by
registering a new entry instead of rewriting the server.
"""
from __future__ import annotations

import datetime as _dt
import http.server
import json
import os
import socketserver
import threading
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
SETTINGS_FILE = ROOT / "netguard_ai_settings.json"
AUDIT_DIR = ROOT / "reports"
AUDIT_LOG = AUDIT_DIR / "ai_audit.log"
CAPTURES_DIR = ROOT / "captures"

ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-6-20251022"
DEFAULT_MAX_TOKENS = 2048
DEFAULT_PORT = 8770

SYSTEM_PROMPT = (
    "Tu es l'assistant IA de NetGuard Pro, une suite de cybersécurité réseau. "
    "Tu aides l'utilisateur à comprendre l'état de son réseau, identifier les menaces, "
    "et recommander des actions concrètes. "
    "Réponds en français, sois direct et opérationnel. "
    "Quand tu reçois des données de scan ou de capture, analyse-les comme un analyste SOC senior. "
    "Mets en évidence les anomalies, classe-les par sévérité (critique / élevée / moyenne / faible), "
    "et termine toujours par 1-3 actions recommandées."
)


def _load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {}


def _api_key() -> str | None:
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env:
        return env.strip()
    s = _load_settings()
    k = s.get("anthropic_api_key")
    return k.strip() if isinstance(k, str) and k.strip() else None


def _model() -> str:
    return _load_settings().get("model", DEFAULT_MODEL)


def _audit(event: str, payload: dict) -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    record = {"ts": _dt.datetime.utcnow().isoformat() + "Z", "event": event, **payload}
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _read_recent_captures(limit: int = 5) -> list[dict]:
    if not CAPTURES_DIR.exists():
        return []
    files = sorted(CAPTURES_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    out: list[dict] = []
    for p in files[:limit]:
        try:
            out.append({"file": p.name, "data": json.loads(p.read_text(encoding="utf-8"))})
        except (json.JSONDecodeError, OSError):
            continue
    return out


def _read_recent_reports(limit: int = 5) -> list[dict]:
    if not AUDIT_DIR.exists():
        return []
    files = sorted(
        (p for p in AUDIT_DIR.glob("*.json") if p.name != AUDIT_LOG.name),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    out: list[dict] = []
    for p in files[:limit]:
        try:
            out.append({"file": p.name, "data": json.loads(p.read_text(encoding="utf-8"))})
        except (json.JSONDecodeError, OSError):
            continue
    return out


def _call_claude(messages: list[dict], system: str | None = None) -> dict:
    key = _api_key()
    if not key:
        return {"ok": False, "error": "missing_api_key", "reply": ""}
    body = {
        "model": _model(),
        "max_tokens": DEFAULT_MAX_TOKENS,
        "messages": messages,
    }
    if system:
        body["system"] = system
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        ANTHROPIC_ENDPOINT,
        data=data,
        method="POST",
        headers={
            "x-api-key": key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"http_{e.code}", "reply": e.read().decode("utf-8", errors="replace")}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "error": "network", "reply": str(e)}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"ok": False, "error": "bad_json", "reply": raw}
    text_parts = [b.get("text", "") for b in parsed.get("content", []) if b.get("type") == "text"]
    usage = parsed.get("usage", {})
    return {
        "ok": True,
        "reply": "\n".join(t for t in text_parts if t),
        "tokens_in": usage.get("input_tokens", 0),
        "tokens_out": usage.get("output_tokens", 0),
        "model": parsed.get("model", _model()),
    }


def cap_analyze_network(_: dict) -> dict:
    captures = _read_recent_captures()
    reports = _read_recent_reports()
    if not captures and not reports:
        ctx = "Aucune capture ni rapport récent disponible dans `captures/` ou `reports/`."
    else:
        ctx = json.dumps(
            {"captures_recents": captures, "rapports_recents": reports},
            ensure_ascii=False,
            indent=2,
        )[:30000]
    user = (
        "Analyse l'état de mon réseau à partir des données ci-dessous. "
        "Identifie les anomalies, classe par sévérité, et propose 3 actions concrètes.\n\n"
        f"DONNÉES:\n{ctx}"
    )
    return _call_claude([{"role": "user", "content": user}], system=SYSTEM_PROMPT)


def cap_explain_threats(args: dict) -> dict:
    threats = args.get("threats")
    if not threats:
        threats = _read_recent_reports()
    user = (
        "Explique en langage clair les menaces suivantes à un utilisateur non-expert. "
        "Pour chaque menace : ce que c'est, le risque réel, l'urgence.\n\n"
        f"MENACES:\n{json.dumps(threats, ensure_ascii=False, indent=2)[:25000]}"
    )
    return _call_claude([{"role": "user", "content": user}], system=SYSTEM_PROMPT)


def cap_recommend_actions(args: dict) -> dict:
    context = args.get("context") or {
        "captures": _read_recent_captures(3),
        "reports": _read_recent_reports(3),
    }
    user = (
        "À partir de l'état réseau ci-dessous, donne-moi un plan d'action priorisé "
        "(P0 immédiat / P1 cette semaine / P2 ce mois). "
        "Sois concret : commandes, configs, pas de blabla.\n\n"
        f"ÉTAT:\n{json.dumps(context, ensure_ascii=False, indent=2)[:25000]}"
    )
    return _call_claude([{"role": "user", "content": user}], system=SYSTEM_PROMPT)


CAPABILITIES: dict[str, dict[str, Any]] = {
    "analyze_network": {
        "label": "Analyser mon réseau",
        "description": "Analyse les dernières captures et rapports puis classe les anomalies par sévérité.",
        "handler": cap_analyze_network,
    },
    "explain_threats": {
        "label": "Expliquer les menaces",
        "description": "Vulgarise les menaces récentes pour un public non-technique.",
        "handler": cap_explain_threats,
    },
    "recommend_actions": {
        "label": "Recommander des actions",
        "description": "Plan d'action priorisé P0/P1/P2 basé sur l'état actuel.",
        "handler": cap_recommend_actions,
    },
}


def register_capability(name: str, label: str, description: str, handler: Callable[[dict], dict]) -> None:
    CAPABILITIES[name] = {"label": label, "description": description, "handler": handler}


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # silence default logging
        return

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/?"):
            self.path = "/netguard_ai.html"
            return super().do_GET()
        if self.path == "/api/health":
            return self._json(200, {"ok": True, "has_key": bool(_api_key()), "model": _model()})
        if self.path == "/api/capabilities":
            return self._json(200, {
                "capabilities": [
                    {"name": n, "label": c["label"], "description": c["description"]}
                    for n, c in CAPABILITIES.items()
                ]
            })
        return super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/chat":
            payload = self._read_json()
            messages = payload.get("messages") or []
            user_msg = payload.get("message")
            if user_msg:
                messages.append({"role": "user", "content": user_msg})
            if not messages:
                return self._json(400, {"ok": False, "error": "empty_messages"})
            result = _call_claude(messages, system=SYSTEM_PROMPT)
            _audit("chat", {"messages": len(messages), "ok": result.get("ok"), "tokens_in": result.get("tokens_in"), "tokens_out": result.get("tokens_out")})
            return self._json(200, result)
        if self.path.startswith("/api/capability/"):
            name = self.path[len("/api/capability/"):]
            cap = CAPABILITIES.get(name)
            if not cap:
                return self._json(404, {"ok": False, "error": "unknown_capability", "available": list(CAPABILITIES)})
            args = self._read_json()
            result = cap["handler"](args)
            _audit("capability", {"name": name, "ok": result.get("ok"), "tokens_in": result.get("tokens_in"), "tokens_out": result.get("tokens_out")})
            return self._json(200, result)
        return self._json(404, {"ok": False, "error": "not_found"})


class _ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run(port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    os.chdir(ROOT)
    server = _ThreadedServer(("127.0.0.1", port), _Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"[NetGuard AI] Server ready on {url}")
    if not _api_key():
        print("[NetGuard AI] WARNING: no ANTHROPIC_API_KEY set (env var or netguard_ai_settings.json).")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NetGuard Pro — AI window backend")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    run(port=args.port, open_browser=not args.no_browser)
