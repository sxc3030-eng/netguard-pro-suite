"""NetGuard Pro — AI window backend.

Local HTTP server that bridges the AI window (netguard_ai.html) to one of
several LLM providers (Anthropic, OpenAI, Google). Built around a pluggable
provider registry + a pluggable capability registry so future Mythos workloads
(analyse / fix / certify) can be added by registering an entry instead of
rewriting the server.
"""
from __future__ import annotations

import datetime as _dt
import http.server
import json
import os
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
SETTINGS_FILE = ROOT / "netguard_ai_settings.json"
AUDIT_DIR = ROOT / "reports"
AUDIT_LOG = AUDIT_DIR / "ai_audit.log"
ACTIONS_LOG = AUDIT_DIR / "ai_actions.log"
CAPTURES_DIR = ROOT / "captures"

NETGUARD_WS_URL = os.environ.get("NETGUARD_WS_URL", "ws://localhost:8765")

DEFAULT_PORT = 8770
DEFAULT_MAX_TOKENS = 2048

SYSTEM_PROMPTS = {
    "fr": (
        "Tu es l'assistant IA de NetGuard Pro, une suite de cybersécurité réseau. "
        "Tu aides l'utilisateur à comprendre l'état de son réseau, identifier les menaces, "
        "et recommander des actions concrètes. "
        "Réponds en français, sois direct et opérationnel. "
        "Quand tu reçois des données de scan ou de capture, analyse-les comme un analyste SOC senior. "
        "Mets en évidence les anomalies, classe-les par sévérité (critique / élevée / moyenne / faible), "
        "et termine toujours par 1-3 actions recommandées."
    ),
    "en": (
        "You are the AI assistant for NetGuard Pro, a network cybersecurity suite. "
        "You help the user understand the state of their network, identify threats, "
        "and recommend concrete actions. "
        "Answer in English, be direct and operational. "
        "When you receive scan or capture data, analyze it like a senior SOC analyst. "
        "Highlight anomalies, classify them by severity (critical / high / medium / low), "
        "and always end with 1-3 recommended actions."
    ),
    "es": (
        "Eres el asistente IA de NetGuard Pro, una suite de ciberseguridad de red. "
        "Ayudas al usuario a comprender el estado de su red, identificar amenazas "
        "y recomendar acciones concretas. "
        "Responde en español, sé directo y operacional. "
        "Cuando recibas datos de escaneo o captura, analízalos como un analista SOC senior. "
        "Destaca las anomalías, clasifícalas por gravedad (crítica / alta / media / baja) "
        "y termina siempre con 1-3 acciones recomendadas."
    ),
}


# ── Persistent AI memory (cross-session) ────────────────────────────────────
_AI_MEMORY_FILE = ROOT / "netguard_ai_memory.md"
_AI_MEMORY_MAX_BYTES = 60_000   # truncate from top if larger (newest entries are kept)
_AI_MEMORY_VALID_SECTIONS = ("Findings", "Decisions", "Context")


def _read_ai_memory() -> str:
    try:
        text = _AI_MEMORY_FILE.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return ""
    if len(text.encode("utf-8")) > _AI_MEMORY_MAX_BYTES:
        # Keep only last 800 lines so prompt stays bounded
        lines = text.splitlines()
        text = "\n".join(lines[-800:])
    return text


def _append_ai_memory(section: str, note: str) -> bool:
    """Insert a timestamped note at the top of `section` (newest first). Creates file/section if missing."""
    if section not in _AI_MEMORY_VALID_SECTIONS:
        return False
    note = (note or "").strip()
    if not note:
        return False
    # Cap a single note size
    if len(note) > 1000:
        note = note[:1000] + "…"
    try:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        entry = f"- [{ts}] {note}"
        try:
            text = _AI_MEMORY_FILE.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            text = ""
        marker = f"## {section}"
        if not text:
            text = (
                "# NetGuard AI Memory\n\n"
                "_Persistent across sessions. Updated by the AI via the `save_memory_note` tool._\n\n"
                "## Findings\n\n"
                "## Decisions\n\n"
                "## Context\n\n"
            )
        if marker in text:
            idx = text.find(marker)
            eol = text.find("\n", idx) + 1
            # Skip blank lines right after the marker
            while eol < len(text) and text[eol] == "\n":
                eol += 1
            text = text[:eol] + entry + "\n" + text[eol:]
        else:
            text += f"\n{marker}\n\n{entry}\n"
        _AI_MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _AI_MEMORY_FILE.write_text(text, encoding="utf-8")
        try:
            os.chmod(_AI_MEMORY_FILE, 0o600)
        except OSError:
            pass
        return True
    except OSError:
        return False


def _system_prompt(lang: str | None) -> str:
    base = SYSTEM_PROMPTS.get((lang or "fr").lower(), SYSTEM_PROMPTS["fr"])
    memory = _read_ai_memory()
    memory_intro = {
        "fr": (
            "\n\n=== MEMOIRE PERSISTANTE (entre sessions) ===\n"
            "Notes sauvegardees lors de conversations precedentes avec cet utilisateur. "
            "Traite-les comme ta memoire long-terme : findings confirmes, investigations en cours, "
            "preferences utilisateur, decisions passees. Reference-les quand pertinent.\n\n"
        ),
        "en": (
            "\n\n=== PERSISTENT MEMORY (across sessions) ===\n"
            "Notes saved from previous conversations with this user. "
            "Treat as your long-term memory: confirmed findings, ongoing investigations, "
            "user preferences, prior decisions. Reference when relevant.\n\n"
        ),
        "es": (
            "\n\n=== MEMORIA PERSISTENTE (entre sesiones) ===\n"
            "Notas guardadas de conversaciones anteriores con este usuario. "
            "Tratalas como tu memoria a largo plazo: hallazgos confirmados, investigaciones en curso, "
            "preferencias del usuario, decisiones previas. Referencia cuando sea relevante.\n\n"
        ),
    }.get((lang or "fr").lower(), "\n\n=== PERSISTENT MEMORY ===\n\n")

    memory_outro = {
        "fr": (
            "\n=== FIN MEMOIRE ===\n\n"
            "Quand l'utilisateur partage une donnee qui merite d'etre retenue entre sessions "
            "(IP confirmee, hypothese validee, decision prise), appelle l'outil save_memory_note "
            "(necessite approbation). Sections valides : Findings, Decisions, Context."
        ),
        "en": (
            "\n=== END MEMORY ===\n\n"
            "When the user shares a finding worth remembering across sessions "
            "(confirmed IP, validated hypothesis, decision), call the save_memory_note tool "
            "(needs approval). Valid sections: Findings, Decisions, Context."
        ),
        "es": (
            "\n=== FIN MEMORIA ===\n\n"
            "Cuando el usuario comparta un hallazgo que valga la pena recordar entre sesiones "
            "(IP confirmada, hipotesis validada, decision), llama a la herramienta save_memory_note "
            "(necesita aprobacion). Secciones validas: Findings, Decisions, Context."
        ),
    }.get((lang or "fr").lower(), "\n=== END MEMORY ===\n")

    if memory.strip():
        return base + memory_intro + memory + memory_outro
    empty_hint = {
        "fr": "\n\nMemoire persistante actuellement vide. Quand l'utilisateur partage un fait durable, appelle save_memory_note.",
        "en": "\n\nPersistent memory currently empty. When the user shares lasting context, call save_memory_note.",
        "es": "\n\nMemoria persistente actualmente vacia. Cuando el usuario comparta contexto duradero, llama save_memory_note.",
    }.get((lang or "fr").lower(), "")
    return base + empty_hint


CAP_PROMPTS = {
    "analyze_network": {
        "fr": "Analyse l'état de mon réseau à partir des données ci-dessous. Identifie les anomalies, classe par sévérité, et propose 3 actions concrètes.\n\nDONNÉES:\n{ctx}",
        "en": "Analyze the state of my network from the data below. Identify anomalies, classify by severity, and propose 3 concrete actions.\n\nDATA:\n{ctx}",
        "es": "Analiza el estado de mi red a partir de los datos a continuación. Identifica las anomalías, clasifica por gravedad y propone 3 acciones concretas.\n\nDATOS:\n{ctx}",
    },
    "no_data": {
        "fr": "Aucune capture ni rapport récent disponible dans `captures/` ou `reports/`.",
        "en": "No recent capture or report available in `captures/` or `reports/`.",
        "es": "No hay captura ni informe reciente disponible en `captures/` o `reports/`.",
    },
    "explain_threats": {
        "fr": "Explique en langage clair les menaces suivantes à un utilisateur non-expert. Pour chaque menace : ce que c'est, le risque réel, l'urgence.\n\nMENACES:\n{ctx}",
        "en": "Explain the following threats in plain language for a non-expert user. For each threat: what it is, the real risk, the urgency.\n\nTHREATS:\n{ctx}",
        "es": "Explica en lenguaje claro las siguientes amenazas a un usuario no experto. Para cada amenaza: qué es, el riesgo real, la urgencia.\n\nAMENAZAS:\n{ctx}",
    },
    "recommend_actions": {
        "fr": "À partir de l'état réseau ci-dessous, donne-moi un plan d'action priorisé (P0 immédiat / P1 cette semaine / P2 ce mois). Sois concret : commandes, configs, pas de blabla.\n\nÉTAT:\n{ctx}",
        "en": "From the network state below, give me a prioritized action plan (P0 immediate / P1 this week / P2 this month). Be concrete: commands, configs, no fluff.\n\nSTATE:\n{ctx}",
        "es": "A partir del estado de la red a continuación, dame un plan de acción priorizado (P0 inmediato / P1 esta semana / P2 este mes). Sé concreto: comandos, configs, sin relleno.\n\nESTADO:\n{ctx}",
    },
}


def _cap_prompt(name: str, lang: str | None, ctx: str) -> str:
    bundle = CAP_PROMPTS.get(name, {})
    template = bundle.get((lang or "fr").lower(), bundle.get("fr", ""))
    return template.format(ctx=ctx) if "{ctx}" in template else template


# ── Tools (agent mode — block IPs / clear threats / etc. via NetGuard WS) ──

# Anthropic-format tool schemas. Mirrored to OpenAI/Google in `_tools_for_provider`.
TOOLS = [
    {
        "name": "get_state",
        "description": "Read the current NetGuard Pro state — counters, recent threats, blocked IPs, suspicious sources. Read-only, no side effects. Always safe to call.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "needs_approval": False,
    },
    {
        "name": "list_blocked_ips",
        "description": "Return the list of currently-blocked IPs. Read-only.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "needs_approval": False,
    },
    {
        "name": "block_ip",
        "description": "Add an IP to NetGuard's block list. Requires explicit user approval. Use a clear, specific reason — it is logged.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 or IPv6 address."},
                "reason": {"type": "string", "description": "Why this IP should be blocked (Z-score, attack signature, etc.)."},
            },
            "required": ["ip", "reason"],
        },
        "needs_approval": True,
    },
    {
        "name": "unblock_ip",
        "description": "Remove an IP from NetGuard's block list. Requires explicit user approval.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
        "needs_approval": True,
    },
    {
        "name": "clear_threats",
        "description": "Clear NetGuard's current threats list (does not unblock IPs). Requires explicit user approval.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "needs_approval": True,
    },
    {
        "name": "toggle_auto_block",
        "description": "Toggle NetGuard's automatic IP-blocking feature. Requires explicit user approval.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "needs_approval": True,
    },
    {
        "name": "set_auto_block_hits",
        "description": "Set the threshold (number of hits) that triggers an automatic block. Requires explicit user approval.",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "integer", "minimum": 1, "maximum": 50}},
            "required": ["value"],
        },
        "needs_approval": True,
    },
    {
        "name": "audit_program",
        "description": "Run a configuration audit on NetGuard Pro. Reads settings, blocked IPs, and active rules. Returns structured findings with severity (critical/high/medium/low), category, and a `suggested_fix` field that names a tool you can call next (e.g. block_ip, toggle_auto_block) to remediate. Read-only, no side effects, no approval required.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "needs_approval": False,
    },
    {
        "name": "audit_network",
        "description": "Run a network-state audit. Reads recent threats, top suspicious IPs, traffic anomalies, geo distribution. Returns structured findings with severity and a `suggested_fix` for each (typically block_ip with the offending address). Read-only, no approval required. Pair with the modifying tools to remediate.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "needs_approval": False,
    },
    {
        "name": "read_memory",
        "description": "Read your persistent memory file (notes saved across sessions: confirmed findings, decisions, user context). The current contents are also auto-injected into your system prompt — call this only if you need the full raw text.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "needs_approval": False,
    },
    {
        "name": "save_memory_note",
        "description": "Save a note to persistent memory so it survives across sessions. Use for: confirmed suspicious IPs and the reason; validated hypotheses; user decisions; ongoing investigations; lasting user context. Keep notes concise (1-3 lines), factual, and timestamped automatically. Sections: 'Findings' (security-relevant facts), 'Decisions' (actions taken / planned), 'Context' (user/network preferences). Requires user approval.",
        "input_schema": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "enum": ["Findings", "Decisions", "Context"],
                    "description": "Which memory section to append to.",
                },
                "note": {
                    "type": "string",
                    "description": "The note content. 1-3 short lines max. Auto-prefixed with UTC timestamp.",
                },
            },
            "required": ["section", "note"],
        },
        "needs_approval": True,
    },
]

_TOOL_BY_NAME = {t["name"]: t for t in TOOLS}


def _tool_needs_approval(name: str) -> bool:
    return _TOOL_BY_NAME.get(name, {}).get("needs_approval", True)


def _tools_anthropic() -> list[dict]:
    return [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in TOOLS]


def _tools_openai() -> list[dict]:
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in TOOLS]


_TOKEN_FILE = ROOT / ".netguard_token"


def _read_ws_token() -> str:
    """Read the WS auth token written by netguard.py at startup."""
    try:
        return _TOKEN_FILE.read_text(encoding="utf-8").strip()
    except (OSError, FileNotFoundError):
        return ""


def _ws_send_sync(payload: dict, timeout: float = 5.0) -> dict:
    """One-shot authenticated WebSocket exchange with the running NetGuard process."""
    try:
        import asyncio
        import websockets  # type: ignore
    except ImportError as e:
        return {"ok": False, "error": f"websockets_lib_missing: {e}"}

    token = _read_ws_token()
    if not token:
        return {"ok": False, "error": "ws_token_missing: .netguard_token not found — start netguard.py first"}

    async def _go() -> dict:
        try:
            async with websockets.connect(NETGUARD_WS_URL, open_timeout=2) as ws:
                # 1) Authenticate
                await ws.send(json.dumps({"cmd": "auth", "token": token}))
                try:
                    ack_raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                except asyncio.TimeoutError:
                    return {"ok": False, "error": "auth_no_response"}
                try:
                    ack = json.loads(ack_raw)
                except json.JSONDecodeError:
                    return {"ok": False, "error": "auth_bad_response"}
                if ack.get("type") != "auth_ok":
                    return {"ok": False, "error": f"auth_failed: {ack.get('type', 'unknown')}"}
                # 2) Drain the unsolicited initial state push (NetGuard sends it after auth_ok)
                try:
                    await asyncio.wait_for(ws.recv(), timeout=0.5)
                except asyncio.TimeoutError:
                    pass  # No initial push — fine
                # 3) Send the actual command
                await ws.send(json.dumps(payload))
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                except asyncio.TimeoutError:
                    return {"ok": True, "note": "command sent, no response in time"}
                try:
                    return {"ok": True, "data": json.loads(raw)}
                except json.JSONDecodeError:
                    return {"ok": True, "data": raw}
        except OSError as e:
            return {"ok": False, "error": f"netguard_unreachable: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"ws_error: {type(e).__name__}: {e}"}

    return asyncio.run(_go())


def _execute_tool(name: str, args: dict) -> dict:
    """Translate a tool call to a NetGuard cmd via WebSocket."""
    args = args or {}
    if name == "get_state":
        return _ws_send_sync({"cmd": "get_state"}, timeout=3.0)
    if name == "list_blocked_ips":
        return _ws_send_sync({"cmd": "get_blocked_ips"})
    if name == "block_ip":
        ip = args.get("ip", "").strip()
        reason = args.get("reason", "AI-suggested block").strip()
        if not ip:
            return {"ok": False, "error": "missing_ip"}
        return _ws_send_sync({"cmd": "block_ip", "ip": ip, "reason": reason})
    if name == "unblock_ip":
        ip = args.get("ip", "").strip()
        if not ip:
            return {"ok": False, "error": "missing_ip"}
        return _ws_send_sync({"cmd": "unblock_ip", "ip": ip})
    if name == "clear_threats":
        return _ws_send_sync({"cmd": "clear_threats"})
    if name == "toggle_auto_block":
        return _ws_send_sync({"cmd": "toggle_auto_block"})
    if name == "set_auto_block_hits":
        v = args.get("value")
        if not isinstance(v, int):
            return {"ok": False, "error": "invalid_value"}
        return _ws_send_sync({"cmd": "set_auto_block_hits", "value": v})
    if name == "audit_program":
        return _audit_program()
    if name == "audit_network":
        return _audit_network()
    if name == "read_memory":
        text = _read_ai_memory()
        return {"ok": True, "data": {"memory": text, "bytes": len(text.encode("utf-8")), "path": str(_AI_MEMORY_FILE)}}
    if name == "save_memory_note":
        section = (args.get("section") or "Findings").strip()
        note = (args.get("note") or "").strip()
        if section not in _AI_MEMORY_VALID_SECTIONS:
            return {"ok": False, "error": f"invalid_section: must be one of {_AI_MEMORY_VALID_SECTIONS}"}
        if not note:
            return {"ok": False, "error": "missing_note"}
        if _append_ai_memory(section, note):
            return {"ok": True, "saved": True, "section": section, "path": str(_AI_MEMORY_FILE)}
        return {"ok": False, "error": "write_failed"}
    return {"ok": False, "error": f"unknown_tool:{name}"}


def _read_netguard_settings() -> dict:
    path = ROOT / "netguard_settings.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _audit_program() -> dict:
    """Configuration audit. Returns findings with severity + suggested_fix."""
    findings: list[dict] = []
    cfg = _read_netguard_settings()
    state_resp = _ws_send_sync({"cmd": "get_state"}, timeout=3.0)
    blocked_resp = _ws_send_sync({"cmd": "get_blocked_ips"}, timeout=3.0)

    state = state_resp.get("data", {}) if state_resp.get("ok") else {}
    blocked = []
    if blocked_resp.get("ok") and isinstance(blocked_resp.get("data"), dict):
        blocked = blocked_resp["data"].get("ips", []) or []

    auto_block_enabled = cfg.get("auto_block_enabled", state.get("auto_block_enabled", False))
    if not auto_block_enabled:
        findings.append({
            "id": "auto_block_off",
            "severity": "high",
            "category": "config",
            "title": "Auto-block désactivé",
            "detail": "Les IPs malveillantes ne sont pas bloquées automatiquement. Risque de compromission élevé en cas d'attaque scriptée.",
            "suggested_fix": {"tool": "toggle_auto_block", "input": {}},
        })

    threshold = cfg.get("auto_block_hits", 10)
    if isinstance(threshold, int) and threshold > 20:
        findings.append({
            "id": "auto_block_threshold_high",
            "severity": "medium",
            "category": "config",
            "title": f"Seuil auto-block élevé ({threshold})",
            "detail": "Une IP attaquante doit générer beaucoup de hits avant blocage. Détection lente.",
            "suggested_fix": {"tool": "set_auto_block_hits", "input": {"value": 10}},
        })

    if cfg.get("dpi_enabled") is False:
        findings.append({
            "id": "dpi_disabled",
            "severity": "medium",
            "category": "config",
            "title": "DPI (Deep Packet Inspection) désactivé",
            "detail": "L'inspection profonde des paquets est éteinte — les attaques par payload ne sont pas détectées.",
            "suggested_fix": None,
        })

    if not blocked:
        findings.append({
            "id": "blacklist_empty",
            "severity": "low",
            "category": "config",
            "title": "Aucune IP bloquée",
            "detail": "La blacklist locale est vide. Si NetGuard tourne depuis longtemps, c'est suspect — vérifie les rapports.",
            "suggested_fix": None,
        })

    return {
        "ok": True,
        "summary": {
            "auto_block_enabled": bool(auto_block_enabled),
            "auto_block_threshold": threshold,
            "blocked_count": len(blocked),
            "dpi_enabled": cfg.get("dpi_enabled", "unknown"),
        },
        "findings": findings,
        "findings_count": len(findings),
    }


def _audit_network() -> dict:
    """Network-state audit: anomalies, hot IPs, traffic patterns."""
    findings: list[dict] = []
    state_resp = _ws_send_sync({"cmd": "get_state"}, timeout=3.0)
    if not state_resp.get("ok"):
        return {"ok": False, "error": state_resp.get("error", "netguard_unreachable"), "findings": []}
    state = state_resp.get("data", {})
    if not isinstance(state, dict):
        return {"ok": False, "error": "bad_state_shape", "findings": []}

    counts = state.get("counts", {}) if isinstance(state.get("counts"), dict) else {}
    threats = state.get("threats", []) or []
    top_ips = state.get("top_ips", []) or []
    blocked_set = set(state.get("blocked_ips", []) or [])

    # Hot IPs not yet blocked
    for ip_entry in top_ips[:8]:
        ip = ip_entry.get("ip") if isinstance(ip_entry, dict) else None
        if not ip or ip in blocked_set:
            continue
        pkts = ip_entry.get("packets", 0) if isinstance(ip_entry, dict) else 0
        threat_score = ip_entry.get("threat_score", 0) if isinstance(ip_entry, dict) else 0
        if pkts > 1000 or threat_score >= 50:
            findings.append({
                "id": f"hot_ip_{ip}",
                "severity": "high" if threat_score >= 70 else "medium",
                "category": "anomaly",
                "title": f"IP suspecte non-bloquée : {ip}",
                "detail": f"{pkts} paquets, score menace {threat_score}. Volume hors-norme.",
                "suggested_fix": {
                    "tool": "block_ip",
                    "input": {"ip": ip, "reason": f"Audit: {pkts} packets, threat score {threat_score}"},
                },
            })

    # Critical threats unhandled
    critical = [t for t in threats if isinstance(t, dict) and t.get("severity", "").lower() in ("critical", "high")]
    if critical:
        findings.append({
            "id": "unhandled_critical_threats",
            "severity": "high",
            "category": "threats",
            "title": f"{len(critical)} menaces critiques/élevées non traitées",
            "detail": "Liste partielle: " + ", ".join(t.get("type", "?") for t in critical[:5]),
            "suggested_fix": None,
        })

    # Traffic baselines
    pps = counts.get("pkt_per_sec", counts.get("pps", 0))
    if isinstance(pps, (int, float)) and pps > 5000:
        findings.append({
            "id": "high_pps",
            "severity": "medium",
            "category": "anomaly",
            "title": f"Trafic élevé : {int(pps)} pkts/s",
            "detail": "Au-dessus du baseline typique. Vérifie s'il s'agit d'une utilisation légitime ou d'une attaque DDoS.",
            "suggested_fix": None,
        })

    return {
        "ok": True,
        "summary": {
            "packets_per_sec": pps,
            "threats_total": len(threats),
            "threats_critical": len(critical),
            "top_ips_seen": len(top_ips),
            "currently_blocked": len(blocked_set),
        },
        "findings": findings,
        "findings_count": len(findings),
    }


def _log_action(event: str, payload: dict) -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    record = {"ts": _dt.datetime.utcnow().isoformat() + "Z", "event": event, **payload}
    with ACTIONS_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ── Settings ────────────────────────────────────────────────────────────────

def _load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            return _migrate_legacy_settings(data) if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            pass
    return {}


def _migrate_legacy_settings(data: dict) -> dict:
    """Old settings shape: {anthropic_api_key, model}. Promote to provider-scoped."""
    legacy_key = data.pop("anthropic_api_key", None) if "anthropic_api_key" in data else None
    legacy_model = data.get("model")
    if legacy_key or (legacy_model and "providers" not in data and "provider" not in data):
        providers = data.setdefault("providers", {})
        anth = providers.setdefault("anthropic", {})
        if legacy_key and not anth.get("api_key"):
            anth["api_key"] = legacy_key
        if legacy_model and not anth.get("model"):
            anth["model"] = legacy_model
        data.setdefault("provider", "anthropic")
    if "provider" not in data:
        data["provider"] = "anthropic"
    if "providers" not in data:
        data["providers"] = {}
    return data


def _save_settings(data: dict) -> None:
    SETTINGS_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# ── Provider abstraction ────────────────────────────────────────────────────

class Provider(ABC):
    name: str
    label: str
    default_model: str
    models: list[str]
    env_keys: list[str]

    @abstractmethod
    def call(self, messages: list[dict], system: str, model: str, api_key: str) -> dict:
        ...

    def get_api_key(self, settings: dict) -> str | None:
        for env in self.env_keys:
            v = os.environ.get(env)
            if v:
                return v.strip()
        prov = settings.get("providers", {}).get(self.name, {})
        k = prov.get("api_key")
        return k.strip() if isinstance(k, str) and k.strip() else None

    def get_model(self, settings: dict) -> str:
        prov = settings.get("providers", {}).get(self.name, {})
        m = prov.get("model")
        return m if isinstance(m, str) and m.strip() else self.default_model


def _http_post(url: str, headers: dict, body: dict, timeout: int = 120) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


class AnthropicProvider(Provider):
    name = "anthropic"
    label = "Anthropic Claude"
    default_model = "claude-sonnet-4-6"
    models = [
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
    ]
    env_keys = ["ANTHROPIC_API_KEY"]
    endpoint = "https://api.anthropic.com/v1/messages"
    api_version = "2023-06-01"

    def call(self, messages, system, model, api_key, tools=None):
        body: dict = {
            "model": model,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "messages": messages,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools
        headers = {
            "x-api-key": api_key,
            "anthropic-version": self.api_version,
            "content-type": "application/json",
        }
        status, raw = _http_post(self.endpoint, headers, body)
        if status >= 400:
            return {"ok": False, "error": f"http_{status}", "reply": raw}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad_json", "reply": raw}
        content_blocks = parsed.get("content", [])
        text_parts: list[str] = []
        tool_calls: list[dict] = []
        for b in content_blocks:
            t = b.get("type")
            if t == "text":
                text_parts.append(b.get("text", ""))
            elif t == "tool_use":
                tool_calls.append({
                    "id": b.get("id"),
                    "name": b.get("name"),
                    "input": b.get("input", {}),
                    "needs_approval": _tool_needs_approval(b.get("name", "")),
                })
        usage = parsed.get("usage", {})
        return {
            "ok": True,
            "reply": "\n".join(t for t in text_parts if t),
            "tool_calls": tool_calls,
            "assistant_blocks": content_blocks,
            "stop_reason": parsed.get("stop_reason"),
            "tokens_in": usage.get("input_tokens", 0),
            "tokens_out": usage.get("output_tokens", 0),
            "model": parsed.get("model", model),
        }


class OpenAIProvider(Provider):
    name = "openai"
    label = "OpenAI"
    default_model = "gpt-4o"
    models = [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "o1-preview",
    ]
    env_keys = ["OPENAI_API_KEY"]
    endpoint = "https://api.openai.com/v1/chat/completions"

    def call(self, messages, system, model, api_key, tools=None):
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)
        body = {
            "model": model,
            "messages": msgs,
            "max_tokens": DEFAULT_MAX_TOKENS,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        status, raw = _http_post(self.endpoint, headers, body)
        if status >= 400:
            return {"ok": False, "error": f"http_{status}", "reply": raw}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad_json", "reply": raw}
        choices = parsed.get("choices", [])
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        usage = parsed.get("usage", {})
        return {
            "ok": True,
            "reply": text,
            "tokens_in": usage.get("prompt_tokens", 0),
            "tokens_out": usage.get("completion_tokens", 0),
            "model": parsed.get("model", model),
        }


class GoogleProvider(Provider):
    name = "google"
    label = "Google Gemini"
    default_model = "gemini-2.0-flash"
    models = [
        "gemini-2.0-flash",
        "gemini-2.0-pro",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
    ]
    env_keys = ["GOOGLE_API_KEY", "GEMINI_API_KEY"]

    def call(self, messages, system, model, api_key, tools=None):
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={urllib.parse.quote(api_key)}"
        contents = []
        for m in messages:
            role = m.get("role", "user")
            contents.append({
                "role": "user" if role == "user" else "model",
                "parts": [{"text": m.get("content", "")}],
            })
        body: dict = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": DEFAULT_MAX_TOKENS},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        headers = {"Content-Type": "application/json"}
        status, raw = _http_post(url, headers, body)
        if status >= 400:
            return {"ok": False, "error": f"http_{status}", "reply": raw}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad_json", "reply": raw}
        cands = parsed.get("candidates", [])
        text = ""
        if cands:
            parts = cands[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
        usage = parsed.get("usageMetadata", {})
        return {
            "ok": True,
            "reply": text,
            "tokens_in": usage.get("promptTokenCount", 0),
            "tokens_out": usage.get("candidatesTokenCount", 0),
            "model": model,
        }


PROVIDERS: dict[str, Provider] = {
    "anthropic": AnthropicProvider(),
    "openai": OpenAIProvider(),
    "google": GoogleProvider(),
}


def _active_provider(settings: dict | None = None) -> Provider:
    s = settings if settings is not None else _load_settings()
    name = s.get("provider", "anthropic")
    return PROVIDERS.get(name, PROVIDERS["anthropic"])


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


def _call_active(messages: list[dict], system: str | None, *, tools: bool = False) -> dict:
    settings = _load_settings()
    provider = _active_provider(settings)
    api_key = provider.get_api_key(settings)
    if not api_key:
        return {"ok": False, "error": "missing_api_key", "reply": "", "provider": provider.name}
    model = provider.get_model(settings)

    tool_arg = None
    if tools:
        if provider.name == "anthropic":
            tool_arg = _tools_anthropic()
        elif provider.name == "openai":
            tool_arg = _tools_openai()

    try:
        result = provider.call(messages, system or "", model, api_key, tools=tool_arg)
    except TypeError:
        # Older providers may not yet accept the tools= kwarg.
        result = provider.call(messages, system or "", model, api_key)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "error": "network", "reply": str(e), "provider": provider.name}
    result["provider"] = provider.name
    return result


# ── Capabilities ────────────────────────────────────────────────────────────

def cap_analyze_network(args: dict) -> dict:
    lang = args.get("lang", "fr")
    captures = _read_recent_captures()
    reports = _read_recent_reports()
    if not captures and not reports:
        ctx = _cap_prompt("no_data", lang, "")
    else:
        ctx = json.dumps(
            {"captures": captures, "reports": reports},
            ensure_ascii=False,
            indent=2,
        )[:30000]
    user = _cap_prompt("analyze_network", lang, ctx)
    return _call_active([{"role": "user", "content": user}], _system_prompt(lang))


def cap_explain_threats(args: dict) -> dict:
    lang = args.get("lang", "fr")
    threats = args.get("threats")
    if not threats:
        threats = _read_recent_reports()
    ctx = json.dumps(threats, ensure_ascii=False, indent=2)[:25000]
    user = _cap_prompt("explain_threats", lang, ctx)
    return _call_active([{"role": "user", "content": user}], _system_prompt(lang))


def cap_recommend_actions(args: dict) -> dict:
    lang = args.get("lang", "fr")
    context = args.get("context") or {
        "captures": _read_recent_captures(3),
        "reports": _read_recent_reports(3),
    }
    ctx = json.dumps(context, ensure_ascii=False, indent=2)[:25000]
    user = _cap_prompt("recommend_actions", lang, ctx)
    return _call_active([{"role": "user", "content": user}], _system_prompt(lang))


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


# ── HTTP layer ──────────────────────────────────────────────────────────────

class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
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
            settings = _load_settings()
            provider = _active_provider(settings)
            return self._json(200, {
                "ok": True,
                "provider": provider.name,
                "has_key": bool(provider.get_api_key(settings)),
                "model": provider.get_model(settings),
            })
        if self.path == "/api/providers":
            settings = _load_settings()
            return self._json(200, {
                "active": settings.get("provider", "anthropic"),
                "providers": [
                    {
                        "name": p.name,
                        "label": p.label,
                        "models": p.models,
                        "default_model": p.default_model,
                        "has_key": bool(p.get_api_key(settings)),
                        "current_model": p.get_model(settings),
                    }
                    for p in PROVIDERS.values()
                ],
            })
        if self.path == "/api/capabilities":
            return self._json(200, {
                "capabilities": [
                    {"name": n, "label": c["label"], "description": c["description"]}
                    for n, c in CAPABILITIES.items()
                ]
            })
        if self.path == "/api/tools":
            return self._json(200, {
                "tools": [
                    {"name": t["name"], "description": t["description"],
                     "needs_approval": t["needs_approval"],
                     "input_schema": t["input_schema"]}
                    for t in TOOLS
                ],
            })
        return super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/settings":
            payload = self._read_json()
            settings = _load_settings()
            providers = settings.setdefault("providers", {})

            new_active = payload.get("provider")
            if isinstance(new_active, str) and new_active in PROVIDERS:
                settings["provider"] = new_active

            target_name = (payload.get("target") or settings.get("provider") or "anthropic").lower()
            if target_name not in PROVIDERS:
                return self._json(400, {"ok": False, "error": "unknown_provider"})
            target = PROVIDERS[target_name]
            scope = providers.setdefault(target_name, {})

            new_key = (payload.get("api_key") or "").strip()
            if new_key:
                if target_name == "anthropic" and not new_key.startswith("sk-ant-"):
                    return self._json(400, {"ok": False, "error": "invalid_key_format"})
                if target_name == "openai" and not new_key.startswith("sk-"):
                    return self._json(400, {"ok": False, "error": "invalid_key_format"})
                scope["api_key"] = new_key

            new_model = (payload.get("model") or "").strip()
            if new_model:
                scope["model"] = new_model

            try:
                _save_settings(settings)
            except OSError as e:
                return self._json(500, {"ok": False, "error": f"write_failed: {e}"})

            _audit("settings_update", {
                "provider": settings.get("provider"),
                "target": target_name,
                "key_set": bool(new_key),
                "model": scope.get("model"),
            })
            active = _active_provider(settings)
            return self._json(200, {
                "ok": True,
                "provider": active.name,
                "has_key": bool(active.get_api_key(settings)),
                "model": active.get_model(settings),
            })

        if self.path == "/api/chat":
            payload = self._read_json()
            messages = payload.get("messages") or []
            user_msg = payload.get("message")
            lang = payload.get("lang", "fr")
            agent_mode = bool(payload.get("agent_mode", False))
            if user_msg is not None and user_msg != "":
                messages.append({"role": "user", "content": user_msg})
            if not messages:
                return self._json(400, {"ok": False, "error": "empty_messages"})
            result = _call_active(messages, _system_prompt(lang), tools=agent_mode)
            _audit("chat", {
                "lang": lang,
                "provider": result.get("provider"),
                "messages": len(messages),
                "agent_mode": agent_mode,
                "tool_calls": len(result.get("tool_calls", []) or []),
                "ok": result.get("ok"),
                "tokens_in": result.get("tokens_in"),
                "tokens_out": result.get("tokens_out"),
            })
            return self._json(200, result)

        if self.path == "/api/tool-execute":
            payload = self._read_json()
            name = (payload.get("name") or "").strip()
            args = payload.get("input") or {}
            decision = (payload.get("decision") or "approve").lower()
            tool_use_id = payload.get("tool_use_id") or ""
            if name not in _TOOL_BY_NAME:
                return self._json(404, {"ok": False, "error": "unknown_tool"})

            if decision != "approve":
                _log_action("tool_rejected", {"name": name, "input": args, "tool_use_id": tool_use_id})
                return self._json(200, {
                    "ok": True,
                    "decision": "rejected",
                    "tool_use_id": tool_use_id,
                    "tool_result": "User rejected this action.",
                })

            result = _execute_tool(name, args)
            _log_action("tool_executed", {
                "name": name, "input": args, "tool_use_id": tool_use_id,
                "result_ok": result.get("ok"), "result_error": result.get("error"),
            })
            payload_text = json.dumps(result, ensure_ascii=False)
            return self._json(200, {
                "ok": True,
                "decision": "approved",
                "tool_use_id": tool_use_id,
                "tool_result": payload_text,
                "raw": result,
            })

        if self.path.startswith("/api/capability/"):
            name = self.path[len("/api/capability/"):]
            cap = CAPABILITIES.get(name)
            if not cap:
                return self._json(404, {"ok": False, "error": "unknown_capability", "available": list(CAPABILITIES)})
            args = self._read_json()
            result = cap["handler"](args)
            _audit("capability", {
                "name": name,
                "provider": result.get("provider"),
                "ok": result.get("ok"),
                "tokens_in": result.get("tokens_in"),
                "tokens_out": result.get("tokens_out"),
            })
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
    settings = _load_settings()
    provider = _active_provider(settings)
    print(f"[NetGuard AI] Active provider: {provider.label} ({provider.get_model(settings)})")
    if not provider.get_api_key(settings):
        print(f"[NetGuard AI] WARNING: no API key for {provider.label} (env vars or settings.json).")
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
