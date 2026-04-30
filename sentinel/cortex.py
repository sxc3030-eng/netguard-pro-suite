"""
SentinelOS — Cortex Brain v2.0
Central orchestrator that connects to all security agents,
correlates threats, and serves the unified dashboard.

Architecture:
    cortex.py (port 8900)
        +-- AgentConnector × 6 -> WebSocket clients to each agent
        +-- AgentManager       -> subprocess management
        +-- ThreatCorrelator   -> cross-agent threat scoring
        +-- PlaybookEngine     -> SOAR automated responses
        +-- ThreatIntelFeed    -> threat intelligence feeds
        +-- AlertManager       -> Telegram/Discord notifications
        +-- ChatEngine         -> contextual security advice
        +-- AgentBus           -> inter-agent pub/sub
        +-- WebSocket server   -> serves dashboard state
        +-- pywebview          -> native window
"""

import os
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

import json
import time
import asyncio
import logging
import subprocess
import threading
import psutil
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import websockets

# Add parent dir so we can import shared modules
SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SENTINEL_DIR)
sys.path.insert(0, BASE_DIR)

from agent_bus import AgentBus
from playbook_engine import PlaybookEngine
from threat_intel import ThreatIntelFeed
from alert_manager import AlertManager
from vault_helpers import (
    get_secret as _vault_get_secret,
    migrate_to_vault as _vault_migrate_settings,
    SENTINEL_VAULT_KEYS,
)

# ===========================================================================
# CONFIGURATION
# ===========================================================================

VERSION = "2.0.0"
CORTEX_PORT = 8900
IS_WINDOWS = sys.platform == "win32"

SETTINGS_FILE = os.path.join(SENTINEL_DIR, "sentinel_settings.json")
LOG_DIR = os.path.join(SENTINEL_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "cortex.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SentinelOS.Cortex")

# Agent definitions
AGENTS = {
    "netguard": {
        "name": "NetGuard Pro",
        "port": 8765,
        "script": os.path.join(BASE_DIR, "netguard.py"),
        "icon": "shield",
        "color": "#4d9fff",
        "description": "Surveillance reseau & Firewall",
    },
    "cleanguard": {
        "name": "CleanGuard Pro",
        "port": 8810,
        "script": os.path.join(BASE_DIR, "cleanguard", "cleanguard.py"),
        "icon": "broom",
        "color": "#ffb347",
        "description": "Antivirus & Nettoyage systeme",
    },
    "mailshield": {
        "name": "MailShield Pro",
        "port": 8801,
        "script": os.path.join(BASE_DIR, "mailshield", "mailshield.py"),
        "icon": "envelope",
        "color": "#3dffb4",
        "description": "Protection email & Anti-phishing",
    },
    "vpnguard": {
        "name": "VPN Guard Pro",
        "port": 8820,
        "script": os.path.join(BASE_DIR, "vpnguard", "vpnguard.py"),
        "icon": "lock",
        "color": "#00d4ff",
        "description": "VPN WireGuard & Tunnel chiffre",
    },
    "honeypot": {
        "name": "HoneyPot Agent",
        "port": 8830,
        "script": os.path.join(BASE_DIR, "honeypot", "honeypot.py"),
        "icon": "honey-pot",
        "color": "#ff6b6b",
        "description": "Detection par leurres & faux services",
    },
    "fim": {
        "name": "File Integrity Monitor",
        "port": 8840,
        "script": os.path.join(BASE_DIR, "fim", "file_integrity_monitor.py"),
        "icon": "file-shield",
        "color": "#a855f7",
        "description": "Surveillance integrite fichiers systeme",
    },
    "strikeback": {
        "name": "StrikeBack Agent",
        "port": 8850,
        "script": os.path.join(BASE_DIR, "strikeback", "strikeback.py"),
        "icon": "sword",
        "color": "#ff3d3d",
        "description": "Defense active & contre-attaque",
    },
    "recorder": {
        "name": "RecordAgent",
        "port": 8860,
        "script": os.path.join(BASE_DIR, "recorder", "recorder.py"),
        "icon": "record",
        "color": "#60a5fa",
        "description": "Enregistrement forensique incidents",
    },
}


# ===========================================================================
# SETTINGS
# ===========================================================================

def load_settings() -> dict:
    defaults = {
        "auto_start_agents": False,
        "theme": "dark",
        "language": "fr",
        "cortex_port": CORTEX_PORT,
        "state_poll_interval": 10,
        "threat_history_max": 200,
        "startup_enabled": False,
    }
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            defaults.update(saved)
    except Exception as e:
        logger.warning(f"Could not load settings: {e}")
    return defaults


def save_settings(settings: dict):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Could not save settings: {e}")


SETTINGS = load_settings()


def migrate_to_vault() -> tuple[list[str], int]:
    """Move every plaintext alert-channel secret in ``sentinel_settings.json``
    into the shared :class:`SecretVault`.

    Caller is responsible for ensuring the vault is unlocked first
    (typically via the ``vault_migrate`` WS command on
    ``netguard.py`` which handles the suite-wide master-password
    dance). Returns ``(migrated_keys, count)`` — empty result is normal
    when nothing needs migrating.

    The settings file is rewritten with the plaintext values stripped
    and a ``.pre-vault.bak`` backup is left next to it. The in-memory
    :data:`SETTINGS` dict is also updated so a running Cortex picks up
    the change without needing a restart.
    """
    return _vault_migrate_settings(
        SETTINGS,
        settings_path=Path(SETTINGS_FILE),
        save_callback=lambda: save_settings(SETTINGS),
    )


# ===========================================================================
# AGENT CONNECTOR — WebSocket client to each agent
# ===========================================================================

class AgentConnector:
    """Connects to a single agent's WebSocket and receives its state."""

    def __init__(self, agent_key: str, agent_info: dict, bus: AgentBus):
        self.key = agent_key
        self.info = agent_info
        self.port = agent_info["port"]
        self.bus = bus
        self.ws = None
        self.state = {}
        self.connected = False
        self.last_update = 0
        self.error = None
        self._running = False

    async def connect_loop(self):
        """Main loop: connect -> listen -> reconnect on failure.
        Uses exponential backoff + port check to avoid spamming connections."""
        self._running = True
        self._retry_delay = 10  # Start at 10s, back off to 30s max
        uri = f"ws://localhost:{self.port}"
        while self._running:
            # Quick port check before attempting WS connection
            if not self._is_port_open():
                if self.connected:
                    self.connected = False
                    self.ws = None
                self.error = "Agent not listening"
                await asyncio.sleep(self._retry_delay)
                self._retry_delay = min(self._retry_delay + 5, 30)
                continue

            try:
                async with websockets.connect(uri, ping_interval=30,
                                               ping_timeout=15,
                                               close_timeout=5) as ws:
                    self.ws = ws
                    self.connected = True
                    self.error = None
                    self._retry_delay = 10  # Reset backoff on success
                    logger.info(f"[Connector] Connected to {self.info['name']} on port {self.port}")
                    self.bus.publish("agent.connected", self.key,
                                    {"agent": self.key, "port": self.port})

                    # Request initial state
                    await ws.send(json.dumps({"cmd": "get_state"}))

                    async for message in ws:
                        try:
                            msg = json.loads(message)
                            self._handle_message(msg)
                        except json.JSONDecodeError:
                            pass

            except (ConnectionRefusedError, OSError, websockets.exceptions.ConnectionClosed):
                self.connected = False
                self.ws = None
                self.error = "Connection lost"
                if self._running:
                    await asyncio.sleep(self._retry_delay)
                    self._retry_delay = min(self._retry_delay + 5, 30)
            except Exception as e:
                self.connected = False
                self.ws = None
                self.error = str(e)
                logger.error(f"[Connector] Error with {self.key}: {e}")
                if self._running:
                    await asyncio.sleep(self._retry_delay)
                    self._retry_delay = min(self._retry_delay + 5, 30)

    def _is_port_open(self) -> bool:
        """Quick TCP check — is the agent port actually listening?"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex(("localhost", self.port))
            s.close()
            return result == 0
        except Exception:
            return False

    def _handle_message(self, msg: dict):
        """Process incoming message from agent."""
        msg_type = msg.get("type", "")

        if msg_type == "state":
            self.state = msg
            self.last_update = time.time()
            # Publish state change on bus
            self.bus.publish(f"agent.state_update", self.key,
                            {"agent": self.key, "state_type": msg_type})

            # Extract threats/alerts and publish them
            self._extract_events(msg)

        elif msg_type in ("threat_detected", "alert"):
            self.bus.publish("threat.detected", self.key, msg, severity="warning")

    def _extract_events(self, state: dict):
        """Extract significant events from agent state for correlation."""
        # NetGuard threats
        if self.key == "netguard":
            threats = state.get("threats", [])
            if threats:
                count = state.get("threats_count", len(threats))
                blocked = state.get("packets_blocked", 0)
                self.bus.publish("network.threats", self.key,
                                {"count": count, "blocked": blocked},
                                severity="warning" if count > 0 else "info")

        # CleanGuard scan threats
        elif self.key == "cleanguard":
            scan_threats = state.get("scan_threats_count", 0)
            if scan_threats > 0:
                self.bus.publish("clean.threats_found", self.key,
                                {"count": scan_threats},
                                severity="warning")

        # VPN Guard connection
        elif self.key == "vpnguard":
            vpn_connected = state.get("connected", False)
            kill_switch = state.get("kill_switch_active", False)
            self.bus.publish("vpn.status", self.key,
                            {"connected": vpn_connected, "kill_switch": kill_switch})

        # HoneyPot alerts
        elif self.key == "honeypot":
            alerts_count = state.get("alerts_count", 0)
            traps_triggered = state.get("traps_triggered", 0)
            if traps_triggered > 0:
                self.bus.publish("honeypot.trap_triggered", self.key,
                                {"traps_triggered": traps_triggered, "alerts": alerts_count},
                                severity="critical")
            service_stats = state.get("service_stats", {})
            total_conns = service_stats.get("total_connections", 0)
            if total_conns > 0:
                self.bus.publish("honeypot.service_probe", self.key,
                                {"total_connections": total_conns},
                                severity="warning")

        # FIM alerts
        elif self.key == "fim":
            changes = state.get("changes_detected", 0)
            added = state.get("files_added", 0)
            deleted = state.get("files_deleted", 0)
            if changes > 0 or deleted > 0:
                self.bus.publish("fim.change_detected", self.key,
                                {"modified": changes, "added": added, "deleted": deleted},
                                severity="critical" if deleted > 0 else "warning")

    async def send_command(self, cmd: str, params: dict = None) -> bool:
        """Send a command to this agent."""
        if not self.connected or not self.ws:
            return False
        try:
            msg = {"cmd": cmd}
            if params:
                msg.update(params)
            await self.ws.send(json.dumps(msg))
            return True
        except Exception as e:
            logger.error(f"[Connector] Send error to {self.key}: {e}")
            return False

    def stop(self):
        self._running = False

    def get_summary(self) -> dict:
        """Get a summary of this agent's status."""
        return {
            "key": self.key,
            "name": self.info["name"],
            "port": self.port,
            "icon": self.info["icon"],
            "color": self.info["color"],
            "description": self.info["description"],
            "connected": self.connected,
            "last_update": self.last_update,
            "error": self.error,
            "state": self.state,
        }


# ===========================================================================
# AGENT MANAGER — Process management for all agents
# ===========================================================================

class AgentManager:
    """Launches and manages agent processes."""

    def __init__(self):
        self._processes: dict[str, subprocess.Popen] = {}
        self._start_times: dict[str, float] = {}

    def start_agent(self, key: str) -> bool:
        """Start an agent process."""
        if key in self._processes and self._processes[key].poll() is None:
            logger.info(f"[Manager] {key} already running (PID {self._processes[key].pid})")
            return True

        info = AGENTS.get(key)
        if not info:
            logger.error(f"[Manager] Unknown agent: {key}")
            return False

        script = info["script"]
        if not os.path.exists(script):
            logger.error(f"[Manager] Script not found: {script}")
            return False

        try:
            kwargs = {}
            exe = sys.executable
            if IS_WINDOWS:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                # Use pythonw.exe to avoid any console window flash
                pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
                if os.path.isfile(pythonw):
                    exe = pythonw
                # Hide the window via startupinfo as an extra safeguard
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0  # SW_HIDE
                kwargs["startupinfo"] = si

            # Set working directory to the script's directory
            cwd = os.path.dirname(script)

            proc = subprocess.Popen(
                [exe, script, "--headless"],
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **kwargs,
            )
            self._processes[key] = proc
            self._start_times[key] = time.time()
            logger.info(f"[Manager] Started {info['name']} (PID {proc.pid})")
            return True
        except Exception as e:
            logger.error(f"[Manager] Failed to start {key}: {e}")
            return False

    def stop_agent(self, key: str) -> bool:
        """Stop an agent process."""
        proc = self._processes.get(key)
        if not proc or proc.poll() is not None:
            logger.info(f"[Manager] {key} not running")
            return True
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            logger.info(f"[Manager] Stopped {key}")
            return True
        except Exception as e:
            logger.error(f"[Manager] Failed to stop {key}: {e}")
            return False

    def restart_agent(self, key: str) -> bool:
        self.stop_agent(key)
        time.sleep(1)
        return self.start_agent(key)

    def get_status(self, key: str) -> dict:
        """Get process status for an agent."""
        proc = self._processes.get(key)
        running = proc is not None and proc.poll() is None
        pid = proc.pid if running else None

        # Get CPU/RAM if running
        cpu = 0
        mem_mb = 0
        if running and pid:
            try:
                p = psutil.Process(pid)
                cpu = p.cpu_percent(interval=0)
                mem_mb = round(p.memory_info().rss / (1024 * 1024), 1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return {
            "running": running,
            "pid": pid,
            "cpu": cpu,
            "mem_mb": mem_mb,
            "uptime": time.time() - self._start_times.get(key, time.time()) if running else 0,
        }

    def start_all(self):
        for key in AGENTS:
            self.start_agent(key)

    def stop_all(self):
        for key in AGENTS:
            self.stop_agent(key)

    def is_running(self, key: str) -> bool:
        proc = self._processes.get(key)
        return proc is not None and proc.poll() is None


# ===========================================================================
# THREAT CORRELATOR — Cross-agent threat scoring
# ===========================================================================

class ThreatCorrelator:
    """Correlates events from all agents into a global threat score."""

    def __init__(self, bus: AgentBus):
        self.bus = bus
        self._threat_score = 0
        self._factors = []
        self._alerts = []
        self._max_alerts = 200

        # Subscribe to threat events
        bus.subscribe("threat.*", self._on_threat)
        bus.subscribe("network.*", self._on_network)
        bus.subscribe("vpn.*", self._on_vpn)
        bus.subscribe("clean.*", self._on_clean)
        bus.subscribe("honeypot.*", self._on_honeypot)
        bus.subscribe("fim.*", self._on_fim)

    def _on_threat(self, event):
        self._add_alert("threat", event)

    def _on_network(self, event):
        if event.severity in ("warning", "critical"):
            self._add_alert("network", event)

    def _on_vpn(self, event):
        if event.data.get("connected") is False:
            self._add_alert("vpn", event)

    def _on_clean(self, event):
        if event.severity in ("warning", "critical"):
            self._add_alert("clean", event)

    def _on_honeypot(self, event):
        self._add_alert("honeypot", event)

    def _on_fim(self, event):
        self._add_alert("fim", event)

    def _add_alert(self, category: str, event):
        alert = {
            "category": category,
            "source": event.source,
            "channel": event.channel,
            "data": event.data,
            "severity": event.severity,
            "ts": event.ts,
        }
        self._alerts.append(alert)
        if len(self._alerts) > self._max_alerts:
            self._alerts = self._alerts[-self._max_alerts:]

    def calculate_threat_level(self, connectors: dict) -> int:
        """Calculate global threat level (0-100) based on all agent states."""
        score = 0
        factors = []

        for key, conn in connectors.items():
            if not conn.connected:
                score += 5
                factors.append(f"{conn.info['name']} deconnecte")
                continue

            state = conn.state

            if key == "netguard":
                threats = state.get("threats_count", 0)
                blocked = state.get("packets_blocked", 0)
                total = state.get("packets_total", 1) or 1
                block_rate = blocked / total * 100

                if threats > 10:
                    score += 25
                    factors.append(f"{threats} menaces reseau detectees")
                elif threats > 0:
                    score += 10
                    factors.append(f"{threats} menace(s) reseau")

                if block_rate > 20:
                    score += 15
                    factors.append(f"Taux de blocage eleve ({block_rate:.0f}%)")

                # Attack chains
                chains = state.get("attack_chains", {})
                if chains:
                    score += 20
                    factors.append(f"{len(chains)} chaine(s) d'attaque en cours")

            elif key == "cleanguard":
                scan_threats = state.get("scan_threats_count", 0)
                realtime = state.get("realtime_protection", False)

                if scan_threats > 0:
                    score += 20
                    factors.append(f"{scan_threats} menace(s) systeme")
                if not realtime:
                    score += 10
                    factors.append("Protection temps reel desactivee")

            elif key == "vpnguard":
                vpn_on = state.get("connected", False)
                kill_switch = state.get("kill_switch_enabled", False)
                dns_protected = state.get("dns_protected", False)

                if not vpn_on:
                    score += 5
                    factors.append("VPN non connecte")
                if not kill_switch and vpn_on:
                    score += 5
                    factors.append("Kill Switch desactive")
                if not dns_protected:
                    score += 3
                    factors.append("Protection DNS inactive")

            elif key == "mailshield":
                # MailShield has simpler state
                pass

            elif key == "honeypot":
                traps_triggered = state.get("traps_triggered", 0)
                service_stats = state.get("service_stats", {})
                total_probes = service_stats.get("total_connections", 0)
                if traps_triggered > 0:
                    score += 25
                    factors.append(f"{traps_triggered} piege(s) honeypot declenche(s)")
                if total_probes > 0:
                    score += 10
                    factors.append(f"{total_probes} sonde(s) sur faux services")

            elif key == "fim":
                changes = state.get("changes_detected", 0)
                deleted = state.get("files_deleted", 0)
                added = state.get("files_added", 0)
                if deleted > 0:
                    score += 25
                    factors.append(f"{deleted} fichier(s) systeme supprime(s)")
                if changes > 0:
                    score += 15
                    factors.append(f"{changes} fichier(s) systeme modifie(s)")
                if added > 0:
                    score += 5
                    factors.append(f"{added} nouveau(x) fichier(s) detecte(s)")

        score = min(100, max(0, score))
        self._threat_score = score
        self._factors = factors
        return score

    def get_threat_level(self) -> dict:
        return {
            "score": self._threat_score,
            "factors": self._factors,
            "grade": self._score_to_grade(self._threat_score),
        }

    def get_alerts(self, limit: int = 50) -> list:
        return self._alerts[-limit:]

    @staticmethod
    def _score_to_grade(score: int) -> str:
        if score <= 10:
            return "A"
        elif score <= 25:
            return "B"
        elif score <= 50:
            return "C"
        elif score <= 75:
            return "D"
        return "F"


# ===========================================================================
# CHAT ENGINE — Contextual security advice (bilingual FR/EN)
# ===========================================================================

class ChatEngine:
    """Generates contextual security advice based on agent states."""

    # Knowledge base: keyword -> (fr_response, en_response, suggestions_fr, suggestions_en)
    KNOWLEDGE = {
        "netguard": {
            "status": {
                "keywords": ["status", "etat", "reseau", "network", "state"],
                "response": {
                    "fr": "Voici l'etat actuel de NetGuard :\n- Paquets analyses : {packets_total}\n- Paquets bloques : {packets_blocked}\n- Menaces detectees : {threats_count}\n- Connexions actives : {active_conns}\n- DPI : {dpi}\n- Suricata IDS : {suricata}",
                    "en": "Here is NetGuard's current status:\n- Packets analyzed: {packets_total}\n- Packets blocked: {packets_blocked}\n- Threats detected: {threats_count}\n- Active connections: {active_conns}\n- DPI: {dpi}\n- Suricata IDS: {suricata}",
                },
                "suggestions": {
                    "fr": ["Menaces actives ?", "Activer le DPI", "Comment bloquer une IP ?"],
                    "en": ["Active threats?", "Enable DPI", "How to block an IP?"],
                },
            },
            "threats": {
                "keywords": ["menace", "threat", "alerte", "alert", "danger", "attack", "attaque"],
                "response": {
                    "fr": "{threats_count} menace(s) detectee(s) actuellement.\n{threat_detail}\n\nConseil : Activez le DPI et Suricata IDS pour une meilleure detection. Verifiez regulierement les alertes et bloquez les IP suspectes.",
                    "en": "{threats_count} threat(s) currently detected.\n{threat_detail}\n\nAdvice: Enable DPI and Suricata IDS for better detection. Regularly check alerts and block suspicious IPs.",
                },
                "suggestions": {
                    "fr": ["Bloquer une IP", "Voir la timeline", "Activer Suricata"],
                    "en": ["Block an IP", "View timeline", "Enable Suricata"],
                },
            },
            "block_ip": {
                "keywords": ["bloquer", "block", "ip", "bannir", "ban"],
                "response": {
                    "fr": "Pour bloquer une IP avec NetGuard :\n1. Ouvrez le dashboard NetGuard dedie\n2. Allez dans l'onglet 'Firewall'\n3. Entrez l'IP a bloquer dans le champ\n4. Cliquez sur 'Bloquer'\n\nOu utilisez la commande : block_ip avec l'adresse IP.\nLes IP bloquees sont listees dans l'onglet Firewall.",
                    "en": "To block an IP with NetGuard:\n1. Open the dedicated NetGuard dashboard\n2. Go to the 'Firewall' tab\n3. Enter the IP to block\n4. Click 'Block'\n\nOr use the command: block_ip with the IP address.\nBlocked IPs are listed in the Firewall tab.",
                },
                "suggestions": {
                    "fr": ["Voir les IP bloquees", "Etat du reseau ?"],
                    "en": ["View blocked IPs", "Network status?"],
                },
            },
            "dpi": {
                "keywords": ["dpi", "inspection", "deep packet", "analyse"],
                "response": {
                    "fr": "Le DPI (Deep Packet Inspection) analyse le contenu des paquets reseau pour detecter :\n- Protocoles suspects\n- Transferts de donnees masques\n- Communications chiffrees suspectes\n\nStatut actuel : {dpi}\nPour l'activer/desactiver, utilisez le dashboard NetGuard > DPI.",
                    "en": "DPI (Deep Packet Inspection) analyzes network packet content to detect:\n- Suspicious protocols\n- Hidden data transfers\n- Suspicious encrypted communications\n\nCurrent status: {dpi}\nTo enable/disable, use NetGuard dashboard > DPI.",
                },
                "suggestions": {
                    "fr": ["Etat du reseau ?", "Activer Suricata"],
                    "en": ["Network status?", "Enable Suricata"],
                },
            },
        },
        "cleanguard": {
            "status": {
                "keywords": ["status", "etat", "sante", "health", "state", "systeme", "system"],
                "response": {
                    "fr": "Etat de CleanGuard :\n- Score de sante : {health_score}/100 (Grade {health_grade})\n- Protection temps reel : {realtime}\n- Menaces scan : {scan_threats}\n- Fichiers en quarantaine : {quarantine}\n- Scan en cours : {scanning}",
                    "en": "CleanGuard status:\n- Health score: {health_score}/100 (Grade {health_grade})\n- Real-time protection: {realtime}\n- Scan threats: {scan_threats}\n- Quarantined files: {quarantine}\n- Scan active: {scanning}",
                },
                "suggestions": {
                    "fr": ["Lancer un scan", "Vider la quarantaine", "Protection temps reel ?"],
                    "en": ["Run a scan", "Clear quarantine", "Real-time protection?"],
                },
            },
            "scan": {
                "keywords": ["scan", "scanner", "analyse", "analyze", "malware", "virus"],
                "response": {
                    "fr": "Types de scan disponibles :\n- Scan rapide : analyse les zones critiques (fichiers temp, startup, processus)\n- Scan complet : analyse tout le systeme (plus long)\n- Scan personnalise : choisissez les dossiers a analyser\n\nConseil : Faites un scan rapide quotidien et un scan complet hebdomadaire.",
                    "en": "Available scan types:\n- Quick scan: analyzes critical areas (temp files, startup, processes)\n- Full scan: analyzes the entire system (takes longer)\n- Custom scan: choose folders to analyze\n\nAdvice: Run a quick scan daily and a full scan weekly.",
                },
                "suggestions": {
                    "fr": ["Lancer scan rapide", "Etat de sante ?"],
                    "en": ["Run quick scan", "Health status?"],
                },
            },
            "quarantine": {
                "keywords": ["quarantaine", "quarantine", "isoler", "isolate", "supprimer", "delete"],
                "response": {
                    "fr": "La quarantaine isole les fichiers suspects sans les supprimer.\n- {quarantine} fichier(s) en quarantaine\n\nActions possibles :\n- Restaurer : remettre le fichier a sa place (si faux positif)\n- Supprimer : suppression definitive\n\nConseil : Verifiez regulierement la quarantaine et supprimez les fichiers confirmes malveillants.",
                    "en": "Quarantine isolates suspicious files without deleting them.\n- {quarantine} file(s) in quarantine\n\nAvailable actions:\n- Restore: put the file back (if false positive)\n- Delete: permanent deletion\n\nAdvice: Regularly check quarantine and delete confirmed malicious files.",
                },
                "suggestions": {
                    "fr": ["Lancer un scan", "Etat de sante ?"],
                    "en": ["Run a scan", "Health status?"],
                },
            },
            "realtime": {
                "keywords": ["temps reel", "realtime", "real-time", "protection", "bouclier", "shield"],
                "response": {
                    "fr": "La protection temps reel surveille en permanence :\n- Les fichiers crees ou modifies\n- Les processus lances\n- Les connexions reseau suspectes\n\nStatut actuel : {realtime}\n\nConseil : Gardez toujours la protection temps reel activee pour une securite optimale.",
                    "en": "Real-time protection continuously monitors:\n- Files created or modified\n- Launched processes\n- Suspicious network connections\n\nCurrent status: {realtime}\n\nAdvice: Always keep real-time protection enabled for optimal security.",
                },
                "suggestions": {
                    "fr": ["Lancer un scan", "Etat de sante ?"],
                    "en": ["Run a scan", "Health status?"],
                },
            },
        },
        "mailshield": {
            "status": {
                "keywords": ["status", "etat", "email", "mail", "state"],
                "response": {
                    "fr": "MailShield Pro est actif et protege vos emails.\n\nFonctionnalites :\n- Detection anti-phishing\n- Analyse des pieces jointes\n- Filtrage du spam\n- Chiffrement des emails\n\nConseil : Synchronisez regulierement pour verifier les nouveaux emails suspects.",
                    "en": "MailShield Pro is active and protecting your emails.\n\nFeatures:\n- Anti-phishing detection\n- Attachment analysis\n- Spam filtering\n- Email encryption\n\nAdvice: Sync regularly to check for new suspicious emails.",
                },
                "suggestions": {
                    "fr": ["Synchroniser", "Anti-phishing actif ?", "Configurer le filtrage"],
                    "en": ["Sync", "Anti-phishing active?", "Configure filtering"],
                },
            },
            "phishing": {
                "keywords": ["phishing", "hameconnage", "suspect", "suspicious", "spam", "arnaque", "scam"],
                "response": {
                    "fr": "Comment detecter le phishing :\n- Verifiez l'expediteur (domaine suspect ?)\n- Mefiez-vous des liens raccourcis\n- Ne donnez jamais vos mots de passe par email\n- Attention aux pieces jointes .exe, .bat, .scr\n\nMailShield analyse automatiquement chaque email pour ces indicateurs.",
                    "en": "How to detect phishing:\n- Check the sender (suspicious domain?)\n- Beware of shortened links\n- Never share passwords via email\n- Watch out for .exe, .bat, .scr attachments\n\nMailShield automatically analyzes each email for these indicators.",
                },
                "suggestions": {
                    "fr": ["Synchroniser les emails", "Etat de MailShield ?"],
                    "en": ["Sync emails", "MailShield status?"],
                },
            },
            "sync": {
                "keywords": ["sync", "synchroniser", "synchronize", "actualiser", "refresh"],
                "response": {
                    "fr": "Pour synchroniser vos emails :\n1. MailShield va se connecter a votre serveur mail\n2. Analyser les nouveaux messages\n3. Signaler les emails suspects\n\nLa synchronisation est en cours...",
                    "en": "To sync your emails:\n1. MailShield will connect to your mail server\n2. Analyze new messages\n3. Flag suspicious emails\n\nSync is in progress...",
                },
                "suggestions": {
                    "fr": ["Etat de MailShield ?", "Anti-phishing actif ?"],
                    "en": ["MailShield status?", "Anti-phishing active?"],
                },
            },
        },
        "vpnguard": {
            "status": {
                "keywords": ["status", "etat", "vpn", "connexion", "connection", "state"],
                "response": {
                    "fr": "Etat de VPN Guard :\n- VPN : {vpn_status}\n- Profil actif : {profile}\n- IP publique : {public_ip}\n- Kill Switch : {kill_switch}\n- DNS protege : {dns}\n- Trafic : RX {rx} / TX {tx}",
                    "en": "VPN Guard status:\n- VPN: {vpn_status}\n- Active profile: {profile}\n- Public IP: {public_ip}\n- Kill Switch: {kill_switch}\n- DNS protected: {dns}\n- Traffic: RX {rx} / TX {tx}",
                },
                "suggestions": {
                    "fr": ["Connecter le VPN", "Verifier fuite DNS", "Mon IP publique ?"],
                    "en": ["Connect VPN", "Check DNS leak", "My public IP?"],
                },
            },
            "connect": {
                "keywords": ["connecter", "connect", "demarrer", "start", "lancer", "launch"],
                "response": {
                    "fr": "Pour connecter le VPN :\n1. Assurez-vous que WireGuard est installe\n2. Un profil doit etre configure avec un serveur distant\n3. Cliquez sur 'Connecter' ou utilisez la commande quick_connect\n\nConseil : Activez le Kill Switch pour empecher les fuites si le VPN se deconnecte.",
                    "en": "To connect the VPN:\n1. Make sure WireGuard is installed\n2. A profile must be configured with a remote server\n3. Click 'Connect' or use the quick_connect command\n\nAdvice: Enable Kill Switch to prevent leaks if the VPN disconnects.",
                },
                "suggestions": {
                    "fr": ["Activer Kill Switch", "Etat du VPN ?", "Verifier fuite DNS"],
                    "en": ["Enable Kill Switch", "VPN status?", "Check DNS leak"],
                },
            },
            "dns": {
                "keywords": ["dns", "fuite", "leak", "protection"],
                "response": {
                    "fr": "La protection DNS empeche les requetes DNS de fuiter hors du tunnel VPN.\n- DNS protege : {dns}\n\nProcedure de verification :\n1. Allez dans VPN Guard > DNS\n2. Cliquez sur 'Verifier fuite DNS'\n3. Le resultat indiquera si vos requetes passent bien par le tunnel\n\nConseil : Utilisez des serveurs DNS securises (1.1.1.1 ou 9.9.9.9).",
                    "en": "DNS protection prevents DNS queries from leaking outside the VPN tunnel.\n- DNS protected: {dns}\n\nVerification procedure:\n1. Go to VPN Guard > DNS\n2. Click 'Check DNS leak'\n3. The result will indicate if your queries go through the tunnel\n\nAdvice: Use secure DNS servers (1.1.1.1 or 9.9.9.9).",
                },
                "suggestions": {
                    "fr": ["Etat du VPN ?", "Activer Kill Switch"],
                    "en": ["VPN status?", "Enable Kill Switch"],
                },
            },
            "kill_switch": {
                "keywords": ["kill switch", "killswitch", "coupe-circuit", "securite", "safety"],
                "response": {
                    "fr": "Le Kill Switch coupe votre connexion Internet si le VPN se deconnecte accidentellement.\n- Statut actuel : {kill_switch}\n\nPourquoi l'activer :\n- Empeche les fuites de donnees\n- Protege votre IP reelle\n- Essentiel sur les Wi-Fi publics\n\nActivez-le dans VPN Guard > Kill Switch.",
                    "en": "Kill Switch cuts your Internet connection if the VPN disconnects accidentally.\n- Current status: {kill_switch}\n\nWhy enable it:\n- Prevents data leaks\n- Protects your real IP\n- Essential on public Wi-Fi\n\nEnable it in VPN Guard > Kill Switch.",
                },
                "suggestions": {
                    "fr": ["Connecter le VPN", "Etat du VPN ?"],
                    "en": ["Connect VPN", "VPN status?"],
                },
            },
            "ip": {
                "keywords": ["ip", "publique", "public", "adresse", "address"],
                "response": {
                    "fr": "Votre IP publique actuelle : {public_ip}\n\nSi le VPN est actif, cette IP devrait etre celle du serveur VPN, pas la votre.\nSi vous voyez votre vraie IP avec le VPN actif, il y a peut-etre une fuite.",
                    "en": "Your current public IP: {public_ip}\n\nIf the VPN is active, this IP should be the VPN server's, not yours.\nIf you see your real IP with VPN active, there might be a leak.",
                },
                "suggestions": {
                    "fr": ["Verifier fuite DNS", "Etat du VPN ?"],
                    "en": ["Check DNS leak", "VPN status?"],
                },
            },
        },
        "honeypot": {
            "status": {
                "keywords": ["status", "etat", "honeypot", "piege", "trap", "state"],
                "response": {
                    "fr": "Etat du HoneyPot :\n- Pieges actifs : {traps_total}\n- Pieges declenches : {traps_triggered}\n- Sondes detectees : {total_probes}\n- IPs uniques : {unique_ips}\n- Alertes : {alerts_count}\n\nLe honeypot attire les attaquants avec de faux fichiers et services pour les detecter.",
                    "en": "HoneyPot status:\n- Active traps: {traps_total}\n- Traps triggered: {traps_triggered}\n- Probes detected: {total_probes}\n- Unique IPs: {unique_ips}\n- Alerts: {alerts_count}\n\nThe honeypot lures attackers with fake files and services to detect them.",
                },
                "suggestions": {
                    "fr": ["Pieges declenches ?", "Faux services ?", "Alertes recentes ?"],
                    "en": ["Triggered traps?", "Fake services?", "Recent alerts?"],
                },
            },
            "traps": {
                "keywords": ["piege", "trap", "fichier", "file", "bait", "leurre", "appat"],
                "response": {
                    "fr": "Le HoneyPot cree des fichiers appats (passwords.txt, cles SSH, config SQL, etc.) pour detecter les intrus.\n\nSi un attaquant accede ou modifie ces fichiers, une alerte critique est declenchee.\n\n{traps_triggered} piege(s) declenche(s) actuellement.\n\nConseil : Ne modifiez pas les fichiers dans le dossier 'traps'.",
                    "en": "The HoneyPot creates bait files (passwords.txt, SSH keys, SQL config, etc.) to detect intruders.\n\nIf an attacker accesses or modifies these files, a critical alert is triggered.\n\n{traps_triggered} trap(s) currently triggered.\n\nAdvice: Do not modify files in the 'traps' folder.",
                },
                "suggestions": {
                    "fr": ["Etat du honeypot ?", "Faux services ?"],
                    "en": ["HoneyPot status?", "Fake services?"],
                },
            },
            "services": {
                "keywords": ["service", "faux", "fake", "port", "ssh", "ftp", "http", "sonde", "probe", "scan"],
                "response": {
                    "fr": "Le HoneyPot ecoute sur des ports courants :\n- Port 2222 (Faux SSH)\n- Port 8888 (Faux HTTP)\n- Port 2121 (Faux FTP)\n\nToute connexion sur ces ports est suspecte et logguee.\n\n{total_probes} sonde(s) detectee(s) depuis {unique_ips} IP(s) unique(s).",
                    "en": "The HoneyPot listens on common ports:\n- Port 2222 (Fake SSH)\n- Port 8888 (Fake HTTP)\n- Port 2121 (Fake FTP)\n\nAny connection on these ports is suspicious and logged.\n\n{total_probes} probe(s) detected from {unique_ips} unique IP(s).",
                },
                "suggestions": {
                    "fr": ["Etat du honeypot ?", "Pieges declenches ?"],
                    "en": ["HoneyPot status?", "Triggered traps?"],
                },
            },
        },
        "fim": {
            "status": {
                "keywords": ["status", "etat", "fim", "integrite", "integrity", "fichier", "file", "state"],
                "response": {
                    "fr": "Etat du FIM (File Integrity Monitor) :\n- Fichiers surveilles : {baseline_files}\n- Modifications detectees : {changes_detected}\n- Fichiers ajoutes : {files_added}\n- Fichiers supprimes : {files_deleted}\n- Dernier scan : {last_scan}\n- Intervalle : {scan_interval}s\n\nLe FIM surveille les fichiers systeme critiques pour detecter les modifications non autorisees.",
                    "en": "FIM (File Integrity Monitor) status:\n- Monitored files: {baseline_files}\n- Modifications detected: {changes_detected}\n- Files added: {files_added}\n- Files deleted: {files_deleted}\n- Last scan: {last_scan}\n- Interval: {scan_interval}s\n\nFIM monitors critical system files for unauthorized changes.",
                },
                "suggestions": {
                    "fr": ["Reconstruire la baseline", "Alertes recentes ?", "Fichiers surveilles ?"],
                    "en": ["Rebuild baseline", "Recent alerts?", "Monitored files?"],
                },
            },
            "baseline": {
                "keywords": ["baseline", "reference", "hash", "reconstruire", "rebuild", "reset"],
                "response": {
                    "fr": "La baseline est la reference de l'etat normal de vos fichiers systeme.\n\nElle contient le hash SHA256 de chaque fichier surveille.\n- Fichiers en baseline : {baseline_files}\n\nReconstruire la baseline :\n1. Allez dans l'onglet FIM du dashboard\n2. Cliquez sur 'Reconstruire la baseline'\n3. Tous les fichiers seront re-hashes\n\nConseil : Reconstruisez apres chaque mise a jour systeme legitime.",
                    "en": "The baseline is the reference of the normal state of your system files.\n\nIt contains the SHA256 hash of each monitored file.\n- Files in baseline: {baseline_files}\n\nRebuild the baseline:\n1. Go to the FIM tab in the dashboard\n2. Click 'Rebuild baseline'\n3. All files will be re-hashed\n\nAdvice: Rebuild after each legitimate system update.",
                },
                "suggestions": {
                    "fr": ["Etat du FIM ?", "Alertes recentes ?"],
                    "en": ["FIM status?", "Recent alerts?"],
                },
            },
            "changes": {
                "keywords": ["modification", "change", "modifie", "modified", "supprime", "deleted", "ajoute", "added", "alerte", "alert"],
                "response": {
                    "fr": "Le FIM detecte 3 types de changements :\n- Fichier modifie : le contenu a change (hash different)\n- Fichier ajoute : nouveau fichier dans un dossier surveille\n- Fichier supprime : fichier disparu (CRITIQUE)\n\nActuellement :\n- {changes_detected} modification(s)\n- {files_added} ajout(s)\n- {files_deleted} suppression(s)\n\nConseil : Toute suppression de fichier systeme est suspecte. Investiguez immediatement.",
                    "en": "FIM detects 3 types of changes:\n- File modified: content changed (different hash)\n- File added: new file in a monitored folder\n- File deleted: file disappeared (CRITICAL)\n\nCurrently:\n- {changes_detected} modification(s)\n- {files_added} addition(s)\n- {files_deleted} deletion(s)\n\nAdvice: Any system file deletion is suspicious. Investigate immediately.",
                },
                "suggestions": {
                    "fr": ["Reconstruire la baseline", "Etat du FIM ?"],
                    "en": ["Rebuild baseline", "FIM status?"],
                },
            },
        },
    }

    # Default response when no keyword matches
    DEFAULT_RESPONSE = {
        "fr": "Je ne suis pas sur de comprendre votre question. Essayez l'une des suggestions ci-dessous, ou posez une question sur :\n- L'etat de l'agent\n- Les menaces detectees\n- Les procedures de securite\n- La configuration",
        "en": "I'm not sure I understand your question. Try one of the suggestions below, or ask about:\n- Agent status\n- Detected threats\n- Security procedures\n- Configuration",
    }

    def __init__(self, connectors: dict):
        self.connectors = connectors
        self._chat_history: dict[str, list] = defaultdict(list)

    def _get_agent_vars(self, agent_key: str) -> dict:
        """Extract template variables from agent state."""
        conn = self.connectors.get(agent_key)
        if not conn or not conn.state:
            return {}
        s = conn.state
        v = {}

        if agent_key == "netguard":
            v["packets_total"] = s.get("packets_total", 0)
            v["packets_blocked"] = s.get("packets_blocked", 0)
            v["threats_count"] = s.get("threats_count", 0)
            v["active_conns"] = s.get("active_conns", 0)
            v["dpi"] = "Actif" if s.get("dpi_enabled") else "Inactif"
            v["suricata"] = "Actif" if s.get("suricata_enabled") else "Inactif"
            threats = s.get("threats", [])
            if threats:
                detail_lines = []
                for th in threats[-3:]:
                    detail_lines.append(f"  - {th.get('type','?')} : {th.get('ip', th.get('src','?'))}")
                v["threat_detail"] = "\n".join(detail_lines)
            else:
                v["threat_detail"] = "  Aucune menace active."

        elif agent_key == "cleanguard":
            v["health_score"] = s.get("health_score", 0)
            v["health_grade"] = s.get("health_grade", "--")
            v["realtime"] = "Actif" if s.get("realtime_protection") else "Inactif"
            v["scan_threats"] = s.get("scan_threats_count", 0)
            v["quarantine"] = s.get("quarantine_count", 0)
            v["scanning"] = "Oui" if s.get("scan_active") else "Non"

        elif agent_key == "vpnguard":
            v["vpn_status"] = "Connecte" if s.get("connected") else "Deconnecte"
            v["profile"] = s.get("active_profile_name", s.get("active_profile", "--"))
            v["public_ip"] = s.get("public_ip", "--")
            v["kill_switch"] = "Actif" if s.get("kill_switch_enabled") else "Inactif"
            v["dns"] = "Oui" if s.get("dns_protected") else "Non"
            rx = s.get("bytes_rx", 0)
            tx = s.get("bytes_tx", 0)
            v["rx"] = self._fmt_bytes(rx)
            v["tx"] = self._fmt_bytes(tx)

        elif agent_key == "honeypot":
            traps = s.get("traps", [])
            v["traps_total"] = len(traps)
            v["traps_triggered"] = s.get("traps_triggered", 0)
            service_stats = s.get("service_stats", {})
            v["total_probes"] = service_stats.get("total_connections", 0)
            v["unique_ips"] = service_stats.get("unique_ips", 0)
            v["alerts_count"] = s.get("alerts_count", 0)

        elif agent_key == "fim":
            v["baseline_files"] = s.get("baseline_files", 0)
            v["changes_detected"] = s.get("changes_detected", 0)
            v["files_added"] = s.get("files_added", 0)
            v["files_deleted"] = s.get("files_deleted", 0)
            v["scan_interval"] = s.get("scan_interval", 30)
            last = s.get("last_scan", 0)
            if last > 0:
                from datetime import datetime
                v["last_scan"] = datetime.fromtimestamp(last).strftime("%H:%M:%S")
            else:
                v["last_scan"] = "--"

        return v

    @staticmethod
    def _fmt_bytes(b):
        if b >= 1073741824:
            return f"{b / 1073741824:.1f} GB"
        if b >= 1048576:
            return f"{b / 1048576:.1f} MB"
        if b >= 1024:
            return f"{b / 1024:.1f} KB"
        return f"{b} B"

    def _find_topic(self, agent_key: str, message: str) -> dict | None:
        """Find the best matching topic for a user message."""
        msg_lower = message.lower()
        agent_kb = self.KNOWLEDGE.get(agent_key, {})

        best_match = None
        best_score = 0

        for topic_key, topic_data in agent_kb.items():
            score = 0
            for kw in topic_data.get("keywords", []):
                if kw in msg_lower:
                    score += 1
            if score > best_score:
                best_score = score
                best_match = topic_data

        return best_match

    def process_message(self, agent_key: str, user_msg: str, lang: str = "fr") -> dict:
        """Process a user message and generate a contextual response."""
        lang = lang if lang in ("fr", "en") else "fr"
        topic = self._find_topic(agent_key, user_msg)
        variables = self._get_agent_vars(agent_key)

        if topic:
            raw = topic["response"].get(lang, topic["response"]["fr"])
            try:
                message = raw.format(**variables)
            except (KeyError, IndexError):
                message = raw
            suggestions = topic.get("suggestions", {}).get(lang, [])
        else:
            message = self.DEFAULT_RESPONSE.get(lang, self.DEFAULT_RESPONSE["fr"])
            # Provide default suggestions
            default_sugs = {
                "fr": ["Etat de l'agent ?", "Menaces actives ?", "Aide"],
                "en": ["Agent status?", "Active threats?", "Help"],
            }
            suggestions = default_sugs.get(lang, default_sugs["fr"])

        # Store in history
        self._chat_history[agent_key].append({
            "role": "user", "text": user_msg, "ts": time.time()
        })
        self._chat_history[agent_key].append({
            "role": "agent", "text": message, "ts": time.time()
        })

        return {
            "type": "chat_response",
            "agent": agent_key,
            "message": message,
            "suggestions": suggestions,
            "ts": time.time(),
        }

    def get_auto_advice(self, agent_key: str, lang: str = "fr") -> dict:
        """Generate automatic advice based on current agent state."""
        lang = lang if lang in ("fr", "en") else "fr"
        conn = self.connectors.get(agent_key)
        advice_parts = []
        suggestions = []

        if not conn or not conn.connected:
            if lang == "fr":
                advice_parts.append(f"L'agent n'est pas connecte. Essayez de le demarrer.")
                suggestions = ["Demarrer l'agent"]
            else:
                advice_parts.append(f"The agent is not connected. Try starting it.")
                suggestions = ["Start agent"]
        else:
            s = conn.state or {}

            if agent_key == "netguard":
                threats = s.get("threats_count", 0)
                dpi = s.get("dpi_enabled", False)
                suricata = s.get("suricata_enabled", False)
                if threats > 0:
                    advice_parts.append(
                        f"{'Attention' if lang=='fr' else 'Warning'}: {threats} {'menace(s) detectee(s)' if lang=='fr' else 'threat(s) detected'}!"
                    )
                if not dpi:
                    advice_parts.append(
                        "Le DPI n'est pas actif. Activez-le pour une analyse approfondie." if lang == "fr"
                        else "DPI is not active. Enable it for deep analysis."
                    )
                if not suricata:
                    advice_parts.append(
                        "Suricata IDS est desactive. Activez-le pour la detection d'intrusion." if lang == "fr"
                        else "Suricata IDS is disabled. Enable it for intrusion detection."
                    )
                if not advice_parts:
                    advice_parts.append(
                        "Tout est normal. Le reseau est surveille." if lang == "fr"
                        else "Everything is normal. Network is being monitored."
                    )
                suggestions = (["Voir les menaces", "Activer le DPI"] if lang == "fr"
                               else ["View threats", "Enable DPI"])

            elif agent_key == "cleanguard":
                score = s.get("health_score", 100)
                realtime = s.get("realtime_protection", False)
                scan_threats = s.get("scan_threats_count", 0)
                if score < 70:
                    advice_parts.append(
                        f"Score de sante bas ({score}/100). Un nettoyage est recommande." if lang == "fr"
                        else f"Low health score ({score}/100). Cleanup is recommended."
                    )
                if not realtime:
                    advice_parts.append(
                        "Protection temps reel desactivee ! Activez-la immediatement." if lang == "fr"
                        else "Real-time protection disabled! Enable it immediately."
                    )
                if scan_threats > 0:
                    advice_parts.append(
                        f"{scan_threats} menace(s) trouvee(s) lors du dernier scan." if lang == "fr"
                        else f"{scan_threats} threat(s) found in last scan."
                    )
                if not advice_parts:
                    advice_parts.append(
                        "Systeme en bonne sante. Protection active." if lang == "fr"
                        else "System healthy. Protection active."
                    )
                suggestions = (["Lancer un scan", "Etat de sante ?"] if lang == "fr"
                               else ["Run a scan", "Health status?"])

            elif agent_key == "vpnguard":
                vpn_on = s.get("connected", False)
                ks = s.get("kill_switch_enabled", False)
                dns = s.get("dns_protected", False)
                if not vpn_on:
                    advice_parts.append(
                        "VPN non connecte. Votre trafic n'est pas chiffre." if lang == "fr"
                        else "VPN not connected. Your traffic is not encrypted."
                    )
                if vpn_on and not ks:
                    advice_parts.append(
                        "Kill Switch desactive. Activez-le pour eviter les fuites." if lang == "fr"
                        else "Kill Switch disabled. Enable it to prevent leaks."
                    )
                if not dns:
                    advice_parts.append(
                        "Protection DNS inactive. Vos requetes DNS peuvent fuiter." if lang == "fr"
                        else "DNS protection inactive. Your DNS queries may leak."
                    )
                if not advice_parts:
                    advice_parts.append(
                        "VPN actif et securise. Bonne configuration !" if lang == "fr"
                        else "VPN active and secure. Good configuration!"
                    )
                suggestions = (["Connecter le VPN", "Verifier fuite DNS"] if lang == "fr"
                               else ["Connect VPN", "Check DNS leak"])

            elif agent_key == "mailshield":
                advice_parts.append(
                    "MailShield est actif. Synchronisez pour verifier les nouveaux emails." if lang == "fr"
                    else "MailShield is active. Sync to check for new emails."
                )
                suggestions = (["Synchroniser", "Anti-phishing actif ?"] if lang == "fr"
                               else ["Sync", "Anti-phishing active?"])

            elif agent_key == "honeypot":
                traps_triggered = s.get("traps_triggered", 0)
                service_stats = s.get("service_stats", {})
                total_probes = service_stats.get("total_connections", 0)
                if traps_triggered > 0:
                    advice_parts.append(
                        f"ALERTE : {traps_triggered} piege(s) declenche(s) ! Un intrus a accede aux fichiers appats." if lang == "fr"
                        else f"ALERT: {traps_triggered} trap(s) triggered! An intruder accessed bait files."
                    )
                if total_probes > 0:
                    advice_parts.append(
                        f"{total_probes} sonde(s) detectee(s) sur les faux services." if lang == "fr"
                        else f"{total_probes} probe(s) detected on fake services."
                    )
                if not advice_parts:
                    advice_parts.append(
                        "HoneyPot actif. Aucune intrusion detectee." if lang == "fr"
                        else "HoneyPot active. No intrusion detected."
                    )
                suggestions = (["Etat du honeypot ?", "Faux services ?"] if lang == "fr"
                               else ["HoneyPot status?", "Fake services?"])

            elif agent_key == "fim":
                changes = s.get("changes_detected", 0)
                deleted = s.get("files_deleted", 0)
                baseline = s.get("baseline_files", 0)
                if deleted > 0:
                    advice_parts.append(
                        f"CRITIQUE : {deleted} fichier(s) systeme supprime(s) ! Investiguez immediatement." if lang == "fr"
                        else f"CRITICAL: {deleted} system file(s) deleted! Investigate immediately."
                    )
                if changes > 0:
                    advice_parts.append(
                        f"{changes} fichier(s) modifie(s) detecte(s). Verifiez si ces modifications sont legitimes." if lang == "fr"
                        else f"{changes} modified file(s) detected. Verify if these changes are legitimate."
                    )
                if not advice_parts:
                    advice_parts.append(
                        f"FIM actif. {baseline} fichiers surveilles. Aucune anomalie." if lang == "fr"
                        else f"FIM active. {baseline} files monitored. No anomalies."
                    )
                suggestions = (["Reconstruire la baseline", "Alertes recentes ?"] if lang == "fr"
                               else ["Rebuild baseline", "Recent alerts?"])

        message = "\n".join(advice_parts) if advice_parts else (
            "Tout semble normal." if lang == "fr" else "Everything looks normal."
        )

        return {
            "type": "chat_response",
            "agent": agent_key,
            "message": message,
            "suggestions": suggestions,
            "ts": time.time(),
        }

    def get_history(self, agent_key: str, limit: int = 50) -> list:
        return self._chat_history.get(agent_key, [])[-limit:]


# ===========================================================================
# CORTEX API — pywebview JavaScript bridge
# ===========================================================================

class CortexAPI:
    """API exposed to the dashboard via pywebview."""

    def __init__(self, manager: AgentManager, connectors: dict,
                 correlator: ThreatCorrelator, bus: AgentBus,
                 chat_engine: ChatEngine = None,
                 playbook_engine: PlaybookEngine = None,
                 threat_intel: ThreatIntelFeed = None,
                 alert_manager: AlertManager = None):
        self.manager = manager
        self.connectors = connectors
        self.correlator = correlator
        self.bus = bus
        self.chat = chat_engine
        self.playbook = playbook_engine
        self.threat_intel = threat_intel
        self.alert_mgr = alert_manager
        self._loop = None

    def set_loop(self, loop):
        self._loop = loop

    # --- Global State -------------------------------------------------

    def get_global_state(self) -> str:
        """Get complete state of all agents + metrics."""
        agents = {}
        for key, conn in self.connectors.items():
            proc_status = self.manager.get_status(key)
            summary = conn.get_summary()
            summary["process"] = proc_status
            agents[key] = summary

        # Calculate threat level
        self.correlator.calculate_threat_level(self.connectors)
        threat = self.correlator.get_threat_level()

        # System metrics
        try:
            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
        except Exception:
            cpu, mem, disk = 0, None, None

        state = {
            "type": "global_state",
            "version": VERSION,
            "ts": time.time(),
            "agents": agents,
            "threat_level": threat,
            "system": {
                "cpu_percent": cpu,
                "ram_total_gb": round(mem.total / (1024 ** 3), 1) if mem else 0,
                "ram_used_gb": round(mem.used / (1024 ** 3), 1) if mem else 0,
                "ram_percent": mem.percent if mem else 0,
                "disk_total_gb": round(disk.total / (1024 ** 3), 1) if disk else 0,
                "disk_used_gb": round(disk.used / (1024 ** 3), 1) if disk else 0,
                "disk_percent": disk.percent if disk else 0,
            },
            "bus_stats": self.bus.get_stats(),
            "timeline": self.bus.get_timeline(limit=50),
        }
        return json.dumps(state, default=str)

    def get_agent_state(self, agent_key: str) -> str:
        """Get detailed state for a single agent."""
        conn = self.connectors.get(agent_key)
        if not conn:
            return json.dumps({"error": f"Agent inconnu: {agent_key}"})
        summary = conn.get_summary()
        summary["process"] = self.manager.get_status(agent_key)
        return json.dumps(summary, default=str)

    # --- Agent Commands -----------------------------------------------

    def send_agent_command(self, agent_key: str, cmd: str, params_json: str = "{}") -> str:
        """Send a command to a specific agent."""
        conn = self.connectors.get(agent_key)
        if not conn:
            return json.dumps({"error": f"Agent inconnu: {agent_key}"})
        if not conn.connected:
            return json.dumps({"error": f"{conn.info['name']} non connecte"})

        try:
            params = json.loads(params_json) if params_json else {}
        except json.JSONDecodeError:
            params = {}

        if self._loop:
            future = asyncio.run_coroutine_threadsafe(
                conn.send_command(cmd, params), self._loop
            )
            result = future.result(timeout=5)
            return json.dumps({"success": result})
        return json.dumps({"error": "Event loop not available"})

    # --- Agent Lifecycle ----------------------------------------------

    def start_agent(self, agent_key: str) -> str:
        ok = self.manager.start_agent(agent_key)
        self.bus.publish("agent.started", "cortex", {"agent": agent_key})
        return json.dumps({"success": ok})

    def stop_agent(self, agent_key: str) -> str:
        ok = self.manager.stop_agent(agent_key)
        self.bus.publish("agent.stopped", "cortex", {"agent": agent_key})
        return json.dumps({"success": ok})

    def restart_agent(self, agent_key: str) -> str:
        ok = self.manager.restart_agent(agent_key)
        self.bus.publish("agent.restarted", "cortex", {"agent": agent_key})
        return json.dumps({"success": ok})

    def open_agent_window(self, agent_key: str) -> str:
        """Launch agent as a separate GUI window (no --headless)."""
        info = AGENTS.get(agent_key)
        if not info:
            return json.dumps({"error": f"Unknown agent: {agent_key}"})
        script = info["script"]
        if not os.path.exists(script):
            return json.dumps({"error": f"Script not found: {script}"})
        try:
            exe = sys.executable
            kwargs = {}
            if IS_WINDOWS:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
                if os.path.isfile(pythonw):
                    exe = pythonw
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                kwargs["startupinfo"] = si
            subprocess.Popen(
                [exe, script],
                cwd=os.path.dirname(script),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **kwargs,
            )
            logger.info(f"[Cortex] Opened {info['name']} window")
            return json.dumps({"success": True})
        except Exception as e:
            logger.error(f"[Cortex] Failed to open {agent_key} window: {e}")
            return json.dumps({"error": str(e)})

    # --- Threat Info --------------------------------------------------

    def get_threat_level(self) -> str:
        self.correlator.calculate_threat_level(self.connectors)
        return json.dumps(self.correlator.get_threat_level())

    def get_alerts(self, limit: int = 50) -> str:
        return json.dumps(self.correlator.get_alerts(limit), default=str)

    def get_timeline(self, limit: int = 100) -> str:
        return json.dumps(self.bus.get_timeline(limit), default=str)

    # --- Settings -----------------------------------------------------

    def get_settings(self) -> str:
        return json.dumps(SETTINGS)

    def save_settings(self, settings_json: str) -> str:
        global SETTINGS
        try:
            new_settings = json.loads(settings_json)
            SETTINGS.update(new_settings)
            save_settings(SETTINGS)
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"error": str(e)})

    # --- Chat ---------------------------------------------------------

    def chat_message(self, agent_key: str, message: str, lang: str = "fr") -> str:
        """Process a chat message and return a contextual response."""
        if not self.chat:
            return json.dumps({"type": "chat_response", "agent": agent_key,
                               "message": "Chat non disponible", "suggestions": [], "ts": time.time()})
        result = self.chat.process_message(agent_key, message, lang)
        return json.dumps(result, default=str)

    def chat_advice(self, agent_key: str, lang: str = "fr") -> str:
        """Get automatic advice for an agent based on its current state."""
        if not self.chat:
            return json.dumps({"type": "chat_response", "agent": agent_key,
                               "message": "Chat non disponible", "suggestions": [], "ts": time.time()})
        result = self.chat.get_auto_advice(agent_key, lang)
        return json.dumps(result, default=str)

    def chat_history(self, agent_key: str, limit: int = 50) -> str:
        """Get chat history for an agent."""
        if not self.chat:
            return json.dumps([])
        return json.dumps(self.chat.get_history(agent_key, limit), default=str)

    # --- Playbooks (SOAR) --------------------------------------------

    def get_playbooks(self, lang: str = "fr") -> str:
        """Get all SOAR playbooks."""
        if not self.playbook:
            return json.dumps([])
        return json.dumps(self.playbook.get_playbooks(lang), default=str)

    def toggle_playbook(self, pb_id: str) -> str:
        """Toggle a playbook on/off."""
        if not self.playbook:
            return json.dumps({"error": "Playbook engine unavailable"})
        new_state = self.playbook.toggle_playbook(pb_id)
        return json.dumps({"success": True, "enabled": new_state})

    def get_playbook_log(self, limit: int = 50) -> str:
        """Get playbook execution history."""
        if not self.playbook:
            return json.dumps([])
        return json.dumps(self.playbook.get_execution_log(limit), default=str)

    # --- Threat Intelligence -----------------------------------------

    def get_threat_intel_stats(self) -> str:
        """Get threat intelligence feed statistics."""
        if not self.threat_intel:
            return json.dumps({"error": "Threat intel unavailable"})
        return json.dumps(self.threat_intel.get_stats(), default=str)

    def check_ip_reputation(self, ip: str) -> str:
        """Check if an IP is in threat databases."""
        if not self.threat_intel:
            return json.dumps({"error": "Threat intel unavailable"})
        return json.dumps(self.threat_intel.check_ip(ip), default=str)

    def update_threat_feeds(self) -> str:
        """Manually trigger a threat feed update."""
        if not self.threat_intel:
            return json.dumps({"error": "Threat intel unavailable"})
        threading.Thread(target=self.threat_intel.update_feeds, daemon=True).start()
        return json.dumps({"success": True, "message": "Update started"})

    # --- Alert Manager -----------------------------------------------

    def get_alert_config(self) -> str:
        """Get alert notification configuration."""
        if not self.alert_mgr:
            return json.dumps({"error": "Alert manager unavailable"})
        return json.dumps(self.alert_mgr.get_config(), default=str)

    def update_alert_config(self, config_json: str) -> str:
        """Update alert notification configuration."""
        if not self.alert_mgr:
            return json.dumps({"error": "Alert manager unavailable"})
        try:
            config = json.loads(config_json)
            self.alert_mgr.update_config(config)
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def test_telegram(self) -> str:
        """Send a test Telegram notification."""
        if not self.alert_mgr:
            return json.dumps({"success": False, "error": "Alert manager unavailable"})
        ok = self.alert_mgr.test_telegram()
        return json.dumps({"success": ok})

    def test_discord(self) -> str:
        """Send a test Discord notification."""
        if not self.alert_mgr:
            return json.dumps({"success": False, "error": "Alert manager unavailable"})
        ok = self.alert_mgr.test_discord()
        return json.dumps({"success": ok})

    def get_alert_log(self, limit: int = 50) -> str:
        """Get recent sent alert log."""
        if not self.alert_mgr:
            return json.dumps([])
        return json.dumps(self.alert_mgr.get_log(limit), default=str)

    # --- Diagnostics --------------------------------------------------

    def get_diagnostics(self) -> str:
        diag = {
            "cortex_version": VERSION,
            "python_version": sys.version,
            "os": f"{sys.platform} {os.name}",
            "cortex_port": CORTEX_PORT,
            "uptime_s": time.time() - _START_TIME,
            "agents": {},
        }
        for key, conn in self.connectors.items():
            diag["agents"][key] = {
                "name": conn.info["name"],
                "port": conn.port,
                "connected": conn.connected,
                "process": self.manager.get_status(key),
                "error": conn.error,
                "last_update": conn.last_update,
            }
        return json.dumps(diag, default=str)


# ===========================================================================
# WEBSOCKET SERVER — Serves dashboard + external clients
# ===========================================================================

_ws_clients = set()


async def ws_handler(websocket, path=None):
    """Handle WebSocket connections from the dashboard."""
    _ws_clients.add(websocket)
    logger.info(f"[WS] Dashboard connected ({len(_ws_clients)} clients)")
    try:
        async for message in websocket:
            try:
                msg = json.loads(message)
                await handle_ws_command(websocket, msg)
            except json.JSONDecodeError:
                pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        _ws_clients.discard(websocket)
        logger.info(f"[WS] Dashboard disconnected ({len(_ws_clients)} clients)")


async def handle_ws_command(ws, msg: dict):
    """Route WebSocket commands from the dashboard."""
    cmd = msg.get("cmd", "")

    if cmd == "get_state":
        state_json = _api.get_global_state()
        await ws.send(state_json)

    elif cmd == "get_agent_state":
        key = msg.get("agent", "")
        result = _api.get_agent_state(key)
        await ws.send(result)

    elif cmd == "send_agent_command":
        key = msg.get("agent", "")
        agent_cmd = msg.get("agent_cmd", "")
        params = json.dumps(msg.get("params", {}))
        result = _api.send_agent_command(key, agent_cmd, params)
        await ws.send(result)

    elif cmd == "start_agent":
        result = _api.start_agent(msg.get("agent", ""))
        await ws.send(result)

    elif cmd == "stop_agent":
        result = _api.stop_agent(msg.get("agent", ""))
        await ws.send(result)

    elif cmd == "restart_agent":
        result = _api.restart_agent(msg.get("agent", ""))
        await ws.send(result)

    elif cmd == "open_agent_window":
        result = _api.open_agent_window(msg.get("agent", ""))
        await ws.send(result)

    elif cmd == "get_threat_level":
        result = _api.get_threat_level()
        await ws.send(result)

    elif cmd == "get_alerts":
        limit = msg.get("limit", 50)
        result = _api.get_alerts(limit)
        await ws.send(result)

    elif cmd == "get_timeline":
        limit = msg.get("limit", 100)
        result = _api.get_timeline(limit)
        await ws.send(result)

    elif cmd == "get_settings":
        await ws.send(_api.get_settings())

    elif cmd == "save_settings":
        result = _api.save_settings(json.dumps(msg.get("settings", {})))
        await ws.send(result)

    elif cmd == "get_diagnostics":
        await ws.send(_api.get_diagnostics())

    elif cmd == "chat_message":
        agent = msg.get("agent", "")
        message = msg.get("message", "")
        lang = msg.get("lang", "fr")
        result = _api.chat_message(agent, message, lang)
        await ws.send(result)

    elif cmd == "chat_advice":
        agent = msg.get("agent", "")
        lang = msg.get("lang", "fr")
        result = _api.chat_advice(agent, lang)
        await ws.send(result)

    elif cmd == "chat_history":
        agent = msg.get("agent", "")
        limit = msg.get("limit", 50)
        result = _api.chat_history(agent, limit)
        await ws.send(result)

    # --- Playbook commands ----------------------------------------
    elif cmd == "get_playbooks":
        lang = msg.get("lang", "fr")
        result = _api.get_playbooks(lang)
        await ws.send(result)

    elif cmd == "toggle_playbook":
        pb_id = msg.get("playbook_id", "")
        result = _api.toggle_playbook(pb_id)
        await ws.send(result)

    elif cmd == "get_playbook_log":
        limit = msg.get("limit", 50)
        result = _api.get_playbook_log(limit)
        await ws.send(result)

    # --- Threat Intel commands ------------------------------------
    elif cmd == "get_threat_intel":
        result = _api.get_threat_intel_stats()
        await ws.send(result)

    elif cmd == "check_ip":
        ip = msg.get("ip", "")
        result = _api.check_ip_reputation(ip)
        await ws.send(result)

    elif cmd == "update_threat_feeds":
        result = _api.update_threat_feeds()
        await ws.send(result)

    # --- Alert Manager commands -----------------------------------
    elif cmd == "get_alert_config":
        result = _api.get_alert_config()
        await ws.send(result)

    elif cmd == "update_alert_config":
        config = msg.get("config", {})
        result = _api.update_alert_config(json.dumps(config))
        await ws.send(result)

    elif cmd == "test_telegram":
        result = _api.test_telegram()
        await ws.send(result)

    elif cmd == "test_discord":
        result = _api.test_discord()
        await ws.send(result)

    elif cmd == "get_alert_log":
        limit = msg.get("limit", 50)
        result = _api.get_alert_log(limit)
        await ws.send(result)


async def broadcast_state():
    """Periodically broadcast global state to all connected dashboard clients."""
    while True:
        if _ws_clients:
            try:
                state_json = _api.get_global_state()
                dead = set()
                for client in _ws_clients.copy():
                    try:
                        await client.send(state_json)
                    except Exception:
                        dead.add(client)
                _ws_clients.difference_update(dead)
            except Exception as e:
                logger.error(f"[WS] Broadcast error: {e}")
        await asyncio.sleep(max(SETTINGS.get("state_poll_interval", 10), 8))


# ===========================================================================
# STATE POLLING — Request state from agents periodically
# ===========================================================================

async def poll_agent_states(connectors: dict):
    """Periodically request get_state from all connected agents."""
    while True:
        for key, conn in connectors.items():
            if conn.connected and conn.ws:
                try:
                    await conn.send_command("get_state")
                except Exception:
                    conn.connected = False
                    conn.ws = None
        await asyncio.sleep(max(SETTINGS.get("state_poll_interval", 10), 8))


# ===========================================================================
# MAIN — Start everything
# ===========================================================================

_START_TIME = time.time()
_api = None  # Will be set in main


def run_async_loop(loop, connectors, manager, bus):
    """Run the async event loop in a background thread."""
    asyncio.set_event_loop(loop)

    async def main_async():
        # Start WebSocket server
        server = await websockets.serve(ws_handler, "localhost", CORTEX_PORT,
                                                ping_interval=30, ping_timeout=15)
        logger.info(f"[Cortex] WebSocket server on ws://localhost:{CORTEX_PORT}")

        # Start connector loops
        tasks = []
        for key, conn in connectors.items():
            tasks.append(asyncio.create_task(conn.connect_loop()))

        # Start state polling
        tasks.append(asyncio.create_task(poll_agent_states(connectors)))

        # Start broadcast loop
        tasks.append(asyncio.create_task(broadcast_state()))

        # Wait forever
        await asyncio.gather(*tasks, return_exceptions=True)

    loop.run_until_complete(main_async())


def main():
    global _api

    logger.info("=" * 60)
    logger.info(f"  SentinelOS Cortex v{VERSION}")
    logger.info(f"  Starting on port {CORTEX_PORT}")
    logger.info(f"  Agents: {len(AGENTS)} ({', '.join(AGENTS.keys())})")
    logger.info("=" * 60)

    # Initialize components
    bus = AgentBus()
    manager = AgentManager()
    connectors = {}
    for key, info in AGENTS.items():
        connectors[key] = AgentConnector(key, info, bus)

    correlator = ThreatCorrelator(bus)
    chat_engine = ChatEngine(connectors)

    # Phase 3 components
    playbook_engine = PlaybookEngine(bus, connectors)
    threat_intel = ThreatIntelFeed(bus)
    # AlertManager itself is vault-aware (it calls vault_helpers.get_secret
    # with these settings as fallback). We just pass the legacy plaintext
    # fields so a clean install with no vault keeps working unchanged.
    alert_settings = {
        "telegram_bot_token": SETTINGS.get("telegram_bot_token", ""),
        "telegram_chat_id": SETTINGS.get("telegram_chat_id", ""),
        "discord_webhook_url": SETTINGS.get("discord_webhook_url", ""),
        "slack_webhook_url": SETTINGS.get("slack_webhook_url", ""),
        "teams_webhook_url": SETTINGS.get("teams_webhook_url", ""),
        "language": SETTINGS.get("language", "fr"),
    }
    alert_mgr = AlertManager(bus, alert_settings)

    _api = CortexAPI(manager, connectors, correlator, bus, chat_engine,
                     playbook_engine, threat_intel, alert_mgr)

    # Give playbook engine access to API for executing cross-agent commands
    playbook_engine.set_api(_api)

    # Start threat intelligence auto-update
    threat_intel.start_auto_update()
    logger.info("[Cortex] Phase 3 components initialized (Playbooks, ThreatIntel, Alerts)")

    # Agents are NOT auto-started — user launches them from the dashboard
    logger.info("[Cortex] Agents will be started manually from the dashboard")

    # Start async loop in background thread
    loop = asyncio.new_event_loop()
    _api.set_loop(loop)
    async_thread = threading.Thread(
        target=run_async_loop,
        args=(loop, connectors, manager, bus),
        daemon=True,
    )
    async_thread.start()
    logger.info("[Cortex] Async loop started")

    # Give WebSocket server time to start
    time.sleep(1)

    # --- Open Dashboard directly ----------------------------------
    dashboard_path = os.path.join(SENTINEL_DIR, "sentinel_dashboard.html")

    if not os.path.exists(dashboard_path):
        logger.error(f"[Cortex] Dashboard not found: {dashboard_path}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        try:
            import webview
            window = webview.create_window(
                f"SentinelOS v{VERSION} — Centre de Commandement",
                dashboard_path,
                js_api=_api,
                width=1400,
                height=900,
                min_size=(1024, 700),
                background_color="#0a0e17",
            )
            logger.info("[Cortex] Opening SentinelOS dashboard...")
            webview.start(debug=False)
        except ImportError:
            logger.warning("[Cortex] pywebview not installed, opening in browser")
            import webbrowser
            from pathlib import Path
            webbrowser.open(Path(dashboard_path).as_uri())
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        except Exception as e:
            logger.error(f"[Cortex] Dashboard error: {e}")
            import webbrowser
            from pathlib import Path
            webbrowser.open(Path(dashboard_path).as_uri())
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    # Cleanup
    logger.info("[Cortex] Shutting down...")
    playbook_engine.stop()
    threat_intel.stop()
    alert_mgr.stop()
    for conn in connectors.values():
        conn.stop()
    manager.stop_all()
    logger.info("[Cortex] Goodbye.")


if __name__ == "__main__":
    main()
