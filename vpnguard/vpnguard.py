#!/usr/bin/env python3
"""
VPN Guard Pro v1.0.0 — VPN WireGuard autonome avec Kill Switch, DNS Protection,
Split Tunneling, Wi-Fi auto-connect, Profils, et Stats temps reel.
Partie de l'ecosysteme NetGuard Pro.
"""

import asyncio
import base64
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import logging
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[!] websockets manquant: pip install websockets")

try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

IS_WINDOWS = platform.system() == "Windows"

# ── Security validators (Phase 3 hardening) ─────────────────────────────────
_WG_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_WG_DANGEROUS_KEYS = {"postup", "postdown", "preup", "predown"}


def _validate_wg_name(name: str) -> bool:
    """Reject path-traversal and shell-special characters in profile/peer names."""
    return isinstance(name, str) and bool(_WG_NAME_RE.match(name))


def _validate_wg_config(content: str) -> tuple:
    """Reject WireGuard configs containing PostUp/PostDown/PreUp/PreDown (shell-exec)."""
    if not isinstance(content, str):
        return False, "Contenu manquant"
    if len(content) > 64 * 1024:
        return False, "Config trop longue (>64KB)"
    for line_no, line in enumerate(content.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or (s.startswith("[") and s.endswith("]")):
            continue
        if "=" not in s:
            continue
        key = s.split("=", 1)[0].strip().lower()
        if key in _WG_DANGEROUS_KEYS:
            return False, f"Cle dangereuse '{key}' interdite (ligne {line_no}) — peut executer du shell au tunnel up/down"
    return True, ""


def _safe_path_join(base_dir: str, filename: str) -> str:
    """Return base_dir/filename only if the resolved path stays under base_dir. Else raise ValueError."""
    base_real = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base_dir, filename))
    if not (candidate == base_real or candidate.startswith(base_real + os.sep)):
        raise ValueError(f"Chemin hors du dossier autorise: {filename!r}")
    return candidate
IS_LINUX = platform.system() == "Linux"

VERSION = "1.0.0"
BASE_DIR = Path(__file__).parent.resolve()
SETTINGS_FILE = BASE_DIR / "vpnguard_settings.json"
CONFIGS_DIR = BASE_DIR / "configs"
PROFILES_DIR = BASE_DIR / "profiles"
LOGS_DIR = BASE_DIR / "logs"

for d in [CONFIGS_DIR, PROFILES_DIR, LOGS_DIR]:
    d.mkdir(exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("VPNGuard")

try:
    sys.path.insert(0, str(BASE_DIR.parent))
    from startup_utils import is_startup_enabled, toggle_startup as toggle_startup_reg, minimize_to_tray
    HAS_STARTUP_UTILS = True
except ImportError:
    HAS_STARTUP_UTILS = False


# =============================================================================
# CONFIG
# =============================================================================

@dataclass
class Config:
    ws_port: int = 8820
    theme: str = "dark"
    language: str = "fr"
    mode: str = "server"
    active_profile: str = "default"
    wg_interface: str = "wg0"
    wg_listen_port: int = 51820
    wg_address: str = "10.66.66.1/24"
    wg_dns: str = "1.1.1.1, 9.9.9.9"
    wg_endpoint: str = ""
    wg_post_up: str = ""
    wg_post_down: str = ""
    kill_switch_enabled: bool = False
    dns_leak_protection: bool = True
    auto_connect: bool = False
    auto_connect_untrusted_wifi: bool = True
    split_tunnel_enabled: bool = False
    split_tunnel_apps: list = field(default_factory=list)
    split_tunnel_bypass: list = field(default_factory=list)
    trusted_networks: list = field(default_factory=list)
    connection_log_max: int = 500

CFG = Config()


def load_settings():
    if not SETTINGS_FILE.exists():
        return
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)
        for k, v in s.items():
            if hasattr(CFG, k):
                setattr(CFG, k, v)
        log.info("[SETTINGS] Charge")
    except Exception as e:
        log.error(f"[SETTINGS] Erreur: {e}")


def save_settings():
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(asdict(CFG), f, indent=2, ensure_ascii=False)
    except Exception as e:
        log.error(f"[SETTINGS] Erreur sauvegarde: {e}")


# =============================================================================
# TIMELINE
# =============================================================================

TIMELINE = deque(maxlen=200)

def timeline_add(icon, text, category="info"):
    TIMELINE.appendleft({
        "time": datetime.now().isoformat(),
        "icon": icon,
        "text": text,
        "category": category,
    })


# =============================================================================
# WIREGUARD CORE — extracted from netguard.py
# =============================================================================

class WireGuardCore:
    """Core WireGuard operations: key generation, tunnel management, peer management"""

    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.server_privkey = ""
        self.server_pubkey = ""
        self.peers = []
        self.status = {"running": False, "interface": "", "peers_connected": 0}
        self._wg_bin = None
        self._wireguard_bin = None

    def find_binary(self, name: str) -> str:
        found = shutil.which(name)
        if found:
            return found
        if IS_WINDOWS:
            candidates = [
                os.path.join(r"C:\Program Files\WireGuard", name),
                os.path.join(r"C:\Program Files\WireGuard", name + ".exe"),
                os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WireGuard", name),
                os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WireGuard", name + ".exe"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c
        return name

    def wg_cmd(self) -> str:
        if self._wg_bin is None:
            self._wg_bin = self.find_binary("wg")
        return self._wg_bin

    def wireguard_cmd(self) -> str:
        if self._wireguard_bin is None:
            self._wireguard_bin = self.find_binary("wireguard")
        return self._wireguard_bin

    def is_installed(self) -> bool:
        try:
            kwargs = {}
            if IS_WINDOWS:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run([self.wg_cmd(), "--version"],
                                   capture_output=True, text=True, timeout=5, **kwargs)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def genkey_python(self) -> tuple:
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
            privkey_obj = X25519PrivateKey.generate()
            priv_b64 = base64.b64encode(privkey_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
            pub_b64 = base64.b64encode(privkey_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            return priv_b64, pub_b64
        except ImportError:
            log.error("[WG] cryptography non installe: pip install cryptography")
            return "", ""
        except Exception as e:
            log.error(f"[WG] Erreur genkey Python: {e}")
            return "", ""

    def genpsk_python(self) -> str:
        return base64.b64encode(os.urandom(32)).decode()

    def genkey(self) -> tuple:
        try:
            _kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
            result = subprocess.run([self.wg_cmd(), "genkey"],
                                   capture_output=True, text=True, timeout=5, **_kw)
            privkey = result.stdout.strip()
            if not privkey:
                raise ValueError("empty")
            result2 = subprocess.run([self.wg_cmd(), "pubkey"], input=privkey,
                                    capture_output=True, text=True, timeout=5, **_kw)
            pubkey = result2.stdout.strip()
            if not pubkey:
                raise ValueError("empty")
            return privkey, pubkey
        except Exception:
            return self.genkey_python()

    def init_server(self):
        os.makedirs(self.config_dir, exist_ok=True)
        keyfile = os.path.join(self.config_dir, "server_keys.json")
        if os.path.exists(keyfile):
            try:
                with open(keyfile, "r") as f:
                    keys = json.load(f)
                self.server_privkey = keys.get("privkey", "")
                self.server_pubkey = keys.get("pubkey", "")
                if self.server_privkey and self.server_pubkey:
                    log.info(f"[WG] Cles serveur chargees. PubKey: {self.server_pubkey[:20]}...")
                    return
            except Exception:
                pass
        self.server_privkey, self.server_pubkey = self.genkey()
        if self.server_privkey:
            try:
                with open(keyfile, "w") as f:
                    json.dump({"privkey": self.server_privkey, "pubkey": self.server_pubkey}, f)
                try:
                    os.chmod(keyfile, 0o600)
                except OSError:
                    pass
                log.info(f"[WG] Nouvelles cles serveur generees")
            except Exception as e:
                log.error(f"[WG] Erreur sauvegarde cles: {e}")

    def generate_server_config(self) -> str:
        if not self.server_privkey:
            self.init_server()
        lines = [
            "[Interface]",
            f"PrivateKey = {self.server_privkey}",
            f"Address = {CFG.wg_address}",
            f"ListenPort = {CFG.wg_listen_port}",
            f"DNS = {CFG.wg_dns}",
        ]
        if CFG.wg_post_up:
            lines.append(f"PostUp = {CFG.wg_post_up}")
        if CFG.wg_post_down:
            lines.append(f"PostDown = {CFG.wg_post_down}")
        for peer in self.peers:
            lines += ["", "[Peer]", f"PublicKey = {peer['pubkey']}", f"AllowedIPs = {peer['address']}/32"]
            if peer.get("preshared_key"):
                lines.append(f"PresharedKey = {peer['preshared_key']}")
        config = "\n".join(lines) + "\n"
        config_path = os.path.join(self.config_dir, f"{CFG.wg_interface}.conf")
        with open(config_path, "w") as f:
            f.write(config)
        return config_path

    def generate_peer_config(self, peer: dict) -> str:
        endpoint = CFG.wg_endpoint or "YOUR_SERVER_IP:51820"
        return f"""[Interface]
PrivateKey = {peer['privkey']}
Address = {peer['address']}/32
DNS = {CFG.wg_dns}

[Peer]
PublicKey = {self.server_pubkey}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

    def add_peer(self, name: str) -> dict:
        if not _validate_wg_name(name):
            return {"error": f"Nom de peer invalide: {name!r} (lettres/chiffres/_/- seulement, max 40)"}
        if not self.server_privkey:
            self.init_server()
        privkey, pubkey = self.genkey()
        if not privkey:
            return {"error": "Impossible de generer les cles. WireGuard installe?"}
        base_parts = CFG.wg_address.split("/")[0].split(".")
        used_ips = {p["address"] for p in self.peers}
        next_ip = ""
        for i in range(2, 254):
            candidate = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
            if candidate not in used_ips and candidate != CFG.wg_address.split("/")[0]:
                next_ip = candidate
                break
        if not next_ip:
            return {"error": "Plus d'adresses IP disponibles"}
        try:
            _kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
            psk_result = subprocess.run([self.wg_cmd(), "genpsk"],
                                       capture_output=True, text=True, timeout=5, **_kw)
            psk = psk_result.stdout.strip() or self.genpsk_python()
        except Exception:
            psk = self.genpsk_python()
        peer = {
            "name": name, "pubkey": pubkey, "privkey": privkey,
            "preshared_key": psk, "address": next_ip,
            "allowed_ips": f"{next_ip}/32",
            "created": datetime.now().isoformat(),
            "last_handshake": "", "transfer_rx": 0, "transfer_tx": 0,
        }
        self.peers.append(peer)
        os.makedirs(self.config_dir, exist_ok=True)
        peer_conf = self.generate_peer_config(peer)
        peer_file = os.path.join(self.config_dir, f"peer_{name}.conf")
        with open(peer_file, "w") as f:
            f.write(peer_conf)
        self.generate_server_config()
        self.save_peers()
        timeline_add("👤", f"Peer ajoute: {name} ({next_ip})", "vpn")
        return {"ok": True, "peer": {k: v for k, v in peer.items() if k != "privkey"}, "config": peer_conf, "config_file": peer_file}

    def remove_peer(self, name: str) -> dict:
        peer = next((p for p in self.peers if p["name"] == name), None)
        if not peer:
            return {"error": f"Peer '{name}' non trouve"}
        self.peers = [p for p in self.peers if p["name"] != name]
        peer_file = os.path.join(self.config_dir, f"peer_{name}.conf")
        if os.path.exists(peer_file):
            os.remove(peer_file)
        self.generate_server_config()
        self.save_peers()
        if self.status.get("running"):
            try:
                _kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
                subprocess.run([self.wg_cmd(), "set", CFG.wg_interface, "peer", peer["pubkey"], "remove"],
                               capture_output=True, timeout=10, **_kw)
            except Exception:
                pass
        timeline_add("👤", f"Peer supprime: {name}", "vpn")
        return {"ok": True}

    def _ensure_manager_service(self):
        """Ensure the WireGuard Manager Service is installed (Windows only)."""
        if not IS_WINDOWS:
            return
        try:
            # Check if the service is already running
            r = subprocess.run(["sc", "query", "WireGuardManager"],
                              capture_output=True, text=True, timeout=5)
            if "RUNNING" in r.stdout:
                return  # Already running
            if "does not exist" in r.stdout or r.returncode != 0:
                # Install the manager service
                log.info("[WG] Installation du WireGuard Manager Service...")
                subprocess.run([self.wireguard_cmd(), "/installmanagerservice"],
                              capture_output=True, text=True, timeout=15,
                              creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
                time.sleep(2)
        except Exception as e:
            log.warning(f"[WG] Manager service check: {e}")

    def start_tunnel(self, config_path=None) -> dict:
        if not config_path:
            if not self.server_privkey:
                self.init_server()
            config_path = self.generate_server_config()
        abs_config = os.path.abspath(config_path)

        # Verify config file exists
        if not os.path.isfile(abs_config):
            return {"error": f"Fichier de configuration introuvable: {abs_config}"}

        try:
            if IS_LINUX:
                result = subprocess.run(["wg-quick", "up", abs_config],
                                       capture_output=True, text=True, timeout=15)
            elif IS_WINDOWS:
                # First ensure the Manager Service is running
                self._ensure_manager_service()

                # Install tunnel service (this starts the tunnel)
                log.info(f"[WG] Demarrage tunnel: {abs_config}")
                result = subprocess.run(
                    [self.wireguard_cmd(), "/installtunnelservice", abs_config],
                    capture_output=True, text=True, timeout=20,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                return {"error": "OS non supporte"}

            if result.returncode != 0:
                stderr = result.stderr.strip() or result.stdout.strip()
                if "access" in stderr.lower() or "denied" in stderr.lower() or "privilege" in stderr.lower():
                    return {"error": "Droits administrateur requis. Lancez VPN Guard avec LANCER_VPNGUARD.bat"}
                if "already exists" in stderr.lower() or "already" in stderr.lower():
                    # Tunnel already running, treat as success
                    log.info("[WG] Tunnel deja actif")
                else:
                    return {"error": f"Erreur WireGuard: {stderr}"}

            # Wait for tunnel to come up
            time.sleep(2)

            # Verify tunnel is running
            verify = subprocess.run(
                [self.wg_cmd(), "show", CFG.wg_interface],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
            )
            if verify.returncode == 0 and verify.stdout.strip():
                self.status["running"] = True
                self.status["interface"] = CFG.wg_interface
                timeline_add("🟢", "VPN connecte", "vpn")
                return {"ok": True, "status": "started"}
            else:
                # Try alternative check on Windows - service might be starting
                if IS_WINDOWS:
                    time.sleep(2)
                    verify2 = subprocess.run(
                        [self.wg_cmd(), "show", CFG.wg_interface],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if verify2.returncode == 0 and verify2.stdout.strip():
                        self.status["running"] = True
                        self.status["interface"] = CFG.wg_interface
                        timeline_add("🟢", "VPN connecte", "vpn")
                        return {"ok": True, "status": "started"}

                self.status["running"] = False
                return {"error": "Le tunnel n'a pas demarre. Verifiez les droits admin et la config WireGuard."}

        except FileNotFoundError:
            msg = "WireGuard non installe. "
            if IS_WINDOWS:
                msg += "Lancez LANCER_VPNGUARD.bat pour l'installer automatiquement."
            else:
                msg += "sudo apt install wireguard"
            return {"error": msg}
        except subprocess.TimeoutExpired:
            return {"error": "Timeout: WireGuard met trop de temps a demarrer."}
        except Exception as e:
            log.error(f"[WG] Erreur start_tunnel: {e}")
            return {"error": str(e)}

    def stop_tunnel(self) -> dict:
        try:
            if IS_LINUX:
                config_path = os.path.join(self.config_dir, f"{CFG.wg_interface}.conf")
                subprocess.run(["wg-quick", "down", config_path],
                              capture_output=True, text=True, timeout=15)
            elif IS_WINDOWS:
                subprocess.run(
                    [self.wireguard_cmd(), "/uninstalltunnelservice", CFG.wg_interface],
                    capture_output=True, text=True, timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            self.status["running"] = False
            self.status["peers_connected"] = 0
            timeline_add("🔴", "VPN deconnecte", "vpn")
            return {"ok": True, "status": "stopped"}
        except FileNotFoundError:
            return {"error": "WireGuard non installe"}
        except Exception as e:
            log.error(f"[WG] Erreur stop_tunnel: {e}")
            return {"error": str(e)}

    def get_status(self) -> dict:
        try:
            kwargs = {}
            if IS_WINDOWS:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run([self.wg_cmd(), "show", CFG.wg_interface],
                                   capture_output=True, text=True, timeout=5, **kwargs)
            if result.returncode != 0:
                self.status["running"] = False
                return self.status
            self.status["running"] = True
            self.status["interface"] = CFG.wg_interface
            connected = 0
            current_peer_pub = ""
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("peer:"):
                    current_peer_pub = line.split(":", 1)[1].strip()
                elif line.startswith("latest handshake:") and current_peer_pub:
                    hs = line.split(":", 1)[1].strip()
                    for p in self.peers:
                        if p["pubkey"] == current_peer_pub:
                            p["last_handshake"] = hs
                    connected += 1
                elif line.startswith("transfer:") and current_peer_pub:
                    parts = line.split(":", 1)[1].strip()
                    for p in self.peers:
                        if p["pubkey"] == current_peer_pub:
                            p["transfer_info"] = parts
            self.status["peers_connected"] = connected
        except FileNotFoundError:
            self.status["running"] = False
            self.status["not_installed"] = True
        except Exception:
            self.status["running"] = False
        return self.status

    def save_peers(self):
        try:
            peers_file = os.path.join(self.config_dir, "peers.json")
            with open(peers_file, "w", encoding="utf-8") as f:
                json.dump(self.peers, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log.error(f"[WG] Erreur sauvegarde peers: {e}")

    def load_peers(self):
        peers_file = os.path.join(self.config_dir, "peers.json")
        if os.path.exists(peers_file):
            try:
                with open(peers_file, "r", encoding="utf-8") as f:
                    self.peers = json.load(f)
                log.info(f"[WG] {len(self.peers)} peers charges")
            except Exception as e:
                log.error(f"[WG] Erreur chargement peers: {e}")

    def import_config(self, conf_content: str, name: str) -> dict:
        """Import a .conf file as a client profile (validated)"""
        if not _validate_wg_name(name):
            return {"error": f"Nom invalide: {name!r} (lettres/chiffres/_/- seulement, max 40)"}
        ok, err = _validate_wg_config(conf_content)
        if not ok:
            return {"error": err}
        try:
            conf_path = _safe_path_join(self.config_dir, f"client_{name}.conf")
        except ValueError as e:
            return {"error": str(e)}
        try:
            with open(conf_path, "w", encoding="utf-8") as f:
                f.write(conf_content)
            try:
                os.chmod(conf_path, 0o600)
            except OSError:
                pass
            timeline_add("📥", f"Config importee: {name}", "vpn")
            return {"ok": True, "path": conf_path, "name": name}
        except Exception as e:
            return {"error": str(e)}


# =============================================================================
# KILL SWITCH — Windows Firewall rules
# =============================================================================

_KILLSWITCH_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_KILLSWITCH_IFACE_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,64}$")
_KILLSWITCH_UNSAFE_CHARS = set('"\';\n\r&|`<>$')


class KillSwitch:
    RULE_PREFIX = "VPNGuard_KillSwitch"

    def __init__(self):
        self.active = False

    def enable(self, tunnel_interface: str = "") -> dict:
        if not IS_WINDOWS:
            return {"error": "Kill Switch supporte uniquement sur Windows"}
        # Validate tunnel_interface (CRITICAL: was shell-injection sink before)
        if tunnel_interface and not _KILLSWITCH_IFACE_RE.match(tunnel_interface):
            return {"error": f"Nom d'interface invalide: {tunnel_interface!r}"}
        try:
            # Block all outbound
            self._add_rule(f"{self.RULE_PREFIX}_BlockAll", "out", "block")
            # Allow VPN tunnel traffic
            if tunnel_interface:
                self._add_rule(f"{self.RULE_PREFIX}_AllowVPN", "out", "allow",
                              extra_args=["localip=any", "remoteip=any",
                                          f"interface={tunnel_interface}"])
            # Allow local network
            for net in ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]:
                self._add_rule(f"{self.RULE_PREFIX}_AllowLAN_{net.replace('/', '_').replace('.', '_')}", "out", "allow",
                              extra_args=[f"remoteip={net}"])
            # Allow DHCP
            self._add_rule(f"{self.RULE_PREFIX}_AllowDHCP", "out", "allow",
                          extra_args=["protocol=udp", "remoteport=67-68"])
            # Allow loopback
            self._add_rule(f"{self.RULE_PREFIX}_AllowLoopback", "out", "allow",
                          extra_args=["remoteip=127.0.0.0/8"])
            self.active = True
            timeline_add("🛡", "Kill Switch active", "security")
            return {"enabled": True}
        except Exception as e:
            return {"error": str(e)}

    def disable(self) -> dict:
        if not IS_WINDOWS:
            return {"error": "Kill Switch supporte uniquement sur Windows"}
        try:
            # Remove all VPNGuard rules
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name=all"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if self.RULE_PREFIX in line and "Rule Name:" in line:
                    rule_name = line.split(":", 1)[1].strip()
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                        capture_output=True, timeout=10
                    )
            self.active = False
            timeline_add("🛡", "Kill Switch desactive", "security")
            return {"enabled": False}
        except Exception as e:
            return {"error": str(e)}

    def check_status(self) -> dict:
        if not IS_WINDOWS:
            return {"active": False, "rules": []}
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name=all"],
                capture_output=True, text=True, timeout=10
            )
            rules = [line.split(":", 1)[1].strip() for line in result.stdout.splitlines()
                     if self.RULE_PREFIX in line and "Rule Name:" in line]
            self.active = len(rules) > 0
            return {"active": self.active, "rules": rules}
        except Exception:
            return {"active": False, "rules": []}

    def _add_rule(self, name: str, direction: str, action: str, extra_args=None):
        # Strict validation — defends against shell injection / arg smuggling
        if not _KILLSWITCH_NAME_RE.match(name):
            log.error(f"[KILLSWITCH] Invalid rule name: {name!r}")
            return
        if direction not in ("in", "out"):
            log.error(f"[KILLSWITCH] Invalid direction: {direction!r}")
            return
        if action not in ("allow", "block"):
            log.error(f"[KILLSWITCH] Invalid action: {action!r}")
            return
        args = ["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", f"dir={direction}", f"action={action}"]
        if extra_args:
            for a in extra_args:
                if not isinstance(a, str) or any(c in a for c in _KILLSWITCH_UNSAFE_CHARS):
                    log.error(f"[KILLSWITCH] Rejected unsafe rule arg: {a!r}")
                    return
                args.append(a)
        subprocess.run(args, capture_output=True, timeout=10)

    def cleanup_orphaned(self):
        """Remove orphaned Kill Switch rules on startup"""
        self.disable()


# =============================================================================
# DNS PROTECTOR
# =============================================================================

class DNSProtector:
    def __init__(self):
        self.original_dns = {}
        self.protected = False

    def get_public_ip(self) -> dict:
        import urllib.request
        try:
            req = urllib.request.Request("https://api.ipify.org?format=json",
                                        headers={"User-Agent": "VPNGuard/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return {"ip": data.get("ip", ""), "ok": True}
        except Exception:
            try:
                req = urllib.request.Request("https://ifconfig.me/ip",
                                            headers={"User-Agent": "VPNGuard/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    ip = resp.read().decode().strip()
                    return {"ip": ip, "ok": True}
            except Exception as e:
                return {"ip": "", "ok": False, "error": str(e)}

    def check_leak(self) -> dict:
        ip_info = self.get_public_ip()
        return {
            "public_ip": ip_info.get("ip", ""),
            "dns_protected": self.protected,
            "vpn_dns": CFG.wg_dns,
        }

    def enable(self) -> dict:
        self.protected = True
        timeline_add("🔒", "Protection DNS activee", "security")
        return {"enabled": True, "dns": CFG.wg_dns}

    def disable(self) -> dict:
        self.protected = False
        timeline_add("🔓", "Protection DNS desactivee", "security")
        return {"enabled": False}


# =============================================================================
# SPLIT TUNNEL (simplified — beta)
# =============================================================================

class SplitTunnel:
    def __init__(self):
        self.apps_vpn = []
        self.apps_bypass = []
        self.active = False

    def enable(self) -> dict:
        self.active = True
        timeline_add("🔀", "Split Tunneling active", "network")
        return {"enabled": True}

    def disable(self) -> dict:
        self.active = False
        timeline_add("🔀", "Split Tunneling desactive", "network")
        return {"enabled": False}

    def add_app(self, path: str, mode: str) -> dict:
        if mode == "vpn":
            if path not in self.apps_vpn:
                self.apps_vpn.append(path)
        else:
            if path not in self.apps_bypass:
                self.apps_bypass.append(path)
        return {"ok": True, "apps_vpn": self.apps_vpn, "apps_bypass": self.apps_bypass}

    def remove_app(self, path: str) -> dict:
        self.apps_vpn = [a for a in self.apps_vpn if a != path]
        self.apps_bypass = [a for a in self.apps_bypass if a != path]
        return {"ok": True}

    def list_running_apps(self) -> list:
        if not HAS_PSUTIL:
            return []
        apps = []
        seen = set()
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                exe = info.get("exe") or ""
                name = info.get("name") or ""
                if exe and name and exe not in seen and not name.startswith("svchost"):
                    seen.add(exe)
                    apps.append({"pid": info["pid"], "name": name, "exe": exe})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(apps, key=lambda x: x["name"].lower())[:100]

    def get_status(self) -> dict:
        return {"enabled": self.active, "apps_vpn": self.apps_vpn, "apps_bypass": self.apps_bypass}


# =============================================================================
# WIFI MONITOR
# =============================================================================

class WiFiMonitor:
    def __init__(self):
        self.monitoring = False
        self.current_ssid = ""
        self.current_is_trusted = True
        self._thread = None
        self._stop = False

    def get_current_network(self) -> dict:
        if not IS_WINDOWS:
            return {"ssid": "", "signal": 0, "auth": "", "is_trusted": True}
        try:
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                    capture_output=True, text=True, timeout=5)
            info = {"ssid": "", "signal": 0, "auth": "", "is_trusted": True, "state": ""}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    info["ssid"] = line.split(":", 1)[1].strip()
                elif line.startswith("Signal") or line.startswith("signal"):
                    try:
                        info["signal"] = int(line.split(":", 1)[1].strip().replace("%", ""))
                    except ValueError:
                        pass
                elif line.startswith("Authentification") or line.startswith("Authentication"):
                    info["auth"] = line.split(":", 1)[1].strip()
                elif "tat" in line.lower() or "state" in line.lower():
                    info["state"] = line.split(":", 1)[1].strip()
            self.current_ssid = info["ssid"]
            info["is_trusted"] = info["ssid"] in CFG.trusted_networks
            self.current_is_trusted = info["is_trusted"]
            return info
        except Exception:
            return {"ssid": "", "signal": 0, "auth": "", "is_trusted": True}

    def scan_networks(self) -> list:
        if not IS_WINDOWS:
            return []
        try:
            result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                                    capture_output=True, text=True, timeout=10)
            networks = []
            current = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    if current.get("ssid"):
                        networks.append(current)
                    ssid = line.split(":", 1)[1].strip()
                    current = {"ssid": ssid, "signal": 0, "auth": "", "is_trusted": ssid in CFG.trusted_networks}
                elif line.startswith("Signal") or line.startswith("signal"):
                    try:
                        current["signal"] = int(line.split(":", 1)[1].strip().replace("%", ""))
                    except ValueError:
                        pass
                elif line.startswith("Authentification") or line.startswith("Authentication"):
                    current["auth"] = line.split(":", 1)[1].strip()
            if current.get("ssid"):
                networks.append(current)
            return networks
        except Exception:
            return []

    def start_monitoring(self, on_untrusted=None):
        self.monitoring = True
        self._stop = False
        def _monitor():
            while not self._stop:
                info = self.get_current_network()
                if info["ssid"] and not info["is_trusted"] and on_untrusted:
                    on_untrusted(info["ssid"])
                time.sleep(30)
        self._thread = threading.Thread(target=_monitor, daemon=True)
        self._thread.start()

    def stop_monitoring(self):
        self._stop = True
        self.monitoring = False


# =============================================================================
# CONNECTION LOGGER
# =============================================================================

class ConnectionLogger:
    def __init__(self):
        self.log_file = LOGS_DIR / "connection_history.json"
        self.entries = []
        self.current_session = None
        self._load()

    def start_session(self, profile: str, server_ip: str = "", mode: str = "server"):
        self.current_session = {
            "id": len(self.entries) + 1,
            "profile": profile,
            "server_ip": server_ip,
            "mode": mode,
            "start_time": datetime.now().isoformat(),
            "end_time": "",
            "duration_s": 0,
            "bytes_rx": 0,
            "bytes_tx": 0,
            "disconnect_reason": "",
        }

    def end_session(self, reason: str = "manual"):
        if not self.current_session:
            return
        self.current_session["end_time"] = datetime.now().isoformat()
        start = datetime.fromisoformat(self.current_session["start_time"])
        self.current_session["duration_s"] = int((datetime.now() - start).total_seconds())
        self.current_session["disconnect_reason"] = reason
        self.entries.insert(0, self.current_session)
        if len(self.entries) > CFG.connection_log_max:
            self.entries = self.entries[:CFG.connection_log_max]
        self.current_session = None
        self._save()

    def get_history(self, limit: int = 50) -> list:
        return self.entries[:limit]

    def get_current(self) -> dict:
        if not self.current_session:
            return {}
        start = datetime.fromisoformat(self.current_session["start_time"])
        self.current_session["duration_s"] = int((datetime.now() - start).total_seconds())
        return self.current_session

    def clear_history(self):
        self.entries = []
        self._save()

    def _save(self):
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self.entries, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _load(self):
        if self.log_file.exists():
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    self.entries = json.load(f)
            except Exception:
                pass


# =============================================================================
# PROFILE MANAGER
# =============================================================================

class ProfileManager:
    def __init__(self):
        self.profiles_file = PROFILES_DIR / "profiles.json"
        self.profiles = {}
        self._load()
        if not self.profiles:
            self._create_defaults()

    def _create_defaults(self):
        self.profiles = {
            "default": {"name": "Maison", "type": "server", "wg_address": "10.66.66.1/24",
                       "wg_dns": "1.1.1.1, 9.9.9.9", "wg_endpoint": "", "wg_listen_port": 51820},
            "bureau": {"name": "Bureau", "type": "server", "wg_address": "10.66.66.1/24",
                      "wg_dns": "1.1.1.1, 9.9.9.9", "wg_endpoint": "", "wg_listen_port": 51820},
            "public": {"name": "Wi-Fi Public", "type": "server", "wg_address": "10.66.66.1/24",
                      "wg_dns": "1.1.1.1, 9.9.9.9", "wg_endpoint": "", "wg_listen_port": 51820},
        }
        self._save()

    def create_profile(self, key: str, config: dict) -> dict:
        self.profiles[key] = config
        self._save()
        return {"ok": True, "profile": config}

    def delete_profile(self, key: str) -> dict:
        if key in self.profiles:
            del self.profiles[key]
            self._save()
        return {"ok": True}

    def update_profile(self, key: str, config: dict) -> dict:
        if key in self.profiles:
            self.profiles[key].update(config)
            self._save()
        return {"ok": True}

    def get_profile(self, key: str) -> dict:
        return self.profiles.get(key, {})

    def list_profiles(self) -> list:
        return [{"key": k, **v} for k, v in self.profiles.items()]

    def import_conf(self, content: str, name: str) -> dict:
        # Validate name (anti path traversal / weird chars in stored key)
        key = (name or "").lower().replace(" ", "_")
        if not _validate_wg_name(key):
            return {"error": f"Nom de profil invalide: {name!r} (lettres/chiffres/_/- seulement, max 40)"}
        # Validate content (reject PostUp/PostDown shell injection)
        ok, err = _validate_wg_config(content)
        if not ok:
            return {"error": err}
        config = {"name": name, "type": "client", "conf_content": content}
        # Parse .conf for details
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("Endpoint"):
                config["wg_endpoint"] = line.split("=", 1)[1].strip()
            elif line.startswith("DNS"):
                config["wg_dns"] = line.split("=", 1)[1].strip()
            elif line.startswith("Address"):
                config["wg_address"] = line.split("=", 1)[1].strip()
        self.profiles[key] = config
        self._save()
        timeline_add("📥", f"Profil importe: {name}", "vpn")
        return {"ok": True, "key": key, "profile": config}

    def _save(self):
        try:
            with open(self.profiles_file, "w", encoding="utf-8") as f:
                json.dump(self.profiles, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _load(self):
        if self.profiles_file.exists():
            try:
                with open(self.profiles_file, "r", encoding="utf-8") as f:
                    self.profiles = json.load(f)
            except Exception:
                pass


# =============================================================================
# VPN ENGINE — main orchestrator
# =============================================================================

class VPNEngine:
    def __init__(self):
        self.wg = WireGuardCore(str(CONFIGS_DIR))
        self.kill_switch = KillSwitch()
        self.dns = DNSProtector()
        self.split_tunnel = SplitTunnel()
        self.wifi = WiFiMonitor()
        self.logger = ConnectionLogger()
        self.profiles = ProfileManager()

        self.connected = False
        self.connect_time = None
        self.public_ip = ""
        self.speed_rx = 0.0
        self.speed_tx = 0.0
        self.bytes_rx = 0
        self.bytes_tx = 0
        self._prev_rx = 0
        self._prev_tx = 0
        self._stats_stop = False

        self.clients = set()  # WebSocket fallback

    def quick_connect(self) -> dict:
        profile = self.profiles.get_profile(CFG.active_profile)
        if profile.get("type") == "client" and profile.get("conf_content"):
            conf_path = os.path.join(str(CONFIGS_DIR), f"client_{CFG.active_profile}.conf")
            with open(conf_path, "w") as f:
                f.write(profile["conf_content"])
            result = self.wg.start_tunnel(conf_path)
        else:
            result = self.wg.start_tunnel()

        if result.get("ok"):
            self.connected = True
            self.connect_time = datetime.now()
            self.logger.start_session(CFG.active_profile, CFG.wg_endpoint, CFG.mode)
            if CFG.kill_switch_enabled:
                self.kill_switch.enable(CFG.wg_interface)
            if CFG.dns_leak_protection:
                self.dns.enable()
            self._start_stats_monitor()
            # Get public IP after connection
            threading.Thread(target=self._update_public_ip, daemon=True).start()
        return result

    def quick_disconnect(self) -> dict:
        result = self.wg.stop_tunnel()
        self.connected = False
        self.connect_time = None
        self._stats_stop = True
        self.speed_rx = 0
        self.speed_tx = 0
        if self.kill_switch.active:
            self.kill_switch.disable()
        if self.dns.protected:
            self.dns.disable()
        self.logger.end_session("manual")
        # Get public IP after disconnection
        threading.Thread(target=self._update_public_ip, daemon=True).start()
        return result

    def _update_public_ip(self):
        info = self.dns.get_public_ip()
        self.public_ip = info.get("ip", "")

    def _start_stats_monitor(self):
        self._stats_stop = False
        self._prev_rx = 0
        self._prev_tx = 0
        def _monitor():
            while not self._stats_stop and self.connected:
                try:
                    _kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
                    result = subprocess.run([self.wg.wg_cmd(), "show", CFG.wg_interface, "transfer"],
                                            capture_output=True, text=True, timeout=5, **_kw)
                    if result.returncode == 0 and result.stdout.strip():
                        for line in result.stdout.strip().splitlines():
                            parts = line.split("\t")
                            if len(parts) >= 3:
                                rx = int(parts[1])
                                tx = int(parts[2])
                                if self._prev_rx > 0:
                                    self.speed_rx = rx - self._prev_rx
                                    self.speed_tx = tx - self._prev_tx
                                self._prev_rx = rx
                                self._prev_tx = tx
                                self.bytes_rx = rx
                                self.bytes_tx = tx
                except Exception:
                    pass
                time.sleep(1)
        threading.Thread(target=_monitor, daemon=True).start()

    def _on_untrusted_wifi(self, ssid: str):
        if CFG.auto_connect_untrusted_wifi and not self.connected:
            timeline_add("📶", f"Wi-Fi non fiable detecte: {ssid} — connexion VPN auto", "network")
            self.quick_connect()

    def build_state(self) -> dict:
        duration_s = 0
        if self.connect_time:
            duration_s = int((datetime.now() - self.connect_time).total_seconds())

        wg_status = self.wg.get_status()
        wifi_info = self.wifi.get_current_network()
        session = self.logger.get_current()

        return {
            "type": "state",
            "ts": time.time(),
            "version": VERSION,
            "connected": self.connected,
            "duration_s": duration_s,
            "public_ip": self.public_ip,
            "speed_rx": self.speed_rx,
            "speed_tx": self.speed_tx,
            "bytes_rx": self.bytes_rx,
            "bytes_tx": self.bytes_tx,
            "active_profile": CFG.active_profile,
            "active_profile_name": self.profiles.get_profile(CFG.active_profile).get("name", CFG.active_profile),
            "mode": CFG.mode,
            # WireGuard
            "wg_installed": self.wg.is_installed(),
            "wg_status": wg_status,
            "wg_peers": [{k: v for k, v in p.items() if k not in ("privkey", "preshared_key")} for p in self.wg.peers],
            "wg_server_pubkey": self.wg.server_pubkey,
            "wg_listen_port": CFG.wg_listen_port,
            "wg_address": CFG.wg_address,
            # Security
            "kill_switch_enabled": CFG.kill_switch_enabled,
            "kill_switch_active": self.kill_switch.active,
            "dns_protected": self.dns.protected,
            "dns_servers": CFG.wg_dns,
            # Split Tunnel
            "split_tunnel": self.split_tunnel.get_status(),
            # Wi-Fi
            "wifi": wifi_info,
            "trusted_networks": CFG.trusted_networks,
            "auto_connect": CFG.auto_connect,
            "auto_connect_wifi": CFG.auto_connect_untrusted_wifi,
            # Profiles
            "profiles": self.profiles.list_profiles(),
            # Timeline
            "timeline": list(TIMELINE)[:50],
        }


# =============================================================================
# WEBSOCKET HANDLER (fallback mode)
# =============================================================================

CLIENTS = set()

async def handle_ws_command(ws, msg: dict, engine: VPNEngine):
    cmd = msg.get("cmd")

    if cmd == "get_state":
        await ws.send(json.dumps(engine.build_state(), default=str))
    elif cmd == "quick_connect":
        result = engine.quick_connect()
        await ws.send(json.dumps({"type": "connect_result", **result}, default=str))
    elif cmd == "quick_disconnect":
        result = engine.quick_disconnect()
        await ws.send(json.dumps({"type": "disconnect_result", **result}, default=str))
    elif cmd == "connect_profile":
        name = msg.get("name", "default")
        CFG.active_profile = name
        result = engine.quick_connect()
        await ws.send(json.dumps({"type": "connect_result", **result}, default=str))
    # Peers
    elif cmd == "add_peer":
        result = engine.wg.add_peer(msg.get("name", ""))
        await ws.send(json.dumps({"type": "peer_added", **result}, default=str))
    elif cmd == "remove_peer":
        result = engine.wg.remove_peer(msg.get("name", ""))
        await ws.send(json.dumps({"type": "peer_removed", **result}, default=str))
    elif cmd == "get_peer_config":
        name = msg.get("name", "")
        peer = next((p for p in engine.wg.peers if p["name"] == name), None)
        if peer:
            config = engine.wg.generate_peer_config(peer)
            await ws.send(json.dumps({"type": "peer_config", "name": name, "config": config}))
    elif cmd == "get_peers":
        safe = [{k: v for k, v in p.items() if k not in ("privkey", "preshared_key")} for p in engine.wg.peers]
        await ws.send(json.dumps({"type": "peers_list", "peers": safe}, default=str))
    # Import
    elif cmd == "import_config":
        result = engine.wg.import_config(msg.get("content", ""), msg.get("name", "imported"))
        await ws.send(json.dumps({"type": "config_imported", **result}))
    # Kill Switch
    elif cmd == "toggle_kill_switch":
        CFG.kill_switch_enabled = not CFG.kill_switch_enabled
        if CFG.kill_switch_enabled and engine.connected:
            engine.kill_switch.enable(CFG.wg_interface)
        elif not CFG.kill_switch_enabled:
            engine.kill_switch.disable()
        save_settings()
        await ws.send(json.dumps({"type": "kill_switch_toggled", "enabled": CFG.kill_switch_enabled, "active": engine.kill_switch.active}))
    # DNS
    elif cmd == "toggle_dns_protection":
        CFG.dns_leak_protection = not CFG.dns_leak_protection
        if CFG.dns_leak_protection:
            engine.dns.enable()
        else:
            engine.dns.disable()
        save_settings()
        await ws.send(json.dumps({"type": "dns_toggled", "enabled": CFG.dns_leak_protection}))
    elif cmd == "check_dns_leak":
        result = engine.dns.check_leak()
        await ws.send(json.dumps({"type": "dns_leak_result", **result}))
    elif cmd == "get_public_ip":
        result = engine.dns.get_public_ip()
        await ws.send(json.dumps({"type": "public_ip", **result}))
    # Split Tunnel
    elif cmd == "toggle_split_tunnel":
        CFG.split_tunnel_enabled = not CFG.split_tunnel_enabled
        if CFG.split_tunnel_enabled:
            engine.split_tunnel.enable()
        else:
            engine.split_tunnel.disable()
        save_settings()
        await ws.send(json.dumps({"type": "split_tunnel_toggled", **engine.split_tunnel.get_status()}))
    elif cmd == "split_add_app":
        result = engine.split_tunnel.add_app(msg.get("path", ""), msg.get("mode", "vpn"))
        await ws.send(json.dumps({"type": "split_app_added", **result}))
    elif cmd == "split_remove_app":
        result = engine.split_tunnel.remove_app(msg.get("path", ""))
        await ws.send(json.dumps({"type": "split_app_removed", **result}))
    elif cmd == "list_running_apps":
        apps = engine.split_tunnel.list_running_apps()
        await ws.send(json.dumps({"type": "running_apps", "apps": apps}))
    # Wi-Fi
    elif cmd == "get_network":
        info = engine.wifi.get_current_network()
        await ws.send(json.dumps({"type": "network_info", **info}))
    elif cmd == "scan_networks":
        networks = engine.wifi.scan_networks()
        await ws.send(json.dumps({"type": "networks_list", "networks": networks}))
    elif cmd == "add_trusted":
        ssid = msg.get("ssid", "")
        if ssid and ssid not in CFG.trusted_networks:
            CFG.trusted_networks.append(ssid)
            save_settings()
        await ws.send(json.dumps({"type": "trusted_updated", "networks": CFG.trusted_networks}))
    elif cmd == "remove_trusted":
        ssid = msg.get("ssid", "")
        CFG.trusted_networks = [n for n in CFG.trusted_networks if n != ssid]
        save_settings()
        await ws.send(json.dumps({"type": "trusted_updated", "networks": CFG.trusted_networks}))
    elif cmd == "toggle_auto_connect":
        CFG.auto_connect_untrusted_wifi = not CFG.auto_connect_untrusted_wifi
        save_settings()
        await ws.send(json.dumps({"type": "auto_connect_toggled", "enabled": CFG.auto_connect_untrusted_wifi}))
    # Profiles
    elif cmd == "list_profiles":
        await ws.send(json.dumps({"type": "profiles_list", "profiles": engine.profiles.list_profiles()}))
    elif cmd == "create_profile":
        result = engine.profiles.create_profile(msg.get("key", ""), msg.get("config", {}))
        await ws.send(json.dumps({"type": "profile_created", **result}))
    elif cmd == "delete_profile":
        result = engine.profiles.delete_profile(msg.get("key", ""))
        await ws.send(json.dumps({"type": "profile_deleted", **result}))
    elif cmd == "set_active_profile":
        CFG.active_profile = msg.get("key", "default")
        save_settings()
        await ws.send(json.dumps({"type": "profile_set", "active": CFG.active_profile}))
    elif cmd == "import_profile":
        result = engine.profiles.import_conf(msg.get("content", ""), msg.get("name", "imported"))
        await ws.send(json.dumps({"type": "profile_imported", **result}))
    # History
    elif cmd == "get_history":
        limit = msg.get("limit", 50)
        await ws.send(json.dumps({"type": "history", "entries": engine.logger.get_history(limit)}, default=str))
    elif cmd == "clear_history":
        engine.logger.clear_history()
        await ws.send(json.dumps({"type": "history_cleared"}))
    # Settings
    elif cmd == "get_settings":
        await ws.send(json.dumps({"type": "settings", **asdict(CFG)}))
    elif cmd == "save_settings":
        for k, v in msg.items():
            if k != "cmd" and hasattr(CFG, k):
                setattr(CFG, k, v)
        save_settings()
        await ws.send(json.dumps({"type": "settings_saved"}))
    # Server config
    elif cmd == "wg_set_config":
        if "wg_endpoint" in msg: CFG.wg_endpoint = msg["wg_endpoint"]
        elif "endpoint" in msg: CFG.wg_endpoint = msg["endpoint"]
        if "wg_listen_port" in msg: CFG.wg_listen_port = int(msg["wg_listen_port"])
        elif "listen_port" in msg: CFG.wg_listen_port = int(msg["listen_port"])
        if "wg_address" in msg: CFG.wg_address = msg["wg_address"]
        elif "address" in msg: CFG.wg_address = msg["address"]
        if "wg_dns" in msg: CFG.wg_dns = msg["wg_dns"]
        elif "dns" in msg: CFG.wg_dns = msg["dns"]
        if "wg_interface" in msg: CFG.wg_interface = msg["wg_interface"]
        if "wg_post_up" in msg: CFG.wg_post_up = msg["wg_post_up"]
        if "wg_post_down" in msg: CFG.wg_post_down = msg["wg_post_down"]
        save_settings()
        await ws.send(json.dumps({"type": "wg_config_saved"}))
    # Diagnostics
    elif cmd == "get_diagnostics":
        diag = _build_diagnostics(engine)
        await ws.send(json.dumps({"type": "diagnostics", **diag}, default=str))


def _build_diagnostics(engine: VPNEngine) -> dict:
    """Build a comprehensive system diagnostic report."""
    # WireGuard check
    wg_installed = engine.wg.is_installed()
    wg_version = ""
    wg_path = ""
    if wg_installed:
        try:
            r = subprocess.run([engine.wg.wg_cmd(), "--version"], capture_output=True, text=True, timeout=5)
            wg_version = r.stdout.strip() or r.stderr.strip()
            wg_path = engine.wg.wg_cmd()
        except Exception:
            pass

    # Admin check
    is_admin = False
    if IS_WINDOWS:
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    else:
        is_admin = os.getuid() == 0 if hasattr(os, "getuid") else False

    # Tunnel status
    tunnel_status = ""
    try:
        _kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
        r = subprocess.run([engine.wg.wg_cmd(), "show"], capture_output=True, text=True, timeout=5, **_kw)
        tunnel_status = r.stdout.strip() if r.returncode == 0 else "Aucun tunnel actif"
    except Exception:
        tunnel_status = "Impossible de verifier"

    # Firewall rules count
    fw_rules = 0
    if IS_WINDOWS:
        try:
            r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=VPNGuard"],
                              capture_output=True, text=True, timeout=5)
            fw_rules = r.stdout.count("Nom de la") + r.stdout.count("Rule Name")
        except Exception:
            pass

    # Internet check
    internet_ok = False
    try:
        import urllib.request
        urllib.request.urlopen("https://www.google.com", timeout=5)
        internet_ok = True
    except Exception:
        pass

    return {
        "wg_installed": wg_installed,
        "wg_version": wg_version,
        "wg_path": wg_path,
        "is_admin": is_admin,
        "python_version": sys.version,
        "os_info": platform.platform(),
        "firewall_rules": fw_rules,
        "tunnel_status": tunnel_status,
        "internet": internet_ok,
        "public_ip": engine.public_ip or "",
        "configs_dir": str(CONFIGS_DIR),
        "profiles_count": len(engine.profiles.profiles),
        "peers_count": len(engine.wg.peers),
        "connected": engine.connected,
        "kill_switch_active": engine.kill_switch.active,
        "dns_protected": engine.dns.protected,
    }


async def ws_handler(websocket, engine):
    CLIENTS.add(websocket)
    try:
        await websocket.send(json.dumps(engine.build_state(), default=str))
        async for raw in websocket:
            try:
                msg = json.loads(raw)
                await handle_ws_command(websocket, msg, engine)
            except json.JSONDecodeError:
                pass
            except Exception as e:
                await websocket.send(json.dumps({"type": "error", "message": str(e)}))
    except Exception:
        pass
    finally:
        CLIENTS.discard(websocket)


async def broadcast_state(engine):
    save_counter = 0
    while True:
        await asyncio.sleep(1)
        save_counter += 1
        if save_counter >= 60:
            save_settings()
            save_counter = 0
        if CLIENTS:
            try:
                msg = json.dumps(engine.build_state(), default=str)
                dead = set()
                for ws in list(CLIENTS):
                    try:
                        await ws.send(msg)
                    except Exception:
                        dead.add(ws)
                CLIENTS -= dead
            except Exception:
                pass


# =============================================================================
# PYWEBVIEW API
# =============================================================================

class VPNGuardAPI:
    """API exposed to JavaScript via pywebview.api"""

    def __init__(self, engine: VPNEngine):
        self._engine = engine
        self._window = None
        self._stop_broadcast = False
        self._loop = None

    def set_window(self, window):
        self._window = window

    def get_state(self):
        return json.loads(json.dumps(self._engine.build_state(), default=str))

    def send_command(self, cmd, params=None):
        if params is None:
            params = {}
        msg = {"cmd": cmd, **params}

        class FakeWS:
            def __init__(self):
                self.responses = []
            async def send(self, data):
                self.responses.append(json.loads(data))

        fake = FakeWS()
        loop = self._loop
        if loop and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(handle_ws_command(fake, msg, self._engine), loop)
            try:
                future.result(timeout=30)
            except Exception as e:
                return {"type": "error", "message": str(e)}
        else:
            try:
                asyncio.run(handle_ws_command(fake, msg, self._engine))
            except Exception as e:
                return {"type": "error", "message": str(e)}

        if fake.responses:
            return fake.responses[-1]
        return {"type": "ack", "cmd": cmd}

    # Startup & Tray
    def get_startup_state(self):
        if not HAS_STARTUP_UTILS:
            return {"enabled": False, "available": False}
        return {"enabled": is_startup_enabled("VPN Guard Pro"), "available": True}

    def toggle_startup_boot(self):
        if not HAS_STARTUP_UTILS:
            return {"enabled": False, "available": False}
        bat_path = str(BASE_DIR.parent / "LANCER_VPNGUARD.bat")
        new_state = toggle_startup_reg("VPN Guard Pro", bat_path)
        return {"enabled": new_state, "available": True}

    def minimize_to_tray_action(self):
        if not HAS_STARTUP_UTILS or not self._window:
            return {"success": False}
        def _on_quit():
            if self._window:
                self._window.destroy()
        minimize_to_tray(self._window, "VPN Guard Pro", on_quit=_on_quit)
        return {"success": True}


def _pywebview_state_broadcast(api):
    """Background thread: push state to pywebview window periodically"""
    while not api._stop_broadcast:
        try:
            if api._window:
                state = api._engine.build_state()
                js_data = json.dumps(state, default=str)
                api._window.evaluate_js(f"if(typeof handleMsg==='function')handleMsg({js_data})")
        except Exception:
            pass
        interval = 1 if api._engine.connected else 4
        time.sleep(interval)


# =============================================================================
# MAIN
# =============================================================================

def main_webview():
    load_settings()
    engine = VPNEngine()
    engine.wg.init_server()
    engine.wg.load_peers()

    # Cleanup orphaned kill switch rules
    engine.kill_switch.cleanup_orphaned()

    print(f"""
+--------------------------------------------------------------+
|       VPN Guard Pro v{VERSION} -- Fenetre native               |
+--------------------------------------------------------------+
|  WireGuard VPN | Kill Switch | DNS Protection                |
|  Split Tunneling | Wi-Fi Auto-Connect | Profils              |
+--------------------------------------------------------------+
    """)

    # Auto-connect if configured
    if CFG.auto_connect:
        threading.Thread(target=engine.quick_connect, daemon=True).start()

    # Start Wi-Fi monitoring
    if CFG.auto_connect_untrusted_wifi:
        engine.wifi.start_monitoring(on_untrusted=engine._on_untrusted_wifi)

    timeline_add("🚀", "VPN Guard Pro demarre", "system")

    # Async event loop for command handling
    loop = asyncio.new_event_loop()
    def _run_loop():
        asyncio.set_event_loop(loop)
        loop.run_forever()
    threading.Thread(target=_run_loop, daemon=True).start()

    api = VPNGuardAPI(engine)
    api._loop = loop

    dashboard_path = str(BASE_DIR / "vpnguard_dashboard.html")

    window = webview.create_window(
        f"VPN Guard Pro v{VERSION}",
        dashboard_path,
        js_api=api,
        width=1360,
        height=860,
        min_size=(1000, 650),
        background_color="#0a0a10",
    )
    api.set_window(window)

    def on_loaded():
        print("[+] Dashboard charge dans la fenetre native")
        threading.Thread(target=_pywebview_state_broadcast, args=(api,), daemon=True).start()

    window.events.loaded += on_loaded

    try:
        webview.start(debug=False)
    finally:
        api._stop_broadcast = True
        engine.wifi.stop_monitoring()
        if engine.connected:
            engine.quick_disconnect()
        loop.call_soon_threadsafe(loop.stop)
        save_settings()
        print("[*] VPN Guard Pro ferme.")


async def main_async():
    load_settings()
    engine = VPNEngine()
    engine.wg.init_server()
    engine.wg.load_peers()
    engine.kill_switch.cleanup_orphaned()

    timeline_add("🚀", "VPN Guard Pro demarre (mode WebSocket)", "system")

    if CFG.auto_connect:
        threading.Thread(target=engine.quick_connect, daemon=True).start()
    if CFG.auto_connect_untrusted_wifi:
        engine.wifi.start_monitoring(on_untrusted=engine._on_untrusted_wifi)

    port = CFG.ws_port
    print(f"""
+--------------------------------------------------------------+
|       VPN Guard Pro v{VERSION} -- Mode WebSocket               |
+--------------------------------------------------------------+
|  WebSocket : ws://localhost:{port}                             |
|  Dashboard : vpnguard_dashboard.html                          |
+--------------------------------------------------------------+
    """)

    asyncio.create_task(broadcast_state(engine))

    try:
        async with websockets.serve(lambda ws: ws_handler(ws, engine), "localhost", port):
            print(f"[+] WebSocket demarre sur le port {port}")
            await asyncio.Future()
    except Exception as e:
        print(f"[!] Erreur WebSocket: {e}")


def main():
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    if not headless and HAS_WEBVIEW:
        print("[*] pywebview detecte -- lancement en mode fenetre native")
        main_webview()
    else:
        if not HAS_WS:
            print("[ERREUR] websockets non installe. pip install websockets")
            return
        print("[*] Mode " + ("headless (Cortex)" if headless else "WebSocket"))
        try:
            asyncio.run(main_async())
        except KeyboardInterrupt:
            print("\n[*] Arret de VPN Guard Pro...")
            save_settings()


if __name__ == "__main__":
    main()
