"""
SentinelOS — Network Mapper v1.0
Visual network topology mapper that scans your local network,
discovers devices, classifies them, and renders an interactive map.

Usage:
    python sentinel_mapper.py          → GUI mode (pywebview)
    python sentinel_mapper.py --headless  → WebSocket only (no GUI)
"""

import os
import sys

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

import json
import time
import socket
import struct
import logging
from logging.handlers import RotatingFileHandler
import threading
import subprocess
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional imports
try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

# ─── Constants ────────────────────────────────────────────────────────────

VERSION = "1.0.0"
SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))
MAP_HTML = os.path.join(SENTINEL_DIR, "sentinel_map.html")
SETTINGS_FILE = os.path.join(SENTINEL_DIR, "sentinel_settings.json")
MAP_SAVE_FILE = os.path.join(SENTINEL_DIR, "network_map.json")
IS_WINDOWS = os.name == 'nt'

COMMON_PORTS = [22, 53, 80, 443, 445, 548, 3389, 5000, 5900, 8080, 8443, 9100]

# Ensure logs dir BEFORE creating the file handler (fresh install crashed here)
os.makedirs(os.path.join(SENTINEL_DIR, "logs"), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(os.path.join(SENTINEL_DIR, "logs", "mapper.log"),
                            maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("SentinelMapper")

# ─── Device Types ─────────────────────────────────────────────────────────

DEVICE_TYPES = {
    "router":   {"icon": "\U0001f310", "label": "Routeur",   "label_en": "Router",   "color": "#ff6b35"},
    "switch":   {"icon": "\U0001f500", "label": "Switch",    "label_en": "Switch",   "color": "#ffa500"},
    "pc":       {"icon": "\U0001f4bb", "label": "PC",        "label_en": "PC",       "color": "#4d9fff"},
    "laptop":   {"icon": "\U0001f4bb", "label": "Laptop",    "label_en": "Laptop",   "color": "#4d9fff"},
    "mobile":   {"icon": "\U0001f4f1", "label": "Mobile",    "label_en": "Mobile",   "color": "#a855f7"},
    "printer":  {"icon": "\U0001f5a8", "label": "Imprimante","label_en": "Printer",  "color": "#22c55e"},
    "server":   {"icon": "\U0001f5a5", "label": "Serveur",   "label_en": "Server",   "color": "#ef4444"},
    "iot":      {"icon": "\U0001f4e1", "label": "IoT",       "label_en": "IoT",      "color": "#06b6d4"},
    "camera":   {"icon": "\U0001f4f7", "label": "Camera",    "label_en": "Camera",   "color": "#eab308"},
    "tv":       {"icon": "\U0001f4fa", "label": "TV/Media",  "label_en": "TV/Media", "color": "#8b5cf6"},
    "nas":      {"icon": "\U0001f4be", "label": "NAS",       "label_en": "NAS",      "color": "#f97316"},
    "unknown":  {"icon": "\u2753",     "label": "Inconnu",   "label_en": "Unknown",  "color": "#6b7280"},
}


# ═══════════════════════════════════════════════════════════════════════════
# MAC VENDOR DATABASE
# ═══════════════════════════════════════════════════════════════════════════

MAC_VENDORS = {
    # Networking
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:15:5D": "Hyper-V",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:1A:2B": "Cisco", "00:1B:54": "Cisco", "00:26:CB": "Cisco",
    "00:17:C5": "Cisco", "00:1C:58": "Cisco",
    "00:1E:58": "D-Link", "00:22:B0": "D-Link", "1C:7E:E5": "D-Link",
    "00:14:BF": "Linksys", "00:1A:70": "Linksys",
    "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link", "EC:08:6B": "TP-Link",
    "00:24:B2": "Netgear", "08:BD:43": "Netgear", "20:E5:2A": "Netgear",
    "00:1F:33": "Netgear",
    "2C:56:DC": "ASUS", "04:D9:F5": "ASUS", "1C:87:2C": "ASUS",
    # Apple
    "AC:DE:48": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple",
    "3C:22:FB": "Apple", "DC:A9:04": "Apple", "78:7B:8A": "Apple",
    "F4:5C:89": "Apple", "BC:D0:74": "Apple",
    # Samsung
    "00:21:19": "Samsung", "00:26:37": "Samsung", "5C:0A:5B": "Samsung",
    "8C:77:12": "Samsung", "C0:BD:D1": "Samsung",
    # Microsoft
    "00:15:5D": "Microsoft", "00:50:F2": "Microsoft", "28:18:78": "Microsoft",
    "7C:1E:52": "Microsoft",
    # Intel
    "00:1B:21": "Intel", "00:1E:64": "Intel", "3C:97:0E": "Intel",
    "68:05:CA": "Intel", "A4:4C:C8": "Intel",
    # Printers
    "00:1E:0B": "HP", "00:21:5A": "HP", "3C:D9:2B": "HP",
    "00:00:48": "Epson", "00:26:AB": "Epson",
    "00:00:85": "Canon", "00:1E:8F": "Canon",
    "00:80:77": "Brother", "00:1B:A9": "Brother",
    # Xiaomi / Mobile
    "00:9E:C8": "Xiaomi", "28:6C:07": "Xiaomi", "64:CC:2E": "Xiaomi",
    "58:44:98": "Xiaomi",
    "C0:EE:FB": "OnePlus",
    "AC:37:43": "HTC",
    "00:BB:3A": "Google", "F4:F5:D8": "Google", "30:FD:38": "Google",
    # IoT / Raspberry
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "18:B4:30": "Nest", "64:16:66": "Nest",
    "B0:CE:18": "LG", "00:1E:75": "LG",
    "00:04:4B": "Roku", "D8:31:34": "Roku",
    "68:54:FD": "Amazon", "44:65:0D": "Amazon",
    # NAS
    "00:11:32": "Synology", "00:11:32": "Synology",
    "00:08:9B": "QNAP",
}

# Vendor → device type mapping
VENDOR_DEVICE_MAP = {
    "printer": ["HP", "Epson", "Canon", "Brother", "Xerox", "Lexmark", "Ricoh"],
    "mobile":  ["Apple", "Samsung", "Xiaomi", "OnePlus", "HTC", "Google", "Huawei", "OPPO", "Vivo"],
    "iot":     ["Raspberry Pi", "Nest", "Amazon", "Tuya", "Shelly", "Sonoff"],
    "tv":      ["LG", "Roku", "Chromecast", "Fire TV"],
    "nas":     ["Synology", "QNAP", "WD"],
    "router":  ["Cisco", "D-Link", "Linksys", "TP-Link", "Netgear", "ASUS"],
}


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK SCANNER
# ═══════════════════════════════════════════════════════════════════════════

class NetworkScanner:
    """Scans the local network and discovers devices."""

    def __init__(self):
        self.devices = []
        self.gateway_ip = None
        self.local_ip = None
        self.subnet = None
        self.interface_name = None
        self._scanning = False

    def get_network_info(self) -> dict:
        """Detect local network information."""
        info = {"gateway": None, "local_ip": None, "subnet": None, "interface": None}
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
            info["local_ip"] = self.local_ip

            # Derive subnet
            parts = self.local_ip.split(".")
            self.subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            info["subnet"] = self.subnet

            # Get gateway
            self.gateway_ip = self._get_gateway()
            info["gateway"] = self.gateway_ip

            # Interface name
            self.interface_name = self._get_interface_name()
            info["interface"] = self.interface_name

        except Exception as e:
            logger.error(f"[Scanner] Network info error: {e}")

        return info

    def _get_gateway(self) -> str:
        """Get the default gateway IP."""
        try:
            if IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
                    capture_output=True, text=True, timeout=5,
                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW
                )
                gw = result.stdout.strip()
                if gw and gw.count(".") == 3:
                    return gw
            # Fallback: guess .1
            if self.local_ip:
                parts = self.local_ip.split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except Exception:
            pass
        if self.local_ip:
            parts = self.local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        return None

    def _get_interface_name(self) -> str:
        """Get active network interface name."""
        try:
            if IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name"],
                    capture_output=True, text=True, timeout=5,
                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW
                )
                name = result.stdout.strip()
                if name:
                    return name
        except Exception:
            pass
        return "Unknown"

    def scan_network(self, callback=None) -> list:
        """Scan the local network for devices. Returns list of device dicts."""
        if self._scanning:
            return self.devices
        self._scanning = True
        self.devices = []

        try:
            self.get_network_info()
            if not self.subnet:
                logger.error("[Scanner] No subnet detected")
                self._scanning = False
                return []

            logger.info(f"[Scanner] Scanning {self.subnet} ...")

            # Method 1: ARP scan (fastest, most accurate)
            if HAS_SCAPY:
                self.devices = self._arp_scan()
            else:
                # Method 2: Ping sweep (fallback)
                self.devices = self._ping_sweep()

            # Add gateway if not found
            if self.gateway_ip and not any(d["ip"] == self.gateway_ip for d in self.devices):
                hostname = self._resolve_hostname(self.gateway_ip)
                self.devices.insert(0, {
                    "ip": self.gateway_ip, "mac": "—", "hostname": hostname or "Gateway",
                    "vendor": "", "status": "up", "open_ports": [],
                })

            # Add self if not found
            if self.local_ip and not any(d["ip"] == self.local_ip for d in self.devices):
                self.devices.append({
                    "ip": self.local_ip, "mac": "—", "hostname": socket.gethostname(),
                    "vendor": "", "status": "up", "open_ports": [],
                })

            # Classify all devices
            classifier = DeviceClassifier(self.gateway_ip)
            for dev in self.devices:
                dev["type"] = classifier.classify(dev)
                dev["id"] = dev["ip"].replace(".", "_")

            # Quick port scan on discovered devices (threaded, fast)
            self._scan_ports_all()

            # Re-classify after port scan
            for dev in self.devices:
                dev["type"] = classifier.classify(dev)

            logger.info(f"[Scanner] Found {len(self.devices)} devices")

        except Exception as e:
            logger.error(f"[Scanner] Scan error: {e}")
        finally:
            self._scanning = False

        return self.devices

    def _arp_scan(self) -> list:
        """ARP scan using Scapy."""
        devices = []
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
            result = srp(packet, timeout=4, verbose=False)[0]
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc.upper()
                hostname = self._resolve_hostname(ip)
                vendor = self._mac_vendor(mac)
                devices.append({
                    "ip": ip, "mac": mac, "hostname": hostname,
                    "vendor": vendor, "status": "up", "open_ports": [],
                })
        except Exception as e:
            logger.warning(f"[Scanner] ARP scan failed: {e}, falling back to ping sweep")
            devices = self._ping_sweep()
        return devices

    def _ping_sweep(self) -> list:
        """Ping sweep fallback when Scapy is not available."""
        devices = []
        subnet_parts = self.local_ip.split(".")
        base = f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}"

        si = None
        cf = 0
        if IS_WINDOWS:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            cf = subprocess.CREATE_NO_WINDOW

        def ping_host(ip):
            try:
                cmd = ["ping", "-n", "1", "-w", "300", ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
                r = subprocess.run(cmd, capture_output=True, timeout=2,
                                   startupinfo=si, creationflags=cf)
                if r.returncode == 0:
                    hostname = self._resolve_hostname(ip)
                    return {"ip": ip, "mac": "—", "hostname": hostname,
                            "vendor": "", "status": "up", "open_ports": []}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(ping_host, f"{base}.{i}"): i for i in range(1, 255)}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    devices.append(result)

        return devices

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _mac_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC address OUI prefix."""
        if not mac or mac == "—":
            return ""
        prefix = mac[:8].upper()
        return MAC_VENDORS.get(prefix, "")

    def _scan_ports_all(self):
        """Quick port scan on all discovered devices (threaded)."""
        def scan_one(dev):
            dev["open_ports"] = self._quick_port_scan(dev["ip"])

        with ThreadPoolExecutor(max_workers=20) as pool:
            pool.map(scan_one, self.devices)

    def _quick_port_scan(self, ip: str, ports=None) -> list:
        """Quick TCP connect scan on common ports."""
        if ports is None:
            ports = COMMON_PORTS
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        return open_ports

    def scan_single_device(self, ip: str) -> dict:
        """Detailed scan of a single device."""
        hostname = self._resolve_hostname(ip)
        open_ports = self._quick_port_scan(ip,
            [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
             548, 993, 995, 3306, 3389, 5000, 5432, 5900, 8080, 8443, 9100])
        return {
            "ip": ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "port_services": {p: self._port_service(p) for p in open_ports},
        }

    @staticmethod
    def _port_service(port: int) -> str:
        """Return common service name for a port."""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 548: "AFP", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5000: "UPnP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9100: "Print",
        }
        return services.get(port, f"Port {port}")


# ═══════════════════════════════════════════════════════════════════════════
# DEVICE CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════

class DeviceClassifier:
    """Classifies network devices by type based on multiple heuristics."""

    def __init__(self, gateway_ip: str = None):
        self.gateway_ip = gateway_ip

    def classify(self, device: dict) -> str:
        """Classify a device into a type category."""
        ip = device.get("ip", "")
        mac = device.get("mac", "")
        vendor = device.get("vendor", "")
        hostname = device.get("hostname", "").lower()
        ports = device.get("open_ports", [])

        # Gateway → router
        if ip == self.gateway_ip:
            return "router"

        # IP ending in .1 or .254 likely router/gateway
        last_octet = int(ip.split(".")[-1]) if ip else 0
        if last_octet in (1, 254) and (53 in ports or 80 in ports):
            return "router"

        # Vendor-based classification
        for dev_type, vendors in VENDOR_DEVICE_MAP.items():
            if any(v.lower() in vendor.lower() for v in vendors):
                # Special case: networking vendors with port 80 are routers
                if dev_type == "router" and 80 in ports:
                    return "router"
                if dev_type == "router":
                    return "unknown"  # networking vendor but not acting as router
                return dev_type

        # Port-based classification
        if 9100 in ports:
            return "printer"
        if 445 in ports or 3389 in ports:
            if 22 in ports:
                return "server"
            return "pc"
        if 22 in ports and not (80 in ports):
            return "server" if 3306 in ports or 5432 in ports else "pc"
        if 548 in ports:  # AFP (Apple Filing Protocol)
            return "pc"
        if 5000 in ports and not ports:  # UPnP only
            return "iot"

        # Hostname-based hints
        if any(kw in hostname for kw in ["iphone", "ipad", "android", "galaxy", "pixel"]):
            return "mobile"
        if any(kw in hostname for kw in ["print", "laserjet", "deskjet", "officejet"]):
            return "printer"
        if any(kw in hostname for kw in ["nas", "synology", "diskstation", "qnap"]):
            return "nas"
        if any(kw in hostname for kw in ["cam", "camera", "ipcam", "nvr", "dvr"]):
            return "camera"
        if any(kw in hostname for kw in ["tv", "roku", "chromecast", "firestick", "smarttv"]):
            return "tv"
        if any(kw in hostname for kw in ["raspberrypi", "raspberry", "pi-hole"]):
            return "iot"
        if any(kw in hostname for kw in ["server", "srv", "dc", "domain"]):
            return "server"
        if any(kw in hostname for kw in ["desktop", "laptop", "pc", "workstation"]):
            return "pc"

        return "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# MAPPER API — pywebview bridge
# ═══════════════════════════════════════════════════════════════════════════

class MapperAPI:
    """API exposed to the HTML dashboard via pywebview."""

    def __init__(self):
        self._scanner = NetworkScanner()
        self._window = None
        self._saved_positions = {}
        self._saved_labels = {}
        self._device_last_seen = {}   # device_id -> epoch of last scan that saw it
        self._load_saved_map()

    def set_window(self, window):
        self._window = window

    # ─── Scan ─────────────────────────────────────────────────────────

    def scan_network(self) -> str:
        """Launch a network scan. Returns JSON with all discovered devices."""
        devices = self._scanner.scan_network()
        # Apply saved positions and labels
        now = time.time()
        for dev in devices:
            did = dev["id"]
            self._device_last_seen[did] = now
            if did in self._saved_positions:
                dev["x"] = self._saved_positions[did]["x"]
                dev["y"] = self._saved_positions[did]["y"]
            if did in self._saved_labels:
                dev["custom_label"] = self._saved_labels[did]
        self._prune_saved_map(now)
        return json.dumps({"devices": devices, "count": len(devices)}, ensure_ascii=False)

    def get_devices(self) -> str:
        """Return current device list."""
        devices = self._scanner.devices
        for dev in devices:
            did = dev["id"]
            if did in self._saved_positions:
                dev["x"] = self._saved_positions[did]["x"]
                dev["y"] = self._saved_positions[did]["y"]
            if did in self._saved_labels:
                dev["custom_label"] = self._saved_labels[did]
        return json.dumps(devices, ensure_ascii=False)

    def get_network_info(self) -> str:
        """Return network info (gateway, subnet, interface, local IP)."""
        info = self._scanner.get_network_info()
        return json.dumps(info, ensure_ascii=False)

    def quick_port_scan(self, ip: str) -> str:
        """Detailed port scan on a single device."""
        result = self._scanner.scan_single_device(ip)
        return json.dumps(result, ensure_ascii=False)

    # ─── Map State ────────────────────────────────────────────────────

    def update_device_position(self, device_id: str, x: float, y: float) -> str:
        """Save a device's position after drag & drop."""
        self._saved_positions[device_id] = {"x": x, "y": y}
        self._save_map()
        return json.dumps({"success": True})

    def update_device_label(self, device_id: str, label: str) -> str:
        """Set a custom label for a device."""
        self._saved_labels[device_id] = label
        self._save_map()
        return json.dumps({"success": True})

    def save_map(self) -> str:
        """Explicitly save the map state."""
        self._save_map()
        return json.dumps({"success": True, "path": MAP_SAVE_FILE})

    def load_map(self) -> str:
        """Load saved map state."""
        self._load_saved_map()
        return json.dumps({
            "positions": self._saved_positions,
            "labels": self._saved_labels,
        }, ensure_ascii=False)

    def get_device_types(self) -> str:
        """Return the device type definitions (icons, colors)."""
        return json.dumps(DEVICE_TYPES, ensure_ascii=False)

    # ─── Internal ─────────────────────────────────────────────────────

    _SAVED_MAP_TTL_SEC = 30 * 86400   # forget positions/labels of devices unseen for 30 days

    def _prune_saved_map(self, now: float):
        """Drop saved positions/labels for device ids not seen by any scan for 30 days.
        Without this, every DHCP/guest device ever dragged or labelled stays in
        network_map.json forever (and the whole file is rewritten on each drag)."""
        cutoff = now - self._SAVED_MAP_TTL_SEC
        stale = [did for did in set(self._saved_positions) | set(self._saved_labels)
                 if self._device_last_seen.get(did, now) < cutoff]
        for did in stale:
            self._saved_positions.pop(did, None)
            self._saved_labels.pop(did, None)
            self._device_last_seen.pop(did, None)
        if stale:
            logger.info(f"[Mapper] {len(stale)} stale device(s) pruned from saved map")
            self._save_map()

    def _save_map(self):
        """Persist map positions and labels to disk."""
        try:
            data = {
                "positions": self._saved_positions,
                "labels": self._saved_labels,
                "last_seen": self._device_last_seen,
                "last_saved": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            with open(MAP_SAVE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[Mapper] Save error: {e}")

    def _load_saved_map(self):
        """Load saved map state from disk."""
        try:
            if os.path.exists(MAP_SAVE_FILE):
                with open(MAP_SAVE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._saved_positions = data.get("positions", {})
                self._device_last_seen = data.get("last_seen", {})
                self._saved_labels = data.get("labels", {})
                logger.info(f"[Mapper] Loaded map: {len(self._saved_positions)} positions")
        except Exception as e:
            logger.warning(f"[Mapper] Could not load saved map: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN — pywebview window
# ═══════════════════════════════════════════════════════════════════════════

def main():
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    api = MapperAPI()

    if not headless and HAS_WEBVIEW:
        logger.info(f"[Mapper] SentinelOS Network Mapper v{VERSION} — GUI mode")

        if not os.path.exists(MAP_HTML):
            logger.error(f"[Mapper] HTML file not found: {MAP_HTML}")
            return

        window = webview.create_window(
            f"SentinelOS - Network Mapper v{VERSION}",
            MAP_HTML,
            js_api=api,
            width=1400,
            height=900,
            min_size=(1000, 650),
            background_color="#0f0f13",
            maximized=True,
        )
        api.set_window(window)
        webview.start(debug=False)

    else:
        logger.info(f"[Mapper] SentinelOS Network Mapper v{VERSION} — headless mode")
        logger.info("[Mapper] Running scan...")
        devices = api._scanner.scan_network()
        logger.info(f"[Mapper] Found {len(devices)} devices:")
        for dev in devices:
            logger.info(f"  {dev['ip']:15s}  {dev.get('type','?'):10s}  {dev.get('hostname',''):30s}  {dev.get('vendor','')}")


if __name__ == "__main__":
    main()
