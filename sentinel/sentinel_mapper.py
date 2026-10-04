"""
SentinelOS  - Network Mapper v1.0
Visual network topology mapper that scans your local network,
discovers devices, classifies them, and renders an interactive map.

Usage:
    python sentinel_mapper.py          -> GUI mode (pywebview)
    python sentinel_mapper.py --headless  -> WebSocket only (no GUI)
"""

import os
import sys

# Fix pythonw (no console)  - redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

import copy
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

# - Constants -
VERSION = "1.0.0"
SENTINEL_DIR = os.path.dirname(os.path.abspath(__file__))

# NetGuard AI shared modules
sys.path.insert(0, os.path.dirname(SENTINEL_DIR))
try:
    from permissions import PermissionManager
    HAS_PERMISSIONS = True
except ImportError:
    HAS_PERMISSIONS = False

try:
    from toast_notifications import toast_block, toast_unblock, toast_scan, toast_event
    HAS_TOAST = True
except ImportError:
    HAS_TOAST = False
MAP_HTML = os.path.join(SENTINEL_DIR, "sentinel_map.html")
SETTINGS_FILE = os.path.join(SENTINEL_DIR, "sentinel_settings.json")
# Writable location (Store/MSIX installs are read-only): shared NetGuard data dir
try:
    from netguard_paths import data_path as _ng_data_path
    _DATA_SENTINEL = _ng_data_path("sentinel")
except Exception:  # standalone use
    _DATA_SENTINEL = SENTINEL_DIR
os.makedirs(_DATA_SENTINEL, exist_ok=True)
MAP_SAVE_FILE = os.path.join(_DATA_SENTINEL, "network_map.json")
IS_WINDOWS = os.name == 'nt'

COMMON_PORTS = [22, 53, 80, 443, 445, 548, 3389, 5000, 5900, 8080, 8443, 9100]

# Ensure logs dir BEFORE creating the file handler (fresh install crashed here)
_LOG_DIR = os.path.join(_DATA_SENTINEL, "logs")
os.makedirs(_LOG_DIR, exist_ok=True)
_handlers = [logging.StreamHandler(sys.stdout)]
try:
    _handlers.insert(0, RotatingFileHandler(os.path.join(_LOG_DIR, "mapper.log"),
                                            maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"))
except OSError:
    pass   # read-only location: console only, never crash at import
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_handlers,
)
logger = logging.getLogger("SentinelMapper")


def _valid_ip(ip) -> bool:
    """IPs arrive from the page JS and end up in netsh arguments / rule names."""
    if not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def _valid_port(port):
    try:
        p = int(port)
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None

# - Device Types -

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


# ------------------------------------------------------------------------------------------------------------------------------------------------------
# MAC VENDOR DATABASE
# ------------------------------------------------------------------------------------------------------------------------------------------------------

MAC_VENDORS = {
    # Networking
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:15:5D": "Hyper-V",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:1A:2B": "Cisco", "00:1B:54": "Cisco", "00:26:CB": "Cisco",
    "00:17:C5": "Cisco", "00:1C:58": "Cisco",
    "00:1E:58": "D-Link", "00:22:B0": "D-Link", "1C:7E:E5": "D-Link", "BC:22:28": "D-Link",
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
    "00:11:32": "Synology",
    "00:08:9B": "QNAP",
    # Routers / ISP equipment
    "3C:B7:4B": "Vantiva", "F4:CA:E5": "Vantiva", "00:26:44": "Technicolor",
    "F0:AF:85": "CommScope", "20:3D:66": "CommScope",
    "00:1D:CE": "ARRIS", "E8:ED:05": "ARRIS", "F8:0B:BE": "ARRIS",
    # Laptop / PC manufacturers
    "9C:5A:44": "Compal",  # Makes laptops for Dell/Lenovo
    "20:4E:F6": "AzureWave",  # Wi-Fi modules in laptops/IoT
    "D4:6A:6A": "Foxconn",  # Hon Hai  - makes components for many brands
    # IoT chips
    "D4:F9:8D": "Espressif",  # ESP32/ESP8266
    "B4:E6:2D": "Espressif",
    "AC:67:B2": "Espressif",
}

# Vendor -> device type mapping
VENDOR_DEVICE_MAP = {
    "printer": ["HP", "Epson", "Canon", "Brother", "Xerox", "Lexmark", "Ricoh"],
    "mobile":  ["Apple", "Samsung", "Xiaomi", "OnePlus", "HTC", "Google", "Huawei", "OPPO", "Vivo"],
    "iot":     ["Raspberry Pi", "Nest", "Amazon", "Tuya", "Shelly", "Sonoff", "Espressif"],
    "tv":      ["LG", "Roku", "Chromecast", "Fire TV"],
    "nas":     ["Synology", "QNAP", "WD"],
    "router":  ["Cisco", "D-Link", "Linksys", "TP-Link", "Netgear", "ASUS",
                 "Vantiva", "Technicolor", "CommScope", "ARRIS"],
    "pc":      ["Compal", "AzureWave", "Foxconn"],
}


# ------------------------------------------------------------------------------------------------------------------------------------------------------
# NETWORK SCANNER
# ------------------------------------------------------------------------------------------------------------------------------------------------------

class NetworkScanner:
    """Scans the local network and discovers devices across multiple interfaces."""

    # Skip these virtual adapter patterns
    VIRTUAL_PATTERNS = ['Virtual', 'Hyper-V', 'VirtualBox', 'WireGuard', 'Loopback', 'WSL',
                        'Docker', 'vEthernet', 'Bluetooth', 'WAN Miniport', 'Wi-Fi Direct']

    def __init__(self):
        self.devices = []
        self.gateway_ip = None
        self.local_ip = None
        self.subnet = None
        self.interface_name = None
        self.interfaces = []  # All detected real interfaces
        self._scapy_iface = None
        self._scanning = False

    def get_network_info(self) -> dict:
        """Detect local network information and all real interfaces."""
        info = {"gateway": None, "local_ip": None, "subnet": None, "interface": None, "interfaces": []}
        try:
            # Get local IP (default route)
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

            # Detect ALL real interfaces
            self.interfaces = self._get_all_interfaces()
            info["interfaces"] = self.interfaces

            # Primary interface name
            for iface in self.interfaces:
                if iface["ip"] == self.local_ip:
                    self.interface_name = iface["name"]
                    break
            if not self.interface_name:
                self.interface_name = self._get_interface_name()
            info["interface"] = self.interface_name

            # Find matching Scapy interface (for ARP scan)
            if HAS_SCAPY:
                self._scapy_iface = self._find_scapy_iface()
                if self._scapy_iface:
                    logger.info(f"[Scanner] Scapy interface: {self._scapy_iface}")

        except Exception as e:
            logger.error(f"[Scanner] Network info error: {e}")

        return info

    def _get_all_interfaces(self) -> list:
        """Detect all real network interfaces with IPv4 addresses."""
        interfaces = []
        try:
            if IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                # Get adapters with IP addresses, filter virtual
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-NetIPAddress -AddressFamily IPv4 | "
                     "Where-Object {$_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown'} | "
                     "Select-Object IPAddress, InterfaceAlias, PrefixLength | ConvertTo-Json -Compress"],
                    capture_output=True, text=True, timeout=8,
                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.stdout.strip():
                    entries = json.loads(result.stdout.strip())
                    if isinstance(entries, dict):
                        entries = [entries]
                    for entry in entries:
                        ip = entry.get("IPAddress", "")
                        alias = entry.get("InterfaceAlias", "")
                        prefix = entry.get("PrefixLength", 24)
                        # Skip virtual adapters
                        if any(vp.lower() in alias.lower() for vp in self.VIRTUAL_PATTERNS):
                            continue
                        # Skip link-local (169.254.x.x)
                        if ip.startswith("169.254."):
                            continue
                        # Compute subnet
                        parts = ip.split(".")
                        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
                        interfaces.append({
                            "name": alias,
                            "ip": ip,
                            "subnet": subnet,
                            "prefix": prefix,
                        })
                        logger.info(f"[Scanner] Interface: {alias}  - {ip} ({subnet})")
        except Exception as e:
            logger.warning(f"[Scanner] Could not enumerate interfaces: {e}")

        # Fallback: at least add the default interface
        if not interfaces and self.local_ip:
            parts = self.local_ip.split(".")
            interfaces.append({
                "name": self.interface_name or "Default",
                "ip": self.local_ip,
                "subnet": f"{parts[0]}.{parts[1]}.{parts[2]}.0/24",
                "prefix": 24,
            })
        return interfaces

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
        """Get active REAL network interface name (skip virtual adapters)."""
        try:
            if IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                # Get all Up adapters, filter out virtual ones
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and "
                     "$_.InterfaceDescription -notmatch 'Virtual|Hyper-V|VirtualBox|WireGuard|Loopback|WSL'} "
                     "| Select-Object -First 1 -ExpandProperty Name"],
                    capture_output=True, text=True, timeout=5,
                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW
                )
                name = result.stdout.strip()
                if name:
                    return name
                # Fallback: any Up adapter
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name"],
                    capture_output=True, text=True, timeout=5,
                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW
                )
                name = result.stdout.strip()
                if name:
                    return name
        except Exception:
            pass
        return "Unknown"

    def _find_scapy_iface(self) -> str:
        """Find the Scapy interface ID that matches our local IP (Wi-Fi/Ethernet)."""
        try:
            from scapy.all import IFACES
            for iface_id, iface in IFACES.items():
                ip = getattr(iface, 'ip', '')
                name = getattr(iface, 'name', '')
                desc = getattr(iface, 'description', '').lower()
                # Match by IP address
                if ip == self.local_ip:
                    # Skip virtual/loopback
                    if any(virt in desc for virt in ['virtual', 'hyper-v', 'loopback', 'wsl', 'wireguard']):
                        continue
                    logger.info(f"[Scanner] Matched Scapy iface '{name}' (IP={ip})")
                    return str(iface_id)
        except Exception as e:
            logger.warning(f"[Scanner] Could not find Scapy iface: {e}")
        return None

    def scan_network(self, callback=None) -> list:
        """Scan the local network for devices across ALL detected interfaces.
        Returns list of device dicts."""
        if self._scanning:
            return self.devices
        self._scanning = True
        self.devices = []

        try:
            self.get_network_info()
            if not self.subnet and not self.interfaces:
                logger.error("[Scanner] No subnet detected")
                self._scanning = False
                return []

            # - Scan each real interface -
            known_ips = set()
            ifaces_to_scan = self.interfaces if self.interfaces else [
                {"name": self.interface_name or "Default", "ip": self.local_ip,
                 "subnet": self.subnet, "prefix": 24}
            ]

            for iface in ifaces_to_scan:
                iface_name = iface["name"]
                iface_ip = iface["ip"]
                iface_subnet = iface["subnet"]
                parts = iface_ip.split(".")
                subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."

                logger.info(f"[Scanner] Scanning interface '{iface_name}'  - {iface_subnet} ...")

                # Method 1: Get-NetNeighbor (Windows)  - fastest
                if IS_WINDOWS:
                    iface_devices = self._parse_arp_table(
                        subnet_filter=subnet_prefix, iface_name=iface_name
                    )
                    for dev in iface_devices:
                        if dev["ip"] not in known_ips:
                            self.devices.append(dev)
                            known_ips.add(dev["ip"])

                # Method 2: Ping sweep  - only if very few results for this interface
                iface_count = sum(1 for d in self.devices if d.get("network") == iface_name)
                if iface_count < 3:
                    logger.info(f"[Scanner] Few devices on '{iface_name}', running ping sweep...")
                    ping_results = self._ping_sweep_subnet(iface_ip)
                    for dev in ping_results:
                        if dev["ip"] not in known_ips:
                            dev["network"] = iface_name
                            self.devices.append(dev)
                            known_ips.add(dev["ip"])

            # Method 3 (fallback): Scapy ARP  - only if almost nothing total
            if len(self.devices) < 2 and HAS_SCAPY:
                logger.info("[Scanner] Few devices found, trying Scapy ARP scan...")
                arp_results = self._arp_scan()
                for dev in arp_results:
                    if dev["ip"] not in known_ips:
                        dev["network"] = self.interface_name or ""
                        self.devices.append(dev)
                        known_ips.add(dev["ip"])
                    else:
                        for existing in self.devices:
                            if existing["ip"] == dev["ip"] and existing["mac"] == " -" and dev["mac"] != " -":
                                existing["mac"] = dev["mac"]
                                existing["vendor"] = dev["vendor"]
                                break

            # Add gateway if not found
            if self.gateway_ip and not any(d["ip"] == self.gateway_ip for d in self.devices):
                hostname = self._resolve_hostname(self.gateway_ip)
                self.devices.insert(0, {
                    "ip": self.gateway_ip, "mac": " -", "hostname": hostname or "Gateway",
                    "vendor": "", "status": "up", "open_ports": [],
                    "network": self.interface_name or "",
                })

            # Add self if not found
            if self.local_ip and not any(d["ip"] == self.local_ip for d in self.devices):
                self.devices.append({
                    "ip": self.local_ip, "mac": " -", "hostname": socket.gethostname(),
                    "vendor": "", "status": "up", "open_ports": [],
                    "network": self.interface_name or "",
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

            # Log summary per interface
            iface_counts = {}
            for d in self.devices:
                net = d.get("network", "?")
                iface_counts[net] = iface_counts.get(net, 0) + 1
            for net, cnt in iface_counts.items():
                logger.info(f"[Scanner] Interface '{net}': {cnt} devices")
            logger.info(f"[Scanner] Total: {len(self.devices)} devices across {len(ifaces_to_scan)} interface(s)")

        except Exception as e:
            logger.error(f"[Scanner] Scan error: {e}")
        finally:
            self._scanning = False

        return self.devices

    def _arp_scan(self) -> list:
        """ARP scan using Scapy on the correct interface."""
        devices = []
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
            # Use the correct interface (crucial on multi-adapter systems)
            srp_kwargs = {"timeout": 4, "verbose": False}
            if self._scapy_iface:
                srp_kwargs["iface"] = self._scapy_iface
                logger.info(f"[Scanner] ARP scan on interface: {self._scapy_iface}")
            result = srp(packet, **srp_kwargs)[0]
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

    def _ping_sweep_subnet(self, iface_ip: str) -> list:
        """Ping sweep a specific subnet based on interface IP."""
        parts = iface_ip.split(".")
        base = f"{parts[0]}.{parts[1]}.{parts[2]}"
        return self._ping_sweep(base)

    def _ping_sweep(self, base: str = None) -> list:
        """Ping sweep fallback when Scapy is not available."""
        devices = []
        if base is None:
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
                    return {"ip": ip, "mac": " -", "hostname": hostname,
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
        if not mac or mac == " -":
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

    def _parse_arp_table(self, subnet_filter: str = None, iface_name: str = None) -> list:
        """Get devices from system neighbor/ARP table. Uses Get-NetNeighbor on Windows
        (more complete than arp -a) and sends a broadcast ping first to populate the cache.
        This catches phones/tablets that don't respond to unicast ping.

        Args:
            subnet_filter: e.g. "10.0.0."  - only return IPs matching this prefix.
                           If None, uses self.local_ip subnet.
            iface_name:    Interface name to tag devices with (e.g. "Wi-Fi 2").
        """
        devices = []
        si = None
        cf = 0
        if IS_WINDOWS:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            cf = subprocess.CREATE_NO_WINDOW

        # Determine subnet prefix for filtering
        subnet_prefix = subnet_filter or ""
        if not subnet_prefix and self.local_ip:
            parts = self.local_ip.split(".")
            subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."

        if subnet_prefix and not subnet_prefix.endswith("."):
            # Ensure format "x.x.x."
            parts = subnet_prefix.replace("/", ".").split(".")
            subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."

        # Send broadcast ping to populate ARP cache
        if subnet_prefix:
            broadcast_ip = subnet_prefix + "255"
            try:
                subprocess.run(
                    ["ping", "-n", "2", "-w", "500", broadcast_ip],
                    capture_output=True, timeout=3, startupinfo=si, creationflags=cf
                )
            except Exception:
                pass

        try:
            if IS_WINDOWS:
                # Get-NetNeighbor is much more reliable than arp -a
                # Returns Reachable, Stale, Delay, Probe states (all valid neighbors)
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-NetNeighbor -AddressFamily IPv4 | "
                     "Where-Object {$_.State -ne 'Unreachable' -and $_.State -ne 'Permanent' -and "
                     "$_.LinkLayerAddress -ne '' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and "
                     "$_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF'} | "
                     "Select-Object IPAddress, LinkLayerAddress, State | "
                     "ConvertTo-Json -Compress"],
                    capture_output=True, text=True, timeout=10,
                    startupinfo=si, creationflags=cf
                )
                if result.stdout.strip():
                    entries = json.loads(result.stdout.strip())
                    if isinstance(entries, dict):
                        entries = [entries]  # single result comes as dict not list
                    seen_ips = set()
                    valid_entries = []
                    for entry in entries:
                        ip_addr = entry.get("IPAddress", "")
                        mac_raw = entry.get("LinkLayerAddress", "")
                        if not ip_addr or not mac_raw or not subnet_prefix:
                            continue
                        if not ip_addr.startswith(subnet_prefix):
                            continue
                        if ip_addr in seen_ips:
                            continue
                        last_octet = int(ip_addr.split(".")[-1])
                        if last_octet in (0, 255):
                            continue
                        seen_ips.add(ip_addr)
                        mac_addr = mac_raw.replace("-", ":").upper()
                        vendor = self._mac_vendor(mac_addr)
                        valid_entries.append({"ip": ip_addr, "mac": mac_addr, "vendor": vendor})

                    # Parallel hostname resolution (much faster than sequential)
                    def resolve(entry):
                        entry["hostname"] = self._resolve_hostname(entry["ip"])
                        return entry
                    with ThreadPoolExecutor(max_workers=20) as pool:
                        valid_entries = list(pool.map(resolve, valid_entries))

                    for entry in valid_entries:
                        devices.append({
                            "ip": entry["ip"], "mac": entry["mac"], "hostname": entry["hostname"],
                            "vendor": entry["vendor"], "status": "up", "open_ports": [],
                            "network": iface_name or self.interface_name or "",
                        })
                    logger.info(f"[Scanner] Get-NetNeighbor ({iface_name or 'default'}): {len(devices)} entries")
            else:
                # Linux fallback: arp -a
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=5,
                    startupinfo=si, creationflags=cf
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    ip_addr = mac_addr = None
                    for p in line.split():
                        if p.startswith("(") and p.endswith(")"):
                            ip_addr = p[1:-1]
                        if ":" in p and len(p) == 17:
                            mac_addr = p.upper()
                    if ip_addr and mac_addr and subnet_prefix and ip_addr.startswith(subnet_prefix):
                        hostname = self._resolve_hostname(ip_addr)
                        vendor = self._mac_vendor(mac_addr)
                        devices.append({
                            "ip": ip_addr, "mac": mac_addr, "hostname": hostname,
                            "vendor": vendor, "status": "up", "open_ports": [],
                            "network": iface_name or self.interface_name or "",
                        })
                logger.info(f"[Scanner] ARP table ({iface_name or 'default'}): {len(devices)} entries")
        except Exception as e:
            logger.warning(f"[Scanner] Neighbor table parse failed: {e}")
        return devices

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


# ------------------------------------------------------------------------------------------------------------------------------------------------------
# DEVICE CLASSIFIER
# ------------------------------------------------------------------------------------------------------------------------------------------------------

class DeviceClassifier:
    """Classifies network devices by type based on multiple heuristics."""

    def __init__(self, gateway_ip: str = None):
        self.gateway_ip = gateway_ip

    @staticmethod
    def _is_randomized_mac(mac: str) -> bool:
        """Check if MAC address is locally administered (randomized).
        Modern phones/tablets randomize their MAC for privacy."""
        if not mac or mac == " -" or len(mac) < 2:
            return False
        try:
            first_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
            return bool(first_byte & 0x02)  # locally administered bit
        except ValueError:
            return False

    def classify(self, device: dict) -> str:
        """Classify a device into a type category."""
        ip = device.get("ip", "")
        mac = device.get("mac", "")
        vendor = device.get("vendor", "")
        hostname = device.get("hostname", "").lower()
        ports = device.get("open_ports", [])

        # Gateway -> router
        if ip == self.gateway_ip:
            return "router"

        # IP ending in .1 or .254 likely router/gateway
        last_octet = int(ip.split(".")[-1]) if ip else 0
        if last_octet in (1, 254) and (53 in ports or 80 in ports):
            return "router"

        # Port 9100 = printer (check BEFORE vendor, because printer components
        # may have generic vendor MACs like Foxconn/Hon Hai)
        if 9100 in ports:
            return "printer"

        # Hostname pattern: NPI = HP Network Printer Interface
        if hostname.startswith("npi"):
            return "printer"

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
        if any(kw in hostname for kw in ["iphone", "ipad", "android", "galaxy", "pixel",
                                          "phone", "samsung", "xiaomi", "huawei", "oneplus",
                                          "oppo", "redmi", "motorola", "nokia"]):
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

        # Randomized MAC -> almost certainly a phone or tablet
        # (phones/tablets use MAC randomization for privacy, PCs/IoT generally don't)
        if self._is_randomized_mac(mac):
            return "mobile"

        # No open ports + no hostname -> likely a sleeping phone/tablet
        if not ports and not hostname:
            return "mobile"

        return "unknown"


# ------------------------------------------------------------------------------------------------------------------------------------------------------
# SENTINEL FIREWALL  - Windows Firewall integration
# ------------------------------------------------------------------------------------------------------------------------------------------------------

class SentinelFirewall:
    """Manages Windows Firewall rules for device blocking via netsh advfirewall.
    Tracks blocked devices, connection attempts, and per-port rules."""

    RULE_PREFIX = "SentinelOS_"
    FIREWALL_SAVE = os.path.join(_DATA_SENTINEL, "firewall_state.json")

    def __init__(self):
        self.blocked_devices = {}   # ip -> {blocked_at, attempts, last_attempt, label, block_all, blocked_ports}
        self.monitoring = True
        self._admin = None          # cached admin check
        self._load_state()

    # - Admin check -
    def is_admin(self) -> bool:
        """Check if running with administrator privileges."""
        if self._admin is None:
            try:
                import ctypes
                self._admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                self._admin = False
        return self._admin

    # - Block / Unblock device -
    def block_device(self, ip: str, label: str = "") -> dict:
        """Block all traffic to/from an IP address."""
        if not _valid_ip(ip):
            return {"success": False, "error": "IP invalide"}
        ip = ip.strip()
        if not self.is_admin():
            return {"success": False, "error": "Droits administrateur requis. Relancez SentinelOS en tant qu'administrateur."}

        try:
            rule_in = f"{self.RULE_PREFIX}Block_{ip.replace('.','_')}_IN"
            rule_out = f"{self.RULE_PREFIX}Block_{ip.replace('.','_')}_OUT"

            # Remove existing rules first (avoid duplicates)
            self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_in}"])
            self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_out}"])

            # Add block rules (both directions)
            r1 = self._run_netsh([
                "advfirewall", "firewall", "add", "rule",
                f"name={rule_in}", "dir=in", "action=block",
                f"remoteip={ip}", "enable=yes"
            ])
            r2 = self._run_netsh([
                "advfirewall", "firewall", "add", "rule",
                f"name={rule_out}", "dir=out", "action=block",
                f"remoteip={ip}", "enable=yes"
            ])

            if r1["success"] and r2["success"]:
                now = time.strftime("%Y-%m-%d %H:%M:%S")
                self.blocked_devices[ip] = {
                    "blocked_at": now,
                    "attempts": self.blocked_devices.get(ip, {}).get("attempts", 0),
                    "last_attempt": "",
                    "label": label,
                    "block_all": True,
                    "blocked_ports": [],
                }
                self._save_state()
                logger.info(f"[Firewall] BLOCKED {ip} ({label})")
                return {"success": True, "ip": ip, "message": f"{ip} bloqué"}
            else:
                err = r1.get("error", "") or r2.get("error", "")
                return {"success": False, "error": f"Echec netsh: {err}"}

        except Exception as e:
            logger.error(f"[Firewall] Block error: {e}")
            return {"success": False, "error": str(e)}

    def unblock_device(self, ip: str) -> dict:
        """Remove all block rules for an IP address."""
        if not _valid_ip(ip):
            return {"success": False, "error": "IP invalide"}
        ip = ip.strip()
        if not self.is_admin():
            return {"success": False, "error": "Droits administrateur requis."}

        try:
            # Delete all SentinelOS rules for this IP
            ip_tag = ip.replace('.', '_')
            for suffix in ["_IN", "_OUT"]:
                self._run_netsh(["advfirewall", "firewall", "delete", "rule",
                                 f"name={self.RULE_PREFIX}Block_{ip_tag}{suffix}"])

            # Delete port-specific rules
            if ip in self.blocked_devices:
                for port in self.blocked_devices[ip].get("blocked_ports", []):
                    for suffix in ["_IN", "_OUT"]:
                        self._run_netsh(["advfirewall", "firewall", "delete", "rule",
                                         f"name={self.RULE_PREFIX}Port_{ip_tag}_{port}{suffix}"])

            if ip in self.blocked_devices:
                del self.blocked_devices[ip]
            self._save_state()
            logger.info(f"[Firewall] UNBLOCKED {ip}")
            return {"success": True, "ip": ip, "message": f"{ip} débloqué"}

        except Exception as e:
            logger.error(f"[Firewall] Unblock error: {e}")
            return {"success": False, "error": str(e)}

    # - Port-level blocking -
    def block_port(self, ip: str, port: int, protocol: str = "tcp") -> dict:
        """Block a specific port for an IP address."""
        protocol = protocol if protocol in ("tcp", "udp") else "tcp"
        if not _valid_ip(ip):
            return {"success": False, "error": "IP invalide"}
        ip = ip.strip()
        port = _valid_port(port)
        if port is None:
            return {"success": False, "error": "port invalide"}
        if not self.is_admin():
            return {"success": False, "error": "Droits administrateur requis."}

        try:
            ip_tag = ip.replace('.', '_')
            rule_in = f"{self.RULE_PREFIX}Port_{ip_tag}_{port}_IN"
            rule_out = f"{self.RULE_PREFIX}Port_{ip_tag}_{port}_OUT"

            self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_in}"])
            self._run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_out}"])

            r1 = self._run_netsh([
                "advfirewall", "firewall", "add", "rule",
                f"name={rule_in}", "dir=in", "action=block",
                f"remoteip={ip}", f"protocol={protocol}", f"localport={port}", "enable=yes"
            ])
            r2 = self._run_netsh([
                "advfirewall", "firewall", "add", "rule",
                f"name={rule_out}", "dir=out", "action=block",
                f"remoteip={ip}", f"protocol={protocol}", f"remoteport={port}", "enable=yes"
            ])

            if r1["success"] and r2["success"]:
                if ip not in self.blocked_devices:
                    self.blocked_devices[ip] = {
                        "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "attempts": 0, "last_attempt": "", "label": "",
                        "block_all": False, "blocked_ports": [],
                    }
                if port not in self.blocked_devices[ip]["blocked_ports"]:
                    self.blocked_devices[ip]["blocked_ports"].append(port)
                self._save_state()
                logger.info(f"[Firewall] Blocked port {port}/{protocol} for {ip}")
                return {"success": True, "message": f"Port {port} bloqué pour {ip}"}

            return {"success": False, "error": "Echec netsh"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def unblock_port(self, ip: str, port: int) -> dict:
        """Remove port-specific block rule."""
        if not _valid_ip(ip):
            return {"success": False, "error": "IP invalide"}
        ip = ip.strip()
        port = _valid_port(port)
        if port is None:
            return {"success": False, "error": "port invalide"}
        if not self.is_admin():
            return {"success": False, "error": "Droits administrateur requis."}

        try:
            ip_tag = ip.replace('.', '_')
            for suffix in ["_IN", "_OUT"]:
                self._run_netsh(["advfirewall", "firewall", "delete", "rule",
                                 f"name={self.RULE_PREFIX}Port_{ip_tag}_{port}{suffix}"])

            if ip in self.blocked_devices:
                ports = self.blocked_devices[ip].get("blocked_ports", [])
                if port in ports:
                    ports.remove(port)
                # If no more rules, remove device entry
                if not self.blocked_devices[ip]["block_all"] and not ports:
                    del self.blocked_devices[ip]
            self._save_state()
            logger.info(f"[Firewall] Unblocked port {port} for {ip}")
            return {"success": True, "message": f"Port {port} débloqué pour {ip}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    # - Query -
    def is_blocked(self, ip: str) -> bool:
        """Check if a device is fully blocked."""
        entry = self.blocked_devices.get(ip)
        return bool(entry and entry.get("block_all", False))

    def get_device_firewall(self, ip: str) -> dict:
        """Get firewall state for a specific device."""
        entry = self.blocked_devices.get(ip)
        if not entry:
            return {"blocked": False, "block_all": False, "blocked_ports": [], "attempts": 0, "last_attempt": ""}
        return {
            "blocked": True,
            "block_all": entry.get("block_all", False),
            "blocked_ports": entry.get("blocked_ports", []),
            "attempts": entry.get("attempts", 0),
            "last_attempt": entry.get("last_attempt", ""),
            "blocked_at": entry.get("blocked_at", ""),
        }

    def get_all_rules(self) -> dict:
        """Get summary of all firewall rules."""
        total_attempts = sum(d.get("attempts", 0) for d in self.blocked_devices.values())
        fully_blocked = sum(1 for d in self.blocked_devices.values() if d.get("block_all"))
        port_blocked = sum(1 for d in self.blocked_devices.values() if d.get("blocked_ports") and not d.get("block_all"))
        return {
            "blocked_count": len(self.blocked_devices),
            "fully_blocked": fully_blocked,
            "port_blocked": port_blocked,
            "total_attempts": total_attempts,
            "is_admin": self.is_admin(),
            "monitoring": self.monitoring,
            "devices": {ip: {
                "label": d.get("label", ""),
                "block_all": d.get("block_all", False),
                "blocked_ports": d.get("blocked_ports", []),
                "attempts": d.get("attempts", 0),
                "last_attempt": d.get("last_attempt", ""),
                "blocked_at": d.get("blocked_at", ""),
            } for ip, d in self.blocked_devices.items()},
        }

    def record_attempt(self, ip: str):
        """Record a connection attempt from a blocked device."""
        if ip in self.blocked_devices:
            self.blocked_devices[ip]["attempts"] = self.blocked_devices[ip].get("attempts", 0) + 1
            self.blocked_devices[ip]["last_attempt"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self._save_state()

    def check_blocked_activity(self, visible_ips: set):
        """Check if any blocked devices are still visible on the network (= attempted connection)."""
        for ip in list(self.blocked_devices.keys()):
            if ip in visible_ips and self.blocked_devices[ip].get("block_all"):
                self.record_attempt(ip)

    # - Sync rules from Windows -
    def sync_rules(self) -> dict:
        """Verify that our tracked rules actually exist in Windows Firewall."""
        if not self.is_admin():
            return {"synced": False, "error": "Pas admin"}

        try:
            result = self._run_netsh(["advfirewall", "firewall", "show", "rule",
                                       f"name=all", "dir=in"], parse=True)
            active_rules = result.get("output", "")
            synced = 0
            for ip in list(self.blocked_devices.keys()):
                ip_tag = ip.replace('.', '_')
                rule_name = f"{self.RULE_PREFIX}Block_{ip_tag}_IN"
                if rule_name in active_rules:
                    synced += 1
                else:
                    # Rule was deleted externally
                    logger.warning(f"[Firewall] Rule missing for {ip}, removing from state")
                    del self.blocked_devices[ip]
            self._save_state()
            return {"synced": True, "count": synced}
        except Exception as e:
            return {"synced": False, "error": str(e)}

    # - Internal -
    def _run_netsh(self, args: list, parse: bool = False) -> dict:
        """Execute a netsh command."""
        try:
            si = None
            cf = 0
            if IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                cf = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                ["netsh"] + args,
                capture_output=True, text=True, timeout=10,
                startupinfo=si, creationflags=cf
            )
            success = result.returncode == 0 or "Ok" in result.stdout or "ok" in result.stdout.lower()
            out = {"success": success, "output": result.stdout.strip()}
            if not success and result.stderr:
                out["error"] = result.stderr.strip()
            return out
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _save_state(self):
        """Persist firewall state to disk."""
        try:
            data = {
                "blocked_devices": self.blocked_devices,
                "monitoring": self.monitoring,
                "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            with open(self.FIREWALL_SAVE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[Firewall] Save error: {e}")

    def _load_state(self):
        """Load firewall state from disk."""
        try:
            if os.path.exists(self.FIREWALL_SAVE):
                with open(self.FIREWALL_SAVE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.blocked_devices = data.get("blocked_devices", {})
                self.monitoring = data.get("monitoring", True)
                logger.info(f"[Firewall] Loaded state: {len(self.blocked_devices)} blocked devices")
        except Exception as e:
            logger.warning(f"[Firewall] Could not load state: {e}")


# ------------------------------------------------------------------------------------------------------------------------------------------------------
# MAPPER API  - pywebview bridge
# ------------------------------------------------------------------------------------------------------------------------------------------------------

class MapperAPI:
    """API exposed to the HTML dashboard via pywebview."""

    def __init__(self):
        self._scanner = NetworkScanner()
        self._firewall = SentinelFirewall()
        self._perm = PermissionManager() if HAS_PERMISSIONS else None
        self._window = None
        self._saved_positions = {}
        self._saved_labels = {}
        self._device_last_seen = {}   # device_id -> epoch of last scan that saw it
        self._saved_devices = []
        self._last_scan_time = ""
        self._auth_user = None  # Current authenticated user
        self._load_saved_map()

    def set_window(self, window):
        self._window = window

    # - Scan -

    def scan_network(self) -> str:
        """Launch a network scan. Returns JSON with all discovered devices."""
        devices = self._scanner.scan_network()
        self._last_scan_time = time.strftime("%Y-%m-%d %H:%M:%S")
        _now = time.time()
        for _d in devices:
            if _d.get("id"):
                self._device_last_seen[_d["id"]] = _now
        self._prune_saved_map(_now)

        # Merge: keep previously cached devices that are not in current scan (mark offline)
        current_ips = {d["ip"] for d in devices}
        for cached in self._saved_devices:
            if cached.get("ip") not in current_ips:
                offline_dev = copy.deepcopy(cached)
                offline_dev["status"] = "offline"
                devices.append(offline_dev)

        # Apply saved positions and labels
        for dev in devices:
            did = dev.get("id", dev["ip"].replace(".", "_"))
            dev["id"] = did
            if did in self._saved_positions:
                dev["x"] = self._saved_positions[did]["x"]
                dev["y"] = self._saved_positions[did]["y"]
            if did in self._saved_labels:
                dev["custom_label"] = self._saved_labels[did]

        # Check blocked devices still visible (= connection attempt)
        visible_ips = {d["ip"] for d in devices if d.get("status") not in ("offline", "cached")}
        self._firewall.check_blocked_activity(visible_ips)

        # Tag devices with firewall status
        for dev in devices:
            fw = self._firewall.get_device_firewall(dev["ip"])
            dev["fw_blocked"] = fw.get("block_all", False)
            dev["fw_attempts"] = fw.get("attempts", 0)
            dev["fw_blocked_ports"] = fw.get("blocked_ports", [])

        # Save full device data for persistence
        self._saved_devices = [d for d in devices if d.get("status") != "offline"]
        self._save_map()

        # Toast notification for scan results
        if HAS_TOAST:
            new_count = sum(1 for d in devices if d.get("status") == "up")
            toast_scan("SentinelOS", f"{new_count} devices found on {len(self._scanner.interfaces)} interface(s)")

        return json.dumps({"devices": devices, "count": len(devices),
                           "last_scan": self._last_scan_time}, ensure_ascii=False)

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

    # - Map State -

    def update_device_position(self, device_id: str, x: float, y: float) -> str:
        """Save a device's position after drag & drop."""
        self._saved_positions[device_id] = {"x": x, "y": y}
        self._save_map()
        return json.dumps({"success": True})

    def update_device_label(self, device_id: str, label: str) -> str:
        """Set a custom label for a device."""
        label = "".join(ch for ch in str(label) if ch.isprintable() and ch not in "<>\"'`")[:64]
        self._saved_labels[str(device_id)[:128]] = label
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

    # - Firewall API -

    def fw_block_device(self, ip: str, label: str = "") -> str:
        """Block a device via Windows Firewall."""
        if self._perm and not self._perm.check("sentinel_mapper", "execute", self._auth_user):
            return json.dumps({"success": False, "error": "Permission denied / Accès refusé"})
        result = self._firewall.block_device(ip, label)
        if result.get("success") and HAS_TOAST:
            toast_block("SentinelOS", ip, label or "Blocked from network map")
        return json.dumps(result, ensure_ascii=False)

    def fw_unblock_device(self, ip: str) -> str:
        """Unblock a device."""
        if self._perm and not self._perm.check("sentinel_mapper", "execute", self._auth_user):
            return json.dumps({"success": False, "error": "Permission denied / Accès refusé"})
        result = self._firewall.unblock_device(ip)
        if result.get("success") and HAS_TOAST:
            toast_unblock("SentinelOS", ip)
        return json.dumps(result, ensure_ascii=False)

    def fw_block_port(self, ip: str, port: int, protocol: str = "tcp") -> str:
        """Block a specific port for a device."""
        if self._perm and not self._perm.check("sentinel_mapper", "execute", self._auth_user):
            return json.dumps({"success": False, "error": "Permission denied / Accès refusé"})
        result = self._firewall.block_port(ip, int(port), protocol)
        return json.dumps(result, ensure_ascii=False)

    def fw_unblock_port(self, ip: str, port: int) -> str:
        """Unblock a specific port for a device."""
        if self._perm and not self._perm.check("sentinel_mapper", "execute", self._auth_user):
            return json.dumps({"success": False, "error": "Permission denied / Accès refusé"})
        result = self._firewall.unblock_port(ip, int(port))
        return json.dumps(result, ensure_ascii=False)

    def fw_get_device_status(self, ip: str) -> str:
        """Get firewall status for a specific device."""
        status = self._firewall.get_device_firewall(ip)
        return json.dumps(status, ensure_ascii=False)

    def fw_get_all_rules(self) -> str:
        """Get all firewall rules summary."""
        rules = self._firewall.get_all_rules()
        return json.dumps(rules, ensure_ascii=False)

    def fw_is_admin(self) -> str:
        """Check if running as administrator."""
        return json.dumps({"admin": self._firewall.is_admin()})

    # - Permission API -

    def perm_get_status(self) -> str:
        """Get permission system status."""
        if not self._perm:
            return json.dumps({"enabled": False, "available": False})
        status = self._perm.get_status()
        status["available"] = True
        return json.dumps(status)

    def perm_enable(self, username: str, password: str) -> str:
        """Enable permission system."""
        if not self._perm:
            return json.dumps({"error": "Permission module not available"})
        result = self._perm.enable(username, password)
        if result.get("ok"):
            self._auth_user = username
        return json.dumps(result)

    def perm_authenticate(self, username: str, password: str) -> str:
        """Authenticate user."""
        if not self._perm:
            return json.dumps({"ok": True, "role": "admin"})
        result = self._perm.authenticate(username, password)
        if result.get("ok"):
            self._auth_user = username
        return json.dumps(result)

    def perm_lock(self, password: str) -> str:
        """Lock permissions."""
        if not self._perm:
            return json.dumps({"error": "Permission module not available"})
        return json.dumps(self._perm.lock(password))

    def perm_unlock(self, password: str) -> str:
        """Unlock permissions."""
        if not self._perm:
            return json.dumps({"error": "Permission module not available"})
        return json.dumps(self._perm.unlock(password))

    # - Internal -

    def get_saved_devices(self) -> str:
        """Return previously saved devices (for display on startup before scan)."""
        devices = copy.deepcopy(self._saved_devices)
        for dev in devices:
            did = dev.get("id", "")
            if did in self._saved_positions:
                dev["x"] = self._saved_positions[did]["x"]
                dev["y"] = self._saved_positions[did]["y"]
            if did in self._saved_labels:
                dev["custom_label"] = self._saved_labels[did]
            dev["status"] = "cached"  # mark as cached / not freshly scanned
            # Tag with firewall status
            fw = self._firewall.get_device_firewall(dev.get("ip", ""))
            dev["fw_blocked"] = fw.get("block_all", False)
            dev["fw_attempts"] = fw.get("attempts", 0)
            dev["fw_blocked_ports"] = fw.get("blocked_ports", [])
        return json.dumps({"devices": devices, "count": len(devices),
                           "last_scan": self._last_scan_time or ""}, ensure_ascii=False)

    _SAVED_MAP_TTL_SEC = 30 * 86400   # forget positions/labels of devices unseen for 30 days

    def _prune_saved_map(self, now: float):
        """Drop saved positions/labels for device ids not seen by any scan for 30 days
        (every DHCP/guest device ever dragged stayed in network_map.json forever)."""
        cutoff = now - self._SAVED_MAP_TTL_SEC
        stale = [did for did in set(self._saved_positions) | set(self._saved_labels)
                 if self._device_last_seen.get(did, now) < cutoff]
        for did in stale:
            self._saved_positions.pop(did, None)
            self._saved_labels.pop(did, None)
            self._device_last_seen.pop(did, None)
        if stale:
            logger.info(f"[Mapper] {len(stale)} stale device(s) pruned from saved map")

    def _save_map(self):
        """Persist map positions, labels, and full device data to disk."""
        try:
            # Clean device data for serialization (remove x/y/custom_label, they're in positions/labels)
            clean_devices = []
            for dev in self._scanner.devices:
                d = {k: v for k, v in dev.items() if k not in ("x", "y", "custom_label")}
                clean_devices.append(d)
            data = {
                "positions": self._saved_positions,
                "labels": self._saved_labels,
                "last_seen": self._device_last_seen,
                "devices": clean_devices,
                "last_scan": self._last_scan_time or "",
                "last_saved": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            with open(MAP_SAVE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"[Mapper] Saved {len(clean_devices)} devices to disk")
        except Exception as e:
            logger.error(f"[Mapper] Save error: {e}")

    def _load_saved_map(self):
        """Load saved map state from disk."""
        try:
            if os.path.exists(MAP_SAVE_FILE):
                with open(MAP_SAVE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._saved_positions = data.get("positions", {})
                self._saved_labels = data.get("labels", {})
                self._device_last_seen = data.get("last_seen", {}) if isinstance(data.get("last_seen"), dict) else {}
                self._saved_devices = data.get("devices", [])
                self._last_scan_time = data.get("last_scan", "")
                logger.info(f"[Mapper] Loaded map: {len(self._saved_devices)} devices, {len(self._saved_positions)} positions")
        except Exception as e:
            logger.warning(f"[Mapper] Could not load saved map: {e}")


# ------------------------------------------------------------------------------------------------------------------------------------------------------
# MAIN  - pywebview window
# ------------------------------------------------------------------------------------------------------------------------------------------------------

def main():
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    api = MapperAPI()

    if not headless and HAS_WEBVIEW:
        logger.info(f"[Mapper] SentinelOS Network Mapper v{VERSION}  - GUI mode")

        if not os.path.exists(MAP_HTML):
            logger.error(f"[Mapper] HTML file not found: {MAP_HTML}")
            return

        window = webview.create_window(
            f"SentinelOS Mapper - NetGuardPro Suite",
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
        logger.info(f"[Mapper] SentinelOS Network Mapper v{VERSION}  - headless mode")
        logger.info("[Mapper] Running scan...")
        result = json.loads(api.scan_network())  # Use MapperAPI to get save/merge
        devices = result.get("devices", [])
        logger.info(f"[Mapper] Found {len(devices)} devices:")
        for dev in devices:
            logger.info(f"  {dev['ip']:15s}  {dev.get('type','?'):10s}  {dev.get('hostname',''):30s}  {dev.get('vendor','')}")


if __name__ == "__main__":
    main()
