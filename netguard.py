"""
NetGuard Pro - Moteur de surveillance réseau
Capture, analyse et bloque les paquets en temps réel
Auteur: NetGuard Pro
Version: 4.1.0
Usage: python netguard.py [--interface eth0] [--port 8765] [--no-block]
"""

import asyncio
import json
import logging
import argparse
import time
import threading
import platform
import ipaddress
import re
import struct
import socket
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Optional
import os
import sys
import hashlib
import secrets as _ng_secrets
import tempfile
import base64

# License manager
try:
    from license_manager import init_license, has_feature, get_trial_banner
    LICENSE = init_license()
except Exception:
    LICENSE = {"tier": "trial", "features": [], "trial": True, "trial_days_left": 30, "expired": False}
    def has_feature(f): return True
    def get_trial_banner(): return ""

# Fix pythonw (no console) — redirect None stdout/stderr to devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import math
import urllib.request
import urllib.error

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[WARN] websockets non installé. Installe avec: pip install websockets")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw, get_if_list
    from scapy.layers.inet6 import IPv6
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[WARN] scapy non installé. Installe avec: pip install scapy")

try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

try:
    from startup_utils import is_startup_enabled, toggle_startup as toggle_startup_reg, get_all_startup_states, minimize_to_tray
    HAS_STARTUP_UTILS = True
except ImportError:
    HAS_STARTUP_UTILS = False

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

@dataclass
class Config:
    interface:              str   = "auto"
    ws_port:                int   = 8765
    can_block:              bool  = True
    log_file:               str   = "netguard.log"
    max_packets_log:        int   = 10_000
    port_scan_threshold:    int   = 15
    port_scan_window:       int   = 10
    brute_force_threshold:  int   = 8
    brute_force_window:     int   = 30
    syn_flood_threshold:    int   = 200
    syn_flood_window:       int   = 5
    dns_tunnel_threshold:   int   = 50
    whitelist: list = field(default_factory=lambda: [
        # Loopback + RFC1918
        "127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
        # IPv4 multicast (mDNS Bonjour, IGMP, etc.)
        "224.0.0.0/4",
        # IPv6 multicast (FF00::/8) + link-local (FE80::/10)
        "ff00::/8", "fe80::/10",
        # Anthropic API (Claude.ai / Claude Code / Claude Desktop)
        "160.79.104.0/21", "2607:6bc0::/32",
        # Vidéotron infrastructure (DNS + user LAN /64)
        "2607:fa48::/32", "2607:fa49::/32",
        # Cloudflare CDN (104.16-31.x.x) — required for ipapi.co + tons of websites
        "104.16.0.0/12", "172.64.0.0/13", "2606:4700::/32",
        # Google public DNS + GCP edge
        "8.8.8.0/24", "8.8.4.0/24", "2001:4860:4860::/48",
        # ip-api.com (208.95.112.0/24 ~)
        "208.95.112.0/24",
    ])
    sensitive_ports:    list = field(default_factory=lambda: [22, 3389, 5900, 23])
    always_block_ports: list = field(default_factory=lambda: [135, 137, 138, 139, 445, 1433, 3306])
    record_enabled:     bool  = False
    record_dir:         str   = "captures"
    record_rotate_min:  int   = 60
    record_max_files:   int   = 24
    dpi_enabled:        bool  = True
    dpi_mask_sensitive: bool  = True
    auto_block_enabled: bool  = True
    auto_block_hits:    int   = 10
    # v3.0 — Advanced Detection
    anomaly_enabled:        bool  = True
    anomaly_zscore:         float = 3.0
    anomaly_baseline_min:   int   = 60
    profile_enabled:        bool  = True
    correlation_enabled:    bool  = True
    correlation_window:     int   = 300
    ja3_enabled:            bool  = True
    entropy_enabled:        bool  = True
    entropy_threshold:      float = 3.5
    # v3.0 — Threat Intelligence
    virustotal_api_key:     str   = ""
    virustotal_enabled:     bool  = False
    otx_api_key:            str   = ""
    otx_enabled:            bool  = False
    abuseipdb_api_key:      str   = ""
    abuseipdb_enabled:      bool  = False
    threat_feeds_enabled:   bool  = True
    threat_feeds_interval:  int   = 3600
    # v3.0 — Active Response
    discord_webhook_url:    str   = ""
    discord_enabled:        bool  = False
    discord_min_severity:   str   = "high"
    telegram_bot_token:     str   = ""
    telegram_chat_id:       str   = ""
    telegram_enabled:       bool  = False
    telegram_min_severity:  str   = "high"
    isolation_enabled:      bool  = False
    quarantine_enabled:     bool  = False
    auto_forensic_enabled:  bool  = True
    auto_forensic_severity: str   = "critical"
    # v3.0 — WireGuard VPN
    wg_enabled:         bool  = False
    wg_interface:       str   = "wg0"
    wg_listen_port:     int   = 51820
    wg_address:         str   = "10.66.66.1/24"
    wg_dns:             str   = "1.1.1.1, 9.9.9.9"
    wg_endpoint:        str   = ""       # public IP/domain:port
    wg_config_dir:      str   = "wireguard"
    wg_post_up:         str   = ""
    wg_post_down:       str   = ""

CFG = Config()

RULES = {
    "block_port_scan":   {"enabled": True,  "label": "Bloquer scan de ports",  "hits": 0},
    "block_ssh_external":{"enabled": True,  "label": "Bloquer SSH externe",    "hits": 0},
    "block_rdp_public":  {"enabled": True,  "label": "Bloquer RDP public",     "hits": 0},
    "block_tor_exits":   {"enabled": True,  "label": "Bloquer Tor exit nodes", "hits": 0},
    "block_p2p":         {"enabled": True,  "label": "Bloquer P2P/Torrent",    "hits": 0},
    "block_syn_flood":   {"enabled": True,  "label": "Bloquer SYN Flood",      "hits": 0},
    "block_brute_force": {"enabled": True,  "label": "Bloquer Brute Force",    "hits": 0},
    "alert_geo":         {"enabled": True,  "label": "Alerter trafic suspect", "hits": 0},
}

TOR_EXIT_NODES: set = set()
BLOCKED_IPS:    set = set()
BLOCKED_NETS:   list = []

KNOWN_BAD_RANGES = ["185.220.0.0/16", "162.247.74.0/24"]
P2P_PORTS = set(range(6881, 6890)) | {51413, 1337, 2710}

# ─── Géoblocage ────────────────────────────────────────────────────────────
GEO_BLOCKED_COUNTRIES: set = set()

GEO_IP_RANGES = {
    "RU": ["5.8.0.0/16","5.44.0.0/22","37.9.0.0/16","46.8.0.0/16","77.37.128.0/17",
           "80.73.0.0/18","81.162.0.0/16","82.138.0.0/17","83.149.0.0/17","84.201.0.0/16",
           "85.90.0.0/15","87.226.128.0/17","89.111.0.0/18","91.108.4.0/22","92.53.0.0/18",
           "93.153.128.0/17","94.25.0.0/16","95.165.0.0/16","109.86.0.0/15","176.14.0.0/16",
           "178.140.0.0/14","185.71.76.0/22","193.232.0.0/14","194.8.0.0/15","195.2.0.0/16"],
    "CN": ["1.0.1.0/24","1.0.2.0/23","27.0.0.0/13","36.0.0.0/11","39.0.0.0/8",
           "42.0.0.0/8","49.0.0.0/8","58.0.0.0/7","60.0.0.0/8","61.0.0.0/8",
           "101.0.0.0/8","106.0.0.0/8","110.0.0.0/7","112.0.0.0/7","114.1.0.0/8",
           "115.0.0.0/8","116.0.0.0/6","120.0.0.0/6","124.1.0.0/7","163.0.0.0/8",
           "171.0.0.0/8","175.0.0.0/8","180.0.0.0/6","182.0.0.0/7","183.0.0.0/8"],
    "KP": ["175.45.176.0/22","210.52.109.0/24"],
    "IR": ["2.144.0.0/13","5.22.0.0/15","5.52.0.0/14","31.2.128.0/17","37.98.128.0/17",
           "37.156.0.0/16","46.100.0.0/14","62.60.0.0/15","78.39.192.0/18","80.71.0.0/17",
           "82.99.192.0/18","85.133.0.0/16","87.107.0.0/16","89.32.0.0/14","91.98.0.0/15",
           "94.182.0.0/15","95.38.0.0/15","109.120.128.0/17","176.65.192.0/18",
           "188.136.0.0/13","194.225.0.0/16","195.146.32.0/19"],
    "KR": ["1.16.0.0/12","1.176.0.0/12","14.1.0.0/11","27.96.0.0/14","49.142.0.0/17",
           "58.120.0.0/13","59.0.0.0/11","61.32.0.0/13","61.40.0.0/13","112.144.0.0/12",
           "119.64.0.0/11","121.128.0.0/11","122.32.0.0/11","125.128.0.0/11",
           "175.192.0.0/11","203.226.0.0/15","210.94.0.0/15","211.36.0.0/14"],
    "BR": ["177.0.0.0/8","179.0.0.0/8","186.192.0.0/11","189.0.0.0/8","200.128.0.0/9","201.0.0.0/8"],
    "NG": ["41.58.0.0/16","41.184.0.0/14","105.112.0.0/12","154.120.0.0/13","197.210.0.0/15","197.242.0.0/15"],
    "IN": ["1.6.0.0/15","14.96.0.0/11","27.4.0.0/14","43.224.0.0/11","45.112.0.0/12",
           "49.32.0.0/12","59.88.0.0/13","103.0.0.0/8","106.64.0.0/10","115.240.0.0/13",
           "117.192.0.0/11","119.224.0.0/11","122.160.0.0/11","180.64.0.0/12","182.64.0.0/10"],
    "US": ["3.0.0.0/8","4.1.0.0/8","8.0.0.0/8","12.0.0.0/8","13.0.0.0/8",
           "15.0.0.0/8","17.0.0.0/8","18.0.0.0/8","23.0.0.0/8","24.1.0.0/8",
           "34.1.0.0/8","35.0.0.0/8","44.1.0.0/8","45.0.0.0/8","52.0.0.0/8",
           "54.1.0.0/8","64.1.0.0/8","65.0.0.0/8","66.0.0.0/8","67.0.0.0/8"],
    "DE": ["5.1.0.0/17","46.4.0.0/14","78.42.0.0/15","80.154.0.0/15","81.169.0.0/16",
           "82.113.0.0/16","84.44.0.0/14","85.14.0.0/15","87.77.0.0/16","89.0.0.0/16",
           "91.65.0.0/16","94.130.0.0/15","213.160.0.0/14"],
    "FR": ["2.0.0.0/11","37.187.0.0/16","46.105.0.0/16","51.77.0.0/16","77.136.0.0/13",
           "78.192.0.0/11","82.64.0.0/11","83.200.0.0/13","86.192.0.0/11","88.120.0.0/13",
           "90.0.0.0/11","109.0.0.0/12","176.139.0.0/16","178.116.0.0/14"],
    "NL": ["2.56.0.0/14","31.3.0.0/16","37.19.0.0/16","45.14.0.0/16","77.243.0.0/16",
           "80.65.0.0/17","82.94.0.0/15","84.22.0.0/15","85.17.0.0/16","87.213.0.0/16",
           "89.188.0.0/15","94.75.0.0/16","95.211.0.0/16","185.220.0.0/16"],
}

GEO_COUNTRY_NAMES = {
    "RU":"Russie","CN":"Chine","KP":"Corée du Nord","IR":"Iran",
    "KR":"Corée du Sud","BR":"Brésil","NG":"Nigeria","IN":"Inde",
    "US":"États-Unis","DE":"Allemagne","FR":"France","NL":"Pays-Bas",
}

_geo_cache: dict = {}
_geo_city_cache: dict = {}  # ip -> {city, country, country_name}

def get_geo_info(ip: str) -> dict:
    """Retourne {country, country_name, city} pour une IP — cache local d'abord, API ensuite"""
    if ip in _geo_city_cache:
        return _geo_city_cache[ip]
    country = get_country(ip)
    result = {
        "country": country or "?",
        "country_name": GEO_COUNTRY_NAMES.get(country, country or "Inconnu"),
        "city": "",
    }
    # Essayer l'API ipapi.co en arrière-plan (non bloquant)
    _geo_city_cache[ip] = result
    return result

def _traceroute(target_ip: str, max_hops: int = 30) -> dict:
    """Trace the network path to target_ip via scapy ICMP probes. Returns ordered hops with geo data.
    Uses scapy.sr() to fan out all TTL probes in parallel — total wall time ~3-6s for 30 hops."""
    if not _validate_ip(target_ip):
        return {"ok": False, "error": "invalid_ip"}
    if is_private(target_ip):
        return {"ok": False, "error": "target_is_private"}
    if not HAS_SCAPY:
        return {"ok": False, "error": "scapy_not_installed"}
    max_hops = max(1, min(int(max_hops or 30), 64))
    try:
        from scapy.all import sr, IP as _IP, ICMP as _ICMP
        from scapy.layers.inet6 import IPv6 as _IPv6
        # IPv4 vs IPv6 probe construction
        is_v6 = ":" in target_ip
        if is_v6:
            from scapy.layers.inet6 import ICMPv6EchoRequest as _ICMPv6
            probes = [_IPv6(dst=target_ip, hlim=ttl) / _ICMPv6() for ttl in range(1, max_hops + 1)]
        else:
            probes = [_IP(dst=target_ip, ttl=ttl) / _ICMP() for ttl in range(1, max_hops + 1)]
        ans, unans = sr(probes, timeout=3, verbose=0)
        hops_dict = {}
        for snd, rcv in ans:
            ttl = int(snd.ttl if not is_v6 else snd.hlim)
            rtt = (rcv.time - snd.sent_time) * 1000 if rcv.time and snd.sent_time else None
            hops_dict[ttl] = {
                "hop":       ttl,
                "ip":        rcv.src,
                "rtt_ms":    round(rtt, 1) if rtt is not None else None,
                "is_target": rcv.src == target_ip,
            }
        for snd in unans:
            ttl = int(snd.ttl if not is_v6 else snd.hlim)
            if ttl not in hops_dict:
                hops_dict[ttl] = {"hop": ttl, "ip": None, "rtt_ms": None, "is_target": False}
        hops = sorted(hops_dict.values(), key=lambda h: h["hop"])
        # Truncate after the target hop (further TTL probes are noise)
        for i, h in enumerate(hops):
            if h.get("is_target"):
                hops = hops[:i + 1]
                break
        # Geolocate each public hop (uses provider chain we wired earlier)
        for h in hops:
            if h["ip"] and not is_private(h["ip"]):
                if h["ip"] not in _geo_city_cache:
                    try:
                        _fetch_city_async(h["ip"])  # sync call here — populates _geo_city_cache
                    except Exception as e:
                        log.debug(f"[TRACE] geo lookup failed for {h['ip']}: {e}")
                geo = _geo_city_cache.get(h["ip"], {})
                h["country"]  = geo.get("country", "")
                h["city"]     = geo.get("city", "")
                h["lat"]      = geo.get("latitude")
                h["lon"]      = geo.get("longitude")
                h["org"]      = geo.get("org", "")
        return {"ok": True, "target": target_ip, "hops": hops, "max_hops": max_hops}
    except PermissionError:
        return {"ok": False, "error": "needs_admin: scapy probes require Administrator/root"}
    except Exception as e:
        log.error(f"[TRACE] {target_ip}: {type(e).__name__}: {e}")
        return {"ok": False, "error": f"traceroute_error: {type(e).__name__}: {e}"}


# ── MaxMind GeoLite2 (local DB, no rate limit, no internet) ──────────────────
_MAXMIND_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geoip", "GeoLite2-City.mmdb")
_MAXMIND_ASN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geoip", "GeoLite2-ASN.mmdb")
_MAXMIND_READER = None
_MAXMIND_ASN_READER = None
_MAXMIND_INIT_TRIED = False


def _get_maxmind_reader():
    """Lazy-init the geoip2 City reader. Returns the reader or None if unavailable."""
    global _MAXMIND_READER, _MAXMIND_ASN_READER, _MAXMIND_INIT_TRIED
    if _MAXMIND_READER is not None:
        return _MAXMIND_READER
    if _MAXMIND_INIT_TRIED:
        return None
    _MAXMIND_INIT_TRIED = True
    try:
        import geoip2.database  # type: ignore
    except ImportError:
        log.info("[GEO] geoip2 not installed (pip install geoip2). Skipping MaxMind, using online providers.")
        return None
    if not os.path.exists(_MAXMIND_DB_PATH):
        log.info(f"[GEO] MaxMind GeoLite2-City.mmdb not found at {_MAXMIND_DB_PATH}; using online providers.")
        return None
    try:
        _MAXMIND_READER = geoip2.database.Reader(_MAXMIND_DB_PATH)
        log.info(f"[GEO] MaxMind GeoLite2 City loaded -> {_MAXMIND_DB_PATH}")
        # ASN DB is optional; if present, gives us org+asn locally too
        if os.path.exists(_MAXMIND_ASN_PATH):
            try:
                _MAXMIND_ASN_READER = geoip2.database.Reader(_MAXMIND_ASN_PATH)
                log.info(f"[GEO] MaxMind GeoLite2 ASN loaded -> {_MAXMIND_ASN_PATH}")
            except Exception as e:
                log.debug(f"[GEO] MaxMind ASN load failed: {e}")
        return _MAXMIND_READER
    except Exception as e:
        log.warning(f"[GEO] MaxMind init failed: {e}")
        return None


def _fetch_geo_maxmind(ip: str):
    """Provider 0 — MaxMind GeoLite2 local DB. <1ms, no rate limit, no internet, no key per call."""
    reader = _get_maxmind_reader()
    if not reader:
        return None
    try:
        r = reader.city(ip)
        org = ""
        asn = ""
        if _MAXMIND_ASN_READER:
            try:
                a = _MAXMIND_ASN_READER.asn(ip)
                org = a.autonomous_system_organization or ""
                asn = f"AS{a.autonomous_system_number}" if a.autonomous_system_number else ""
            except Exception:
                pass
        return {
            "country_code": (r.country.iso_code or "") if r.country else "",
            "country_name": (r.country.name or "") if r.country else "",
            "city":         (r.city.name or "") if r.city else "",
            "latitude":     r.location.latitude if r.location else None,
            "longitude":    r.location.longitude if r.location else None,
            "org":          org,
            "asn":          asn,
            "_provider":    "maxmind",
        }
    except Exception:
        # Common case: IP not in DB (private, reserved, brand-new allocation). Fall through to online.
        return None


def _fetch_geo_ipapi_co(ip: str):
    """Provider 1 — ipapi.co (HTTPS, 1000 req/day free, no key). Returns normalized dict or None."""
    import urllib.request
    url = f"https://ipapi.co/{ip}/json/"
    req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/1.9"})
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read().decode())
    if data.get("error") or not data.get("country_code"):
        return None
    return {
        "country_code": data.get("country_code") or "",
        "country_name": data.get("country_name") or "",
        "city":         data.get("city") or "",
        "latitude":     data.get("latitude"),
        "longitude":    data.get("longitude"),
        "org":          data.get("org") or "",
        "asn":          data.get("asn") or "",
        "_provider":    "ipapi.co",
    }


def _fetch_geo_ip_api_com(ip: str):
    """Provider 2 — ip-api.com (HTTP, 45 req/min free, no key). Used as fallback when ipapi.co rate-limits or fails."""
    import urllib.request
    fields = "status,country,countryCode,city,lat,lon,org,as,isp,query"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/1.9"})
    with urllib.request.urlopen(req, timeout=3) as r:
        data = json.loads(r.read().decode())
    if data.get("status") != "success" or not data.get("countryCode"):
        return None
    # ip-api 'as' field is e.g. "AS8075 Microsoft Corporation" — extract the AS number alone
    as_field = data.get("as") or ""
    asn_num = as_field.split(" ", 1)[0] if as_field.startswith("AS") else ""
    return {
        "country_code": data.get("countryCode") or "",
        "country_name": data.get("country") or "",
        "city":         data.get("city") or "",
        "latitude":     data.get("lat"),
        "longitude":    data.get("lon"),
        "org":          data.get("org") or data.get("isp") or "",
        "asn":          asn_num,
        "_provider":    "ip-api.com",
    }


_GEO_PROVIDERS = (_fetch_geo_maxmind, _fetch_geo_ip_api_com, _fetch_geo_ipapi_co)


def _fetch_city_async(ip: str):
    """Resolve geo for `ip` via provider chain (ipapi.co → ip-api.com fallback). Caches result."""
    result = None
    for provider in _GEO_PROVIDERS:
        try:
            result = provider(ip)
            if result:
                break
        except Exception as e:
            log.debug(f"[GEO] {provider.__name__} failed for {ip}: {e}")
            continue
    if not result:
        return  # All providers failed; cache untouched so a future packet retries
    _geo_city_cache[ip] = {
        "country":      result["country_code"],
        "country_name": result["country_name"],
        "city":         result["city"],
        "latitude":     result["latitude"],
        "longitude":    result["longitude"],
        "org":          result["org"],
        "asn":          result["asn"],
    }
    # _update_ip_intel expects ipapi.co-style 'country_code'/'org'/'asn' keys — bridge them
    _update_ip_intel(ip, {
        "country_code": result["country_code"],
        "city":         result["city"],
        "org":          result["org"],
        "asn":          result["asn"],
    })

# ─── Listes VPN/Tor/Proxy connues ─────────────────────────────────────────
_KNOWN_VPN_ORGS = [
    "nordvpn","expressvpn","surfshark","mullvad","protonvpn","ipvanish",
    "cyberghost","privatevpn","strongvpn","hidemyass","torguard","airvpn",
    "windscribe","tunnelbear","ivpn","ovpn","perfect privacy","hide.me",
    "tor exit","torproject","digitalocean","vultr","linode","hetzner",
    "contabo","hostinger vpn","datacenter","hosting","vps","cloud"
]
_KNOWN_TOR_EXITS: set = set()  # populated lazily
_ABUSEIPDB_CACHE: dict = {}    # ip -> {score, reports}
ABUSEIPDB_API_KEY: str = ""    # Set via config if user has key

def _update_ip_intel(ip: str, geo_data: dict):
    """Met à jour le profil intel d'une IP"""
    org = (geo_data.get("org") or "").lower()
    is_vpn = any(kw in org for kw in _KNOWN_VPN_ORGS)
    is_tor  = ip in _KNOWN_TOR_EXITS

    intel = STATE.ip_intel.get(ip, {})
    intel.update({
        "org":     geo_data.get("org", ""),
        "asn":     geo_data.get("asn", ""),
        "vpn":     is_vpn,
        "tor":     is_tor,
        "country": geo_data.get("country_code", ""),
        "city":    geo_data.get("city", ""),
    })
    STATE.ip_intel[ip] = intel
    _compute_risk_score(ip)

def _compute_risk_score(ip: str) -> int:
    """Calcule un score de risque 0-100 pour une IP"""
    score = 0
    intel = STATE.ip_intel.get(ip, {})
    hits  = STATE.ip_hit_counter.get(ip, 0)
    is_blocked = ip in BLOCKED_IPS

    # Hits répétés
    if hits >= 50:  score += 30
    elif hits >= 20: score += 20
    elif hits >= 5:  score += 10

    # VPN/Proxy
    if intel.get("vpn"): score += 20
    if intel.get("tor"): score += 35

    # Bloqué
    if is_blocked: score += 25

    # AbuseIPDB
    abuse = _ABUSEIPDB_CACHE.get(ip, {})
    if abuse.get("score", 0) > 50: score += 20
    elif abuse.get("score", 0) > 20: score += 10

    # Pays à risque élevé
    HIGH_RISK = {"KP", "IR", "RU", "NG"}
    MED_RISK  = {"CN", "BR", "IN", "UA"}
    country = intel.get("country", get_country(ip) or "")
    if country in HIGH_RISK: score += 15
    elif country in MED_RISK: score += 8

    # Menaces détectées
    threat_count = sum(1 for t in STATE.threats if t.get("src_ip") == ip)
    score += min(threat_count * 5, 25)

    score = min(score, 100)
    STATE.ip_risk_scores[ip] = score
    return score

def _fetch_abuseipdb(ip: str):
    """Vérifie l'IP sur AbuseIPDB (si clé API configurée)"""
    if not ABUSEIPDB_API_KEY or ip in _ABUSEIPDB_CACHE:
        return
    try:
        import urllib.request
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": ABUSEIPDB_API_KEY, "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
        d = data.get("data", {})
        _ABUSEIPDB_CACHE[ip] = {
            "score":   d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "domain":  d.get("domain", ""),
            "isp":     d.get("isp", ""),
        }
        _compute_risk_score(ip)
    except Exception:
        pass

# Country center coordinates for fallback when async geo fetch hasn't completed
_COUNTRY_COORDS = {
    "AF":(69.2,34.5),"AL":(19.8,41.3),"DZ":(3.0,36.8),"AR":(-64.0,-34.6),
    "AU":(133.8,-25.3),"AT":(14.6,47.5),"BD":(90.4,23.7),"BE":(4.4,50.8),
    "BR":(-51.9,-14.2),"BG":(25.5,42.7),"CA":(-106.3,56.1),"CL":(-71.5,-35.7),
    "CN":(104.2,35.9),"CO":(-74.3,4.6),"CZ":(15.5,49.8),"DK":(9.5,56.3),
    "EG":(30.8,26.8),"FI":(25.7,61.9),"FR":(2.2,46.2),"DE":(10.5,51.2),
    "GR":(21.8,39.1),"HK":(114.1,22.4),"HU":(19.5,47.2),"IN":(78.9,20.6),
    "ID":(113.9,-0.8),"IR":(53.7,32.4),"IQ":(44.0,33.2),"IE":(-8.2,53.4),
    "IL":(34.9,31.0),"IT":(12.6,41.9),"JP":(138.3,36.2),"KZ":(66.9,48.0),
    "KE":(37.9,0.0),"KR":(128.0,35.9),"MY":(101.7,4.2),"MX":(-102.6,23.6),
    "MA":(-7.1,31.8),"NL":(5.3,52.1),"NZ":(174.9,-40.9),"NG":(8.7,9.1),
    "NO":(8.5,60.5),"PK":(69.3,30.4),"PH":(122.0,12.9),"PL":(19.1,51.9),
    "PT":(-8.2,39.4),"RO":(24.7,45.9),"RU":(105.3,61.5),"SA":(45.1,23.9),
    "SG":(103.8,1.4),"ZA":(22.9,-30.6),"ES":(-3.7,40.5),"SE":(18.6,60.1),
    "CH":(8.2,46.8),"TW":(121.0,23.7),"TH":(100.5,15.9),"TR":(35.2,38.9),
    "UA":(31.2,48.4),"AE":(54.0,23.4),"GB":(-3.4,55.4),"US":(-98.0,39.5),
    "VN":(105.8,21.0),"VE":(-66.9,10.5),
}

def _get_ip_coords(ip: str, country: str = None):
    """Get lat/lon for an IP. Uses geo cache first, then country fallback with jitter."""
    geo = _geo_city_cache.get(ip, {})
    lat = geo.get("latitude")
    lon = geo.get("longitude")
    if lat is not None and lon is not None:
        return lat, lon
    # Fallback: country center + deterministic jitter
    cc = country or geo.get("country") or get_country(ip) or ""
    if cc and cc in _COUNTRY_COORDS:
        clon, clat = _COUNTRY_COORDS[cc]
        parts = ip.split(".")
        try:
            ox = ((int(parts[2])*17 + int(parts[3])*31) % 100) / 100 * 10 - 5
            oy = ((int(parts[2])*13 + int(parts[3])*7) % 100) / 100 * 6 - 3
        except (IndexError, ValueError):
            ox, oy = 0, 0
        return clat + oy, clon + ox
    return None, None

def get_country(ip: str) -> Optional[str]:
    if is_private(ip):
        return None
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        addr = ipaddress.ip_address(ip)
        for country, ranges in GEO_IP_RANGES.items():
            for net_str in ranges:
                try:
                    if addr in ipaddress.ip_network(net_str, strict=False):
                        _geo_cache[ip] = country
                        return country
                except ValueError:
                    pass
    except ValueError:
        pass
    _geo_cache[ip] = None
    return None

class NetState:
    def __init__(self):
        self.lock                  = threading.Lock()
        self.packets_total         = 0
        self.packets_blocked       = 0
        self.packets_allowed       = 0
        self.bytes_in              = 0
        self.bytes_out             = 0
        self.active_conns          = defaultdict(set)
        self.threats               = deque(maxlen=100)
        self.recent_packets        = deque(maxlen=2000)
        # Per-IP ring buffer — guarantees every IP gets airtime in state broadcasts
        # so chatty IPs (CDN, Claude API) don't starve quiet/new IPs.
        self.ip_recent_packets     = defaultdict(lambda: deque(maxlen=4))
        self.ip_first_seen_ts      = {}  # ip -> first time we ever saw it (for "new IP priority")
        self.geo_hits              = defaultdict(int)
        self.proto_stats           = defaultdict(int)
        self.traffic_history       = deque(maxlen=60)
        self._port_scan_tracker    = defaultdict(list)
        self._brute_force_tracker  = defaultdict(list)
        self._syn_flood_tracker    = defaultdict(list)
        self._dns_tracker          = defaultdict(list)
        self.ip_hit_counter        = defaultdict(int)
        self.dpi_alerts            = deque(maxlen=200)
        self.suricata_alerts       = deque(maxlen=200)
        self.record_active         = False
        self.record_file           = None
        self.record_file_path      = ""
        self.record_packets        = []
        self.record_start_time     = None
        self.record_lock           = threading.Lock()
        # v1.9.0
        self.ip_risk_scores        = {}           # ip -> score 0-100
        self.ip_intel              = {}           # ip -> {vpn, tor, abusive, org, ...}
        self.attack_by_country     = defaultdict(lambda: defaultdict(int))  # country -> type -> count
        self.timeline_events       = deque(maxlen=300)  # {ts, type, ip, country, severity}
        # v3.0
        self.anomaly_alerts     = deque(maxlen=200)
        self.correlation_alerts = deque(maxlen=100)
        self.ja3_alerts         = deque(maxlen=100)
        self.entropy_alerts     = deque(maxlen=100)
        self.threat_intel_hits  = deque(maxlen=200)
        self.forensic_reports   = deque(maxlen=50)
        self.webhook_log        = deque(maxlen=100)

STATE = NetState()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(CFG.log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("netguard")

# ═══════════════════════════════════════════════════════════════════════════
# v3.0 — ADVANCED CYBERSECURITY ENGINE
# ═══════════════════════════════════════════════════════════════════════════

# ─── Anomaly Detection ────────────────────────────────────────────────────
_anomaly_accum: dict = {}  # ip -> {pkts, bytes, ports: set, protos: defaultdict(int)}

class BaselineProfile:
    """Profil statistique par IP pour détection d'anomalies (sans numpy)"""
    def __init__(self):
        self.pkt_rates   = deque(maxlen=120)
        self.byte_vols   = deque(maxlen=120)
        self.port_counts = deque(maxlen=120)

    @staticmethod
    def _mean_std(values):
        if not values:
            return 0.0, 0.0
        n = len(values)
        mean = sum(values) / n
        if n < 2:
            return mean, 0.0
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        return mean, math.sqrt(variance)

    @staticmethod
    def _zscore(current, mean, std):
        if std < 0.001:
            return 0.0
        return (current - mean) / std

IP_BASELINES: dict = {}

# ─── Behavioral Profiling ────────────────────────────────────────────────
class BehaviorProfile:
    """Profil comportemental par IP"""
    def __init__(self):
        self.port_counter   = defaultdict(int)
        self.proto_counter  = defaultdict(int)
        self.pkt_sizes      = deque(maxlen=500)
        self.hour_counter   = defaultdict(int)
        self.total_packets  = 0
        self.first_seen     = time.time()
        self.last_seen      = time.time()
        self._recent_ports  = deque(maxlen=50)
        self._recent_protos = deque(maxlen=50)

    def update(self, dst_port, proto, pkt_size):
        self.port_counter[dst_port] += 1
        self.proto_counter[proto] += 1
        self.pkt_sizes.append(pkt_size)
        self.hour_counter[datetime.now().hour] += 1
        self.total_packets += 1
        self.last_seen = time.time()
        self._recent_ports.append(dst_port)
        self._recent_protos.append(proto)

    def deviation_score(self):
        """Compare comportement récent vs historique. Retourne 0-1 (1 = identique)"""
        if self.total_packets < 100:
            return 1.0
        # Port overlap
        hist_ports = set(list(self.port_counter.keys())[:20])
        recent_ports = set(self._recent_ports)
        if not hist_ports:
            return 1.0
        port_overlap = len(hist_ports & recent_ports) / max(len(hist_ports), 1)
        # Proto overlap
        hist_protos = set(self.proto_counter.keys())
        recent_protos = set(self._recent_protos)
        proto_overlap = len(hist_protos & recent_protos) / max(len(hist_protos), 1)
        return (port_overlap + proto_overlap) / 2.0

IP_BEHAVIOR_PROFILES: dict = {}

# ─── Attack Correlation ──────────────────────────────────────────────────
ATTACK_CHAINS: dict = {}  # ip -> [{phase, ts, type}]
PHASE_MAP = {
    "scan": ["scan", "port"],
    "brute_force": ["brute", "ssh", "rdp", "vnc", "telnet"],
    "exploit": ["sql", "xss", "injection", "rce", "log4", "shell", "spring", "eternal"],
    "c2_communication": ["dns tunnel", "c2", "beacon", "cobalt", "async", "sliver"],
    "dos": ["flood", "dos", "ddos", "syn flood"],
    "recon": ["honeypot", "scanner", "nmap", "masscan"],
    "malware": ["malware", "trojan", "rat", "miner", "crypto"],
}
CHAIN_PATTERNS = [
    {"name": "Recon → Exploit → C2",       "phases": ["recon", "exploit", "c2_communication"]},
    {"name": "Scan → Brute Force → Exploit","phases": ["scan", "brute_force", "exploit"]},
    {"name": "Scan → Exploit → Malware",    "phases": ["scan", "exploit", "malware"]},
    {"name": "Recon → DoS",                 "phases": ["recon", "dos"]},
    {"name": "Brute Force → C2",            "phases": ["brute_force", "c2_communication"]},
]

def _classify_phase(threat_type: str) -> str:
    t = threat_type.lower()
    for phase, keywords in PHASE_MAP.items():
        if any(kw in t for kw in keywords):
            return phase
    return "other"

# ─── JA3 Fingerprinting ──────────────────────────────────────────────────
KNOWN_BAD_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike Beacon",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot",
    "e7d705a3286e19ea42f587b344ee6865": "AsyncRAT",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Metasploit Meterpreter",
    "36f7277af969a6947a61ae0b815907a1": "Sliver C2",
    "1138de370e523e824bbca3fe28040e1f": "Emotet",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Dridex",
    "51c64c77e60f3980eea90869b68c58a8": "Mimikatz",
    "b386946a5a44d1ddcc843bc75336dfce": "Empire",
    "cd08e31494f9531f560d64c695473da9": "IcedID",
    "8bdb3b3a77e5640afab83c5a86d8506d": "QakBot",
}
JA3_CACHE: dict = {}

# ─── Threat Intelligence ─────────────────────────────────────────────────
VT_CACHE: dict = {}
VT_RATE = {"last_min": 0, "count": 0}
OTX_IOC_IPS:     set = set()
OTX_IOC_DOMAINS: set = set()
THREAT_FEED_IPS:    set = set()
THREAT_FEED_DOMAINS: set = set()
THREAT_FEED_LAST_UPDATE: float = 0
_CHECKED_IPS: set = set()  # IPs already submitted to VT/OTX

# ─── Active Response ─────────────────────────────────────────────────────
QUARANTINED_IPS:  set = set()
ISOLATED_DEVICES: set = set()
ALERT_COOLDOWNS:  dict = {}
WEBHOOK_COOLDOWN: int  = 60

# ─── Forensic ─────────────────────────────────────────────────────────────
FORENSIC_QUEUE: list = []

# ─── WireGuard VPN ────────────────────────────────────────────────────────
WG_SERVER_PRIVKEY: str = ""
WG_SERVER_PUBKEY:  str = ""
WG_PEERS: list = []  # [{name, pubkey, privkey, address, allowed_ips, last_handshake, transfer}]
WG_STATUS: dict = {"running": False, "interface": "", "peers_connected": 0}

_SENSITIVE_PATTERNS = [
    (re.compile(rb'password\s*[=:]\s*\S+', re.I),               "password"),
    (re.compile(rb'passwd\s*[=:]\s*\S+', re.I),                 "passwd"),
    (re.compile(rb'token\s*[=:]\s*[A-Za-z0-9+/=]{10,}', re.I), "token"),
    (re.compile(rb'Authorization:\s*\S+', re.I),                 "auth-header"),
    (re.compile(rb'Cookie:\s*\S+', re.I),                        "cookie"),
    (re.compile(rb'\b4[0-9]{12}(?:[0-9]{3})?\b'),               "card-visa"),
    (re.compile(rb'\b5[1-5][0-9]{14}\b'),                        "card-mc"),
]

_ATTACK_PATTERNS = [
    (re.compile(rb"(?:union\s+select|select\s+\*|drop\s+table|insert\s+into)", re.I), "SQL Injection"),
    (re.compile(rb"<script[\s>]", re.I),                                               "XSS"),
    (re.compile(rb"\.\./|\.\.\\"),                                                     "Path Traversal"),
    (re.compile(rb"(?:;|\|)\s*(?:ls|cat|whoami|id|pwd|wget|curl)\b", re.I),           "Command Injection"),
    (re.compile(rb"(?:169\.254\.169\.254|metadata\.google\.internal)", re.I),          "SSRF"),
    (re.compile(rb"\$\{jndi:", re.I),                                                  "Log4Shell"),
    (re.compile(rb"(?:masscan|zgrab|nmap|nikto|sqlmap|dirbuster|gobuster)", re.I),    "Scanner"),
]

# ─── Suricata IDS — règles intégrées + Emerging Threats ──────────────────
SURICATA_ENABLED: bool = True
SURICATA_RULES:   list = []   # liste de dicts {sid, msg, pattern, proto, action}
SURICATA_LOADED:  int  = 0    # nb de règles chargées
SURICATA_RULE_HITS: dict = defaultdict(int)   # compteur de hits par SID
SURICATA_DISABLED_SIDS: set = set()           # SIDs désactivés individuellement
SURICATA_CUSTOM_RULES: list = []              # règles personnalisées (persistées)

ET_RULESETS = {
    "et_scan":    "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-scan.rules",
    "et_exploit": "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-exploit.rules",
    "et_malware": "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-malware.rules",
    "et_dos":     "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-dos.rules",
}

# 27 règles intégrées — fonctionnent sans internet
BUILTIN_ET_RULES = [
    # Log4Shell
    {"sid":9000001,"msg":"ET EXPLOIT Apache Log4j RCE Attempt (jndi)","pattern":rb"\$\{jndi:","proto":"TCP","action":"alert","severity":"critical"},
    # EternalBlue
    {"sid":9000002,"msg":"ET EXPLOIT MS17-010 EternalBlue SMB","pattern":rb"\x00\x00\x00\x85\xff\x53\x4d\x42","proto":"TCP","action":"alert","severity":"critical"},
    # ShellShock
    {"sid":9000003,"msg":"ET EXPLOIT GNU Bash ShellShock Attack","pattern":rb"\(\s*\)\s*\{[^}]*\}\s*;","proto":"TCP","action":"alert","severity":"critical"},
    # Spring4Shell
    {"sid":9000004,"msg":"ET EXPLOIT Spring4Shell RCE Attempt","pattern":rb"class\.module\.classLoader","proto":"TCP","action":"alert","severity":"critical"},
    # Cobalt Strike
    {"sid":9000005,"msg":"ET MALWARE Cobalt Strike Beacon","pattern":rb"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.{16}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00","proto":"TCP","action":"alert","severity":"high"},
    # Metasploit
    {"sid":9000006,"msg":"ET EXPLOIT Metasploit Meterpreter Stage","pattern":rb"MACE\x00\x00\x00","proto":"TCP","action":"alert","severity":"critical"},
    # AsyncRAT
    {"sid":9000007,"msg":"ET MALWARE AsyncRAT C2","pattern":rb"asyncrat|AsyncRAT","proto":"TCP","action":"alert","severity":"high"},
    # Mimikatz
    {"sid":9000008,"msg":"ET MALWARE Mimikatz Credential Dumping","pattern":rb"mimikatz|sekurlsa|lsadump","proto":"TCP","action":"alert","severity":"critical"},
    # Crypto Mining Stratum
    {"sid":9000009,"msg":"ET MALWARE CryptoMiner Stratum Protocol","pattern":rb'"method"\s*:\s*"mining\.(subscribe|authorize|submit)"',"proto":"TCP","action":"alert","severity":"high"},
    # XMRig
    {"sid":9000010,"msg":"ET MALWARE XMRig CryptoMiner","pattern":rb"xmrig|XMRig","proto":"TCP","action":"alert","severity":"high"},
    # SQL Injection
    {"sid":9000011,"msg":"ET WEB_SERVER SQL Injection Attempt","pattern":rb"(?:union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into\s+)","proto":"TCP","action":"alert","severity":"high"},
    # XSS
    {"sid":9000012,"msg":"ET WEB_SERVER XSS Attempt","pattern":rb"<script[\s>].*?(?:alert|document\.cookie|window\.location)","proto":"TCP","action":"alert","severity":"med"},
    # Path Traversal
    {"sid":9000013,"msg":"ET WEB_SERVER Path Traversal Attempt","pattern":rb"(?:\.\./){3,}","proto":"TCP","action":"alert","severity":"med"},
    # Command Injection
    {"sid":9000014,"msg":"ET WEB_SERVER Command Injection Attempt","pattern":rb"(?:;|\|)\s*(?:id|whoami|uname|cat\s+/etc/passwd|wget|curl)\b","proto":"TCP","action":"alert","severity":"high"},
    # SSRF
    {"sid":9000015,"msg":"ET WEB_SERVER SSRF Attempt AWS Metadata","pattern":rb"169\.254\.169\.254","proto":"TCP","action":"alert","severity":"high"},
    # DNS Tor
    {"sid":9000016,"msg":"ET POLICY DNS Query for Tor .onion Domain","pattern":rb"\.onion\x00","proto":"UDP","action":"alert","severity":"med"},
    # Ngrok Tunnel
    {"sid":9000017,"msg":"ET POLICY Ngrok Tunnel Detected","pattern":rb"ngrok\.io|ngrok\.com","proto":"TCP","action":"alert","severity":"med"},
    # Nmap scan
    {"sid":9000018,"msg":"ET SCAN Nmap Scripting Engine","pattern":rb"Nmap Scripting Engine|nmap\.org","proto":"TCP","action":"alert","severity":"low"},
    # Nikto scan
    {"sid":9000019,"msg":"ET SCAN Nikto Web Scanner","pattern":rb"Nikto/","proto":"TCP","action":"alert","severity":"low"},
    # SQLmap
    {"sid":9000020,"msg":"ET SCAN SQLmap SQL Injection Scanner","pattern":rb"sqlmap/","proto":"TCP","action":"alert","severity":"med"},
    # WannaCry
    {"sid":9000021,"msg":"ET EXPLOIT WannaCry Ransomware SMB","pattern":rb"WANNACRY|WanaCrypt0r","proto":"TCP","action":"alert","severity":"critical"},
    # Emotet
    {"sid":9000022,"msg":"ET MALWARE Emotet C2 Checkin","pattern":rb"emotet","proto":"TCP","action":"alert","severity":"critical"},
    # Heartbleed
    {"sid":9000023,"msg":"ET EXPLOIT OpenSSL Heartbleed","pattern":rb"\x18\x03[\x00-\x03]\x00\x03\x01\x40\x00","proto":"TCP","action":"alert","severity":"critical"},
    # BlueKeep
    {"sid":9000024,"msg":"ET EXPLOIT BlueKeep RDP RCE","pattern":rb"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00","proto":"TCP","action":"alert","severity":"critical"},
    # Reverse Shell
    {"sid":9000025,"msg":"ET MALWARE Reverse Shell Attempt","pattern":rb"(?:bash -i|/bin/sh -i|nc -e|ncat -e)","proto":"TCP","action":"alert","severity":"critical"},
    # Proxy HTTP CONNECT
    {"sid":9000026,"msg":"ET POLICY HTTP CONNECT Tunnel","pattern":rb"CONNECT .+:\d+ HTTP/","proto":"TCP","action":"alert","severity":"low"},
    # Default creds
    {"sid":9000027,"msg":"ET EXPLOIT Default Credentials Attempt","pattern":rb"admin:admin|admin:password|root:root|admin:123456","proto":"TCP","action":"alert","severity":"high"},
]

def _compile_builtin_rules() -> list:
    compiled = []
    for r in BUILTIN_ET_RULES:
        try:
            compiled.append({
                "sid":      r["sid"],
                "msg":      r["msg"],
                "pattern":  re.compile(r["pattern"], re.DOTALL | re.IGNORECASE),
                "proto":    r["proto"],
                "action":   r["action"],
                "severity": r["severity"],
            })
        except Exception:
            pass
    return compiled

def _parse_rule_line(line: str) -> Optional[dict]:
    """Parse une règle Suricata/Snort format texte"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Extraire msg
    msg_m = re.search(r'msg\s*:\s*"([^"]+)"', line)
    sid_m = re.search(r'sid\s*:\s*(\d+)', line)
    cont_m = re.search(r'content\s*:\s*"([^"]+)"', line)
    pcre_m = re.search(r'pcre\s*:\s*"([^"]+)"', line)
    if not msg_m:
        return None
    msg = msg_m.group(1)
    sid = int(sid_m.group(1)) if sid_m else 0
    severity = "high" if any(x in msg.upper() for x in ["EXPLOIT","MALWARE","CRITICAL"]) else \
               "med"  if any(x in msg.upper() for x in ["WEB","POLICY","TROJAN"]) else "low"
    # Essayer PCRE d'abord, sinon content
    pattern = None
    if pcre_m:
        try:
            raw = pcre_m.group(1)
            # Retirer les flags Snort (/i, /s, etc.)
            raw = re.sub(r'[/][gimsuy]*$', '', raw).lstrip('/')
            pattern = re.compile(raw.encode(), re.DOTALL | re.IGNORECASE)
        except Exception:
            pattern = None
    if pattern is None and cont_m:
        try:
            raw = cont_m.group(1).encode()
            pattern = re.compile(re.escape(raw), re.DOTALL | re.IGNORECASE)
        except Exception:
            return None
    if pattern is None:
        return None
    return {"sid": sid, "msg": msg, "pattern": pattern, "proto": "TCP", "action": "alert", "severity": severity}

def load_et_rules_online(ruleset_key: str) -> dict:
    """Télécharge un ruleset Emerging Threats depuis internet"""
    import urllib.request
    url = ET_RULESETS.get(ruleset_key)
    if not url:
        return {"ok": False, "error": f"Ruleset inconnu: {ruleset_key}"}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/1.6"})
        with urllib.request.urlopen(req, timeout=15) as r:
            content = r.read().decode("utf-8", errors="ignore")
        rules = []
        for line in content.splitlines():
            parsed = _parse_rule_line(line)
            if parsed:
                rules.append(parsed)
        global SURICATA_RULES, SURICATA_LOADED
        # Ajouter sans doublon (par sid)
        existing_sids = {r["sid"] for r in SURICATA_RULES}
        added = 0
        for r in rules:
            if r["sid"] not in existing_sids:
                SURICATA_RULES.append(r)
                existing_sids.add(r["sid"])
                added += 1
        SURICATA_LOADED = len(SURICATA_RULES)
        log.info(f"[SURICATA] {ruleset_key}: +{added} règles chargées (total: {SURICATA_LOADED})")
        return {"ok": True, "added": added, "total": SURICATA_LOADED}
    except Exception as e:
        log.error(f"[SURICATA] Erreur chargement {ruleset_key}: {e}")
        return {"ok": False, "error": str(e)}

def suricata_match(src_ip: str, payload: bytes, proto: str) -> list:
    """Teste le payload contre toutes les règles Suricata actives"""
    if not SURICATA_ENABLED or not payload or not SURICATA_RULES:
        return []
    hits = []
    for rule in SURICATA_RULES:
        sid = rule.get("sid", 0)
        if sid in SURICATA_DISABLED_SIDS:
            continue
        if rule.get("proto", "TCP") not in (proto, "ANY"):
            continue
        try:
            if rule["pattern"].search(payload):
                SURICATA_RULE_HITS[sid] += 1
                hits.append({
                    "sid":      sid,
                    "msg":      rule["msg"],
                    "severity": rule["severity"],
                    "action":   rule["action"],
                })
        except Exception:
            pass
    return hits

def suricata_add_custom_rule(msg: str, pattern_str: str, proto: str = "TCP",
                              severity: str = "high", action: str = "alert") -> dict:
    """Ajoute une règle personnalisée"""
    global SURICATA_LOADED
    try:
        sid = 9900000 + len(SURICATA_CUSTOM_RULES) + 1
        pattern = re.compile(pattern_str.encode() if isinstance(pattern_str, str) else pattern_str,
                            re.DOTALL | re.IGNORECASE)
        rule = {
            "sid": sid, "msg": msg, "pattern": pattern,
            "proto": proto.upper(), "action": action, "severity": severity,
            "custom": True, "pattern_str": pattern_str,
        }
        SURICATA_RULES.append(rule)
        SURICATA_CUSTOM_RULES.append({
            "sid": sid, "msg": msg, "pattern_str": pattern_str,
            "proto": proto.upper(), "action": action, "severity": severity,
        })
        SURICATA_LOADED = len(SURICATA_RULES)
        log.info(f"[SURICATA] Règle custom ajoutée: SID {sid} — {msg}")
        return {"ok": True, "sid": sid}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def suricata_delete_rule(sid: int) -> dict:
    """Supprime une règle (custom uniquement)"""
    global SURICATA_LOADED
    SURICATA_RULES[:] = [r for r in SURICATA_RULES if r.get("sid") != sid]
    SURICATA_CUSTOM_RULES[:] = [r for r in SURICATA_CUSTOM_RULES if r.get("sid") != sid]
    SURICATA_LOADED = len(SURICATA_RULES)
    return {"ok": True}

def suricata_get_rules_list() -> list:
    """Retourne toutes les règles avec hits et statut"""
    rules = []
    for r in SURICATA_RULES:
        sid = r.get("sid", 0)
        rules.append({
            "sid": sid,
            "msg": r.get("msg", ""),
            "proto": r.get("proto", "TCP"),
            "severity": r.get("severity", "med"),
            "action": r.get("action", "alert"),
            "hits": SURICATA_RULE_HITS.get(sid, 0),
            "enabled": sid not in SURICATA_DISABLED_SIDS,
            "custom": r.get("custom", False),
        })
    return rules

# Charger les règles intégrées au démarrage
SURICATA_RULES = _compile_builtin_rules()
SURICATA_LOADED = len(SURICATA_RULES)
print(f"[SURICATA] {SURICATA_LOADED} règles intégrées chargées")

# ══════════════════════════════════════════════════════════════════════════════
# v4.0 — NEW MODULES: Vulnerability / Backup / Incidents / Training / NAC / IAM
# ══════════════════════════════════════════════════════════════════════════════

# ─── Vulnerability Scanner ────────────────────────────────────────────────────
VULN_SCAN_HISTORY = deque(maxlen=50)

def vuln_scan_ports(target: str, port_range: str = "1-1024") -> dict:
    """Scan TCP ports on a target"""
    import socket
    open_ports = []
    try:
        parts = port_range.split("-")
        start = int(parts[0])
        end = int(parts[1]) if len(parts) > 1 else start
        end = min(end, 65535)
        start = max(start, 1)
    except Exception:
        start, end = 1, 1024

    KNOWN_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    VULN_PORTS = {
        21: "FTP anonymous access possible",
        23: "Telnet unencrypted protocol",
        445: "SMB exposed (WannaCry, EternalBlue risk)",
        3389: "RDP exposed (BlueKeep risk)",
        5900: "VNC exposed (often unencrypted)",
        6379: "Redis exposed (usually no auth)",
        27017: "MongoDB exposed (usually no auth)",
    }

    scanned = 0
    for port in range(start, end + 1):
        scanned += 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = KNOWN_SERVICES.get(port, "unknown")
                vuln = VULN_PORTS.get(port, "")
                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open",
                    "vulnerability": vuln,
                    "risk": "high" if vuln else "info",
                })
            sock.close()
        except Exception:
            pass

    scan_result = {
        "ok": True,
        "target": target,
        "open_ports": open_ports,
        "scanned": scanned,
        "timestamp": datetime.now().isoformat(),
    }
    VULN_SCAN_HISTORY.appendleft(scan_result)
    log.info(f"[VULN] Port scan {target}: {len(open_ports)} open ports / {scanned} scanned")
    return scan_result

def vuln_cve_lookup(cve_id: str) -> dict:
    """Lookup CVE from NIST NVD API"""
    import urllib.request
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/4.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        if data.get("vulnerabilities"):
            vuln = data["vulnerabilities"][0]["cve"]
            desc = ""
            for d in vuln.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = vuln.get("metrics", {})
            score = ""
            severity = ""
            for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if k in metrics and metrics[k]:
                    score = metrics[k][0].get("cvssData", {}).get("baseScore", "")
                    severity = metrics[k][0].get("cvssData", {}).get("baseSeverity", "")
                    break
            return {
                "ok": True,
                "id": vuln.get("id", cve_id),
                "description": desc,
                "score": score,
                "severity": severity,
                "published": vuln.get("published", ""),
                "modified": vuln.get("lastModified", ""),
                "references": [ref.get("url", "") for ref in vuln.get("references", [])[:5]],
            }
        return {"ok": False, "error": "CVE not found"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def vuln_system_check() -> dict:
    """Basic system security check"""
    checks = []
    import subprocess
    _si = None
    _cf = 0
    if os.name == 'nt':
        _si = subprocess.STARTUPINFO()
        _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        _si.wShowWindow = 0
        _cf = subprocess.CREATE_NO_WINDOW

    # Check firewall
    try:
        r = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=5, startupinfo=_si, creationflags=_cf)
        fw_on = "ON" in r.stdout.upper()
        checks.append({"check": "Windows Firewall", "status": "pass" if fw_on else "fail",
                       "detail": "Enabled" if fw_on else "DISABLED - Enable immediately!"})
    except Exception:
        checks.append({"check": "Windows Firewall", "status": "unknown", "detail": "Could not check"})

    # Check Windows Update
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"], capture_output=True, text=True, timeout=10, startupinfo=_si, creationflags=_cf)
        last_update = r.stdout.strip()
        checks.append({"check": "Last Windows Update", "status": "info", "detail": last_update or "Unknown"})
    except Exception:
        checks.append({"check": "Last Windows Update", "status": "unknown", "detail": "Could not check"})

    # Check antivirus
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled"], capture_output=True, text=True, timeout=10, startupinfo=_si, creationflags=_cf)
        av_on = "True" in r.stdout
        checks.append({"check": "Windows Defender", "status": "pass" if av_on else "warn",
                       "detail": "Active" if av_on else "Real-time protection may be disabled"})
    except Exception:
        checks.append({"check": "Windows Defender", "status": "unknown", "detail": "Could not check"})

    # Check open ports
    try:
        r = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=5, startupinfo=_si, creationflags=_cf)
        listening = [l for l in r.stdout.splitlines() if "LISTENING" in l]
        checks.append({"check": "Listening Ports", "status": "info", "detail": f"{len(listening)} ports listening"})
    except Exception:
        checks.append({"check": "Listening Ports", "status": "unknown", "detail": "Could not check"})

    # Check RDP
    try:
        r = subprocess.run(["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "/v", "fDenyTSConnections"], capture_output=True, text=True, timeout=5, startupinfo=_si, creationflags=_cf)
        rdp_disabled = "0x1" in r.stdout
        checks.append({"check": "Remote Desktop (RDP)", "status": "pass" if rdp_disabled else "warn",
                       "detail": "Disabled" if rdp_disabled else "ENABLED - Consider disabling if not needed"})
    except Exception:
        checks.append({"check": "Remote Desktop (RDP)", "status": "unknown", "detail": "Could not check"})

    # Check password policy
    try:
        r = subprocess.run(["net", "accounts"], capture_output=True, text=True, timeout=5, startupinfo=_si, creationflags=_cf)
        checks.append({"check": "Password Policy", "status": "info", "detail": "Checked"})
    except Exception:
        pass

    return {"ok": True, "checks": checks, "timestamp": datetime.now().isoformat()}


# ─── Backup & Recovery ────────────────────────────────────────────────────────
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")
BACKUP_SCHEDULE = {"enabled": False, "interval_hours": 24, "last_backup": ""}


def _secure_json_write(path: str, data, mode: int = 0o600, indent: int = 2):
    """Atomic JSON write + chmod (default 0600). Writes to temp file in same dir then os.replace().
    Hardening: combines Phase 2.2 (perms) and Phase 5.1 (atomicity) from the security audit."""
    parent = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, default=str)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── Backup encryption (Phase 5.2) ───────────────────────────────────────────
_BACKUP_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".netguard_backup_key")
_BACKUP_FERNET = None  # lazy cache


def _get_backup_fernet():
    """Return a Fernet instance using a key persisted at .netguard_backup_key (0600).
    Generate the key on first call if missing. Returns None if cryptography lib is not available."""
    global _BACKUP_FERNET
    if _BACKUP_FERNET is not None:
        return _BACKUP_FERNET
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        log.warning("[BACKUP] cryptography not installed; backups will be plaintext (pip install cryptography)")
        return None
    try:
        if os.path.exists(_BACKUP_KEY_FILE):
            with open(_BACKUP_KEY_FILE, "rb") as f:
                key = f.read().strip()
        else:
            key = Fernet.generate_key()
            with open(_BACKUP_KEY_FILE, "wb") as f:
                f.write(key)
            try:
                os.chmod(_BACKUP_KEY_FILE, 0o600)
            except OSError:
                pass
            log.info(f"[BACKUP] Encryption key generated -> {_BACKUP_KEY_FILE}")
        _BACKUP_FERNET = Fernet(key)
        return _BACKUP_FERNET
    except Exception as e:
        log.error(f"[BACKUP] Cannot init backup encryption: {e}")
        return None

def backup_create(name: str = "", include: list = None) -> dict:
    """Create a backup of NetGuard Pro configuration"""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = name or f"netguard_backup_{ts}"
    backup_path = os.path.join(BACKUP_DIR, f"{backup_name}.json")

    backup_data = {
        "version": "4.1.0",
        "timestamp": datetime.now().isoformat(),
        "name": backup_name,
    }

    if include is None:
        include = ["settings", "rules", "blocked", "geo", "suricata"]

    if "settings" in include:
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                backup_data["settings"] = json.load(f)
        except Exception:
            backup_data["settings"] = {}

    if "rules" in include:
        backup_data["rules"] = {k: {"enabled": v["enabled"], "hits": v["hits"]} for k, v in RULES.items()}

    if "blocked" in include:
        backup_data["blocked_ips"] = list(BLOCKED_IPS)

    if "geo" in include:
        backup_data["geo_countries"] = list(GEO_BLOCKED_COUNTRIES)

    if "suricata" in include:
        backup_data["suricata_custom_rules"] = SURICATA_CUSTOM_RULES
        backup_data["suricata_disabled_sids"] = list(SURICATA_DISABLED_SIDS)

    try:
        fer = _get_backup_fernet()
        if fer:
            plaintext = json.dumps(backup_data, ensure_ascii=False, default=str).encode("utf-8")
            ciphertext = fer.encrypt(plaintext)
            envelope = {"_format": "fernet-v1", "ciphertext": ciphertext.decode("ascii")}
            _secure_json_write(backup_path, envelope)
            encrypted = True
        else:
            _secure_json_write(backup_path, backup_data)
            encrypted = False
        size = os.path.getsize(backup_path)
        BACKUP_SCHEDULE["last_backup"] = datetime.now().isoformat()
        log.info(f"[BACKUP] Created: {backup_path} ({size} bytes, encrypted={encrypted})")
        return {"ok": True, "path": backup_path, "size": size, "name": backup_name, "encrypted": encrypted}
    except Exception as e:
        return {"ok": False, "error": str(e)}

_BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}\.json$")


def backup_restore(filename: str) -> dict:
    """Restore from a backup file (path-traversal hardened)"""
    if not isinstance(filename, str) or not _BACKUP_NAME_RE.match(filename):
        return {"ok": False, "error": "Nom de backup invalide (lettres/chiffres/_/.- only, .json)"}
    base_real = os.path.realpath(BACKUP_DIR)
    path = os.path.realpath(os.path.join(BACKUP_DIR, filename))
    if not (path == base_real or path.startswith(base_real + os.sep)):
        return {"ok": False, "error": "Chemin hors du dossier de backups"}
    if not os.path.exists(path):
        return {"ok": False, "error": "Backup file not found"}
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        if isinstance(raw, dict) and raw.get("_format") == "fernet-v1":
            fer = _get_backup_fernet()
            if not fer:
                return {"ok": False, "error": "Backup chiffre mais cle absente. Restaure .netguard_backup_key d'abord"}
            try:
                plaintext = fer.decrypt(raw["ciphertext"].encode("ascii"))
                data = json.loads(plaintext.decode("utf-8"))
            except Exception as e:
                return {"ok": False, "error": f"Dechiffrement echoue: {e}"}
        else:
            data = raw  # legacy plaintext backup

        if "settings" in data:
            _secure_json_write(SETTINGS_FILE, data["settings"])

        if "blocked_ips" in data:
            BLOCKED_IPS.clear()
            BLOCKED_IPS.update(data["blocked_ips"])

        if "geo_countries" in data:
            global GEO_BLOCKED_COUNTRIES
            GEO_BLOCKED_COUNTRIES = set(data["geo_countries"])

        load_settings()
        log.info(f"[BACKUP] Restored: {filename}")
        return {"ok": True, "restored": filename}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def backup_list() -> list:
    """List available backups"""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backups = []
    for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if f.endswith(".json"):
            path = os.path.join(BACKUP_DIR, f)
            try:
                size = os.path.getsize(path)
                mtime = datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                backups.append({"filename": f, "size": size, "date": mtime})
            except Exception:
                pass
    return backups

def backup_delete(filename: str) -> dict:
    """Delete a backup file"""
    path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(path):
        os.remove(path)
        return {"ok": True}
    return {"ok": False, "error": "File not found"}


# ─── Incident Response / Ticketing ────────────────────────────────────────────
INCIDENTS = []  # list of ticket dicts
INCIDENT_COUNTER = 0

def incident_create(title: str, description: str, severity: str = "medium",
                    assigned_to: str = "", related_ip: str = "") -> dict:
    global INCIDENT_COUNTER
    INCIDENT_COUNTER += 1
    ticket = {
        "id": f"INC-{INCIDENT_COUNTER:04d}",
        "title": title,
        "description": description,
        "severity": severity,
        "status": "open",
        "assigned_to": assigned_to,
        "related_ip": related_ip,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "notes": [],
    }
    INCIDENTS.insert(0, ticket)
    log.info(f"[INCIDENT] Created: {ticket['id']} — {title}")
    return ticket

def incident_update(ticket_id: str, updates: dict) -> dict:
    for t in INCIDENTS:
        if t["id"] == ticket_id:
            if "notes" in updates:
                t["notes"].append({
                    "text": updates["notes"],
                    "timestamp": datetime.now().isoformat(),
                })
                del updates["notes"]
            t.update(updates)
            t["updated_at"] = datetime.now().isoformat()
            return {"ok": True, "ticket": t}
    return {"ok": False, "error": "Ticket not found"}

def incident_list(status_filter: str = "") -> list:
    if status_filter:
        return [t for t in INCIDENTS if t["status"] == status_filter]
    return INCIDENTS

def incident_get(ticket_id: str) -> dict:
    for t in INCIDENTS:
        if t["id"] == ticket_id:
            return t
    return {}

def incident_delete(ticket_id: str) -> dict:
    global INCIDENTS
    INCIDENTS = [t for t in INCIDENTS if t["id"] != ticket_id]
    return {"ok": True}


# ─── Training & Awareness ────────────────────────────────────────────────────
TRAINING_MODULES = [
    {
        "id": "phishing_101",
        "title": "Phishing Detection 101",
        "description": "Learn to identify phishing emails, suspicious links, and social engineering attacks.",
        "category": "email",
        "difficulty": "beginner",
        "duration_min": 15,
        "questions": [
            {"q": "What is the most common sign of a phishing email?", "options": ["Misspelled sender domain", "Blue text", "Long email", "Has images"], "correct": 0},
            {"q": "A colleague sends you an urgent link to 'verify your password'. What should you do?", "options": ["Click immediately", "Forward to IT security", "Verify via another channel", "Delete and ignore"], "correct": 2},
            {"q": "Which URL is likely a phishing attempt?", "options": ["https://google.com", "https://g00gle-security.com/verify", "https://mail.google.com", "https://accounts.google.com"], "correct": 1},
            {"q": "What is 'spear phishing'?", "options": ["Mass email spam", "Targeted attack on specific person", "Fishing website", "Email with attachments"], "correct": 1},
            {"q": "What should you check before clicking a link in an email?", "options": ["The font size", "Hover over to see actual URL", "The email length", "The sender's profile picture"], "correct": 1},
        ],
    },
    {
        "id": "password_security",
        "title": "Password Security & MFA",
        "description": "Best practices for creating strong passwords and using multi-factor authentication.",
        "category": "access",
        "difficulty": "beginner",
        "duration_min": 10,
        "questions": [
            {"q": "Which is the strongest password?", "options": ["password123", "P@ssw0rd!", "correct-horse-battery-staple", "admin"], "correct": 2},
            {"q": "How often should you change your password?", "options": ["Every day", "When there's a breach", "Never", "Every hour"], "correct": 1},
            {"q": "What is MFA?", "options": ["Multiple File Access", "Multi-Factor Authentication", "Main Firewall Admin", "Managed File Archive"], "correct": 1},
            {"q": "Which MFA method is most secure?", "options": ["SMS code", "Hardware security key", "Email code", "Security questions"], "correct": 1},
            {"q": "Should you use the same password for multiple accounts?", "options": ["Yes, easier to remember", "Only for unimportant sites", "Never", "Only with MFA"], "correct": 2},
        ],
    },
    {
        "id": "social_engineering",
        "title": "Social Engineering Defense",
        "description": "Recognize and defend against social engineering tactics used by attackers.",
        "category": "awareness",
        "difficulty": "intermediate",
        "duration_min": 20,
        "questions": [
            {"q": "What is pretexting?", "options": ["Writing code", "Creating false scenario to gain trust", "Sending spam", "Hacking passwords"], "correct": 1},
            {"q": "A caller claims to be from IT and asks for your password. What do you do?", "options": ["Give it immediately", "Hang up and call IT directly", "Email your password instead", "Give a fake password"], "correct": 1},
            {"q": "What is tailgating in security?", "options": ["Following someone through a secure door", "Sending follow-up emails", "Tracking someone online", "Using VPN"], "correct": 0},
            {"q": "Which is a sign of a social engineering attack?", "options": ["Unusual urgency", "Proper grammar", "Known sender", "Normal request"], "correct": 0},
            {"q": "What is baiting?", "options": ["Using malicious USB drives", "Email fishing", "Phone calls", "Web browsing"], "correct": 0},
        ],
    },
    {
        "id": "ransomware_defense",
        "title": "Ransomware Prevention",
        "description": "Learn to prevent, detect, and respond to ransomware attacks.",
        "category": "malware",
        "difficulty": "intermediate",
        "duration_min": 15,
        "questions": [
            {"q": "What is the best defense against ransomware?", "options": ["Paying the ransom", "Regular backups", "Stronger passwords", "Faster internet"], "correct": 1},
            {"q": "How does ransomware typically spread?", "options": ["Through Bluetooth", "Phishing emails with malicious attachments", "Through Wi-Fi signals", "Via printer"], "correct": 1},
            {"q": "Should you pay the ransom if hit?", "options": ["Always", "Never recommended", "Only if cheap", "Wait a week"], "correct": 1},
            {"q": "What file extension indicates a potentially dangerous attachment?", "options": [".pdf", ".exe", ".jpg", ".txt"], "correct": 1},
            {"q": "What is the 3-2-1 backup rule?", "options": ["3 passwords, 2 emails, 1 phone", "3 copies, 2 media types, 1 offsite", "3 users, 2 admins, 1 root", "3 networks, 2 firewalls, 1 VPN"], "correct": 1},
        ],
    },
    {
        "id": "network_security",
        "title": "Network Security Basics",
        "description": "Understanding network threats, firewalls, VPNs, and secure configurations.",
        "category": "network",
        "difficulty": "advanced",
        "duration_min": 20,
        "questions": [
            {"q": "What does a firewall do?", "options": ["Speeds up internet", "Filters network traffic", "Stores passwords", "Creates backups"], "correct": 1},
            {"q": "What is a VPN used for?", "options": ["Blocking ads", "Encrypting network traffic", "Speeding up downloads", "Creating websites"], "correct": 1},
            {"q": "What is a Man-in-the-Middle attack?", "options": ["Physical break-in", "Intercepting communications", "DDoS attack", "Brute force"], "correct": 1},
            {"q": "Which port is commonly used for HTTPS?", "options": ["80", "443", "22", "3389"], "correct": 1},
            {"q": "What does DNS stand for?", "options": ["Digital Network System", "Domain Name System", "Data Network Security", "Dynamic Node Service"], "correct": 1},
        ],
    },
]

TRAINING_SCORES = {}

def training_submit_quiz(module_id: str, answers: dict) -> dict:
    module = next((m for m in TRAINING_MODULES if m["id"] == module_id), None)
    if not module:
        return {"ok": False, "error": "Module not found"}

    correct = 0
    total = len(module["questions"])
    details = []
    for i, q in enumerate(module["questions"]):
        user_answer = answers.get(str(i), -1)
        is_correct = int(user_answer) == q["correct"]
        if is_correct:
            correct += 1
        details.append({
            "question": q["q"],
            "correct": is_correct,
            "user_answer": int(user_answer),
            "correct_answer": q["correct"],
        })

    score = round((correct / total) * 100)
    TRAINING_SCORES[module_id] = {
        "score": score,
        "correct": correct,
        "total": total,
        "passed": score >= 70,
        "timestamp": datetime.now().isoformat(),
    }

    return {"ok": True, "score": score, "correct": correct, "total": total,
            "passed": score >= 70, "details": details, "module_id": module_id}

def training_phishing_sim(target_email: str) -> dict:
    """Simulate a phishing test (local only, no actual email sent)"""
    sim_id = f"SIM-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    return {
        "ok": True,
        "sim_id": sim_id,
        "message": "Phishing simulation created (local mode — no actual email sent)",
        "target": target_email,
        "template": "Password Reset Notification",
    }


# ─── NAC Enhanced ─────────────────────────────────────────────────────────────
NAC_APPROVED = []   # [{"ip": ..., "mac": ..., "name": ..., "approved_at": ...}]
NAC_DENIED = []     # [{"ip": ..., "mac": ..., "denied_at": ...}]
NAC_PENDING = []    # [{"ip": ..., "mac": ..., "first_seen": ...}]
NAC_POLICY = {"default_action": "allow", "require_approval": False, "mac_filter": False}

def nac_approve_device(ip: str, mac: str, name: str = ""):
    NAC_APPROVED.append({"ip": ip, "mac": mac, "name": name or ip, "approved_at": datetime.now().isoformat()})
    NAC_PENDING[:] = [d for d in NAC_PENDING if d.get("ip") != ip]
    NAC_DENIED[:] = [d for d in NAC_DENIED if d.get("ip") != ip]
    log.info(f"[NAC] Device approved: {ip} ({mac})")

def nac_deny_device(ip: str, mac: str):
    NAC_DENIED.append({"ip": ip, "mac": mac, "denied_at": datetime.now().isoformat()})
    NAC_PENDING[:] = [d for d in NAC_PENDING if d.get("ip") != ip]
    NAC_APPROVED[:] = [d for d in NAC_APPROVED if d.get("ip") != ip]
    log.info(f"[NAC] Device denied: {ip} ({mac})")


# ─── IAM Enhanced ─────────────────────────────────────────────────────────────
IAM_USERS = {}      # {username: {password_hash, role, email, mfa_enabled, created_at}}
IAM_SESSIONS = {}   # {session_id: {username, ip, created_at}}
IAM_ROLES = {
    "admin":   {"permissions": ["all"]},
    "analyst": {"permissions": ["read", "alerts", "reports", "threats"]},
    "viewer":  {"permissions": ["read"]},
}

def _hash_password(password: str) -> str:
    """Hash password with scrypt (OWASP n=16384, r=8, p=1). Format: 'scrypt$<salt-hex>$<hash-hex>'."""
    salt = _ng_secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def iam_verify_password(password: str, stored: str) -> bool:
    """Verify password against stored hash. Supports scrypt (new) + sha256 + salt:hash legacy formats."""
    if not stored or not password:
        return False
    try:
        if stored.startswith("scrypt$"):
            _, salt_hex, hash_hex = stored.split("$", 2)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
            return _ng_secrets.compare_digest(actual, expected)
        # Legacy bare SHA256 hex (64 chars)
        if len(stored) == 64 and all(c in "0123456789abcdef" for c in stored.lower()):
            return _ng_secrets.compare_digest(
                hashlib.sha256(password.encode()).hexdigest(),
                stored.lower(),
            )
        # Legacy salt:hash format from netguard_users.json (salt-hex : base64-of-sha256(salt+password))
        if ":" in stored:
            import base64 as _b64
            salt_part, hash_part = stored.split(":", 1)
            try:
                expected = _b64.b64decode(hash_part)
            except Exception:
                return False
            # Try sha256(salt+password)
            try:
                actual = hashlib.sha256((salt_part + password).encode()).digest()
                if _ng_secrets.compare_digest(actual, expected):
                    return True
            except Exception:
                pass
            # Try PBKDF2-HMAC-SHA256 with hex salt
            try:
                actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_part), 100000)
                if _ng_secrets.compare_digest(actual, expected):
                    return True
            except (ValueError, TypeError):
                pass
    except Exception:
        return False
    return False


def iam_create_user(username: str, password: str, role: str = "viewer", email: str = "") -> dict:
    if not username or not password:
        return {"ok": False, "error": "Username and password required"}
    if username in IAM_USERS:
        return {"ok": False, "error": "User already exists"}
    if role not in IAM_ROLES:
        return {"ok": False, "error": f"Invalid role. Valid: {list(IAM_ROLES.keys())}"}
    pw_hash = _hash_password(password)
    IAM_USERS[username] = {
        "password_hash": pw_hash,
        "role": role,
        "email": email,
        "mfa_enabled": False,
        "mfa_secret": "",
        "created_at": datetime.now().isoformat(),
        "last_login": "",
    }
    log.info(f"[IAM] User created: {username} (role: {role})")
    try:
        save_settings()
    except Exception:
        pass
    return {"ok": True, "username": username, "role": role}

def iam_delete_user(username: str) -> dict:
    if username in IAM_USERS:
        del IAM_USERS[username]
        try:
            save_settings()
        except Exception:
            pass
        return {"ok": True}
    return {"ok": False, "error": "User not found"}

def iam_list_users() -> list:
    return [
        {"username": u, "role": d["role"], "email": d.get("email", ""),
         "mfa_enabled": d.get("mfa_enabled", False),
         "created_at": d["created_at"], "last_login": d.get("last_login", "")}
        for u, d in IAM_USERS.items()
    ]

def iam_update_role(username: str, role: str) -> dict:
    if username not in IAM_USERS:
        return {"ok": False, "error": "User not found"}
    if role not in IAM_ROLES:
        return {"ok": False, "error": "Invalid role"}
    IAM_USERS[username]["role"] = role
    try:
        save_settings()
    except Exception:
        pass
    return {"ok": True, "username": username, "role": role}

def iam_toggle_mfa(username: str) -> dict:
    if username not in IAM_USERS:
        return {"ok": False, "error": "User not found"}
    IAM_USERS[username]["mfa_enabled"] = not IAM_USERS[username]["mfa_enabled"]
    if IAM_USERS[username]["mfa_enabled"]:
        IAM_USERS[username]["mfa_secret"] = _ng_secrets.token_hex(16)
    try:
        save_settings()
    except Exception:
        pass
    return {"ok": True, "mfa_enabled": IAM_USERS[username]["mfa_enabled"]}


def dpi_inspect(src_ip: str, payload: bytes) -> list:
    if not payload:
        return []
    alerts = []
    if CFG.dpi_mask_sensitive:
        for pattern, label in _SENSITIVE_PATTERNS:
            if pattern.search(payload):
                alerts.append({"type": "sensitive", "detail": label, "masked": True})
    for pattern, label in _ATTACK_PATTERNS:
        if pattern.search(payload):
            alerts.append({"type": "attack", "detail": label, "masked": False})
    return alerts

def _record_filename() -> str:
    os.makedirs(CFG.record_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return os.path.join(CFG.record_dir, f"capture_{ts}.pcap")

def _write_pcap_global_header(f):
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

def _write_pcap_record(f, raw_bytes: bytes):
    ts = time.time()
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    length  = len(raw_bytes)
    f.write(struct.pack("<IIII", ts_sec, ts_usec, length, length))
    f.write(raw_bytes)

def record_start():
    with STATE.record_lock:
        if STATE.record_active:
            return False
        path = _record_filename()
        STATE.record_file_path = path
        STATE.record_file = open(path, "wb")
        _write_pcap_global_header(STATE.record_file)
        STATE.record_active = True
        STATE.record_start_time = datetime.now()
        STATE.record_packets = []
    log.info(f"[RECORD] Démarré → {path}")
    return True

def record_stop() -> str:
    with STATE.record_lock:
        if not STATE.record_active:
            return ""
        STATE.record_active = False
        if STATE.record_file:
            STATE.record_file.flush()
            STATE.record_file.close()
            STATE.record_file = None
        path = STATE.record_file_path
    log.info(f"[RECORD] Arrêté → {path}")
    return path

def record_write_packet(raw_bytes: bytes):
    with STATE.record_lock:
        if not STATE.record_active or not STATE.record_file:
            return
        _write_pcap_record(STATE.record_file, raw_bytes)
        STATE.record_packets.append(len(raw_bytes))
        if STATE.record_start_time:
            elapsed = (datetime.now() - STATE.record_start_time).total_seconds()
            if elapsed >= CFG.record_rotate_min * 60:
                STATE.record_file.flush()
                STATE.record_file.close()
                STATE.record_file = None
                STATE.record_active = False
                log.info("[RECORD] Rotation automatique")
                _cleanup_old_captures()

def _cleanup_old_captures():
    try:
        files = sorted(
            [f for f in os.listdir(CFG.record_dir) if f.endswith(".pcap")],
            key=lambda f: os.path.getmtime(os.path.join(CFG.record_dir, f))
        )
        while len(files) > CFG.record_max_files:
            oldest = os.path.join(CFG.record_dir, files.pop(0))
            os.remove(oldest)
            log.info(f"[RECORD] Supprimé: {oldest}")
    except Exception as e:
        log.error(f"[RECORD] Erreur nettoyage: {e}")

def record_list() -> list:
    try:
        os.makedirs(CFG.record_dir, exist_ok=True)
        files = []
        for f in sorted(os.listdir(CFG.record_dir)):
            if not f.endswith(".pcap"):
                continue
            path = os.path.join(CFG.record_dir, f)
            size  = os.path.getsize(path)
            mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
            files.append({"name": f, "path": path, "size": size, "date": mtime})
        return files
    except Exception:
        return []

def auto_block_check(src_ip: str):
    if not CFG.auto_block_enabled:
        return
    if is_whitelisted(src_ip) or is_private(src_ip):
        return
    STATE.ip_hit_counter[src_ip] += 1
    if STATE.ip_hit_counter[src_ip] >= CFG.auto_block_hits:
        if src_ip not in BLOCKED_IPS:
            block_ip_os(src_ip, f"Auto-block: {STATE.ip_hit_counter[src_ip]} hits")
            add_threat(src_ip, "Auto-block", f"Seuil de {CFG.auto_block_hits} hits atteint", "high")

def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False

def is_whitelisted(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        for entry in CFG.whitelist:
            try:
                if "/" in entry:
                    if a in ipaddress.ip_network(entry, strict=False):
                        return True
                elif str(a) == entry:
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False

def is_in_bad_range(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        for net_str in KNOWN_BAD_RANGES:
            if a in ipaddress.ip_network(net_str, strict=False):
                return True
    except ValueError:
        pass
    return False

def get_protocol_name(pkt) -> str:
    if HAS_SCAPY:
        if pkt.haslayer(DNS):  return "DNS"
        if pkt.haslayer(TCP):
            dp = pkt[TCP].dport
            if dp == 443:  return "HTTPS"
            if dp == 80:   return "HTTP"
            if dp == 22:   return "SSH"
            if dp == 21:   return "FTP"
            if dp == 25:   return "SMTP"
            if dp == 3389: return "RDP"
            return "TCP"
        if pkt.haslayer(UDP):  return "UDP"
        if pkt.haslayer(ICMP): return "ICMP"
        if pkt.haslayer(ARP):  return "ARP"
    return "OTHER"

import subprocess as _subprocess

def _validate_ip(ip: str) -> bool:
    """Valide qu'une chaîne est une adresse IP légitime (anti-injection)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        log.error(f"[SECURITY] IP invalide rejetée: {ip!r}")
        return False

def block_ip_os(ip: str, reason: str):
    if ip in BLOCKED_IPS:
        return
    if not _validate_ip(ip):
        return
    BLOCKED_IPS.add(ip)
    log.warning(f"[BLOCK] {ip} — {reason}")
    if not CFG.can_block:
        return
    try:
        if IS_LINUX:
            _subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                            capture_output=True, timeout=10)
        elif IS_WINDOWS:
            rule_name = f"NetGuard_Block_{ip.replace('.','_')}"
            _subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                             f"name={rule_name}", "dir=in", "action=block",
                             f"remoteip={ip}", "enable=yes"],
                            capture_output=True, timeout=10)
    except Exception as e:
        log.error(f"Erreur blocage OS pour {ip}: {e}")

def unblock_ip_os(ip: str):
    if not _validate_ip(ip):
        return
    BLOCKED_IPS.discard(ip)
    try:
        if IS_LINUX:
            _subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                            capture_output=True, timeout=10)
        elif IS_WINDOWS:
            rule_name = f"NetGuard_Block_{ip.replace('.','_')}"
            _subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                             f"name={rule_name}"],
                            capture_output=True, timeout=10)
    except Exception as e:
        log.error(f"Erreur déblocage OS pour {ip}: {e}")

def add_threat(src_ip: str, threat_type: str, description: str, severity: str, rule_key: str = None):
    country = get_country(src_ip) or ""
    now = datetime.now()
    threat = {
        "id":          int(time.time() * 1000),
        "timestamp":   now.isoformat(),
        "src_ip":      src_ip,
        "type":        threat_type,
        "description": description,
        "severity":    severity,
        "blocked":     src_ip in BLOCKED_IPS,
        "country":     country,
    }
    STATE.threats.appendleft(threat)
    if rule_key and rule_key in RULES:
        RULES[rule_key]["hits"] += 1

    # Track attack type by country
    if country:
        t = threat_type.lower()
        if "scan" in t or "port" in t:               cat = "Scan"
        elif "brute" in t or "ssh" in t:             cat = "Brute Force"
        elif "flood" in t or "dos" in t:             cat = "DDoS"
        elif "dns" in t:                             cat = "DNS"
        elif "dpi" in t or "sql" in t or "xss" in t: cat = "Web"
        elif "ids" in t or "suricata" in t:          cat = "IDS"
        elif "malware" in t or "c2" in t:            cat = "Malware"
        else:                                        cat = "Autre"
        STATE.attack_by_country[country][cat] += 1

    # Timeline
    STATE.timeline_events.appendleft({
        "ts":       now.strftime("%H:%M:%S"),
        "date":     now.strftime("%Y-%m-%d"),
        "type":     threat_type,
        "ip":       src_ip,
        "country":  country,
        "severity": severity,
    })

    # Update risk score
    _compute_risk_score(src_ip)

    # v3.0 — Correlation & Alerts
    correlate_attack_phase(src_ip, threat_type)
    dispatch_alert(threat)
    # Auto-forensic on critical
    if severity == "critical" and CFG.auto_forensic_enabled:
        threading.Thread(target=generate_forensic_report, args=(src_ip, threat_type), daemon=True).start()

    log.warning(f"[THREAT/{severity.upper()}] {threat_type} — {src_ip} — {description}")
    return threat

def _clean_window(lst: list, window: int) -> list:
    cutoff = time.time() - window
    return [t for t in lst if t > cutoff]

def detect_port_scan(src_ip: str, dst_port: int) -> Optional[str]:
    if not RULES["block_port_scan"]["enabled"]:
        return None
    tracker = STATE._port_scan_tracker[src_ip]
    now = time.time()
    tracker.append((now, dst_port))
    STATE._port_scan_tracker[src_ip] = [(t, p) for t, p in tracker if t > now - CFG.port_scan_window]
    unique_ports = len({p for _, p in STATE._port_scan_tracker[src_ip]})
    if unique_ports >= CFG.port_scan_threshold:
        return f"Scan de {unique_ports} ports en {CFG.port_scan_window}s"
    return None

def detect_brute_force(src_ip: str, dst_port: int, is_syn: bool) -> Optional[str]:
    if not RULES["block_brute_force"]["enabled"] or dst_port not in CFG.sensitive_ports or not is_syn:
        return None
    tracker = STATE._brute_force_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    STATE._brute_force_tracker[src_ip] = _clean_window(tracker, CFG.brute_force_window)
    count = len(STATE._brute_force_tracker[src_ip])
    if count >= CFG.brute_force_threshold:
        port_name = {22: "SSH", 3389: "RDP", 5900: "VNC", 23: "Telnet"}.get(dst_port, str(dst_port))
        return f"Brute Force {port_name}: {count} tentatives/{CFG.brute_force_window}s"
    return None

def detect_syn_flood(src_ip: str, is_syn: bool) -> Optional[str]:
    if not RULES["block_syn_flood"]["enabled"] or not is_syn:
        return None
    tracker = STATE._syn_flood_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    STATE._syn_flood_tracker[src_ip] = _clean_window(tracker, CFG.syn_flood_window)
    count = len(STATE._syn_flood_tracker[src_ip])
    if count >= CFG.syn_flood_threshold:
        return f"SYN Flood: {count} SYN/{CFG.syn_flood_window}s"
    return None

def detect_dns_tunneling(src_ip: str) -> Optional[str]:
    tracker = STATE._dns_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    STATE._dns_tracker[src_ip] = _clean_window(tracker, 5)
    count = len(STATE._dns_tracker[src_ip])
    if count >= CFG.dns_tunnel_threshold:
        return f"DNS Tunneling probable: {count} requêtes/5s"
    return None

# ─── v3.0 — Anomaly Detection ────────────────────────────────────────────
def anomaly_check_ip(ip: str, pkt_rate: int, byte_vol: int, port_count: int):
    """Vérifie les anomalies statistiques pour une IP"""
    if not CFG.anomaly_enabled:
        return
    profile = IP_BASELINES.get(ip)
    if profile is None:
        profile = BaselineProfile()
        IP_BASELINES[ip] = profile
    # Accumulate
    profile.pkt_rates.append(pkt_rate)
    profile.byte_vols.append(byte_vol)
    profile.port_counts.append(port_count)
    # Need minimum baseline
    if len(profile.pkt_rates) < CFG.anomaly_baseline_min:
        return
    # Z-score checks
    alerts = []
    for metric_name, values, current in [
        ("pkt_rate",   list(profile.pkt_rates)[:-1],   pkt_rate),
        ("byte_volume",list(profile.byte_vols)[:-1],   byte_vol),
        ("port_diversity",list(profile.port_counts)[:-1], port_count),
    ]:
        mean, std = BaselineProfile._mean_std(values)
        z = BaselineProfile._zscore(current, mean, std)
        if abs(z) >= CFG.anomaly_zscore:
            alerts.append({
                "ts":       datetime.now().strftime("%H:%M:%S"),
                "ip":       ip,
                "metric":   metric_name,
                "z_score":  round(z, 2),
                "baseline": round(mean, 1),
                "current":  current,
                "severity": "high" if abs(z) > 5 else "med",
            })
    for alert in alerts:
        STATE.anomaly_alerts.appendleft(alert)
        add_threat(ip, f"Anomalie: {alert['metric']}",
                   f"Z-score={alert['z_score']} (baseline={alert['baseline']}, current={alert['current']})",
                   alert['severity'])

def anomaly_flush():
    """Appelé chaque seconde depuis snapshot_traffic pour traiter les accumulateurs"""
    global _anomaly_accum
    for ip, acc in _anomaly_accum.items():
        anomaly_check_ip(ip, acc.get("pkts", 0), acc.get("bytes", 0), len(acc.get("ports", set())))
        # Behavioral profile
        if CFG.profile_enabled and ip in IP_BEHAVIOR_PROFILES:
            prof = IP_BEHAVIOR_PROFILES[ip]
            if prof.total_packets >= 100 and prof.total_packets % 50 == 0:
                score = prof.deviation_score()
                if score < 0.7:
                    alert = {
                        "ts":    datetime.now().strftime("%H:%M:%S"),
                        "ip":    ip,
                        "score": round(score, 2),
                    }
                    STATE.anomaly_alerts.appendleft({
                        **alert, "metric": "behavior_change",
                        "z_score": round((1 - score) * 10, 1),
                        "baseline": "normal", "current": f"similarity={score}",
                        "severity": "high",
                    })
                    add_threat(ip, "Changement comportemental",
                              f"Score similarité={score:.2f} (seuil=0.70)", "high")
    _anomaly_accum = {}

# ─── v3.0 — Attack Correlation ───────────────────────────────────────────
def correlate_attack_phase(ip: str, threat_type: str):
    """Corrèle les événements d'attaque pour détecter des chaînes multi-étapes"""
    if not CFG.correlation_enabled:
        return
    phase = _classify_phase(threat_type)
    if phase == "other":
        return
    now = time.time()
    if ip not in ATTACK_CHAINS:
        ATTACK_CHAINS[ip] = []
    # Prune old entries
    ATTACK_CHAINS[ip] = [e for e in ATTACK_CHAINS[ip] if now - e["ts"] < CFG.correlation_window]
    # Don't add duplicate phases in quick succession
    if ATTACK_CHAINS[ip] and ATTACK_CHAINS[ip][-1]["phase"] == phase and now - ATTACK_CHAINS[ip][-1]["ts"] < 10:
        return
    ATTACK_CHAINS[ip].append({"phase": phase, "ts": now, "type": threat_type})
    # Check chain patterns
    ip_phases = [e["phase"] for e in ATTACK_CHAINS[ip]]
    for pattern in CHAIN_PATTERNS:
        # Check if all pattern phases appear in order
        idx = 0
        for p in ip_phases:
            if idx < len(pattern["phases"]) and p == pattern["phases"][idx]:
                idx += 1
        if idx >= len(pattern["phases"]):
            # Full chain detected!
            alert = {
                "ts":       datetime.now().strftime("%H:%M:%S"),
                "ip":       ip,
                "chain":    pattern["name"],
                "phases":   [e for e in ATTACK_CHAINS[ip]],
                "severity": "critical",
            }
            STATE.correlation_alerts.appendleft(alert)
            add_threat(ip, f"Chaîne d'attaque: {pattern['name']}",
                      f"Phases détectées: {' → '.join(pattern['phases'])}", "critical")
            ATTACK_CHAINS[ip] = []  # Reset after detection
            break

# ─── v3.0 — JA3 Fingerprinting ───────────────────────────────────────────
def extract_ja3(raw_payload: bytes) -> str:
    """Extrait le hash JA3 d'un TLS ClientHello"""
    try:
        if len(raw_payload) < 11:
            return ""
        # Check TLS record header
        if raw_payload[0] != 0x16:  # Handshake
            return ""
        # TLS version from record
        # Handshake type should be ClientHello (1)
        if raw_payload[5] != 0x01:
            return ""
        # Parse ClientHello
        # Skip record header (5) + handshake header (4) + client version (2) + random (32)
        offset = 5 + 4  # record + handshake header
        if offset + 2 > len(raw_payload):
            return ""
        tls_version = struct.unpack("!H", raw_payload[offset:offset+2])[0]
        offset += 2 + 32  # version + random
        # Session ID
        if offset >= len(raw_payload):
            return ""
        sess_len = raw_payload[offset]
        offset += 1 + sess_len
        # Cipher suites
        if offset + 2 > len(raw_payload):
            return ""
        cs_len = struct.unpack("!H", raw_payload[offset:offset+2])[0]
        offset += 2
        cipher_suites = []
        for i in range(0, cs_len, 2):
            if offset + i + 2 > len(raw_payload):
                break
            cs = struct.unpack("!H", raw_payload[offset+i:offset+i+2])[0]
            if cs not in (0x00FF,):  # Skip GREASE
                cipher_suites.append(str(cs))
        offset += cs_len
        # Compression
        if offset >= len(raw_payload):
            return ""
        comp_len = raw_payload[offset]
        offset += 1 + comp_len
        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        if offset + 2 <= len(raw_payload):
            ext_total = struct.unpack("!H", raw_payload[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total
            while offset + 4 <= min(ext_end, len(raw_payload)):
                ext_type = struct.unpack("!H", raw_payload[offset:offset+2])[0]
                ext_len = struct.unpack("!H", raw_payload[offset+2:offset+4])[0]
                offset += 4
                if ext_type not in (0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
                                     0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
                                     0xeaea, 0xfafa):  # Skip GREASE
                    extensions.append(str(ext_type))
                # Elliptic curves (supported_groups)
                if ext_type == 0x000a and ext_len >= 2 and offset + ext_len <= len(raw_payload):
                    curves_len = struct.unpack("!H", raw_payload[offset:offset+2])[0]
                    for j in range(2, min(curves_len + 2, ext_len), 2):
                        if offset + j + 2 <= len(raw_payload):
                            curve = struct.unpack("!H", raw_payload[offset+j:offset+j+2])[0]
                            elliptic_curves.append(str(curve))
                # EC point formats
                if ext_type == 0x000b and ext_len >= 1 and offset + ext_len <= len(raw_payload):
                    fmt_len = raw_payload[offset]
                    for j in range(1, min(fmt_len + 1, ext_len)):
                        if offset + j < len(raw_payload):
                            ec_point_formats.append(str(raw_payload[offset + j]))
                offset += ext_len
        # Build JA3 string
        ja3_str = ",".join([
            str(tls_version),
            "-".join(cipher_suites),
            "-".join(extensions),
            "-".join(elliptic_curves),
            "-".join(ec_point_formats),
        ])
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return ""

def ja3_check(ip: str, ja3_hash: str):
    """Vérifie un hash JA3 contre la liste des malwares connus"""
    if not ja3_hash or not CFG.ja3_enabled:
        return
    JA3_CACHE[ip] = {"hash": ja3_hash, "ts": time.time()}
    label = KNOWN_BAD_JA3.get(ja3_hash)
    if label:
        alert = {
            "ts":    datetime.now().strftime("%H:%M:%S"),
            "ip":    ip,
            "hash":  ja3_hash,
            "label": label,
        }
        STATE.ja3_alerts.appendleft(alert)
        add_threat(ip, f"JA3 Malveillant: {label}", f"Hash={ja3_hash}", "critical")

# ─── v3.0 — Entropy Analysis ─────────────────────────────────────────────
def calc_shannon_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon (0-8 pour des bytes)"""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def entropy_check_dns(ip: str, query_name: str):
    """Vérifie l'entropie des requêtes DNS (détection C2/tunneling)"""
    if not CFG.entropy_enabled or not query_name:
        return
    # Analyse le sous-domaine (avant le TLD)
    parts = query_name.split(".")
    if len(parts) > 2:
        subdomain = ".".join(parts[:-2])
    else:
        subdomain = parts[0]
    if len(subdomain) < 6:
        return
    entropy = calc_shannon_entropy(subdomain.encode())
    if entropy > CFG.entropy_threshold:
        alert = {
            "ts":      datetime.now().strftime("%H:%M:%S"),
            "ip":      ip,
            "domain":  query_name,
            "entropy": round(entropy, 2),
            "type":    "dns",
        }
        STATE.entropy_alerts.appendleft(alert)
        add_threat(ip, "DNS haute entropie",
                  f"Domaine={query_name} Entropie={entropy:.2f} (seuil={CFG.entropy_threshold})", "high")

def entropy_check_payload(ip: str, payload: bytes, dst_port: int):
    """Vérifie l'entropie des payloads (détection C2 chiffré)"""
    if not CFG.entropy_enabled or not payload or len(payload) < 32:
        return
    if dst_port in (443, 8443, 993, 995, 465):  # TLS ports = normal high entropy
        return
    entropy = calc_shannon_entropy(payload)
    if entropy > 7.2:
        alert = {
            "ts":      datetime.now().strftime("%H:%M:%S"),
            "ip":      ip,
            "entropy": round(entropy, 2),
            "size":    len(payload),
            "port":    dst_port,
            "type":    "payload",
        }
        STATE.entropy_alerts.appendleft(alert)
        add_threat(ip, "Payload haute entropie",
                  f"Port={dst_port} Entropie={entropy:.2f} Taille={len(payload)}", "med")

# ─── v3.0 — Threat Intelligence ──────────────────────────────────────────
def _fetch_threat_feeds():
    """Télécharge les feeds de menaces publics (thread daemon)"""
    global THREAT_FEED_IPS, THREAT_FEED_LAST_UPDATE
    feeds = {
        "Feodo Tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "Emerging Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    }
    new_ips = set()
    for name, url in feeds.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuard-Pro/3.0"})
            resp = urllib.request.urlopen(req, timeout=15)
            for line in resp.read().decode(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        ipaddress.ip_address(line)
                        new_ips.add(line)
                    except ValueError:
                        pass
            log.info(f"[THREAT-FEED] {name}: {len(new_ips)} IPs")
        except Exception as e:
            log.warning(f"[THREAT-FEED] Erreur {name}: {e}")
    THREAT_FEED_IPS = new_ips
    THREAT_FEED_LAST_UPDATE = time.time()
    log.info(f"[THREAT-FEED] Total: {len(THREAT_FEED_IPS)} IPs de threat feeds")

def _schedule_feed_refresh():
    """Planifie le refresh périodique des feeds"""
    if not CFG.threat_feeds_enabled:
        return
    def _loop():
        while True:
            try:
                _fetch_threat_feeds()
            except Exception as e:
                log.error(f"[THREAT-FEED] Erreur refresh: {e}")
            time.sleep(CFG.threat_feeds_interval)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()

def _vt_check_ip(ip: str):
    """Vérifie une IP sur VirusTotal (thread)"""
    if not CFG.virustotal_enabled or not CFG.virustotal_api_key:
        return
    # Rate limiting: 4 req/min
    now = time.time()
    if now - VT_RATE.get("last_min", 0) > 60:
        VT_RATE["last_min"] = now
        VT_RATE["count"] = 0
    if VT_RATE["count"] >= 4:
        return
    VT_RATE["count"] += 1
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req = urllib.request.Request(url, headers={
            "x-apikey": CFG.virustotal_api_key,
            "User-Agent": "NetGuard-Pro/3.0",
        })
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        VT_CACHE[ip] = {
            "malicious": malicious, "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "ts": time.time(),
            "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
        }
        if malicious >= 3:
            STATE.threat_intel_hits.appendleft({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "ip": ip, "source": "VirusTotal",
                "detail": f"{malicious} détections malveillantes, {suspicious} suspectes",
                "severity": "critical" if malicious > 10 else "high",
            })
            add_threat(ip, "VirusTotal: IP malveillante",
                      f"{malicious} moteurs AV positifs", "critical" if malicious > 10 else "high")
    except Exception as e:
        log.debug(f"[VT] Erreur pour {ip}: {e}")

def _otx_fetch_pulses():
    """Récupère les IOC depuis AlienVault OTX (thread)"""
    global OTX_IOC_IPS, OTX_IOC_DOMAINS
    if not CFG.otx_enabled or not CFG.otx_api_key:
        return
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"
        req = urllib.request.Request(url, headers={
            "X-OTX-API-KEY": CFG.otx_api_key,
            "User-Agent": "NetGuard-Pro/3.0",
        })
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        new_ips = set()
        new_domains = set()
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                itype = indicator.get("type", "")
                val = indicator.get("indicator", "")
                if itype == "IPv4":
                    new_ips.add(val)
                elif itype in ("domain", "hostname"):
                    new_domains.add(val)
        OTX_IOC_IPS |= new_ips
        OTX_IOC_DOMAINS |= new_domains
        log.info(f"[OTX] Chargé: {len(new_ips)} IPs, {len(new_domains)} domaines")
    except Exception as e:
        log.warning(f"[OTX] Erreur: {e}")

def _abuseipdb_check(ip: str):
    """Vérifie une IP sur AbuseIPDB"""
    if not CFG.abuseipdb_enabled or not CFG.abuseipdb_api_key:
        return
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        req = urllib.request.Request(url, headers={
            "Key": CFG.abuseipdb_api_key,
            "Accept": "application/json",
        })
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        if score > 50:
            STATE.threat_intel_hits.appendleft({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "ip": ip, "source": "AbuseIPDB",
                "detail": f"Score de confiance: {score}%",
                "severity": "high" if score > 80 else "med",
            })
    except Exception as e:
        log.debug(f"[AbuseIPDB] Erreur pour {ip}: {e}")

def ioc_match_ip(ip: str) -> list:
    """Vérifie une IP contre toutes les sources d'IOC"""
    matches = []
    if ip in THREAT_FEED_IPS:
        matches.append({"source": "Threat Feed", "detail": "IP dans les feeds publics"})
    if ip in OTX_IOC_IPS:
        matches.append({"source": "AlienVault OTX", "detail": "IOC trouvé dans les pulses OTX"})
    if ip in VT_CACHE and VT_CACHE[ip].get("malicious", 0) >= 3:
        matches.append({"source": "VirusTotal", "detail": f"{VT_CACHE[ip]['malicious']} détections"})
    return matches

# ─── v3.0 — Active Response ──────────────────────────────────────────────
def _send_discord_alert(threat: dict):
    """Envoie une alerte Discord via webhook (thread)"""
    if not CFG.discord_enabled or not CFG.discord_webhook_url:
        return
    key = f"discord:{threat.get('src_ip', '')}"
    now = time.time()
    if ALERT_COOLDOWNS.get(key, 0) > now - WEBHOOK_COOLDOWN:
        return
    ALERT_COOLDOWNS[key] = now
    try:
        colors = {"critical": 0xFF0000, "high": 0xFF4500, "med": 0xFFAA00, "low": 0x00AAFF}
        payload = json.dumps({
            "embeds": [{
                "title": f"🛡️ NetGuard Alert: {threat.get('type', 'Unknown')}",
                "description": threat.get("description", ""),
                "color": colors.get(threat.get("severity", "med"), 0xAAAAAA),
                "fields": [
                    {"name": "Source IP", "value": threat.get("src_ip", "?"), "inline": True},
                    {"name": "Sévérité", "value": threat.get("severity", "?").upper(), "inline": True},
                    {"name": "Pays", "value": threat.get("country", "?"), "inline": True},
                ],
                "footer": {"text": "NetGuard Pro v3.0"},
                "timestamp": threat.get("timestamp", datetime.now().isoformat()),
            }]
        }).encode()
        req = urllib.request.Request(CFG.discord_webhook_url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
        STATE.webhook_log.appendleft({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "target": "Discord", "ip": threat.get("src_ip", ""), "status": "sent"
        })
    except Exception as e:
        STATE.webhook_log.appendleft({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "target": "Discord", "ip": threat.get("src_ip", ""), "status": f"error: {e}"
        })

def _send_telegram_alert(threat: dict):
    """Envoie une alerte Telegram via Bot API (thread)"""
    if not CFG.telegram_enabled or not CFG.telegram_bot_token or not CFG.telegram_chat_id:
        return
    key = f"telegram:{threat.get('src_ip', '')}"
    now = time.time()
    if ALERT_COOLDOWNS.get(key, 0) > now - WEBHOOK_COOLDOWN:
        return
    ALERT_COOLDOWNS[key] = now
    try:
        sev_emoji = {"critical": "🔴", "high": "🟠", "med": "🟡", "low": "🔵"}
        emoji = sev_emoji.get(threat.get("severity", ""), "⚪")
        text = (f"{emoji} <b>NetGuard Alert</b>\n"
                f"<b>Type:</b> {threat.get('type', '?')}\n"
                f"<b>IP:</b> <code>{threat.get('src_ip', '?')}</code>\n"
                f"<b>Sévérité:</b> {threat.get('severity', '?').upper()}\n"
                f"<b>Pays:</b> {threat.get('country', '?')}\n"
                f"<b>Détail:</b> {threat.get('description', '')}")
        payload = json.dumps({
            "chat_id": CFG.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
        }).encode()
        url = f"https://api.telegram.org/bot{CFG.telegram_bot_token}/sendMessage"
        req = urllib.request.Request(url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
        STATE.webhook_log.appendleft({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "target": "Telegram", "ip": threat.get("src_ip", ""), "status": "sent"
        })
    except Exception as e:
        STATE.webhook_log.appendleft({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "target": "Telegram", "ip": threat.get("src_ip", ""), "status": f"error: {e}"
        })

def dispatch_alert(threat: dict):
    """Point unique d'envoi d'alertes vers Discord/Telegram"""
    sev_order = {"low": 0, "med": 1, "high": 2, "critical": 3}
    threat_sev = sev_order.get(threat.get("severity", ""), 0)
    if CFG.discord_enabled:
        min_sev = sev_order.get(CFG.discord_min_severity, 2)
        if threat_sev >= min_sev:
            threading.Thread(target=_send_discord_alert, args=(threat,), daemon=True).start()
    if CFG.telegram_enabled:
        min_sev = sev_order.get(CFG.telegram_min_severity, 2)
        if threat_sev >= min_sev:
            threading.Thread(target=_send_telegram_alert, args=(threat,), daemon=True).start()

def isolate_device(ip: str):
    """Isole un device LAN (bloque tout trafic sauf gateway)"""
    if not _validate_ip(ip):
        return
    ISOLATED_DEVICES.add(ip)
    log.warning(f"[ISOLATE] Device {ip} isolé du réseau")
    if not CFG.can_block:
        return
    try:
        if IS_LINUX:
            _subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, timeout=10)
            _subprocess.run(["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"], capture_output=True, timeout=10)
        elif IS_WINDOWS:
            name = f"NetGuard_Isolate_{ip.replace('.','_')}"
            _subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}_in", "dir=in", "action=block", f"remoteip={ip}", "enable=yes"],
                capture_output=True, timeout=10)
            _subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}_out", "dir=out", "action=block", f"remoteip={ip}", "enable=yes"],
                capture_output=True, timeout=10)
    except Exception as e:
        log.error(f"[ISOLATE] Erreur: {e}")

def unisolate_device(ip: str):
    """Libère un device isolé"""
    if not _validate_ip(ip):
        return
    ISOLATED_DEVICES.discard(ip)
    log.info(f"[ISOLATE] Device {ip} libéré")
    try:
        if IS_LINUX:
            _subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, timeout=10)
            _subprocess.run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], capture_output=True, timeout=10)
        elif IS_WINDOWS:
            name = f"NetGuard_Isolate_{ip.replace('.','_')}"
            _subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}_in"], capture_output=True, timeout=10)
            _subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}_out"], capture_output=True, timeout=10)
    except Exception as e:
        log.error(f"[ISOLATE] Erreur libération: {e}")

def quarantine_ip(ip: str):
    """Met une IP en quarantaine (DNS seulement)"""
    if not _validate_ip(ip):
        return
    QUARANTINED_IPS.add(ip)
    log.warning(f"[QUARANTINE] {ip} mis en quarantaine")
    if not CFG.can_block:
        return
    try:
        if IS_LINUX:
            _subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"], capture_output=True, timeout=10)
            _subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, timeout=10)
        elif IS_WINDOWS:
            name = f"NetGuard_Quarantine_{ip.replace('.','_')}"
            _subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", "dir=in", "action=block", f"remoteip={ip}", "enable=yes"],
                capture_output=True, timeout=10)
    except Exception as e:
        log.error(f"[QUARANTINE] Erreur: {e}")

def unquarantine_ip(ip: str):
    """Libère une IP de la quarantaine"""
    if not _validate_ip(ip):
        return
    QUARANTINED_IPS.discard(ip)
    log.info(f"[QUARANTINE] {ip} libéré")
    try:
        if IS_LINUX:
            _subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"], capture_output=True, timeout=10)
            _subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, timeout=10)
        elif IS_WINDOWS:
            name = f"NetGuard_Quarantine_{ip.replace('.','_')}"
            _subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], capture_output=True, timeout=10)
    except Exception as e:
        log.error(f"[QUARANTINE] Erreur libération: {e}")

def generate_forensic_report(ip: str, trigger: str) -> str:
    """Génère un rapport forensique détaillé pour une IP"""
    try:
        os.makedirs("reports", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/forensic_{ip.replace('.','_')}_{ts}.json"
        report = {
            "generated_at": datetime.now().isoformat(),
            "target_ip": ip,
            "trigger": trigger,
            "risk_score": STATE.ip_risk_scores.get(ip, 0),
            "ip_intel": STATE.ip_intel.get(ip, {}),
            "threats": [t for t in STATE.threats if t.get("src_ip") == ip],
            "attack_chain": ATTACK_CHAINS.get(ip, []),
            "ja3": JA3_CACHE.get(ip, {}),
            "ioc_matches": ioc_match_ip(ip),
            "anomaly_alerts": [a for a in STATE.anomaly_alerts if a.get("ip") == ip],
            "entropy_alerts": [a for a in STATE.entropy_alerts if a.get("ip") == ip],
            "timeline": [e for e in STATE.timeline_events if e.get("ip") == ip],
            "packets_sample": [p for p in STATE.recent_packets if p.get("src") == ip][:50],
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        entry = {"ts": datetime.now().strftime("%H:%M:%S"), "ip": ip, "trigger": trigger, "path": filename}
        STATE.forensic_reports.appendleft(entry)
        log.info(f"[FORENSIC] Rapport généré: {filename}")
        return filename
    except Exception as e:
        log.error(f"[FORENSIC] Erreur: {e}")
        return ""

# ═══════════════════════════════════════════════════════════════════════════
# v3.0 — WIREGUARD VPN SERVER
# ═══════════════════════════════════════════════════════════════════════════

def _wg_find_binary(name: str) -> str:
    """Trouve le chemin complet d'un binaire WireGuard (wg, wireguard)"""
    import shutil
    # Check PATH first
    found = shutil.which(name)
    if found:
        return found
    # Windows: check standard install locations
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
    return name  # Return as-is, let subprocess handle FileNotFoundError

_WG_BIN = None
_WIREGUARD_BIN = None

def _wg_cmd() -> str:
    """Retourne le chemin vers wg(.exe)"""
    global _WG_BIN
    if _WG_BIN is None:
        _WG_BIN = _wg_find_binary("wg")
    return _WG_BIN

def _wireguard_cmd() -> str:
    """Retourne le chemin vers wireguard(.exe)"""
    global _WIREGUARD_BIN
    if _WIREGUARD_BIN is None:
        _WIREGUARD_BIN = _wg_find_binary("wireguard")
    return _WIREGUARD_BIN

def _wg_genkey_python() -> tuple:
    """Génère une paire de clés WireGuard en pur Python via X25519 (fallback sans wg CLI)"""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        privkey_obj = X25519PrivateKey.generate()
        priv_b64 = base64.b64encode(privkey_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
        pub_b64 = base64.b64encode(privkey_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        log.info("[WG] Clés générées via Python cryptography (fallback)")
        return priv_b64, pub_b64
    except ImportError:
        log.error("[WG] Ni wg CLI ni Python cryptography disponible. Installe: pip install cryptography")
        return "", ""
    except Exception as e:
        log.error(f"[WG] Erreur génération clés Python: {e}")
        return "", ""

def _wg_genpsk_python() -> str:
    """Génère un preshared key en pur Python (fallback sans wg CLI)"""
    return base64.b64encode(os.urandom(32)).decode()

def _wg_genkey() -> tuple:
    """Génère une paire de clés WireGuard (privkey, pubkey) — essaie wg CLI puis fallback Python"""
    try:
        result = _subprocess.run([_wg_cmd(), "genkey"], capture_output=True, text=True, timeout=5)
        privkey = result.stdout.strip()
        if not privkey:
            raise ValueError("wg genkey returned empty")
        result2 = _subprocess.run([_wg_cmd(), "pubkey"], input=privkey, capture_output=True, text=True, timeout=5)
        pubkey = result2.stdout.strip()
        if not pubkey:
            raise ValueError("wg pubkey returned empty")
        return privkey, pubkey
    except (FileNotFoundError, ValueError):
        log.warning("[WG] wg CLI non trouvé, utilisation du fallback Python cryptography")
        return _wg_genkey_python()
    except Exception as e:
        log.warning(f"[WG] Erreur wg CLI ({e}), tentative fallback Python")
        return _wg_genkey_python()

def _wg_init_server():
    """Initialise les clés serveur WireGuard si nécessaire"""
    global WG_SERVER_PRIVKEY, WG_SERVER_PUBKEY
    os.makedirs(CFG.wg_config_dir, exist_ok=True)
    keyfile = os.path.join(CFG.wg_config_dir, "server_keys.json")
    if os.path.exists(keyfile):
        try:
            with open(keyfile, "r") as f:
                keys = json.load(f)
            WG_SERVER_PRIVKEY = keys.get("privkey", "")
            WG_SERVER_PUBKEY = keys.get("pubkey", "")
            if WG_SERVER_PRIVKEY and WG_SERVER_PUBKEY:
                log.info(f"[WG] Clés serveur chargées. PubKey: {WG_SERVER_PUBKEY[:20]}...")
                return
        except Exception:
            pass
    # Generate new keys
    WG_SERVER_PRIVKEY, WG_SERVER_PUBKEY = _wg_genkey()
    if WG_SERVER_PRIVKEY:
        try:
            with open(keyfile, "w") as f:
                json.dump({"privkey": WG_SERVER_PRIVKEY, "pubkey": WG_SERVER_PUBKEY}, f)
            try:
                os.chmod(keyfile, 0o600)
            except OSError:
                pass
            log.info(f"[WG] Nouvelles clés serveur générées. PubKey: {WG_SERVER_PUBKEY[:20]}...")
        except Exception as e:
            log.error(f"[WG] Erreur sauvegarde clés: {e}")

def _wg_generate_server_config() -> str:
    """Génère le fichier de config serveur WireGuard"""
    if not WG_SERVER_PRIVKEY:
        _wg_init_server()
    lines = [
        "[Interface]",
        f"PrivateKey = {WG_SERVER_PRIVKEY}",
        f"Address = {CFG.wg_address}",
        f"ListenPort = {CFG.wg_listen_port}",
        f"DNS = {CFG.wg_dns}",
    ]
    if CFG.wg_post_up:
        lines.append(f"PostUp = {CFG.wg_post_up}")
    if CFG.wg_post_down:
        lines.append(f"PostDown = {CFG.wg_post_down}")
    # Add peers
    for peer in WG_PEERS:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['pubkey']}")
        lines.append(f"AllowedIPs = {peer['address']}/32")
        if peer.get("preshared_key"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")
    config = "\n".join(lines) + "\n"
    config_path = os.path.join(CFG.wg_config_dir, f"{CFG.wg_interface}.conf")
    with open(config_path, "w") as f:
        f.write(config)
    log.info(f"[WG] Config serveur écrite: {config_path}")
    return config_path

def _wg_generate_peer_config(peer: dict) -> str:
    """Génère la config client pour un peer"""
    endpoint = CFG.wg_endpoint or "YOUR_SERVER_IP:51820"
    # Extract network prefix from server address (e.g., 10.66.66 from 10.66.66.1/24)
    server_net = CFG.wg_address.split("/")[0]
    config = f"""[Interface]
PrivateKey = {peer['privkey']}
Address = {peer['address']}/32
DNS = {CFG.wg_dns}

[Peer]
PublicKey = {WG_SERVER_PUBKEY}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    return config

def wg_add_peer(name: str) -> dict:
    """Ajoute un nouveau peer VPN"""
    if not WG_SERVER_PRIVKEY:
        _wg_init_server()
    privkey, pubkey = _wg_genkey()
    if not privkey:
        return {"error": "Impossible de générer les clés. WireGuard est-il installé?"}
    # Calculate next available IP
    base_parts = CFG.wg_address.split("/")[0].split(".")
    used_ips = {p["address"] for p in WG_PEERS}
    next_ip = ""
    for i in range(2, 254):
        candidate = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
        if candidate not in used_ips and candidate != CFG.wg_address.split("/")[0]:
            next_ip = candidate
            break
    if not next_ip:
        return {"error": "Plus d'adresses IP disponibles"}
    # Generate preshared key (wg CLI or Python fallback)
    try:
        psk_result = _subprocess.run([_wg_cmd(), "genpsk"], capture_output=True, text=True, timeout=5)
        psk = psk_result.stdout.strip()
        if not psk:
            psk = _wg_genpsk_python()
    except Exception:
        psk = _wg_genpsk_python()
    peer = {
        "name":          name,
        "pubkey":        pubkey,
        "privkey":       privkey,
        "preshared_key": psk,
        "address":       next_ip,
        "allowed_ips":   f"{next_ip}/32",
        "created":       datetime.now().isoformat(),
        "last_handshake": "",
        "transfer_rx":   0,
        "transfer_tx":   0,
    }
    WG_PEERS.append(peer)
    # Save peer config file
    os.makedirs(CFG.wg_config_dir, exist_ok=True)
    peer_conf = _wg_generate_peer_config(peer)
    peer_file = os.path.join(CFG.wg_config_dir, f"peer_{name}.conf")
    with open(peer_file, "w") as f:
        f.write(peer_conf)
    # Regenerate server config
    _wg_generate_server_config()
    # Save peers list
    _wg_save_peers()
    log.info(f"[WG] Peer ajouté: {name} ({next_ip})")
    return {"ok": True, "peer": {k: v for k, v in peer.items() if k != "privkey"}, "config": peer_conf, "config_file": peer_file}

def wg_remove_peer(name: str) -> dict:
    """Supprime un peer VPN"""
    global WG_PEERS
    peer = next((p for p in WG_PEERS if p["name"] == name), None)
    if not peer:
        return {"error": f"Peer '{name}' non trouvé"}
    WG_PEERS = [p for p in WG_PEERS if p["name"] != name]
    # Remove peer config file
    peer_file = os.path.join(CFG.wg_config_dir, f"peer_{name}.conf")
    if os.path.exists(peer_file):
        os.remove(peer_file)
    # Regenerate server config
    _wg_generate_server_config()
    _wg_save_peers()
    # If WG is running, remove peer live
    if WG_STATUS.get("running"):
        try:
            _subprocess.run([_wg_cmd(), "set", CFG.wg_interface, "peer", peer["pubkey"], "remove"],
                           capture_output=True, timeout=10)
        except Exception:
            pass
    log.info(f"[WG] Peer supprimé: {name}")
    return {"ok": True}

def wg_start() -> dict:
    """Démarre le tunnel WireGuard"""
    global WG_STATUS
    if not WG_SERVER_PRIVKEY:
        _wg_init_server()
    config_path = _wg_generate_server_config()
    abs_config = os.path.abspath(config_path)
    try:
        if IS_LINUX:
            result = _subprocess.run(["wg-quick", "up", abs_config],
                                    capture_output=True, text=True, timeout=15)
        elif IS_WINDOWS:
            # Windows: wireguard.exe /installtunnelservice needs admin rights
            result = _subprocess.run([_wireguard_cmd(), "/installtunnelservice", abs_config],
                                    capture_output=True, text=True, timeout=15)
        else:
            return {"error": "OS non supporté pour WireGuard"}

        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            if "access" in stderr.lower() or "denied" in stderr.lower() or "privilege" in stderr.lower():
                msg = "Droits administrateur requis. Lance NetGuard en tant qu'Administrateur pour démarrer le VPN."
            else:
                msg = f"Erreur WireGuard (code {result.returncode}): {stderr}"
            log.error(f"[WG] {msg}")
            return {"error": msg}

        # Verify tunnel is actually up (give it a moment)
        import time
        time.sleep(1)
        verify = _subprocess.run([_wg_cmd(), "show", CFG.wg_interface],
                                capture_output=True, text=True, timeout=5)
        if verify.returncode == 0:
            WG_STATUS["running"] = True
            WG_STATUS["interface"] = CFG.wg_interface
            WG_STATUS["not_installed"] = False
            log.info(f"[WG] Tunnel {CFG.wg_interface} démarré et vérifié")
            return {"ok": True, "status": "started"}
        else:
            # Command ran but tunnel not active — likely needs admin
            WG_STATUS["running"] = False
            msg = "Le tunnel n'a pas démarré. Lance NetGuard en tant qu'Administrateur (clic droit → Exécuter en admin)."
            log.warning(f"[WG] {msg}")
            return {"error": msg}

    except FileNotFoundError:
        msg = "WireGuard non installé. "
        if IS_WINDOWS:
            msg += "Lance install_wireguard.bat en admin ou installe depuis https://wireguard.com/install/"
        else:
            msg += "Installe avec: sudo apt install wireguard"
        log.error(f"[WG] {msg}")
        return {"error": msg}
    except Exception as e:
        log.error(f"[WG] Erreur démarrage tunnel: {e}")
        return {"error": str(e)}

def wg_stop() -> dict:
    """Arrête le tunnel WireGuard"""
    global WG_STATUS
    config_path = os.path.join(CFG.wg_config_dir, f"{CFG.wg_interface}.conf")
    try:
        if IS_LINUX:
            _subprocess.run(["wg-quick", "down", config_path], capture_output=True, text=True, timeout=15)
        elif IS_WINDOWS:
            _subprocess.run([_wireguard_cmd(), "/uninstalltunnelservice", CFG.wg_interface],
                          capture_output=True, text=True, timeout=15)
        WG_STATUS["running"] = False
        WG_STATUS["peers_connected"] = 0
        log.info(f"[WG] Tunnel {CFG.wg_interface} arrêté")
        return {"ok": True, "status": "stopped"}
    except FileNotFoundError:
        msg = "WireGuard non installé. "
        if IS_WINDOWS:
            msg += "Lance install_wireguard.bat en admin"
        else:
            msg += "Installe avec: sudo apt install wireguard"
        return {"error": msg}
    except Exception as e:
        return {"error": str(e)}

def wg_get_status() -> dict:
    """Récupère le statut du tunnel WireGuard"""
    global WG_STATUS
    try:
        result = _subprocess.run([_wg_cmd(), "show", CFG.wg_interface], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            WG_STATUS["running"] = False
            return WG_STATUS
        WG_STATUS["running"] = True
        WG_STATUS["interface"] = CFG.wg_interface
        # Parse output for peer info
        connected = 0
        lines = result.stdout.splitlines()
        current_peer_pub = ""
        for line in lines:
            line = line.strip()
            if line.startswith("peer:"):
                current_peer_pub = line.split(":", 1)[1].strip()
            elif line.startswith("latest handshake:") and current_peer_pub:
                hs = line.split(":", 1)[1].strip()
                for p in WG_PEERS:
                    if p["pubkey"] == current_peer_pub:
                        p["last_handshake"] = hs
                connected += 1
            elif line.startswith("transfer:") and current_peer_pub:
                parts = line.split(":", 1)[1].strip()
                for p in WG_PEERS:
                    if p["pubkey"] == current_peer_pub:
                        p["transfer_info"] = parts
        WG_STATUS["peers_connected"] = connected
    except FileNotFoundError:
        WG_STATUS["running"] = False
        WG_STATUS["not_installed"] = True
    except Exception:
        WG_STATUS["running"] = False
    return WG_STATUS

def _wg_save_peers():
    """Sauvegarde la liste des peers"""
    try:
        peers_file = os.path.join(CFG.wg_config_dir, "peers.json")
        safe_peers = [{k: v for k, v in p.items()} for p in WG_PEERS]
        with open(peers_file, "w", encoding="utf-8") as f:
            json.dump(safe_peers, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log.error(f"[WG] Erreur sauvegarde peers: {e}")

def _wg_load_peers():
    """Charge la liste des peers"""
    global WG_PEERS
    peers_file = os.path.join(CFG.wg_config_dir, "peers.json")
    if os.path.exists(peers_file):
        try:
            with open(peers_file, "r", encoding="utf-8") as f:
                WG_PEERS = json.load(f)
            log.info(f"[WG] {len(WG_PEERS)} peers chargés")
        except Exception as e:
            log.error(f"[WG] Erreur chargement peers: {e}")

def analyze_packet(pkt):
    if not HAS_SCAPY:
        return

    # Support both IPv4 and IPv6
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
    else:
        return  # Not an IP packet (e.g. pure ARP)

    pkt_len  = len(pkt)
    proto    = get_protocol_name(pkt)
    dst_port = 0
    src_port = 0
    flags    = ""
    is_syn   = False

    # v3.0 — Accumulate anomaly data
    if src_ip not in _anomaly_accum:
        _anomaly_accum[src_ip] = {"pkts": 0, "bytes": 0, "ports": set(), "protos": defaultdict(int)}
    _anomaly_accum[src_ip]["pkts"] += 1
    _anomaly_accum[src_ip]["bytes"] += pkt_len

    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
        src_port = pkt[TCP].sport
        flags    = str(pkt[TCP].flags)
        is_syn   = "S" in flags and "A" not in flags
    elif pkt.haslayer(UDP):
        dst_port = pkt[UDP].dport
        src_port = pkt[UDP].sport

    # v3.0 — Behavioral profiling
    if not is_private(src_ip):
        if src_ip not in IP_BEHAVIOR_PROFILES:
            IP_BEHAVIOR_PROFILES[src_ip] = BehaviorProfile()
        IP_BEHAVIOR_PROFILES[src_ip].update(dst_port, proto, pkt_len)
        _anomaly_accum[src_ip]["ports"].add(dst_port)
        _anomaly_accum[src_ip]["protos"][proto] += 1

    if STATE.record_active:
        try:
            record_write_packet(bytes(pkt))
        except Exception:
            pass

    decision = "allow"
    reason   = ""

    with STATE.lock:
        STATE.packets_total += 1
        STATE.proto_stats[proto] += 1

        if is_private(dst_ip):
            STATE.bytes_in += pkt_len
        else:
            STATE.bytes_out += pkt_len

        if src_ip in BLOCKED_IPS:
            decision = "block"
            reason   = "IP blacklistée"
        elif is_in_bad_range(src_ip):
            decision = "block"
            reason   = "IP dans plage malveillante"
            block_ip_os(src_ip, reason)
        elif not is_private(src_ip) and dst_port in CFG.always_block_ports:
            decision = "block"
            reason   = f"Port {dst_port} toujours bloqué"

        # v3.0 — Threat Feed IOC match
        if src_ip in THREAT_FEED_IPS:
            decision = "block"
            add_threat(src_ip, "Threat Feed IOC", f"IP trouvée dans les feeds de menaces publics", "high")
        if src_ip in OTX_IOC_IPS:
            decision = "block"
            add_threat(src_ip, "OTX IOC", f"IP trouvée dans AlienVault OTX", "high")

        # v3.0 — Threat intel (async, first-time only)
        if not is_private(src_ip) and src_ip not in _CHECKED_IPS:
            _CHECKED_IPS.add(src_ip)
            if CFG.virustotal_enabled:
                threading.Thread(target=_vt_check_ip, args=(src_ip,), daemon=True).start()

        # ── DNS Blackhole ───────────────────────────────────────────────
        if RULES.get("detect_malicious_dns", {}).get("enabled", True) and pkt.haslayer("DNS"):
            try:
                from scapy.layers.dns import DNS, DNSQR
                if pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    queried = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                    if dns_blackhole_check(queried):
                        decision = "block"
                        reason   = f"DNS Blackhole: {queried}"
                        add_threat(src_ip, "DNS Blackhole", f"Requête vers domaine bloqué: {queried}", "high")
            except Exception:
                pass

        # ── Géoblocage
        if GEO_BLOCKED_COUNTRIES and not is_private(src_ip):
            country = get_country(src_ip)
            if country and country in GEO_BLOCKED_COUNTRIES:
                decision = "block"
                reason   = f"Géoblocage: {GEO_COUNTRY_NAMES.get(country, country)}"
                RULES["alert_geo"]["hits"] += 1
                block_ip_os(src_ip, reason)
        elif not is_private(src_ip) and dst_port in CFG.sensitive_ports and RULES["block_ssh_external"]["enabled"]:
            decision = "block"
            reason   = f"Accès port sensible ({dst_port}) depuis IP externe"
            RULES["block_ssh_external"]["hits"] += 1
        elif (dst_port in P2P_PORTS or src_port in P2P_PORTS) and RULES["block_p2p"]["enabled"]:
            decision = "block"
            reason   = "Trafic P2P/BitTorrent"
            RULES["block_p2p"]["hits"] += 1
        else:
            if not is_private(src_ip):
                scan_reason = detect_port_scan(src_ip, dst_port)
                if scan_reason:
                    decision = "block"
                    reason   = scan_reason
                    add_threat(src_ip, "Scan de ports", scan_reason, "high", "block_port_scan")
                    block_ip_os(src_ip, scan_reason)

                if decision == "allow":
                    bf_reason = detect_brute_force(src_ip, dst_port, is_syn)
                    if bf_reason:
                        decision = "block"
                        reason   = bf_reason
                        add_threat(src_ip, "Brute Force", bf_reason, "high", "block_brute_force")
                        block_ip_os(src_ip, bf_reason)

                if decision == "allow":
                    syn_reason = detect_syn_flood(src_ip, is_syn)
                    if syn_reason:
                        decision = "block"
                        reason   = syn_reason
                        add_threat(src_ip, "SYN Flood", syn_reason, "high", "block_syn_flood")
                        block_ip_os(src_ip, syn_reason)

            if decision == "allow" and pkt.haslayer(DNS):
                dns_reason = detect_dns_tunneling(src_ip)
                if dns_reason:
                    decision = "warn"
                    reason   = dns_reason
                    add_threat(src_ip, "DNS Tunneling", dns_reason, "med")

        if CFG.dpi_enabled and decision == "allow":
            payload = b""
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            if payload:
                for hit in dpi_inspect(src_ip, payload):
                    alert = {
                        "ts":     datetime.now().strftime("%H:%M:%S"),
                        "src":    src_ip,
                        "type":   hit["type"],
                        "detail": hit["detail"],
                        "masked": hit["masked"],
                    }
                    STATE.dpi_alerts.appendleft(alert)
                    if hit["type"] == "attack":
                        add_threat(src_ip, f"DPI: {hit['detail']}", f"Payload suspect", "high")
                        auto_block_check(src_ip)

        # ── Suricata IDS ───────────────────────────────────────────────
        if SURICATA_ENABLED and decision == "allow":
            payload = b""
            if HAS_SCAPY and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            if payload:
                for hit in suricata_match(src_ip, payload, proto):
                    alert = {
                        "ts":       datetime.now().strftime("%H:%M:%S"),
                        "src":      src_ip,
                        "sid":      hit["sid"],
                        "msg":      hit["msg"],
                        "severity": hit["severity"],
                    }
                    STATE.suricata_alerts.appendleft(alert)
                    add_threat(src_ip, f"IDS: {hit['msg']}", f"Règle #{hit['sid']} déclenchée", hit["severity"])
                    if hit["severity"] in ("critical", "high"):
                        auto_block_check(src_ip)

        # v3.0 — JA3 Fingerprinting
        if CFG.ja3_enabled and pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            if len(raw) > 10 and raw[0] == 0x16:
                ja3_hash = extract_ja3(raw)
                if ja3_hash:
                    ja3_check(src_ip, ja3_hash)

        # v3.0 — Entropy analysis
        if CFG.entropy_enabled and pkt.haslayer(Raw):
            entropy_check_payload(src_ip, bytes(pkt[Raw].load), dst_port)

        # v3.0 — DNS entropy
        if CFG.entropy_enabled and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            try:
                qname = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
                entropy_check_dns(src_ip, qname)
            except Exception:
                pass

        if decision == "block" and not is_private(src_ip):
            auto_block_check(src_ip)
            # Track geo hits for attacker stats
            country = get_country(src_ip)
            if country:
                STATE.geo_hits[country] += 1
                # Fetch city async if not cached yet
                if src_ip not in _geo_city_cache:
                    threading.Thread(target=_fetch_city_async, args=(src_ip,), daemon=True).start()
                # Fetch AbuseIPDB async if key configured
                if ABUSEIPDB_API_KEY and src_ip not in _ABUSEIPDB_CACHE:
                    threading.Thread(target=_fetch_abuseipdb, args=(src_ip,), daemon=True).start()

        # Fetch geo for ANY new external IP (not just blocked)
        if not is_private(src_ip) and src_ip not in _geo_city_cache:
            threading.Thread(target=_fetch_city_async, args=(src_ip,), daemon=True).start()

        # Update risk score
        _compute_risk_score(src_ip)

        if decision == "block":
            STATE.packets_blocked += 1
        else:
            STATE.packets_allowed += 1
            STATE.active_conns[src_ip].add(dst_port)

        # Get geo info for packet entry (with guaranteed coords via fallback)
        geo = _geo_city_cache.get(src_ip, {})
        country_code = geo.get("country") or get_country(src_ip) or ""
        city = geo.get("city", "")
        lat, lon = _get_ip_coords(src_ip, country_code)
        location = f"{city}, {GEO_COUNTRY_NAMES.get(country_code, country_code)}" if city else GEO_COUNTRY_NAMES.get(country_code, country_code)

        _now_ms = int(time.time() * 1000)
        _pkt_entry = {
            "t":        datetime.now().strftime("%H:%M:%S"),
            "ts_ms":    _now_ms,  # numeric sort key (replaces fragile HH:MM:SS sort)
            "src":      src_ip, "dst": dst_ip,
            "sport":    src_port, "dport": dst_port,
            "proto":    proto, "size": f"{pkt_len}B",
            "status":   decision, "reason": reason, "flags": flags,
            "country":  country_code,
            "city":     city,
            "location": location,
            "lat":      lat,
            "lon":      lon,
        }
        STATE.recent_packets.appendleft(_pkt_entry)
        # Per-IP ring buffer: each IP keeps its own 4 newest packets. Chatty IPs
        # cannot evict quiet/new IPs from the state broadcast.
        STATE.ip_recent_packets[src_ip].appendleft(_pkt_entry)
        if src_ip not in STATE.ip_first_seen_ts:
            STATE.ip_first_seen_ts[src_ip] = _now_ms

import csv
import pathlib

REPORTS_DIR = pathlib.Path("reports")

def ensure_reports_dir():
    REPORTS_DIR.mkdir(exist_ok=True)

def _report_filename(report_type: str, fmt: str) -> pathlib.Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return REPORTS_DIR / f"netguard_{report_type}_{ts}.{fmt}"

def run_report(report_type: str, fmt: str, filter_status: str = "all") -> str:
    ensure_reports_dir()
    path = _report_filename(report_type, fmt)
    with STATE.lock:
        pkts    = list(STATE.recent_packets)
        threats = list(STATE.threats)
    if filter_status != "all":
        pkts = [p for p in pkts if p.get("status") == filter_status]
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"generated_at": datetime.now().isoformat(), "data": pkts if report_type == "packets" else threats}, f, indent=2, ensure_ascii=False)
    else:
        with open(path, "w", newline="", encoding="utf-8") as f:
            if pkts:
                writer = csv.DictWriter(f, fieldnames=list(pkts[0].keys()), extrasaction="ignore")
                writer.writeheader()
                writer.writerows(pkts)
    return str(path)

_last_pkt_total = 0

def snapshot_traffic():
    global _last_pkt_total
    with STATE.lock:
        pps = STATE.packets_total - _last_pkt_total
        _last_pkt_total = STATE.packets_total
        STATE.traffic_history.append({
            "ts": time.time(), "in_bps": STATE.bytes_in,
            "out_bps": STATE.bytes_out, "blocked": STATE.packets_blocked,
            "pps": pps,
        })
        STATE.bytes_in  = 0
        STATE.bytes_out = 0
    # v3.0 — Anomaly detection flush
    anomaly_flush()

CLIENTS: set = set()

def _build_top_ip_entry(ip: str, hits: int) -> dict:
    """Build a top_ips entry with guaranteed lat/lon coordinates."""
    geo = _geo_city_cache.get(ip, {})
    country = geo.get("country") or get_country(ip) or ""
    lat, lon = _get_ip_coords(ip, country)
    return {
        "ip": ip, "hits": hits,
        "country": country,
        "lat": lat, "lon": lon,
        "city": geo.get("city", ""),
        "org": geo.get("org", ""),
    }

def _packets_for_state_msg(_unused_deque, total_limit: int = 400, stale_seconds: int = 600):
    """Build state-broadcast packet payload from the per-IP ring buffer (STATE.ip_recent_packets).
    Every IP that's been active gets up to 4 packets in the broadcast — chatty IPs cannot
    evict quiet or just-discovered IPs. Stale entries (IPs not seen in 10 min) are dropped."""
    cutoff_ms = int(time.time() * 1000) - stale_seconds * 1000
    out = []
    stale_ips = []
    for ip, q in list(STATE.ip_recent_packets.items()):
        if not q:
            stale_ips.append(ip)
            continue
        # If the newest packet for this IP is older than cutoff, drop the IP
        newest_ts = q[0].get("ts_ms", 0) if q else 0
        if newest_ts < cutoff_ms:
            stale_ips.append(ip)
            continue
        out.extend(q)
    # Cleanup stale entries to bound memory
    for ip in stale_ips:
        STATE.ip_recent_packets.pop(ip, None)
        STATE.ip_first_seen_ts.pop(ip, None)
    # Sort newest-first by ts_ms — guarantees recent packets near the top
    out.sort(key=lambda p: p.get("ts_ms", 0), reverse=True)
    return out[:total_limit]


def build_state_message() -> dict:
    with STATE.lock:
        conns_count = sum(len(v) for v in STATE.active_conns.values())
        total       = max(STATE.packets_total, 1)
        proto_total = sum(STATE.proto_stats.values()) or 1
        top_ips     = sorted(STATE.ip_hit_counter.items(), key=lambda x: -x[1])[:10]
        return {
            "type":               "state",
            "ts":                 time.time(),
            "packets_total":      STATE.packets_total,
            "packets_blocked":    STATE.packets_blocked,
            "blocked_rate":       round(STATE.packets_blocked * 100 / total, 1),
            "active_conns":       conns_count,
            "threats_count":      len(STATE.threats),
            "recent_packets":     _packets_for_state_msg(STATE.recent_packets),
            "threats":            list(STATE.threats)[:10],
            "traffic_history":    list(STATE.traffic_history),
            "proto_stats": [
                {"name": k, "count": v, "pct": round(v * 100 / proto_total, 1)}
                for k, v in sorted(STATE.proto_stats.items(), key=lambda x: -x[1])
            ],
            "blocked_ips":        list(BLOCKED_IPS)[:50],
            "rules": [
                {"key": k, "label": v["label"], "enabled": v["enabled"], "hits": v["hits"]}
                for k, v in RULES.items()
            ],
            "dpi_enabled":        CFG.dpi_enabled,
            "dpi_mask":           CFG.dpi_mask_sensitive,
            "auto_block_enabled": CFG.auto_block_enabled,
            "auto_block_hits":    CFG.auto_block_hits,
            "record_active":      STATE.record_active,
            "record_file":        STATE.record_file_path,
            "record_packets":     len(STATE.record_packets),
            "top_ips":            [_build_top_ip_entry(ip, h) for ip, h in top_ips],
            "dpi_alerts":         list(STATE.dpi_alerts)[:20],
            "suricata_enabled":   SURICATA_ENABLED,
            "suricata_rules":     SURICATA_LOADED,
            "suricata_alerts":    list(STATE.suricata_alerts)[:20],
            "suricata_disabled":  len(SURICATA_DISABLED_SIDS),
            "suricata_top_hits":  sorted(SURICATA_RULE_HITS.items(), key=lambda x: -x[1])[:10],
            "geo_blocked_countries": list(GEO_BLOCKED_COUNTRIES),
            "geo_country_names":  GEO_COUNTRY_NAMES,
            "geo_hits": [
                {"country": k, "name": GEO_COUNTRY_NAMES.get(k, k), "hits": v,
                 "lat": _COUNTRY_COORDS.get(k, (0,0))[1], "lon": _COUNTRY_COORDS.get(k, (0,0))[0]}
                for k, v in sorted(STATE.geo_hits.items(), key=lambda x: -x[1])
                if k in _COUNTRY_COORDS
            ],
            # v1.9.0
            "ip_risk_scores": dict(list(sorted(STATE.ip_risk_scores.items(), key=lambda x: -x[1]))[:20]),
            "ip_intel": {ip: STATE.ip_intel[ip] for ip in list(STATE.ip_intel.keys())[:50]},
            "attack_by_country": {
                country: dict(types)
                for country, types in sorted(STATE.attack_by_country.items(),
                    key=lambda x: -sum(x[1].values()))[:15]
            },
            "timeline": list(STATE.timeline_events)[:100],
            # v2.0.0
            "honeypot_enabled": HONEYPOT_ENABLED,
            "honeypot_hits":    HONEYPOT_HITS[-20:],
            "dns_blackhole_count": len(DNS_BLACKHOLE),
            "dns_blackhole_hits":  sum(DNS_BLACKHOLE_HITS.values()),
            "lan_devices":      LAN_DEVICES,
            # v3.0 — Advanced Detection
            "anomaly_enabled":      CFG.anomaly_enabled,
            "anomaly_alerts":       list(STATE.anomaly_alerts)[:20],
            "profile_enabled":      CFG.profile_enabled,
            "correlation_enabled":  CFG.correlation_enabled,
            "correlation_alerts":   list(STATE.correlation_alerts)[:20],
            "ja3_enabled":          CFG.ja3_enabled,
            "ja3_alerts":           list(STATE.ja3_alerts)[:20],
            "entropy_enabled":      CFG.entropy_enabled,
            "entropy_alerts":       list(STATE.entropy_alerts)[:20],
            "attack_chains":        {ip: phases for ip, phases in list(ATTACK_CHAINS.items())[:10] if phases},
            # v3.0 — Threat Intelligence
            "vt_enabled":           CFG.virustotal_enabled,
            "otx_enabled":          CFG.otx_enabled,
            "abuseipdb_enabled":    CFG.abuseipdb_enabled,
            "threat_feeds_enabled": CFG.threat_feeds_enabled,
            "threat_feed_count":    len(THREAT_FEED_IPS),
            "threat_feed_last":     THREAT_FEED_LAST_UPDATE,
            "threat_intel_hits":    list(STATE.threat_intel_hits)[:20],
            # v3.0 — Active Response
            "discord_enabled":      CFG.discord_enabled,
            "telegram_enabled":     CFG.telegram_enabled,
            "quarantined_ips":      list(QUARANTINED_IPS),
            "isolated_devices":     list(ISOLATED_DEVICES),
            "webhook_log":          list(STATE.webhook_log)[:20],
            "forensic_reports":     list(STATE.forensic_reports)[:10],
            # v3.0 — WireGuard VPN
            "wg_enabled":         CFG.wg_enabled,
            "wg_status":          WG_STATUS,
            "wg_peers":           [{k: v for k, v in p.items() if k not in ("privkey", "preshared_key")} for p in WG_PEERS],
            "wg_server_pubkey":   WG_SERVER_PUBKEY,
            "wg_listen_port":     CFG.wg_listen_port,
            "wg_address":         CFG.wg_address,
            # License
            "license_tier":       LICENSE.get("tier", "free"),
            "license_trial":      LICENSE.get("trial", False),
            "license_days_left":  LICENSE.get("trial_days_left", 0),
            "license_expired":    LICENSE.get("expired", False),
            "license_banner":     get_trial_banner(),
        }

# ═══════════════════════════════════════════════════════════════════════════
# v2.0.0 — DÉFENSE ACTIVE
# ═══════════════════════════════════════════════════════════════════════════

# ─── DNS Blackhole ─────────────────────────────────────────────────────────
DNS_BLACKHOLE: set = set()  # domaines bloqués
DNS_BLACKHOLE_HITS: dict = {}  # domaine -> hits

DEFAULT_BLACKHOLE_DOMAINS = [
    # Malware C2
    "emotet.com","trickbot.com","cobaltrike.com","metasploit.com",
    # Trackers publicitaires connus
    "doubleclick.net","googlesyndication.com","adnxs.com","scorecardresearch.com",
    # Phishing connus
    "phishing.example.com",
    # Cryptomining
    "coinhive.com","coin-hive.com","crypto-loot.com","minero.cc",
    # Telemetry Windows (optionnel)
    "telemetry.microsoft.com","vortex.data.microsoft.com",
]

def dns_blackhole_check(domain: str) -> bool:
    """Vérifie si un domaine est dans la blacklist DNS"""
    if not domain:
        return False
    domain = domain.lower().rstrip(".")
    # Check exact + parent domains
    for blocked in DNS_BLACKHOLE:
        if domain == blocked or domain.endswith("." + blocked):
            DNS_BLACKHOLE_HITS[blocked] = DNS_BLACKHOLE_HITS.get(blocked, 0) + 1
            return True
    return False

def dns_blackhole_add(domains: list):
    """Ajoute des domaines à la blacklist"""
    for d in domains:
        d = d.lower().strip().rstrip(".")
        if d:
            DNS_BLACKHOLE.add(d)
    log.info(f"[DNS-BH] {len(DNS_BLACKHOLE)} domaines dans la blacklist")

def dns_blackhole_remove(domain: str):
    DNS_BLACKHOLE.discard(domain.lower().strip())

# Init avec les domaines par défaut
dns_blackhole_add(DEFAULT_BLACKHOLE_DOMAINS)

# ─── Scan LAN ──────────────────────────────────────────────────────────────
LAN_DEVICES: list = []
LAN_SCAN_RUNNING: bool = False

def _get_local_subnet() -> str:
    """Détecte automatiquement le sous-réseau local"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"

def scan_lan() -> list:
    """Scanne le réseau local et retourne les appareils trouvés"""
    global LAN_SCAN_RUNNING, LAN_DEVICES
    if LAN_SCAN_RUNNING:
        return LAN_DEVICES
    LAN_SCAN_RUNNING = True
    devices = []
    try:
        import socket
        import struct
        import subprocess

        subnet = _get_local_subnet()
        log.info(f"[LAN] Scan du sous-réseau: {subnet}")

        # Méthode 1 : ARP scan via scapy
        if HAS_SCAPY:
            try:
                from scapy.layers.l2 import ARP, Ether
                from scapy.sendrecv import srp
                arp = ARP(pdst=subnet)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = srp(packet, timeout=3, verbose=False)[0]
                for sent, received in result:
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(received.psrc)[0]
                    except Exception:
                        pass
                    devices.append({
                        "ip":       received.psrc,
                        "mac":      received.hwsrc,
                        "hostname": hostname,
                        "vendor":   _mac_vendor(received.hwsrc),
                        "status":   "up",
                        "open_ports": [],
                    })
            except Exception as e:
                log.warning(f"[LAN] ARP scan failed: {e}")

        # Méthode 2 : ping sweep si scapy ne fonctionne pas
        if not devices:
            base = subnet.rsplit(".", 1)[0]
            import concurrent.futures
            def ping_host(i):
                ip = f"{base}.{i}"
                try:
                    _psi = None
                    _pcf = 0
                    if os.name == 'nt':
                        _psi = subprocess.STARTUPINFO()
                        _psi.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                        _psi.wShowWindow = 0
                        _pcf = subprocess.CREATE_NO_WINDOW
                    result = subprocess.run(
                        ["ping", "-n", "1", "-w", "200", ip] if os.name == "nt"
                        else ["ping", "-c", "1", "-W", "1", ip],
                        capture_output=True, timeout=2,
                        startupinfo=_psi, creationflags=_pcf
                    )
                    if result.returncode == 0:
                        hostname = ""
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            pass
                        return {"ip": ip, "mac": "—", "hostname": hostname, "vendor": "—", "status": "up", "open_ports": []}
                except Exception:
                    pass
                return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                results = list(ex.map(ping_host, range(1, 255)))
            devices = [r for r in results if r]

        LAN_DEVICES = devices
        log.info(f"[LAN] {len(devices)} appareils trouvés")

    except Exception as e:
        log.error(f"[LAN] Erreur scan: {e}")
    finally:
        LAN_SCAN_RUNNING = False

    return devices

def _mac_vendor(mac: str) -> str:
    """Identifie le fabricant via les 3 premiers octets du MAC"""
    vendors = {
        "00:50:56": "VMware", "00:0c:29": "VMware", "00:15:5d": "Hyper-V",
        "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
        "00:1a:11": "Google", "f4:f5:d8": "Google",
        "ac:bc:32": "Apple", "3c:22:fb": "Apple", "a4:c3:f0": "Apple",
        "00:50:f2": "Microsoft", "28:18:78": "Microsoft",
        "00:1b:21": "Intel", "8c:ec:4b": "Intel",
        "14:59:c0": "Cisco", "00:1e:bd": "Cisco",
    }
    prefix = mac[:8].lower()
    for k, v in vendors.items():
        if mac.lower().startswith(k.lower()):
            return v
    return "Inconnu"

# ─── Honeypot ──────────────────────────────────────────────────────────────
HONEYPOT_ENABLED: bool = False
HONEYPOT_HITS: list = []
HONEYPOT_SERVERS: list = []

class HoneypotServer:
    """Faux service qui logue toutes les connexions"""
    def __init__(self, port: int, service_name: str, banner: str):
        self.port = port
        self.service_name = service_name
        self.banner = banner.encode() + b"\r\n"
        self.server = None
        self.running = False

    async def handle_client(self, reader, writer):
        ip = writer.get_extra_info('peername')[0]
        log.warning(f"[HONEYPOT] {self.service_name}:{self.port} — connexion de {ip}")

        # Log l'intrusion
        hit = {
            "ts":      datetime.now().strftime("%H:%M:%S"),
            "ip":      ip,
            "port":    self.port,
            "service": self.service_name,
            "country": get_country(ip) or "?",
        }
        HONEYPOT_HITS.append(hit)
        if len(HONEYPOT_HITS) > 200:
            HONEYPOT_HITS.pop(0)

        # Ajouter comme menace
        add_threat(ip, f"Honeypot {self.service_name}", f"Connexion sur faux service port {self.port}", "high")
        auto_block_check(ip)

        try:
            writer.write(self.banner)
            await writer.drain()
            # Lire un peu de données (credentials tentés)
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=5)
                if data:
                    hit["data"] = data.decode(errors="replace")[:100]
                    log.warning(f"[HONEYPOT] Données reçues de {ip}: {hit['data'][:50]}")
            except asyncio.TimeoutError:
                pass
        except Exception:
            pass
        finally:
            writer.close()

    async def start(self):
        try:
            self.server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
            self.running = True
            log.info(f"[HONEYPOT] {self.service_name} sur port {self.port}")
            async with self.server:
                await self.server.serve_forever()
        except Exception as e:
            log.error(f"[HONEYPOT] Erreur port {self.port}: {e}")

HONEYPOT_CONFIGS = [
    (22,   "SSH",   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
    (23,   "Telnet","Welcome to Ubuntu 22.04 LTS"),
    (21,   "FTP",   "220 FTP server ready"),
    (3389, "RDP",   "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x02\x00\x00\x00"),
    (8080, "HTTP",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>"),
]

async def start_honeypots():
    global HONEYPOT_SERVERS
    HONEYPOT_SERVERS = []
    for port, name, banner in HONEYPOT_CONFIGS:
        hp = HoneypotServer(port, name, banner)
        HONEYPOT_SERVERS.append(hp)
        asyncio.create_task(hp.start())
    log.info(f"[HONEYPOT] {len(HONEYPOT_SERVERS)} services honeypot démarrés")

async def handle_ws_command(ws, msg: dict):
    global CLIENTS
    cmd = msg.get("cmd")

    if cmd == "get_state":
        await ws.send(json.dumps(build_state_message()))
    elif cmd == "toggle_rule":
        key = msg.get("rule")
        if key in RULES:
            RULES[key]["enabled"] = not RULES[key]["enabled"]
            await ws.send(json.dumps({"type": "rule_updated", "rule": key, "enabled": RULES[key]["enabled"]}))
    elif cmd == "block_ip":
        ip = msg.get("ip", "")
        reason = msg.get("reason", "Blocage manuel")
        if ip:
            block_ip_os(ip, reason)
            add_threat(ip, "Blocage manuel", reason, "med")
            await ws.send(json.dumps({"type": "ip_blocked", "ip": ip}))
    elif cmd == "unblock_ip":
        ip = msg.get("ip", "")
        if ip:
            unblock_ip_os(ip)
            await ws.send(json.dumps({"type": "ip_unblocked", "ip": ip}))
    elif cmd == "get_blocked_ips":
        await ws.send(json.dumps({"type": "blocked_ips", "ips": list(BLOCKED_IPS)}))
    elif cmd == "traceroute":
        ip = (msg.get("ip") or "").strip()
        max_hops = int(msg.get("max_hops", 30) or 30)
        # Notify start so the UI can show a spinner
        try:
            await ws.send(json.dumps({"type": "traceroute_started", "target": ip, "max_hops": max_hops}))
        except Exception:
            pass
        # Run blocking scapy.sr() in executor — total ~3-6 seconds wall time
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _traceroute, ip, max_hops)
        await ws.send(json.dumps({"type": "traceroute_result", **result}))
    elif cmd == "clear_threats":
        STATE.threats.clear()
        await ws.send(json.dumps({"type": "threats_cleared"}))
    elif cmd == "generate_report":
        rtype = msg.get("report_type", "full")
        fmt   = msg.get("format", "json")
        filt  = msg.get("filter", "all")
        try:
            filepath = run_report(rtype, fmt, filt)
            await ws.send(json.dumps({"type": "report_ready", "path": filepath}))
        except Exception as e:
            await ws.send(json.dumps({"type": "report_error", "error": str(e)}))
    elif cmd == "record_start":
        ok = record_start()
        await ws.send(json.dumps({"type": "record_started", "ok": ok, "path": STATE.record_file_path}))
    elif cmd == "record_stop":
        path = record_stop()
        await ws.send(json.dumps({"type": "record_stopped", "path": path}))
    elif cmd == "record_list":
        files = record_list()
        await ws.send(json.dumps({"type": "record_list", "files": files}))
    elif cmd == "toggle_dpi":
        CFG.dpi_enabled = not CFG.dpi_enabled
        await ws.send(json.dumps({"type": "dpi_toggled", "enabled": CFG.dpi_enabled}))
    elif cmd == "toggle_dpi_mask":
        CFG.dpi_mask_sensitive = not CFG.dpi_mask_sensitive
        await ws.send(json.dumps({"type": "dpi_mask_toggled", "enabled": CFG.dpi_mask_sensitive}))
    elif cmd == "get_dpi_alerts":
        await ws.send(json.dumps({"type": "dpi_alerts", "alerts": list(STATE.dpi_alerts)[:50]}))
    elif cmd == "set_auto_block_hits":
        val = int(msg.get("value", 10))
        CFG.auto_block_hits = max(1, min(50, val))
        await ws.send(json.dumps({"type": "auto_block_updated", "hits": CFG.auto_block_hits}))
    elif cmd == "toggle_auto_block":
        CFG.auto_block_enabled = not CFG.auto_block_enabled
        await ws.send(json.dumps({"type": "auto_block_toggled", "enabled": CFG.auto_block_enabled}))
    elif cmd == "update_param":
        key = msg.get("key", "")
        val = msg.get("value")
        if hasattr(CFG, key) and val is not None:
            try:
                setattr(CFG, key, type(getattr(CFG, key))(val))
                await ws.send(json.dumps({"type": "param_updated", "key": key}))
            except Exception as e:
                await ws.send(json.dumps({"type": "param_error", "error": str(e)}))

    # ── v1.6.0 — Suricata IDS ─────────────────────────────────────────
    elif cmd == "toggle_suricata":
        global SURICATA_ENABLED
        SURICATA_ENABLED = not SURICATA_ENABLED
        await ws.send(json.dumps({"type": "suricata_toggled", "enabled": SURICATA_ENABLED}))

    elif cmd == "get_suricata_stats":
        await ws.send(json.dumps({
            "type":    "suricata_stats",
            "enabled": SURICATA_ENABLED,
            "rules":   SURICATA_LOADED,
            "alerts":  list(STATE.suricata_alerts)[:50],
            "disabled_count": len(SURICATA_DISABLED_SIDS),
        }))

    elif cmd == "suricata_get_rules":
        rules = suricata_get_rules_list()
        search = msg.get("search", "").lower()
        sev_filter = msg.get("severity", "")
        if search:
            rules = [r for r in rules if search in r["msg"].lower() or search in str(r["sid"])]
        if sev_filter:
            rules = [r for r in rules if r["severity"] == sev_filter]
        await ws.send(json.dumps({"type": "suricata_rules_list", "rules": rules, "total": SURICATA_LOADED}))

    elif cmd == "suricata_toggle_rule":
        sid = msg.get("sid", 0)
        if sid in SURICATA_DISABLED_SIDS:
            SURICATA_DISABLED_SIDS.discard(sid)
            enabled = True
        else:
            SURICATA_DISABLED_SIDS.add(sid)
            enabled = False
        save_settings()
        await ws.send(json.dumps({"type": "suricata_rule_toggled", "sid": sid, "enabled": enabled}))

    elif cmd == "suricata_add_custom":
        result = suricata_add_custom_rule(
            msg.get("msg", "Custom Rule"),
            msg.get("pattern", ""),
            msg.get("proto", "TCP"),
            msg.get("severity", "high"),
            msg.get("action", "alert"),
        )
        save_settings()
        await ws.send(json.dumps({"type": "suricata_custom_added", **result}))

    elif cmd == "suricata_delete_rule":
        result = suricata_delete_rule(msg.get("sid", 0))
        save_settings()
        await ws.send(json.dumps({"type": "suricata_rule_deleted", **result}))

    elif cmd == "suricata_export_alerts":
        alerts = list(STATE.suricata_alerts)
        await ws.send(json.dumps({"type": "suricata_alerts_export", "alerts": alerts, "count": len(alerts)}))

    elif cmd == "suricata_clear_alerts":
        STATE.suricata_alerts.clear()
        await ws.send(json.dumps({"type": "suricata_alerts_cleared"}))

    elif cmd == "load_et_rules":
        ruleset = msg.get("ruleset", "et_scan")
        def _load():
            result = load_et_rules_online(ruleset)
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type": "et_rules_loaded", "ruleset": ruleset, **result})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_load, daemon=True).start()
        await ws.send(json.dumps({"type": "et_rules_loading", "ruleset": ruleset}))

    elif cmd == "set_geo_countries":
        global GEO_BLOCKED_COUNTRIES
        countries = msg.get("countries", [])
        GEO_BLOCKED_COUNTRIES = set(countries)
        log.info(f"[GEO] Pays bloqués: {GEO_BLOCKED_COUNTRIES}")
        await ws.send(json.dumps({"type": "geo_updated", "countries": list(GEO_BLOCKED_COUNTRIES)}))
        save_settings()

    # ── DNS Blackhole ──────────────────────────────────────────────────────
    elif cmd == "dns_blackhole_add":
        domains = msg.get("domains", [])
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.replace(",","\n").splitlines() if d.strip()]
        dns_blackhole_add(domains)
        await ws.send(json.dumps({"type":"dns_blackhole_updated","domains":list(DNS_BLACKHOLE),"hits":DNS_BLACKHOLE_HITS}))

    elif cmd == "dns_blackhole_remove":
        dns_blackhole_remove(msg.get("domain",""))
        await ws.send(json.dumps({"type":"dns_blackhole_updated","domains":list(DNS_BLACKHOLE),"hits":DNS_BLACKHOLE_HITS}))

    elif cmd == "dns_blackhole_get":
        await ws.send(json.dumps({"type":"dns_blackhole_updated","domains":sorted(DNS_BLACKHOLE),"hits":DNS_BLACKHOLE_HITS}))

    # ── Scan LAN ───────────────────────────────────────────────────────────
    elif cmd == "scan_lan":
        await ws.send(json.dumps({"type":"lan_scan_started","subnet":_get_local_subnet()}))
        def _do_scan():
            devices = scan_lan()
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type":"lan_scan_result","devices":devices,"count":len(devices)})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_do_scan, daemon=True).start()

    # ── Honeypot ───────────────────────────────────────────────────────────
    elif cmd == "toggle_honeypot":
        global HONEYPOT_ENABLED
        HONEYPOT_ENABLED = not HONEYPOT_ENABLED
        if HONEYPOT_ENABLED and not HONEYPOT_SERVERS:
            asyncio.create_task(start_honeypots())
        await ws.send(json.dumps({"type":"honeypot_toggled","enabled":HONEYPOT_ENABLED,"ports":[p for p,_,_ in HONEYPOT_CONFIGS]}))

    elif cmd == "get_honeypot_hits":
        await ws.send(json.dumps({"type":"honeypot_hits","hits":HONEYPOT_HITS[-50:],"enabled":HONEYPOT_ENABLED}))

    # ══════════════════════════════════════════════════════════════════════
    # v3.0 — Advanced Cybersecurity Commands
    # ══════════════════════════════════════════════════════════════════════

    # ── Anomaly Detection ─────────────────────────────────────────────────
    elif cmd == "toggle_anomaly":
        CFG.anomaly_enabled = not CFG.anomaly_enabled
        await ws.send(json.dumps({"type": "anomaly_toggled", "enabled": CFG.anomaly_enabled}))
    elif cmd == "toggle_profiling":
        CFG.profile_enabled = not CFG.profile_enabled
        await ws.send(json.dumps({"type": "profiling_toggled", "enabled": CFG.profile_enabled}))
    elif cmd == "toggle_correlation":
        CFG.correlation_enabled = not CFG.correlation_enabled
        await ws.send(json.dumps({"type": "correlation_toggled", "enabled": CFG.correlation_enabled}))
    elif cmd == "toggle_ja3":
        CFG.ja3_enabled = not CFG.ja3_enabled
        await ws.send(json.dumps({"type": "ja3_toggled", "enabled": CFG.ja3_enabled}))
    elif cmd == "toggle_entropy":
        CFG.entropy_enabled = not CFG.entropy_enabled
        await ws.send(json.dumps({"type": "entropy_toggled", "enabled": CFG.entropy_enabled}))
    elif cmd == "get_anomaly_alerts":
        await ws.send(json.dumps({"type": "anomaly_alerts", "alerts": list(STATE.anomaly_alerts)[:50]}))
    elif cmd == "get_attack_chains":
        chains = {ip: phases for ip, phases in ATTACK_CHAINS.items() if phases}
        await ws.send(json.dumps({"type": "attack_chains", "chains": chains}, default=str))
    elif cmd == "get_ja3_alerts":
        await ws.send(json.dumps({"type": "ja3_alerts", "alerts": list(STATE.ja3_alerts)[:50]}))
    elif cmd == "get_entropy_alerts":
        await ws.send(json.dumps({"type": "entropy_alerts", "alerts": list(STATE.entropy_alerts)[:50]}))

    # ── Threat Intelligence ───────────────────────────────────────────────
    elif cmd == "set_api_keys":
        if "vt_key" in msg:
            CFG.virustotal_api_key = msg["vt_key"]
            CFG.virustotal_enabled = bool(msg["vt_key"])
        if "otx_key" in msg:
            CFG.otx_api_key = msg["otx_key"]
            CFG.otx_enabled = bool(msg["otx_key"])
        if "abuseipdb_key" in msg:
            CFG.abuseipdb_api_key = msg["abuseipdb_key"]
            CFG.abuseipdb_enabled = bool(msg["abuseipdb_key"])
        save_settings()
        await ws.send(json.dumps({"type": "api_keys_saved", "vt": CFG.virustotal_enabled, "otx": CFG.otx_enabled, "abuseipdb": CFG.abuseipdb_enabled}))
    elif cmd == "toggle_virustotal":
        CFG.virustotal_enabled = not CFG.virustotal_enabled
        await ws.send(json.dumps({"type": "vt_toggled", "enabled": CFG.virustotal_enabled}))
    elif cmd == "toggle_otx":
        CFG.otx_enabled = not CFG.otx_enabled
        if CFG.otx_enabled:
            threading.Thread(target=_otx_fetch_pulses, daemon=True).start()
        await ws.send(json.dumps({"type": "otx_toggled", "enabled": CFG.otx_enabled}))
    elif cmd == "toggle_threat_feeds":
        CFG.threat_feeds_enabled = not CFG.threat_feeds_enabled
        await ws.send(json.dumps({"type": "feeds_toggled", "enabled": CFG.threat_feeds_enabled}))
    elif cmd == "refresh_threat_feeds":
        threading.Thread(target=_fetch_threat_feeds, daemon=True).start()
        await ws.send(json.dumps({"type": "feeds_refreshing"}))
    elif cmd == "get_threat_intel":
        await ws.send(json.dumps({
            "type": "threat_intel",
            "hits": list(STATE.threat_intel_hits)[:50],
            "feed_count": len(THREAT_FEED_IPS),
            "otx_count": len(OTX_IOC_IPS),
            "vt_cache": len(VT_CACHE),
            "feed_last_update": THREAT_FEED_LAST_UPDATE,
        }))
    elif cmd == "lookup_ioc":
        val = msg.get("value", "")
        matches = ioc_match_ip(val) if msg.get("ioc_type") == "ip" else []
        await ws.send(json.dumps({"type": "ioc_result", "value": val, "matches": matches}))

    # ── Active Response ───────────────────────────────────────────────────
    elif cmd == "set_discord_webhook":
        CFG.discord_webhook_url = msg.get("url", "")
        CFG.discord_enabled = bool(CFG.discord_webhook_url)
        if "min_severity" in msg:
            CFG.discord_min_severity = msg["min_severity"]
        save_settings()
        await ws.send(json.dumps({"type": "discord_saved", "enabled": CFG.discord_enabled}))
    elif cmd == "test_discord":
        test_threat = {"src_ip": "TEST", "type": "Test Alert", "description": "Ceci est un test NetGuard Pro", "severity": "high", "country": "TEST", "timestamp": datetime.now().isoformat()}
        threading.Thread(target=_send_discord_alert, args=(test_threat,), daemon=True).start()
        await ws.send(json.dumps({"type": "discord_test_sent"}))
    elif cmd == "set_telegram":
        CFG.telegram_bot_token = msg.get("token", "")
        CFG.telegram_chat_id = msg.get("chat_id", "")
        CFG.telegram_enabled = bool(CFG.telegram_bot_token and CFG.telegram_chat_id)
        if "min_severity" in msg:
            CFG.telegram_min_severity = msg["min_severity"]
        save_settings()
        await ws.send(json.dumps({"type": "telegram_saved", "enabled": CFG.telegram_enabled}))
    elif cmd == "test_telegram":
        test_threat = {"src_ip": "TEST", "type": "Test Alert", "description": "Ceci est un test NetGuard Pro", "severity": "high", "country": "TEST", "timestamp": datetime.now().isoformat()}
        threading.Thread(target=_send_telegram_alert, args=(test_threat,), daemon=True).start()
        await ws.send(json.dumps({"type": "telegram_test_sent"}))
    elif cmd == "isolate_device":
        ip = msg.get("ip", "")
        if ip:
            isolate_device(ip)
            await ws.send(json.dumps({"type": "device_isolated", "ip": ip}))
    elif cmd == "unisolate_device":
        ip = msg.get("ip", "")
        if ip:
            unisolate_device(ip)
            await ws.send(json.dumps({"type": "device_unisolated", "ip": ip}))
    elif cmd == "quarantine_ip":
        ip = msg.get("ip", "")
        if ip:
            quarantine_ip(ip)
            await ws.send(json.dumps({"type": "ip_quarantined", "ip": ip}))
    elif cmd == "unquarantine_ip":
        ip = msg.get("ip", "")
        if ip:
            unquarantine_ip(ip)
            await ws.send(json.dumps({"type": "ip_unquarantined", "ip": ip}))
    elif cmd == "get_forensic_reports":
        await ws.send(json.dumps({"type": "forensic_reports", "reports": list(STATE.forensic_reports)}))
    elif cmd == "generate_forensic":
        ip = msg.get("ip", "")
        if ip:
            def _gen():
                path = generate_forensic_report(ip, "Manuel")
                asyncio.run_coroutine_threadsafe(
                    ws.send(json.dumps({"type": "forensic_generated", "ip": ip, "path": path})),
                    asyncio.get_event_loop()
                )
            threading.Thread(target=_gen, daemon=True).start()
            await ws.send(json.dumps({"type": "forensic_generating", "ip": ip}))

    # ── WireGuard VPN ─────────────────────────────────────────────────────
    elif cmd == "wg_start":
        result = wg_start()
        await ws.send(json.dumps({"type": "wg_started", **result}))
    elif cmd == "wg_stop":
        result = wg_stop()
        await ws.send(json.dumps({"type": "wg_stopped", **result}))
    elif cmd == "wg_status":
        status = wg_get_status()
        await ws.send(json.dumps({"type": "wg_status", **status}))
    elif cmd == "wg_add_peer":
        name = msg.get("name", "")
        if name:
            result = wg_add_peer(name)
            await ws.send(json.dumps({"type": "wg_peer_added", **result}, default=str))
    elif cmd == "wg_remove_peer":
        name = msg.get("name", "")
        if name:
            result = wg_remove_peer(name)
            await ws.send(json.dumps({"type": "wg_peer_removed", **result}))
    elif cmd == "wg_get_peers":
        safe_peers = [{k: v for k, v in p.items() if k not in ("privkey", "preshared_key")} for p in WG_PEERS]
        await ws.send(json.dumps({"type": "wg_peers", "peers": safe_peers}))
    elif cmd == "wg_get_config":
        name = msg.get("name", "")
        peer = next((p for p in WG_PEERS if p["name"] == name), None)
        if peer:
            config = _wg_generate_peer_config(peer)
            await ws.send(json.dumps({"type": "wg_peer_config", "name": name, "config": config}))
    elif cmd == "wg_set_config":
        if "endpoint" in msg:
            CFG.wg_endpoint = msg["endpoint"]
        if "listen_port" in msg:
            CFG.wg_listen_port = int(msg["listen_port"])
        if "address" in msg:
            CFG.wg_address = msg["address"]
        if "dns" in msg:
            CFG.wg_dns = msg["dns"]
        save_settings()
        await ws.send(json.dumps({"type": "wg_config_saved"}))

    # ══════════════════════════════════════════════════════════════════════
    # v4.0 — New Modules: Vulnerability / Backup / Incidents / Training / NAC / IAM
    # ══════════════════════════════════════════════════════════════════════

    # ── Vulnerability Scanner ──────────────────────────────────────────
    elif cmd == "vuln_port_scan":
        target = msg.get("target", "127.0.0.1")
        port_range = msg.get("ports", "1-1024")
        def _scan():
            results = vuln_scan_ports(target, port_range)
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type": "vuln_scan_result", "target": target, **results})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_scan, daemon=True).start()
        await ws.send(json.dumps({"type": "vuln_scan_started", "target": target}))

    elif cmd == "vuln_cve_lookup":
        cve_id = msg.get("cve", "")
        def _lookup():
            result = vuln_cve_lookup(cve_id)
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type": "vuln_cve_result", "cve": cve_id, **result})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_lookup, daemon=True).start()

    elif cmd == "vuln_system_check":
        def _check():
            result = vuln_system_check()
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type": "vuln_system_result", **result})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_check, daemon=True).start()
        await ws.send(json.dumps({"type": "vuln_system_checking"}))

    elif cmd == "vuln_get_history":
        await ws.send(json.dumps({"type": "vuln_history", "scans": list(VULN_SCAN_HISTORY)}))

    # ── Backup & Recovery ──────────────────────────────────────────────
    elif cmd == "backup_create":
        name = msg.get("name", "")
        include = msg.get("include", ["settings", "rules", "blocked"])
        def _backup():
            result = backup_create(name, include)
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type": "backup_created", **result})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_backup, daemon=True).start()
        await ws.send(json.dumps({"type": "backup_creating"}))

    elif cmd == "backup_restore":
        filename = msg.get("filename", "")
        def _restore():
            result = backup_restore(filename)
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type": "backup_restored", **result})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_restore, daemon=True).start()
        await ws.send(json.dumps({"type": "backup_restoring"}))

    elif cmd == "backup_list":
        backups = backup_list()
        await ws.send(json.dumps({"type": "backup_list", "backups": backups}))

    elif cmd == "backup_delete":
        result = backup_delete(msg.get("filename", ""))
        await ws.send(json.dumps({"type": "backup_deleted", **result}))

    elif cmd == "backup_schedule":
        BACKUP_SCHEDULE["enabled"] = msg.get("enabled", False)
        BACKUP_SCHEDULE["interval_hours"] = msg.get("interval", 24)
        save_settings()
        await ws.send(json.dumps({"type": "backup_schedule_set", **BACKUP_SCHEDULE}))

    # ── Incident Response / Ticketing ──────────────────────────────────
    elif cmd == "incident_create":
        ticket = incident_create(
            msg.get("title", ""),
            msg.get("description", ""),
            msg.get("severity", "medium"),
            msg.get("assigned_to", ""),
            msg.get("related_ip", ""),
        )
        await ws.send(json.dumps({"type": "incident_created", "ticket": ticket}))

    elif cmd == "incident_update":
        ticket_id = msg.get("id", "")
        updates = {k: v for k, v in msg.items() if k in ("status", "notes", "assigned_to", "severity")}
        result = incident_update(ticket_id, updates)
        await ws.send(json.dumps({"type": "incident_updated", **result}))

    elif cmd == "incident_list":
        status_filter = msg.get("status", "")
        tickets = incident_list(status_filter)
        await ws.send(json.dumps({"type": "incident_list", "tickets": tickets}))

    elif cmd == "incident_get":
        ticket = incident_get(msg.get("id", ""))
        await ws.send(json.dumps({"type": "incident_detail", "ticket": ticket}))

    elif cmd == "incident_delete":
        result = incident_delete(msg.get("id", ""))
        await ws.send(json.dumps({"type": "incident_deleted", **result}))

    # ── Training & Awareness ──────────────────────────────────────────
    elif cmd == "training_get_modules":
        await ws.send(json.dumps({"type": "training_modules", "modules": TRAINING_MODULES}))

    elif cmd == "training_submit_quiz":
        module_id = msg.get("module_id", "")
        answers = msg.get("answers", {})
        result = training_submit_quiz(module_id, answers)
        await ws.send(json.dumps({"type": "training_quiz_result", **result}))

    elif cmd == "training_get_scores":
        await ws.send(json.dumps({"type": "training_scores", "scores": TRAINING_SCORES}))

    elif cmd == "training_phishing_sim":
        result = training_phishing_sim(msg.get("target_email", ""))
        await ws.send(json.dumps({"type": "training_phishing_started", **result}))

    # ── NAC Enhanced ──────────────────────────────────────────────────
    elif cmd == "nac_approve_device":
        ip = msg.get("ip", "")
        mac = msg.get("mac", "")
        name = msg.get("name", "")
        nac_approve_device(ip, mac, name)
        await ws.send(json.dumps({"type": "nac_device_approved", "ip": ip, "mac": mac}))

    elif cmd == "nac_deny_device":
        ip = msg.get("ip", "")
        mac = msg.get("mac", "")
        nac_deny_device(ip, mac)
        await ws.send(json.dumps({"type": "nac_device_denied", "ip": ip, "mac": mac}))

    elif cmd == "nac_get_devices":
        await ws.send(json.dumps({"type": "nac_devices", "approved": NAC_APPROVED, "denied": NAC_DENIED, "pending": NAC_PENDING}))

    elif cmd == "nac_set_policy":
        NAC_POLICY.update({k: v for k, v in msg.items() if k in ("default_action", "require_approval", "mac_filter")})
        save_settings()
        await ws.send(json.dumps({"type": "nac_policy_set", "policy": NAC_POLICY}))

    # ── IAM Enhanced ──────────────────────────────────────────────────
    elif cmd == "iam_create_user":
        result = iam_create_user(
            msg.get("username", ""),
            msg.get("password", ""),
            msg.get("role", "viewer"),
            msg.get("email", ""),
        )
        await ws.send(json.dumps({"type": "iam_user_created", **result}))

    elif cmd == "iam_delete_user":
        result = iam_delete_user(msg.get("username", ""))
        await ws.send(json.dumps({"type": "iam_user_deleted", **result}))

    elif cmd == "iam_list_users":
        users = iam_list_users()
        await ws.send(json.dumps({"type": "iam_users", "users": users}))

    elif cmd == "iam_update_role":
        result = iam_update_role(msg.get("username", ""), msg.get("role", "viewer"))
        await ws.send(json.dumps({"type": "iam_role_updated", **result}))

    elif cmd == "iam_toggle_mfa":
        result = iam_toggle_mfa(msg.get("username", ""))
        await ws.send(json.dumps({"type": "iam_mfa_toggled", **result}))

    elif cmd == "iam_get_sessions":
        await ws.send(json.dumps({"type": "iam_sessions", "sessions": list(IAM_SESSIONS.values())}))


# ═══════════════════════════════════════════════════════════════════════════
# PYWEBVIEW API — Native window mode (direct JS bridge, no WebSocket)
# ═══════════════════════════════════════════════════════════════════════════

class _FakeWS:
    """Fake WebSocket that captures responses for pywebview API"""
    def __init__(self):
        self.responses = []
    async def send(self, data):
        self.responses.append(json.loads(data))

class NetGuardAPI:
    """API exposed to JavaScript via pywebview.api — instant calls, no WebSocket"""

    def __init__(self):
        self._window = None
        self._stop_broadcast = False
        self._loop = None

    def set_window(self, window):
        self._window = window

    def get_state(self):
        return json.loads(json.dumps(build_state_message(), default=str))

    def send_command(self, cmd, params=None):
        """Generic command handler — routes any command through the existing handler"""
        if params is None:
            params = {}
        msg = {"cmd": cmd, **params}

        fake_ws = _FakeWS()
        loop = self._loop
        if loop and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(handle_ws_command(fake_ws, msg), loop)
            try:
                future.result(timeout=30)
            except Exception as e:
                return {"type": "error", "message": str(e)}
        else:
            try:
                asyncio.run(handle_ws_command(fake_ws, msg))
            except Exception as e:
                return {"type": "error", "message": str(e)}

        if fake_ws.responses:
            return fake_ws.responses[-1]
        return {"type": "ack", "cmd": cmd}

    # ── Startup & Tray ────────────────────────────────────────────────
    def get_startup_state(self):
        if not HAS_STARTUP_UTILS:
            return {"enabled": False, "available": False}
        return {"enabled": is_startup_enabled("NetGuard Pro"), "available": True}

    def toggle_startup_boot(self):
        if not HAS_STARTUP_UTILS:
            return {"enabled": False, "available": False}
        bat_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "LANCER_NETGUARD.bat")
        new_state = toggle_startup_reg("NetGuard Pro", bat_path)
        return {"enabled": new_state, "available": True}

    def minimize_to_tray(self):
        if not HAS_STARTUP_UTILS or not self._window:
            return {"success": False}
        def _on_quit():
            if self._window:
                self._window.destroy()
        minimize_to_tray(self._window, "NetGuard Pro", on_quit=_on_quit)
        return {"success": True}

    def get_all_startup_states(self):
        if not HAS_STARTUP_UTILS:
            return {}
        return get_all_startup_states()

    def _ensure_ai_server(self) -> dict:
        """Boot netguard_ai_server.py on port 8770 if not already running. Idempotent."""
        import socket as _socket
        import subprocess as _sp
        import time as _time

        port = 8770
        here = os.path.dirname(os.path.abspath(__file__))

        def _is_up() -> bool:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                return s.connect_ex(("127.0.0.1", port)) == 0
            finally:
                s.close()

        if _is_up():
            return {"success": True, "already_running": True, "port": port}

        script = os.path.join(here, "netguard_ai_server.py")
        if not os.path.isfile(script):
            return {"success": False, "error": "ai_server_missing"}
        flags = _sp.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            _sp.Popen([sys.executable, script, "--no-browser"],
                      cwd=here, creationflags=flags)
        except Exception as e:
            return {"success": False, "error": f"spawn_failed: {e}"}
        for _ in range(25):
            if _is_up():
                return {"success": True, "spawned": True, "port": port}
            _time.sleep(0.2)
        return {"success": False, "error": "server_not_responding"}

    def start_ai_server(self):
        """Spawn the AI server quietly (no browser). Used by the inline dashboard chat drawer."""
        return self._ensure_ai_server()

    def open_ai_window(self, lang="fr"):
        """Boot the AI server and open the standalone window in the default browser."""
        import webbrowser as _wb
        boot = self._ensure_ai_server()
        if not boot.get("success"):
            return boot
        if lang not in ("fr", "en", "es"):
            lang = "fr"
        port = boot.get("port", 8770)
        _wb.open(f"http://127.0.0.1:{port}/?lang={lang}")
        return {"success": True, "url": f"http://127.0.0.1:{port}/?lang={lang}"}


def _pywebview_state_broadcast(api):
    """Background thread: push state to pywebview window periodically"""
    save_counter = 0
    while not api._stop_broadcast:
        try:
            snapshot_traffic()
            save_counter += 1
            if save_counter >= 30:
                save_settings()
                save_counter = 0
            if api._window:
                state = build_state_message()
                js_data = json.dumps(state, default=str)
                api._window.evaluate_js(f"if(typeof handleMsg==='function')handleMsg({js_data})")
        except Exception:
            pass
        time.sleep(1)


async def broadcast_state():
    global CLIENTS
    save_counter = 0
    while True:
        await asyncio.sleep(1)
        snapshot_traffic()
        save_counter += 1
        if save_counter >= 30:
            save_settings()
            save_counter = 0
        if CLIENTS:
            msg = json.dumps(build_state_message())
            dead = set()
            for ws in list(CLIENTS):  # Copy to avoid RuntimeError: Set changed size
                try:
                    await ws.send(msg)
                except Exception:
                    dead.add(ws)
            CLIENTS -= dead

# ── WebSocket authentication (Phase 1 hardening) ────────────────────────
_TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".netguard_token")
WS_TOKEN: str = ""

def _load_or_create_token() -> str:
    """Load WS auth token from disk, or generate a new 32-byte URL-safe token. File chmod 0600."""
    global WS_TOKEN
    try:
        if os.path.exists(_TOKEN_FILE):
            with open(_TOKEN_FILE, "r", encoding="utf-8") as f:
                existing = f.read().strip()
            if len(existing) >= 32:
                WS_TOKEN = existing
                return WS_TOKEN
    except OSError as e:
        log.warning(f"[AUTH] Cannot read token file: {e}")
    WS_TOKEN = _ng_secrets.token_urlsafe(32)
    try:
        with open(_TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(WS_TOKEN)
        try:
            os.chmod(_TOKEN_FILE, 0o600)
        except OSError:
            pass
        log.info(f"[AUTH] WS token generated -> {_TOKEN_FILE}")
    except OSError as e:
        log.error(f"[AUTH] Cannot write token file: {e}")
    return WS_TOKEN

# CSRF protection: only browsers with these origins (or no origin) may connect
_ALLOWED_ORIGIN_PREFIXES = (
    "http://localhost", "https://localhost",
    "http://127.0.0.1", "https://127.0.0.1",
    "http://[::1]", "https://[::1]",
    "file://",
)

async def _check_origin(connection, request):
    """websockets process_request callback: reject non-local Origin (CSRF defence)."""
    try:
        origin = request.headers.get("Origin")
    except Exception:
        origin = None
    if origin is None or origin == "null":
        return None  # file:// or pywebview — allow
    for prefix in _ALLOWED_ORIGIN_PREFIXES:
        if origin == prefix or origin.startswith(prefix + ":") or origin.startswith(prefix + "/"):
            return None
    log.warning(f"[AUTH] Rejected WS connection from origin: {origin}")
    try:
        from http import HTTPStatus
        return connection.respond(HTTPStatus.FORBIDDEN, b"Origin not allowed\n")
    except Exception:
        return None

async def ws_handler(websocket):
    global CLIENTS
    log.info(f"[WS] Client connecting: {websocket.remote_address}")
    # Auth gate — require {"cmd":"auth","token":WS_TOKEN} as the very first message
    try:
        first_raw = await asyncio.wait_for(websocket.recv(), timeout=5.0)
        try:
            first_msg = json.loads(first_raw)
        except json.JSONDecodeError:
            first_msg = {}
        if (not isinstance(first_msg, dict)
                or first_msg.get("cmd") != "auth"
                or not WS_TOKEN
                or not _ng_secrets.compare_digest(str(first_msg.get("token", "")), WS_TOKEN)):
            log.warning(f"[AUTH] WS auth failed from {websocket.remote_address}")
            try:
                await websocket.send(json.dumps({"type": "auth_failed"}))
            except Exception:
                pass
            await websocket.close(code=4401, reason="Unauthorized")
            return
    except asyncio.TimeoutError:
        try:
            await websocket.close(code=4408, reason="Auth timeout")
        except Exception:
            pass
        return
    except Exception as e:
        log.debug(f"[AUTH] WS handshake error: {e}")
        return
    # Authenticated
    try:
        await websocket.send(json.dumps({"type": "auth_ok"}))
    except Exception:
        return
    CLIENTS.add(websocket)
    log.info(f"[WS] Client authenticated: {websocket.remote_address}")
    try:
        await websocket.send(json.dumps(build_state_message()))
        async for raw in websocket:
            try:
                msg = json.loads(raw)
                if isinstance(msg, dict) and msg.get("cmd") == "auth":
                    continue  # already authenticated; ignore late auth attempts
                await handle_ws_command(websocket, msg)
            except json.JSONDecodeError:
                pass
    except Exception as e:
        log.debug(f"[WS] Client déconnecté: {e}")
    finally:
        CLIENTS.discard(websocket)

def auto_select_interface() -> str:
    if not HAS_SCAPY:
        return "eth0"
    # On Windows, use friendly names to find the real active interface
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
            # Priority: real network adapters with an IPv4 address (not 169.254.x.x)
            preferred = ["Wi-Fi", "Ethernet", "Wireless", "Realtek", "Intel", "MediaTek"]
            for pref in preferred:
                for iface in win_ifaces:
                    name = iface.get("name", "")
                    desc = iface.get("description", "")
                    ips  = iface.get("ips", [])
                    # Must have a real IPv4 address (not link-local 169.254.x.x)
                    has_ipv4 = any(
                        ip.count(".") == 3 and not ip.startswith("169.254.") and ip != "127.0.0.1"
                        for ip in ips
                    )
                    if has_ipv4 and (pref.lower() in name.lower() or pref.lower() in desc.lower()):
                        guid = iface.get("guid", "")
                        npf = f"\\Device\\NPF_{guid}" if guid else name
                        log.info(f"[AUTO] Interface trouvée: {name} ({desc}) -> {npf}")
                        return npf
            # Fallback: any interface with a real IPv4
            for iface in win_ifaces:
                ips = iface.get("ips", [])
                has_ipv4 = any(
                    ip.count(".") == 3 and not ip.startswith("169.254.") and ip != "127.0.0.1"
                    for ip in ips
                )
                if has_ipv4:
                    guid = iface.get("guid", "")
                    npf = f"\\Device\\NPF_{guid}" if guid else iface.get("name", "")
                    log.info(f"[AUTO] Fallback interface: {iface.get('name','')} -> {npf}")
                    return npf
        except Exception as e:
            log.warning(f"[AUTO] Windows interface detection failed: {e}")
    # Linux/Mac fallback
    ifaces = get_if_list()
    for pref in ["wlan0", "wlan1", "eth0", "en0", "Wi-Fi", "Ethernet"]:
        for iface in ifaces:
            if pref.lower() in iface.lower():
                return iface
    return ifaces[0] if ifaces else "eth0"

def start_capture(interface: str):
    if not HAS_SCAPY:
        log.error("scapy non disponible. Installe avec: pip install scapy")
        log.error("Sur Windows, installe aussi Npcap: https://npcap.com/#download")
        sys.exit(1)
    log.info(f"[CAPTURE] Démarrage sur: {interface}")

    def safe_analyze(pkt):
        try:
            analyze_packet(pkt)
        except Exception as e:
            log.debug(f"[CAPTURE] Packet analysis error: {e}")

    try:
        sniff(iface=interface, prn=safe_analyze, store=False)
    except PermissionError:
        log.error("ERREUR: Permissions insuffisantes. Lance en tant qu'Administrateur.")
        sys.exit(1)
    except Exception as e:
        log.error(f"Erreur capture: {e}")
        sys.exit(1)

async def main_async(interface: str):
    threading.Thread(target=start_capture, args=(interface,), daemon=True).start()
    # v3.0 — Start threat feeds
    if CFG.threat_feeds_enabled:
        _schedule_feed_refresh()
    if CFG.otx_enabled:
        threading.Thread(target=_otx_fetch_pulses, daemon=True).start()
    # v3.0 — WireGuard
    if CFG.wg_enabled:
        _wg_init_server()
        _wg_load_peers()
    log.info(f"[WS] Serveur WebSocket sur ws://localhost:{CFG.ws_port}")
    if HAS_WS:
        try:
            ver = tuple(int(x) for x in websockets.__version__.split(".")[:2])
        except Exception:
            ver = (0, 0)

        if ver >= (14, 0):
            # websockets 14+ : serve() est un context manager async
            async with websockets.serve(ws_handler, "localhost", CFG.ws_port,
                                        process_request=_check_origin,
                                        max_size=1_048_576):
                log.info("[WS] Serveur démarré (websockets 14+)")
                await broadcast_state()
        else:
            # websockets < 14 : serve() retourne un objet awaitable
            server = await websockets.serve(ws_handler, "localhost", CFG.ws_port,
                                            process_request=_check_origin,
                                            max_size=1_048_576)
            log.info("[WS] Serveur démarré (websockets legacy)")
            await broadcast_state()
    else:
        while True:
            await asyncio.sleep(1)
            snapshot_traffic()

SETTINGS_FILE = "netguard_settings.json"

def save_settings():
    """Sauvegarde les settings dans un fichier JSON"""
    try:
        settings = {
            "rules": {k: v["enabled"] for k, v in RULES.items()},
            "blocked_ips": list(BLOCKED_IPS),
            "geo_blocked_countries": list(GEO_BLOCKED_COUNTRIES),
            "auto_block_enabled": CFG.auto_block_enabled,
            "auto_block_hits": CFG.auto_block_hits,
            "dpi_enabled": CFG.dpi_enabled,
            "dpi_mask_sensitive": CFG.dpi_mask_sensitive,
            "suricata_enabled": SURICATA_ENABLED,
            "suricata_disabled_sids": list(SURICATA_DISABLED_SIDS),
            "suricata_custom_rules": SURICATA_CUSTOM_RULES,
            "suricata_rule_hits": dict(SURICATA_RULE_HITS),
            # v3.0
            "anomaly_enabled": CFG.anomaly_enabled,
            "anomaly_zscore": CFG.anomaly_zscore,
            "profile_enabled": CFG.profile_enabled,
            "correlation_enabled": CFG.correlation_enabled,
            "ja3_enabled": CFG.ja3_enabled,
            "entropy_enabled": CFG.entropy_enabled,
            "entropy_threshold": CFG.entropy_threshold,
            "virustotal_api_key": CFG.virustotal_api_key,
            "virustotal_enabled": CFG.virustotal_enabled,
            "otx_api_key": CFG.otx_api_key,
            "otx_enabled": CFG.otx_enabled,
            "abuseipdb_api_key": CFG.abuseipdb_api_key,
            "abuseipdb_enabled": CFG.abuseipdb_enabled,
            "threat_feeds_enabled": CFG.threat_feeds_enabled,
            "discord_webhook_url": CFG.discord_webhook_url,
            "discord_enabled": CFG.discord_enabled,
            "discord_min_severity": CFG.discord_min_severity,
            "telegram_bot_token": CFG.telegram_bot_token,
            "telegram_chat_id": CFG.telegram_chat_id,
            "telegram_enabled": CFG.telegram_enabled,
            "telegram_min_severity": CFG.telegram_min_severity,
            "isolation_enabled": CFG.isolation_enabled,
            "quarantine_enabled": CFG.quarantine_enabled,
            "auto_forensic_enabled": CFG.auto_forensic_enabled,
            "auto_forensic_severity": CFG.auto_forensic_severity,
            # WireGuard
            "wg_enabled": CFG.wg_enabled,
            "wg_listen_port": CFG.wg_listen_port,
            "wg_address": CFG.wg_address,
            "wg_dns": CFG.wg_dns,
            "wg_endpoint": CFG.wg_endpoint,
            "wg_interface": CFG.wg_interface,
            # v4.0 — New Modules
            "nac_approved": NAC_APPROVED,
            "nac_denied": NAC_DENIED,
            "nac_policy": NAC_POLICY,
            "backup_schedule": BACKUP_SCHEDULE,
            # password_hash is now persisted (settings.json is 0600 — Phase 2.2 hardening)
            "iam_users": dict(IAM_USERS),
            "incidents": INCIDENTS[:50],
            "training_scores": TRAINING_SCORES,
            "detection_params": {
                k: DETECTION_PARAMS[k]["value"]
                for k in DETECTION_PARAMS
            } if 'DETECTION_PARAMS' in globals() else {},
        }
        _secure_json_write(SETTINGS_FILE, settings)
        log.info(f"[SETTINGS] Sauvegardé → {SETTINGS_FILE}")
    except Exception as e:
        log.error(f"[SETTINGS] Erreur sauvegarde: {e}")

def load_settings():
    """Charge les settings depuis le fichier JSON"""
    global GEO_BLOCKED_COUNTRIES, SURICATA_ENABLED, SURICATA_DISABLED_SIDS, SURICATA_CUSTOM_RULES, SURICATA_LOADED
    if not os.path.exists(SETTINGS_FILE):
        log.info("[SETTINGS] Aucun fichier de settings trouvé — paramètres par défaut")
        return
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)

        # Règles
        for k, enabled in s.get("rules", {}).items():
            if k in RULES:
                RULES[k]["enabled"] = enabled

        # IPs bloquées
        for ip in s.get("blocked_ips", []):
            BLOCKED_IPS.add(ip)

        # Géoblocage
        GEO_BLOCKED_COUNTRIES = set(s.get("geo_blocked_countries", []))

        # Config
        CFG.auto_block_enabled  = s.get("auto_block_enabled", True)
        CFG.auto_block_hits     = s.get("auto_block_hits", 10)
        CFG.dpi_enabled         = s.get("dpi_enabled", True)
        CFG.dpi_mask_sensitive  = s.get("dpi_mask_sensitive", True)
        SURICATA_ENABLED        = s.get("suricata_enabled", True)
        SURICATA_DISABLED_SIDS  = set(s.get("suricata_disabled_sids", []))
        SURICATA_RULE_HITS.update(s.get("suricata_rule_hits", {}))
        # Recharger les règles custom
        for cr in s.get("suricata_custom_rules", []):
            try:
                pattern = re.compile(cr["pattern_str"].encode() if isinstance(cr["pattern_str"], str) else cr["pattern_str"],
                                    re.DOTALL | re.IGNORECASE)
                existing_sids = {r["sid"] for r in SURICATA_RULES}
                if cr["sid"] not in existing_sids:
                    SURICATA_RULES.append({
                        "sid": cr["sid"], "msg": cr["msg"], "pattern": pattern,
                        "proto": cr.get("proto", "TCP"), "action": cr.get("action", "alert"),
                        "severity": cr.get("severity", "high"), "custom": True,
                        "pattern_str": cr["pattern_str"],
                    })
                    SURICATA_CUSTOM_RULES.append(cr)
            except Exception:
                pass
        SURICATA_LOADED = len(SURICATA_RULES)

        # v3.0
        CFG.anomaly_enabled       = s.get("anomaly_enabled", True)
        CFG.anomaly_zscore        = s.get("anomaly_zscore", 3.0)
        CFG.profile_enabled       = s.get("profile_enabled", True)
        CFG.correlation_enabled   = s.get("correlation_enabled", True)
        CFG.ja3_enabled           = s.get("ja3_enabled", True)
        CFG.entropy_enabled       = s.get("entropy_enabled", True)
        CFG.entropy_threshold     = s.get("entropy_threshold", 3.5)
        CFG.virustotal_api_key    = s.get("virustotal_api_key", "")
        CFG.virustotal_enabled    = s.get("virustotal_enabled", False)
        CFG.otx_api_key           = s.get("otx_api_key", "")
        CFG.otx_enabled           = s.get("otx_enabled", False)
        CFG.abuseipdb_api_key     = s.get("abuseipdb_api_key", "")
        CFG.abuseipdb_enabled     = s.get("abuseipdb_enabled", False)
        CFG.threat_feeds_enabled  = s.get("threat_feeds_enabled", True)
        CFG.discord_webhook_url   = s.get("discord_webhook_url", "")
        CFG.discord_enabled       = s.get("discord_enabled", False)
        CFG.discord_min_severity  = s.get("discord_min_severity", "high")
        CFG.telegram_bot_token    = s.get("telegram_bot_token", "")
        CFG.telegram_chat_id      = s.get("telegram_chat_id", "")
        CFG.telegram_enabled      = s.get("telegram_enabled", False)
        CFG.telegram_min_severity = s.get("telegram_min_severity", "high")
        CFG.isolation_enabled     = s.get("isolation_enabled", False)
        CFG.quarantine_enabled    = s.get("quarantine_enabled", False)
        CFG.auto_forensic_enabled = s.get("auto_forensic_enabled", True)
        CFG.auto_forensic_severity= s.get("auto_forensic_severity", "critical")
        # WireGuard
        CFG.wg_enabled      = s.get("wg_enabled", False)
        CFG.wg_listen_port  = s.get("wg_listen_port", 51820)
        CFG.wg_address      = s.get("wg_address", "10.66.66.1/24")
        CFG.wg_dns          = s.get("wg_dns", "1.1.1.1, 9.9.9.9")
        CFG.wg_endpoint     = s.get("wg_endpoint", "")
        CFG.wg_interface    = s.get("wg_interface", "wg0")

        # v4.0 — New Modules
        global NAC_APPROVED, NAC_DENIED, NAC_POLICY, BACKUP_SCHEDULE, INCIDENTS, INCIDENT_COUNTER, TRAINING_SCORES
        NAC_APPROVED = s.get("nac_approved", [])
        NAC_DENIED = s.get("nac_denied", [])
        NAC_POLICY.update(s.get("nac_policy", {}))
        BACKUP_SCHEDULE.update(s.get("backup_schedule", {}))
        INCIDENTS = s.get("incidents", [])
        INCIDENT_COUNTER = len(INCIDENTS)
        TRAINING_SCORES = s.get("training_scores", {})

        log.info(f"[SETTINGS] Chargé — {len(BLOCKED_IPS)} IPs bloquées, {len(GEO_BLOCKED_COUNTRIES)} pays géobloqués")
    except Exception as e:
        log.error(f"[SETTINGS] Erreur chargement: {e}")

def _common_init():
    """Common setup for both pywebview and WebSocket modes"""
    parser = argparse.ArgumentParser(description="NetGuard Pro — Surveillance réseau")
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--port",      type=int, default=8765)
    parser.add_argument("--no-block",  action="store_true")
    args = parser.parse_args()

    CFG.ws_port   = args.port
    CFG.can_block = not args.no_block

    interface = args.interface
    if interface == "auto":
        interface = auto_select_interface()
        log.info(f"[AUTO] Interface sélectionnée: {interface}")

    os.makedirs(CFG.record_dir, exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    load_settings()
    _load_or_create_token()

    return interface, args


def main_webview():
    """Launch with pywebview — native window, direct API calls"""
    interface, args = _common_init()

    try:
        print("""
+--------------------------------------------------------------+
|       NetGuard Pro v4.1.0 -- Fenetre native (pywebview)      |
+--------------------------------------------------------------+
|  IDS - DPI - Honeypot - DNS BH - Scan LAN - GeoBlock        |
|  Anomaly Detection - JA3 - Entropy - Attack Correlation      |
|  Threat Intel (VT/OTX/Feeds) - Discord/Telegram Alerts       |
|  Device Isolation - Quarantine - Forensic - WireGuard VPN    |
+--------------------------------------------------------------+
""")
    except UnicodeEncodeError:
        print("[NetGuard Pro v4.1.0] Demarrage (pywebview)...")

    log.info("[MODE] Protection active" if CFG.can_block else "[MODE] Surveillance uniquement")

    # Start packet capture in background
    threading.Thread(target=start_capture, args=(interface,), daemon=True).start()

    # Start threat feeds
    if CFG.threat_feeds_enabled:
        _schedule_feed_refresh()
    if CFG.otx_enabled:
        threading.Thread(target=_otx_fetch_pulses, daemon=True).start()
    if CFG.wg_enabled:
        _wg_init_server()
        _wg_load_peers()

    # Start async event loop in background thread for async command handling + WS server
    loop = asyncio.new_event_loop()
    def _run_loop():
        asyncio.set_event_loop(loop)
        # Also start WebSocket server so map.html and other pages can connect
        async def _start_ws_and_run():
            if HAS_WS:
                try:
                    ver = tuple(int(x) for x in websockets.__version__.split(".")[:2])
                except Exception:
                    ver = (0, 0)
                try:
                    if ver >= (14, 0):
                        async with websockets.serve(ws_handler, "localhost", CFG.ws_port,
                                                    process_request=_check_origin,
                                                    max_size=1_048_576):
                            log.info(f"[WS] Serveur WebSocket demarre sur ws://localhost:{CFG.ws_port} (pywebview+WS)")
                            await broadcast_state()
                    else:
                        server = await websockets.serve(ws_handler, "localhost", CFG.ws_port,
                                                        process_request=_check_origin,
                                                        max_size=1_048_576)
                        log.info(f"[WS] Serveur WebSocket demarre sur ws://localhost:{CFG.ws_port} (pywebview+WS)")
                        await broadcast_state()
                except OSError as e:
                    log.warning(f"[WS] Port {CFG.ws_port} deja utilise, mode pywebview-only: {e}")
                    while True:
                        await asyncio.sleep(1)
            else:
                while True:
                    await asyncio.sleep(1)
        loop.run_until_complete(_start_ws_and_run())
    threading.Thread(target=_run_loop, daemon=True).start()

    api = NetGuardAPI()
    api._loop = loop

    dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netguard_dashboard.html")

    window = webview.create_window(
        "NetGuard Pro v4.1.0",
        dashboard_path,
        js_api=api,
        width=1360,
        height=860,
        min_size=(1000, 650),
        background_color="#0f0f13",
        maximized=True,
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
        loop.call_soon_threadsafe(loop.stop)
        save_settings()
        print("[*] NetGuard Pro ferme.")


def main():
    # --headless flag: run in WebSocket-only mode (no window), used by Cortex
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    if not headless and HAS_WEBVIEW:
        print("[*] pywebview detecte -- lancement en mode fenetre native")
        main_webview()
        return

    # WebSocket-only mode (headless or no pywebview)
    interface, args = _common_init()
    mode_label = "headless (Cortex)" if headless else "WebSocket"
    try:
        print(f"""
+--------------------------------------------------------------+
|       NetGuard Pro v4.1.0 -- Mode {mode_label:<24}|
+--------------------------------------------------------------+
|  IDS - DPI - Honeypot - DNS BH - Scan LAN - GeoBlock        |
|  Anomaly Detection - JA3 - Entropy - Attack Correlation      |
|  Threat Intel (VT/OTX/Feeds) - Discord/Telegram Alerts       |
|  Device Isolation - Quarantine - Forensic - WireGuard VPN    |
+--------------------------------------------------------------+
""")
    except UnicodeEncodeError:
        print("[NetGuard Pro v4.1.0] Demarrage...")
    log.info("[MODE] Protection active" if CFG.can_block else "[MODE] Surveillance uniquement")
    try:
        asyncio.run(main_async(interface))
    except KeyboardInterrupt:
        log.info("Arrêt de NetGuard Pro — sauvegarde des settings...")
        save_settings()

if __name__ == "__main__":
    main()
