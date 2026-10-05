"""
NetGuard AI Suite — License Manager
Trial period (30 days) + feature gating + Ed25519-signed license activation
+ multi-PC seat management (HMAC-signed local activation registry).
"""
import os
import sys
import json
import time
import hmac
import hashlib
import base64
import platform
import socket
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Config ──────────────────────────────────────────────────────────
try:
    from netguard_paths import data_path as _ng_data_path
    LICENSE_FILE = _ng_data_path("netguard_license.json")   # writable even in Store/MSIX installs
except Exception:  # pragma: no cover — standalone use of this module
    LICENSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netguard_license.json")
TRIAL_DAYS = 30

# Activation registry — kept OUTSIDE the vault on purpose so licensing works
# before the vault is unlocked (vault is a paid feature behind licensing).
try:
    # Writable data dir (frozen / Program Files installs are read-only)
    from netguard_paths import DATA_DIR as _NG_DATA_DIR, is_frozen as _ng_is_frozen
    _ACT_DEFAULT = _NG_DATA_DIR if _ng_is_frozen() else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "argus_data")
except Exception:  # pragma: no cover
    _ACT_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "argus_data")
ACTIVATIONS_DIR = os.environ.get("NETGUARD_DATA_DIR", _ACT_DEFAULT)

# Where the "Acheter" button of the dashboard sends the user (Stripe Payment Link).
PURCHASE_URL = os.environ.get(
    "NETGUARD_PURCHASE_URL",
    "https://buy.stripe.com/4gMeVc4IF15G4FRfND7ok00",
)

# Second, independent record of the first launch: deleting netguard_license.json
# used to hand out a brand new 30-day trial.
_TRIAL_REG_KEY = r"Software\NetGuard AI"
_TRIAL_REG_VALUE = "t0"


def _trial_anchor_read() -> str:
    """ISO date of the very first launch stored outside the data folder ('' if none)."""
    if os.environ.get("NETGUARD_DATA_DIR") and not os.environ.get("NETGUARD_TRIAL_ANCHOR"):
        return ""          # throw-away data dir (tests, portable runs): no global marker
    if os.name != "nt":
        return ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _TRIAL_REG_KEY) as k:
            val, _ = winreg.QueryValueEx(k, _TRIAL_REG_VALUE)
            return str(val or "")
    except OSError:
        return ""
    except Exception:
        return ""


def _trial_anchor_write(iso: str) -> None:
    if os.environ.get("NETGUARD_DATA_DIR") and not os.environ.get("NETGUARD_TRIAL_ANCHOR"):
        return
    if os.name != "nt":
        return
    try:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _TRIAL_REG_KEY) as k:
            winreg.SetValueEx(k, _TRIAL_REG_VALUE, 0, winreg.REG_SZ, iso)
    except Exception:
        pass


def _effective_trial_start(file_value: str):
    """Earliest trustworthy trial start among the licence file and the registry marker.
    A date in the future (clock or file tampering) counts as an expired trial."""
    now = datetime.now()
    candidates = []
    for raw in (file_value, _trial_anchor_read()):
        if not raw:
            continue
        try:
            candidates.append(datetime.fromisoformat(raw))
        except Exception:
            return now - timedelta(days=TRIAL_DAYS + 1)      # unreadable → expired
    if not candidates:
        return None
    start = min(candidates)
    if start > now + timedelta(days=1):
        return now - timedelta(days=TRIAL_DAYS + 1)          # future-dated → expired
    return start
ACTIVATIONS_FILE = os.path.join(ACTIVATIONS_DIR, ".activations.json")

# Ed25519 public key for license verification (32 bytes, base64-encoded).
# REPLACE WITH YOUR REAL PUBLIC KEY before shipping. Generate with:
#     python tools/license_keygen.py
# The corresponding PRIVATE key must stay on YOUR licence-issuing server only.
# A placeholder (all zeros) means license activation is disabled — trial still works.
LICENSE_PUBLIC_KEY_B64 = os.environ.get(
    "NETGUARD_LICENSE_PUBKEY",
    "XO8scA3lVtFJTLFGgJEp9RxiEdZstTZkKE+p92DNjMw="
)

# Feature tiers
TIER_FREE = "free"
TIER_TRIAL = "trial"
TIER_PRO = "pro"
TIER_ENTERPRISE = "enterprise"

# Plans (multi-PC) — used in license payloads
PLAN_STARTER = "starter"
PLAN_PRO = "pro"

# Plan → max_seats cap. Starter is hard-capped at 1 even if mint says otherwise.
# Pro accepts 2..5 seats per pricing page (+15$/mo per extra PC up to 5).
PLAN_SEAT_CAPS = {
    PLAN_STARTER: 1,
    PLAN_PRO: 5,
}

# What each tier gets
FEATURES = {
    TIER_FREE: [
        "netguard_core",       # Dashboard + basic IDS + capture
        "dashboard",           # Web dashboard
    ],
    TIER_TRIAL: [
        "netguard_core",
        "dashboard",
        "mailshield",
        "cleanguard",
        "sentinel",
        "vpnguard",
        "honeypot",
        "fim",
        "recorder",
        "strikeback",
        "wireguard",
        "api_rest",
        "multi_users",
        "export_pdf",
    ],
    TIER_PRO: [
        "netguard_core",
        "dashboard",
        "mailshield",
        "cleanguard",
        "sentinel",
        "vpnguard",
        "honeypot",
        "fim",
        "recorder",
        "strikeback",
        "wireguard",
        "api_rest",
        "multi_users",
        "export_pdf",
    ],
    TIER_ENTERPRISE: [
        "netguard_core",
        "dashboard",
        "mailshield",
        "cleanguard",
        "sentinel",
        "vpnguard",
        "honeypot",
        "fim",
        "recorder",
        "strikeback",
        "wireguard",
        "api_rest",
        "multi_users",
        "export_pdf",
        "siem_integration",
        "custom_rules",
        "priority_support",
        "unlimited_sites",
    ],
}


# ── Exceptions ──────────────────────────────────────────────────────
class LicenseError(Exception):
    """Base class for license errors."""


class LicenseSeatExhaustedError(LicenseError):
    """Raised when all seats on a license are already activated."""


class LicenseFingerprintMismatchError(LicenseError):
    """Raised when a license is bound to a fingerprint that doesn't match."""


class LicenseExpiredError(LicenseError):
    """Raised when a license has passed its expires_at."""


# ── Device Fingerprint ──────────────────────────────────────────────
class DeviceFingerprint:
    """Stable per-machine fingerprint used to bind a seat to a device.

    Strategy (highest entropy first):
      1) Motherboard / system UUID (Windows: wmic; Linux: /sys/class/dmi/id/product_uuid)
      2) Primary MAC (psutil if available, else uuid.getnode())
      3) Hostname

    SHA-256 over the joined inputs gives a 64-char hex string.
    The first 12 chars (``fingerprint_short``) are used in the UI.
    """

    @staticmethod
    def _read_machine_uuid() -> str:
        # Windows
        try:
            if platform.system() == "Windows":
                # wmic prints lines: header + UUID. Be tolerant of trailing whitespace.
                out = subprocess.check_output(
                    ["wmic", "csproduct", "get", "UUID"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                for line in out.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.upper() != "UUID":
                        return line
        except Exception:
            pass
        # Windows 11 24H2+ removed wmic: same UUID through CIM, then MachineGuid.
        # (Without this the fingerprint changed after an OS upgrade and a paying
        # user hit "seat exhausted".)
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
                    stderr=subprocess.DEVNULL, timeout=10,
                )
                val = out.decode("utf-8", errors="ignore").strip()
                if val:
                    return val
        except Exception:
            pass
        try:
            if platform.system() == "Windows":
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                    val, _ = winreg.QueryValueEx(k, "MachineGuid")
                    if val:
                        return str(val)
        except Exception:
            pass
        # Linux
        try:
            p = "/sys/class/dmi/id/product_uuid"
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read().strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def _read_primary_mac() -> str:
        # Prefer psutil for a deterministic primary MAC if available
        try:
            import psutil  # type: ignore
            addrs = psutil.net_if_addrs()
            # Skip loopback / docker / vEthernet noise — pick lexicographically first real iface
            preferred = []
            for name, infos in addrs.items():
                low = name.lower()
                if low.startswith(("lo", "loopback")):
                    continue
                if "veth" in low or "docker" in low or "vbox" in low or "vmware" in low:
                    continue
                for info in infos:
                    fam = getattr(info, "family", None)
                    fam_name = getattr(fam, "name", "") if fam is not None else ""
                    addr = getattr(info, "address", "") or ""
                    # AF_LINK on macOS, AF_PACKET on Linux, custom int on Windows
                    if fam_name in ("AF_LINK", "AF_PACKET") or (
                        len(addr) == 17 and addr.count(":") == 5
                    ) or (len(addr) == 17 and addr.count("-") == 5):
                        if addr and addr not in ("00:00:00:00:00:00", "00-00-00-00-00-00"):
                            preferred.append((name, addr))
            if preferred:
                preferred.sort(key=lambda t: t[0].lower())
                return preferred[0][1].replace("-", ":").upper()
        except Exception:
            pass
        # Fallback — uuid.getnode()
        try:
            n = uuid.getnode()
            return ":".join(f"{(n >> i) & 0xff:02X}" for i in range(40, -1, -8))
        except Exception:
            return ""

    @staticmethod
    def current() -> str:
        """Return the SHA-256 fingerprint of *this* machine (hex, 64 chars)."""
        parts = [
            DeviceFingerprint._read_machine_uuid(),
            DeviceFingerprint._read_primary_mac(),
            socket.gethostname() or platform.node() or "",
        ]
        raw = "||".join(p.strip() for p in parts).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def short(fp: str) -> str:
        return (fp or "")[:12]

    @staticmethod
    def verify(stored_fp: str) -> bool:
        """Return True if ``stored_fp`` matches the current machine."""
        return hmac.compare_digest(stored_fp or "", DeviceFingerprint.current())


# ── Activation Registry (HMAC-signed local file) ────────────────────
class ActivationRegistry:
    """Multi-PC seat tracker.

    On-disk format:
        {
          "<license_id>": {
            "entries": [
              {"fingerprint": "<hex>", "hostname": "...", "activated_at": "...", "last_seen": "..."},
              ...
            ],
            "hmac": "<hex>"  # HMAC-SHA256 over the canonical-JSON of "entries"
                              # using key derived from license_id.
          },
          ...
        }

    HMAC key derivation: ``HKDF`` is overkill for this; we use
    ``HMAC-SHA256(b"NetGuard-ActivationRegistry-v1", license_id_bytes)`` which
    binds the integrity key to the license id, so an attacker can't add a
    fingerprint to a license without owning its license_id (which itself is
    signed by Ed25519 in the .lic file).
    """

    HMAC_LABEL = b"NetGuard-ActivationRegistry-v1"

    def __init__(self, path: str = None):
        # Resolve at *call* time so monkeypatching ACTIVATIONS_FILE in tests
        # actually takes effect. (Default-arg evaluation happens at class
        # definition and would freeze the original value.)
        self.path = path if path is not None else ACTIVATIONS_FILE

    # ── helpers ────────────────────────────────────────────────────
    @classmethod
    def _hmac_key(cls, license_id: str) -> bytes:
        return hmac.new(cls.HMAC_LABEL, (license_id or "").encode("utf-8"), hashlib.sha256).digest()

    @classmethod
    def _sign(cls, license_id: str, entries: list) -> str:
        canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(cls._hmac_key(license_id), canonical, hashlib.sha256).hexdigest()

    @classmethod
    def _verify(cls, license_id: str, entries: list, expected: str) -> bool:
        calc = cls._sign(license_id, entries)
        return hmac.compare_digest(calc, expected or "")

    def _load_raw(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    def _save_raw(self, data: dict) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        # Atomic write — never leave a torn registry
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)

    def _entries(self, license_id: str) -> list:
        raw = self._load_raw()
        block = raw.get(license_id) or {}
        entries = block.get("entries") or []
        sig = block.get("hmac") or ""
        # If a block exists but its signature doesn't verify, treat as tampered
        # and refuse to trust it (return empty so callers see "no activations").
        if entries and not self._verify(license_id, entries, sig):
            return []
        return entries

    def _write_entries(self, license_id: str, entries: list) -> None:
        raw = self._load_raw()
        raw[license_id] = {
            "entries": entries,
            "hmac": self._sign(license_id, entries),
        }
        self._save_raw(raw)

    # ── public API ─────────────────────────────────────────────────
    def is_tampered(self, license_id: str) -> bool:
        """Return True if a registry block exists but its HMAC doesn't verify."""
        raw = self._load_raw()
        block = raw.get(license_id)
        if not block:
            return False
        entries = block.get("entries") or []
        sig = block.get("hmac") or ""
        if not entries:
            return False
        return not self._verify(license_id, entries, sig)

    def seats_used(self, license_id: str) -> int:
        return len(self._entries(license_id))

    def is_activated(self, license_id: str, fingerprint: str) -> bool:
        for e in self._entries(license_id):
            if hmac.compare_digest(e.get("fingerprint", ""), fingerprint):
                return True
        return False

    def activate(self, license_id: str, fingerprint: str, max_seats: int,
                 hostname: str = "") -> bool:
        """Add ``fingerprint`` to ``license_id``. Return True on success.

        - No-op (returns True) if already activated.
        - Returns False if seats_used would exceed max_seats.
        """
        entries = self._entries(license_id)
        for e in entries:
            if hmac.compare_digest(e.get("fingerprint", ""), fingerprint):
                # Touch last_seen and persist
                e["last_seen"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                self._write_entries(license_id, entries)
                return True
        if len(entries) >= int(max_seats or 1):
            return False
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        entries.append({
            "fingerprint": fingerprint,
            "hostname": hostname or socket.gethostname() or platform.node() or "",
            "activated_at": now,
            "last_seen": now,
        })
        self._write_entries(license_id, entries)
        return True

    def deactivate(self, license_id: str, fingerprint: str) -> bool:
        entries = self._entries(license_id)
        new_entries = [e for e in entries if not hmac.compare_digest(
            e.get("fingerprint", ""), fingerprint)]
        if len(new_entries) == len(entries):
            return False
        self._write_entries(license_id, new_entries)
        return True

    def list_devices(self, license_id: str) -> list:
        return list(self._entries(license_id))

    def touch(self, license_id: str, fingerprint: str) -> None:
        """Refresh last_seen for ``fingerprint`` if it's already activated."""
        entries = self._entries(license_id)
        changed = False
        for e in entries:
            if hmac.compare_digest(e.get("fingerprint", ""), fingerprint):
                e["last_seen"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                changed = True
                break
        if changed:
            self._write_entries(license_id, entries)


# ── Legacy machine ID (kept for backward compat) ────────────────────
def _get_machine_id() -> str:
    """Generate a unique machine fingerprint (legacy short form, 32 hex chars).

    Older licenses bind to this 32-char prefix via ``payload['machine_id']``.
    Modern multi-PC licenses don't set ``machine_id`` and instead rely on
    the ``ActivationRegistry`` keyed by ``license_id``.
    """
    raw = f"{platform.node()}-{platform.machine()}-{platform.system()}"
    try:
        raw += f"-{uuid.getnode()}"
    except Exception:
        pass
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _load_license() -> dict:
    """Load license data from file"""
    if os.path.exists(LICENSE_FILE):
        try:
            with open(LICENSE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_license(data: dict):
    """Save license data to file (atomic: a crash mid-write must not reset the trial)"""
    try:
        os.makedirs(os.path.dirname(LICENSE_FILE) or ".", exist_ok=True)
        tmp = LICENSE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, LICENSE_FILE)
    except Exception as e:
        print(f"[LICENSE] Erreur sauvegarde: {e}")


def _b64url_decode(s: str) -> bytes:
    """Base64-url decode with padding tolerance."""
    s = s.strip()
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def _verify_license_key(key: str, machine_id: str) -> dict:
    """
    Verify a license key signed with Ed25519.

    Format: NGPRO-<base64url-payload>-<base64url-signature>
    Payload (JSON) may contain (multi-PC fields are optional for back-compat):
        - tier: "pro" | "enterprise"
        - plan: "starter" | "pro"
        - max_seats: int (default 1)
        - license_id: UUIDv4 (required for multi-PC)
        - customer_email: str
        - issued_at: ISO8601
        - expires: ISO8601 | null  (legacy field, still honoured)
        - expires_at: ISO8601 | null  (multi-PC alias)
        - machine_id: <sha256-prefix> | null (legacy single-machine binding)
    """
    if not key or not key.startswith("NGPRO-"):
        return {"valid": False, "error": "Format invalide. Attendu: NGPRO-<payload>-<signature>"}

    # Strip the NGPRO- prefix.
    body = key[len("NGPRO-"):]
    # Ed25519 signatures are always 64 raw bytes -> 86 base64url chars (no
    # padding). The base64url alphabet uses '-' and '_' too, so we cannot rely
    # on splitting by '-'. Instead, take the last 86 chars as the signature.
    SIG_B64_LEN = 86
    if len(body) <= SIG_B64_LEN + 1:
        return {"valid": False, "error": "Format obsolete — re-emettez votre cle (Ed25519 requis)"}
    if body[-(SIG_B64_LEN + 1)] != "-":
        return {"valid": False, "error": "Format obsolete — re-emettez votre cle (Ed25519 requis)"}
    sig_b64 = body[-SIG_B64_LEN:]
    payload_b64 = body[: -(SIG_B64_LEN + 1)]
    if not payload_b64 or not sig_b64:
        return {"valid": False, "error": "Format obsolete — re-emettez votre cle (Ed25519 requis)"}

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return {"valid": False, "error": "Module 'cryptography' requis: pip install cryptography"}

    try:
        pubkey_bytes = base64.b64decode(LICENSE_PUBLIC_KEY_B64)
        if pubkey_bytes == b"\x00" * 32:
            return {"valid": False, "error": "Cle publique de licence non configuree (placeholder). Voir tools/license_keygen.py"}
        if len(pubkey_bytes) != 32:
            return {"valid": False, "error": "Cle publique de licence invalide (doit faire 32 octets Ed25519)"}
    except Exception as e:
        return {"valid": False, "error": f"Cle publique illisible: {e}"}

    try:
        payload_bytes = _b64url_decode(payload_b64)
        sig_bytes = _b64url_decode(sig_b64)
    except Exception:
        return {"valid": False, "error": "Encodage base64 invalide"}

    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(sig_bytes, payload_bytes)
    except InvalidSignature:
        return {"valid": False, "error": "Signature invalide"}
    except Exception as e:
        return {"valid": False, "error": f"Erreur de verification: {e}"}

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return {"valid": False, "error": "Payload JSON invalide"}

    tier = (payload.get("tier") or "").lower()
    if tier not in (TIER_PRO, TIER_ENTERPRISE):
        return {"valid": False, "error": f"Tier non reconnu: {tier}"}

    # Legacy single-machine binding (still honoured for old licenses)
    bound_machine = payload.get("machine_id")
    if bound_machine and bound_machine != machine_id:
        return {"valid": False, "error": "Cle non valide pour cette machine"}

    # Expiration check — accept either "expires" (legacy) or "expires_at" (new)
    expires = payload.get("expires_at") or payload.get("expires")
    if expires:
        try:
            exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            now_dt = datetime.now(exp_dt.tzinfo) if exp_dt.tzinfo else datetime.now()
            if now_dt > exp_dt:
                return {"valid": False, "error": f"Licence expiree le {expires}"}
        except Exception:
            return {"valid": False, "error": "Date d'expiration invalide"}

    # Multi-PC fields — defaults preserve back-compat with single-PC legacy keys
    plan = (payload.get("plan") or "").lower()
    if plan and plan not in (PLAN_STARTER, PLAN_PRO):
        plan = ""
    max_seats = int(payload.get("max_seats") or 1)
    if plan == PLAN_STARTER:
        # Hard cap regardless of what the mint produced
        max_seats = 1
    elif plan == PLAN_PRO:
        max_seats = max(1, min(max_seats, PLAN_SEAT_CAPS[PLAN_PRO]))
    license_id = payload.get("license_id") or ""

    return {
        "valid": True,
        "tier": (TIER_ENTERPRISE if tier == TIER_ENTERPRISE else TIER_PRO),
        "plan": plan or PLAN_STARTER,
        "max_seats": max_seats,
        "license_id": license_id,
        "customer_email": payload.get("customer_email") or "",
        "expires_at": expires,
        "issued_at": payload.get("issued_at"),
        "machine_bound": bool(bound_machine),
    }


# ── LicenseManager (multi-PC orchestrator) ──────────────────────────
class LicenseManager:
    """Thin orchestrator around the verify/activation/registry primitives.

    The legacy module-level functions (init_license, activate_license, etc.)
    still work for back-compat. New multi-PC features live here.
    """

    def __init__(self, license_file: str = None,
                 registry: ActivationRegistry = None):
        self.license_file = license_file if license_file is not None else LICENSE_FILE
        self.registry = registry or ActivationRegistry()

    def _load(self) -> dict:
        if os.path.exists(self.license_file):
            try:
                with open(self.license_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self, data: dict) -> None:
        try:
            tmp = self.license_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self.license_file)
        except Exception as e:
            print(f"[LICENSE] Erreur sauvegarde: {e}")

    def validate(self, *, auto_activate: bool = True) -> dict:
        """Full validation pipeline.

        Order:
          1. Verify Ed25519 signature.
          2. Verify expires_at > now.
          3. Verify the current device fingerprint is in the activation
             registry for this license_id; otherwise auto-activate (if
             ``auto_activate=True`` and seats are available) or raise
             LicenseSeatExhaustedError.

        Raises:
            LicenseError subclasses on validation failure.

        Returns:
            dict with tier/plan/max_seats/seats_used/license_id/expires_at/
            features/fingerprint.
        """
        data = self._load()
        key = data.get("license_key")
        if not key:
            raise LicenseError("Aucune licence active — passe en mode trial/free")

        machine_id = _get_machine_id()
        result = _verify_license_key(key, machine_id)
        if not result.get("valid"):
            raise LicenseError(result.get("error", "Cle invalide"))

        license_id = result.get("license_id") or ""
        max_seats = int(result.get("max_seats") or 1)
        fp = DeviceFingerprint.current()

        # Multi-PC path: license_id is required to use the activation registry.
        # Legacy keys without a license_id behave as single-machine (their
        # Ed25519 ``machine_id`` field already enforces binding).
        seats_used = 0
        activated = True
        if license_id:
            if self.registry.is_tampered(license_id):
                raise LicenseError(
                    "Registre d'activation compromis (HMAC invalide). "
                    "Supprime argus_data/.activations.json et reactive."
                )
            seats_used = self.registry.seats_used(license_id)
            activated = self.registry.is_activated(license_id, fp)
            if not activated:
                if seats_used >= max_seats:
                    raise LicenseSeatExhaustedError(
                        f"Toutes les {max_seats} place(s) de cette licence sont deja "
                        f"utilisees. Desactive une autre machine via Settings -> "
                        f"License -> Manage Devices."
                    )
                if auto_activate:
                    ok = self.registry.activate(license_id, fp, max_seats)
                    if not ok:
                        raise LicenseSeatExhaustedError(
                            "Activation impossible — toutes les places sont prises."
                        )
                    activated = True
                    seats_used = self.registry.seats_used(license_id)
            else:
                # Refresh last_seen
                self.registry.touch(license_id, fp)

        # Persist last successful validation snapshot for the dashboard
        snapshot = {
            "tier": result["tier"],
            "plan": result.get("plan") or PLAN_STARTER,
            "max_seats": max_seats,
            "license_id": license_id,
            "customer_email": result.get("customer_email") or "",
            "expires_at": result.get("expires_at"),
            "issued_at": result.get("issued_at"),
        }
        # Don't clobber other fields (trial_start, machine_id, etc.)
        merged = {**data, **snapshot}
        if data != merged:
            self._save(merged)

        return {
            "tier": result["tier"],
            "plan": result.get("plan") or PLAN_STARTER,
            "max_seats": max_seats,
            "seats_used": seats_used,
            "license_id": license_id,
            "customer_email": result.get("customer_email") or "",
            "expires_at": result.get("expires_at"),
            "fingerprint": fp,
            "fingerprint_short": DeviceFingerprint.short(fp),
            "features": FEATURES.get(result["tier"], FEATURES[TIER_FREE]),
            "activated": activated,
        }

    def list_activated_devices(self, license_id: str = None) -> list:
        """Return the device list with a ``this_machine`` flag added."""
        if license_id is None:
            license_id = (self._load() or {}).get("license_id") or ""
        if not license_id:
            return []
        my_fp = DeviceFingerprint.current()
        out = []
        for e in self.registry.list_devices(license_id):
            fp = e.get("fingerprint", "")
            out.append({
                "fingerprint": fp,
                "fingerprint_short": DeviceFingerprint.short(fp),
                "hostname": e.get("hostname", ""),
                "activated_at": e.get("activated_at", ""),
                "last_seen": e.get("last_seen", ""),
                "this_machine": hmac.compare_digest(fp, my_fp),
            })
        return out

    def deactivate_device(self, fingerprint: str, license_id: str = None) -> bool:
        """Release a seat. Returns True on success, False if not found."""
        if license_id is None:
            license_id = (self._load() or {}).get("license_id") or ""
        if not license_id:
            return False
        return self.registry.deactivate(license_id, fingerprint)

    def status(self) -> dict:
        """Best-effort status dict for the dashboard.

        Never raises — falls back to legacy init_license() result if the
        license isn't multi-PC capable or isn't activated yet.
        """
        try:
            v = self.validate(auto_activate=True)
        except LicenseError:
            base = init_license()
            return {
                "tier": base.get("tier"),
                "plan": None,
                "max_seats": 0,
                "seats_used": 0,
                "license_id": "",
                "expires_at": None,
                "trial": base.get("trial", False),
                "trial_days_left": base.get("trial_days_left", 0),
                "expired": base.get("expired", False),
                "devices": [],
                "fingerprint_short": DeviceFingerprint.short(DeviceFingerprint.current()),
            }
        devices = self.list_activated_devices(v.get("license_id") or None)
        return {
            "tier": v["tier"],
            "plan": v["plan"],
            "max_seats": v["max_seats"],
            "seats_used": v["seats_used"],
            "license_id": v["license_id"],
            "customer_email": v["customer_email"],
            "expires_at": v["expires_at"],
            "trial": False,
            "trial_days_left": 0,
            "expired": False,
            "devices": devices,
            "fingerprint_short": v["fingerprint_short"],
        }


def init_license() -> dict:
    """
    Initialize or load license.
    Returns license state dict (legacy single-machine path).
    """
    data = _load_license()
    machine_id = _get_machine_id()

    # Check if we have an activated license
    if data.get("license_key") and data.get("tier") in (TIER_PRO, TIER_ENTERPRISE):
        result = _verify_license_key(data["license_key"], machine_id)
        if result.get("valid"):
            return {
                "tier": data["tier"],
                "features": FEATURES.get(data["tier"], FEATURES[TIER_FREE]),
                "license_key": data["license_key"],
                "trial": False,
                "trial_days_left": 0,
                "expired": False,
                "machine_id": machine_id,
            }

    # Check trial status
    trial_start = _effective_trial_start(data.get("trial_start") or "")
    if trial_start is None:
        # Very first launch on this Windows account — start trial
        now_iso = datetime.now().isoformat()
        data["trial_start"] = now_iso
        data["machine_id"] = machine_id
        data["tier"] = TIER_TRIAL
        _save_license(data)
        _trial_anchor_write(now_iso)
        print(f"[LICENSE] Periode d'essai activee ({TRIAL_DAYS} jours)")
        return {
            "tier": TIER_TRIAL,
            "features": FEATURES[TIER_TRIAL],
            "trial": True,
            "trial_days_left": TRIAL_DAYS,
            "expired": False,
            "machine_id": machine_id,
        }

    # Existing trial — check if still valid. Keep file and registry marker in sync
    # (file deleted → restored from the marker; marker missing → written).
    if not data.get("trial_start"):
        data["trial_start"] = trial_start.isoformat()
        data.setdefault("machine_id", machine_id)
        data.setdefault("tier", TIER_TRIAL)
        _save_license(data)
    if not _trial_anchor_read():
        _trial_anchor_write(trial_start.isoformat())
    elapsed = (datetime.now() - trial_start).days
    days_left = max(0, min(TRIAL_DAYS, TRIAL_DAYS - elapsed))

    if days_left > 0:
        return {
            "tier": TIER_TRIAL,
            "features": FEATURES[TIER_TRIAL],
            "trial": True,
            "trial_days_left": days_left,
            "expired": False,
            "machine_id": machine_id,
        }

    # Trial expired — downgrade to free
    return {
        "tier": TIER_FREE,
        "features": FEATURES[TIER_FREE],
        "trial": False,
        "trial_days_left": 0,
        "expired": True,
        "machine_id": machine_id,
    }


def activate_license(key: str) -> dict:
    """Activate a license key (multi-PC aware).

    On success, persists license_key + multi-PC metadata to LICENSE_FILE
    and writes the current device fingerprint into the ActivationRegistry
    if the license carries a license_id and seats are available.
    """
    machine_id = _get_machine_id()
    result = _verify_license_key(key, machine_id)

    if not result.get("valid"):
        return {"ok": False, "error": result.get("error", "Cle invalide")}

    tier = result["tier"]
    license_id = result.get("license_id") or ""
    max_seats = int(result.get("max_seats") or 1)

    # Multi-PC: try to claim a seat for this machine before persisting the key.
    if license_id:
        registry = ActivationRegistry()
        if registry.is_tampered(license_id):
            return {"ok": False, "error": "Registre d'activation compromis (HMAC invalide)."}
        fp = DeviceFingerprint.current()
        if not registry.is_activated(license_id, fp):
            ok = registry.activate(license_id, fp, max_seats)
            if not ok:
                return {
                    "ok": False,
                    "error": (f"Toutes les {max_seats} place(s) de cette licence "
                              f"sont deja utilisees. Desactive une autre machine "
                              f"d'abord."),
                    "seat_exhausted": True,
                }

    data = _load_license()
    data["license_key"] = key
    data["tier"] = tier
    data["plan"] = result.get("plan") or PLAN_STARTER
    data["max_seats"] = max_seats
    data["license_id"] = license_id
    data["customer_email"] = result.get("customer_email") or ""
    data["expires_at"] = result.get("expires_at")
    data["issued_at"] = result.get("issued_at")
    data["activated_at"] = datetime.now().isoformat()
    data["machine_id"] = machine_id
    _save_license(data)

    return {
        "ok": True,
        "tier": tier,
        "plan": data["plan"],
        "max_seats": max_seats,
        "license_id": license_id,
        "features": FEATURES[tier],
        "message": f"License {tier.upper()} activee avec succes !",
    }


def deactivate_license() -> dict:
    """Remove license activation locally.

    Also releases the seat in the ActivationRegistry if a license_id is
    known so the user gets the seat back on another machine.
    """
    data = _load_license()
    license_id = data.get("license_id") or ""
    if license_id:
        try:
            ActivationRegistry().deactivate(license_id, DeviceFingerprint.current())
        except Exception:
            pass
    data.pop("license_key", None)
    data.pop("license_id", None)
    data.pop("plan", None)
    data.pop("max_seats", None)
    data.pop("customer_email", None)
    data.pop("expires_at", None)
    data.pop("issued_at", None)
    data["tier"] = TIER_TRIAL if data.get("trial_start") else TIER_FREE
    _save_license(data)
    return {"ok": True, "message": "License desactivee"}


def has_feature(feature: str) -> bool:
    """Check if current license includes a feature"""
    state = init_license()
    return feature in state.get("features", [])


def get_trial_banner() -> str:
    """Return a banner string for the dashboard"""
    state = init_license()
    if state["tier"] == TIER_PRO:
        return ""
    if state["tier"] == TIER_ENTERPRISE:
        return ""
    if state.get("trial") and state["trial_days_left"] > 0:
        d = state["trial_days_left"]
        return f"Periode d'essai : {d} jour{'s' if d > 1 else ''} restant{'s' if d > 1 else ''}. Activez votre licence pour continuer."
    if state.get("expired"):
        return "Periode d'essai terminee. Passez a NetGuard AI pour debloquer toutes les fonctionnalites."
    return ""


# ── CLI test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    state = init_license()
    print(f"Tier:          {state['tier']}")
    print(f"Trial:         {state.get('trial', False)}")
    print(f"Days left:     {state.get('trial_days_left', 0)}")
    print(f"Expired:       {state.get('expired', False)}")
    print(f"Features:      {', '.join(state['features'])}")
    print(f"Machine ID:    {state.get('machine_id', 'N/A')}")
    print(f"Fingerprint:   {DeviceFingerprint.current()[:12]}...")
    print(f"Banner:        {get_trial_banner()}")
    try:
        s = LicenseManager().status()
        print(f"Plan:          {s.get('plan')}")
        print(f"Seats:         {s.get('seats_used')}/{s.get('max_seats')}")
        print(f"Devices:       {len(s.get('devices', []))} active")
    except Exception as e:
        print(f"Status:        unavailable ({e})")
