"""
NetGuard Pro Suite — License Manager
Trial period (30 days) + feature gating + Ed25519-signed license activation
"""
import os
import sys
import json
import time
import hashlib
import base64
import platform
import uuid
from datetime import datetime, timedelta
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Config ──────────────────────────────────────────────────────────
LICENSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netguard_license.json")
TRIAL_DAYS = 30

# Ed25519 public key for license verification (32 bytes, base64-encoded).
# REPLACE WITH YOUR REAL PUBLIC KEY before shipping. Generate with:
#     python tools/license_keygen.py
# The corresponding PRIVATE key must stay on YOUR licence-issuing server only.
# A placeholder (all zeros) means license activation is disabled — trial still works.
LICENSE_PUBLIC_KEY_B64 = os.environ.get(
    "NETGUARD_LICENSE_PUBKEY",
    "qZ3Me9HcO3W0rHANv97FEQMAhDdRA7GvX+iMqX2j/rQ="
)

# Feature tiers
TIER_FREE = "free"
TIER_TRIAL = "trial"
TIER_PRO = "pro"
TIER_ENTERPRISE = "enterprise"

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


def _get_machine_id() -> str:
    """Generate a unique machine fingerprint"""
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
    """Save license data to file"""
    try:
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[LICENSE] Erreur sauvegarde: {e}")


def _b64url_decode(s: str) -> bytes:
    """Base64-url decode with padding tolerance."""
    s = s.strip()
    # Add padding if missing
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def _verify_license_key(key: str, machine_id: str) -> dict:
    """
    Verify a license key signed with Ed25519.

    Format: NGPRO-<base64url-payload>-<base64url-signature>
    Payload (JSON) must contain: {"tier": "pro|enterprise", "expires": "ISO8601" | null,
                                   "machine_id": "<sha256-prefix>" | null, "issued_at": "..."}

    A "machine_id" field of null means the licence is portable (any machine).
    A specific machine_id locks the license to that fingerprint.
    """
    if not key or not key.startswith("NGPRO-"):
        return {"valid": False, "error": "Format invalide. Attendu: NGPRO-<payload>-<signature>"}

    # Reject the obsolete 5-segment hash-only format that this project used previously
    parts = key.split("-")
    if len(parts) != 3:
        return {"valid": False, "error": "Format obsolete — re-emettez votre cle (Ed25519 requis)"}

    _, payload_b64, sig_b64 = parts

    # Verify signature with Ed25519
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

    tier = payload.get("tier", "").lower()
    if tier not in (TIER_PRO, TIER_ENTERPRISE):
        return {"valid": False, "error": f"Tier non reconnu: {tier}"}

    # Machine binding (optional)
    bound_machine = payload.get("machine_id")
    if bound_machine and bound_machine != machine_id:
        return {"valid": False, "error": "Cle non valide pour cette machine"}

    # Expiration check
    expires = payload.get("expires")
    if expires:
        try:
            exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            now_dt = datetime.now(exp_dt.tzinfo) if exp_dt.tzinfo else datetime.now()
            if now_dt > exp_dt:
                return {"valid": False, "error": f"Licence expiree le {expires}"}
        except Exception:
            return {"valid": False, "error": "Date d'expiration invalide"}

    return {"valid": True, "tier": (TIER_ENTERPRISE if tier == TIER_ENTERPRISE else TIER_PRO),
            "expires": expires, "machine_bound": bool(bound_machine)}


def init_license() -> dict:
    """
    Initialize or load license.
    Returns license state dict.
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
    if not data.get("trial_start"):
        # First launch — start trial
        data["trial_start"] = datetime.now().isoformat()
        data["machine_id"] = machine_id
        data["tier"] = TIER_TRIAL
        _save_license(data)
        print(f"[LICENSE] Periode d'essai activee ({TRIAL_DAYS} jours)")
        return {
            "tier": TIER_TRIAL,
            "features": FEATURES[TIER_TRIAL],
            "trial": True,
            "trial_days_left": TRIAL_DAYS,
            "expired": False,
            "machine_id": machine_id,
        }

    # Existing trial — check if still valid
    try:
        trial_start = datetime.fromisoformat(data["trial_start"])
        elapsed = (datetime.now() - trial_start).days
        days_left = max(0, TRIAL_DAYS - elapsed)
    except Exception:
        days_left = 0

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
    """Activate a license key"""
    machine_id = _get_machine_id()
    result = _verify_license_key(key, machine_id)

    if not result.get("valid"):
        return {"ok": False, "error": result.get("error", "Cle invalide")}

    tier = result["tier"]
    data = _load_license()
    data["license_key"] = key
    data["tier"] = tier
    data["activated_at"] = datetime.now().isoformat()
    data["machine_id"] = machine_id
    _save_license(data)

    return {
        "ok": True,
        "tier": tier,
        "features": FEATURES[tier],
        "message": f"License {tier.upper()} activee avec succes !",
    }


def deactivate_license() -> dict:
    """Remove license activation"""
    data = _load_license()
    data.pop("license_key", None)
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
        return "Periode d'essai terminee. Passez a NetGuard Pro pour debloquer toutes les fonctionnalites."
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
    print(f"Banner:        {get_trial_banner()}")
