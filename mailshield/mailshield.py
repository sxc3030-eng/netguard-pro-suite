#!/usr/bin/env python3
"""
MailShield Pro - Client Email Securise avec Filtrage Intelligent
Partie de l'ecosysteme NetGuard Pro
"""

import imaplib
import smtplib
import email
import email.utils
import email.header
import json
import sqlite3
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

import re
import hashlib
import threading
import time
import asyncio
import websockets
import ssl
import base64
import mimetypes
import unicodedata
import secrets
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import webbrowser
import msal

try:
    import webview
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from startup_utils import is_startup_enabled, toggle_startup as toggle_startup_reg, minimize_to_tray
    HAS_STARTUP_UTILS = True
except ImportError:
    HAS_STARTUP_UTILS = False

VERSION = "2.0.0"
SCRIPT_DIR = Path(__file__).parent
DB_PATH = SCRIPT_DIR / "mailshield.db"
SETTINGS_PATH = SCRIPT_DIR / "mailshield_settings.json"
QUARANTINE_DIR = SCRIPT_DIR / "mailshield_quarantine"
LOG_PATH = SCRIPT_DIR / "mailshield.log"

# --- Logging Setup ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_PATH), encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("MailShield")

# --- Password Encryption ------------------------------------------------------

class PasswordVault:
    """Encrypts/decrypts passwords using a machine-unique key + AES-like XOR cipher."""

    def __init__(self):
        self._key = self._derive_key()

    def _derive_key(self):
        """Derive a machine-unique key from hostname + username + script path."""
        seed = f"{os.environ.get('COMPUTERNAME', 'default')}:{os.environ.get('USERNAME', 'user')}:{SCRIPT_DIR}"
        return hashlib.sha256(seed.encode()).digest()

    def encrypt(self, plaintext):
        """Encrypt a password. Returns base64-encoded string prefixed with 'ENC:'."""
        if not plaintext:
            return ""
        if plaintext.startswith("ENC:"):
            return plaintext  # Already encrypted
        data = plaintext.encode("utf-8")
        encrypted = bytes(b ^ self._key[i % len(self._key)] for i, b in enumerate(data))
        return "ENC:" + base64.b64encode(encrypted).decode("ascii")

    def decrypt(self, encrypted):
        """Decrypt a password. If not encrypted (no ENC: prefix), returns as-is."""
        if not encrypted:
            return ""
        if not encrypted.startswith("ENC:"):
            return encrypted  # Legacy plaintext - will be re-encrypted on next save
        try:
            data = base64.b64decode(encrypted[4:])
            decrypted = bytes(b ^ self._key[i % len(self._key)] for i, b in enumerate(data))
            return decrypted.decode("utf-8")
        except Exception:
            return ""

password_vault = PasswordVault()

# --- API Security -------------------------------------------------------------

API_TOKEN_PATH = SCRIPT_DIR / ".api_token"

def get_or_create_api_token():
    """Generate a session API token for local security."""
    if API_TOKEN_PATH.exists():
        token = API_TOKEN_PATH.read_text(encoding="utf-8").strip()
        if len(token) >= 32:
            return token
    token = secrets.token_hex(32)
    API_TOKEN_PATH.write_text(token, encoding="utf-8")
    return token

API_TOKEN = get_or_create_api_token()

# --- Settings ------------------------------------------------------------------

def load_settings():
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
        # Auto-encrypt any plaintext passwords found
        changed = False
        for acc in settings.get("accounts", []):
            pwd = acc.get("password", "")
            if pwd and not pwd.startswith("ENC:"):
                acc["password"] = password_vault.encrypt(pwd)
                changed = True
        if changed:
            save_settings(settings)
            logger.info("Passwords encrypted on load (legacy plaintext detected)")
        return settings
    except Exception as e:
        logger.error(f"Erreur chargement settings: {e}")
        return {}

def save_settings(settings):
    """Save settings with passwords encrypted."""
    # Ensure all passwords are encrypted before saving
    save_copy = json.loads(json.dumps(settings))  # Deep copy
    for acc in save_copy.get("accounts", []):
        pwd = acc.get("password", "")
        if pwd and not pwd.startswith("ENC:"):
            acc["password"] = password_vault.encrypt(pwd)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(save_copy, f, indent=4, ensure_ascii=False)

def get_decrypted_password(account):
    """Get the decrypted password for an account."""
    return password_vault.decrypt(account.get("password", ""))

# --- Database ------------------------------------------------------------------

def init_database():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT UNIQUE,
        account TEXT,
        folder TEXT DEFAULT 'INBOX',
        from_name TEXT,
        from_email TEXT,
        to_email TEXT,
        cc TEXT,
        subject TEXT,
        body_text TEXT,
        body_html TEXT,
        date_sent TEXT,
        date_received TEXT,
        category TEXT DEFAULT 'primary',
        is_read INTEGER DEFAULT 0,
        is_starred INTEGER DEFAULT 0,
        is_deleted INTEGER DEFAULT 0,
        is_spam INTEGER DEFAULT 0,
        trust_score INTEGER DEFAULT 100,
        security_flags TEXT DEFAULT '{}',
        has_attachments INTEGER DEFAULT 0,
        filter_matched TEXT,
        raw_headers TEXT,
        uid INTEGER
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id INTEGER,
        filename TEXT,
        content_type TEXT,
        size_bytes INTEGER,
        extension TEXT,
        is_blocked INTEGER DEFAULT 0,
        is_quarantined INTEGER DEFAULT 0,
        quarantine_path TEXT,
        trust_score INTEGER DEFAULT 100,
        scan_result TEXT,
        data BLOB,
        FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        company TEXT,
        group_name TEXT DEFAULT 'General',
        notes TEXT,
        is_trusted INTEGER DEFAULT 0,
        is_blocked INTEGER DEFAULT 0,
        frequency INTEGER DEFAULT 0,
        avatar_color TEXT,
        date_added TEXT,
        last_contact TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS contact_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        color TEXT DEFAULT '#3498db'
    )""")

    # Blacklist table
    c.execute("""CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        domain TEXT,
        reason TEXT DEFAULT '',
        date_added TEXT,
        is_active INTEGER DEFAULT 1
    )""")

    # Drafts table
    c.execute("""CREATE TABLE IF NOT EXISTS drafts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        to_email TEXT DEFAULT '',
        cc TEXT DEFAULT '',
        bcc TEXT DEFAULT '',
        subject TEXT DEFAULT '',
        body_html TEXT DEFAULT '',
        original_id INTEGER,
        draft_type TEXT DEFAULT 'new',
        date_created TEXT,
        date_modified TEXT
    )""")

    # Threats log table
    c.execute("""CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id INTEGER,
        threat_type TEXT,
        severity TEXT DEFAULT 'medium',
        description TEXT,
        from_email TEXT,
        subject TEXT,
        details TEXT DEFAULT '{}',
        action_taken TEXT DEFAULT 'blocked',
        date_detected TEXT,
        FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE SET NULL
    )""")

    c.execute("CREATE INDEX IF NOT EXISTS idx_emails_category ON emails(category)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_emails_from ON emails(from_email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_emails_date ON emails(date_received)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_email ON blacklist(email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_domain ON blacklist(domain)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_threats_date ON threats(date_detected)")

    # Insert default groups
    for g in ["General", "Famille", "Travail", "Amis", "VIP"]:
        c.execute("INSERT OR IGNORE INTO contact_groups (name) VALUES (?)", (g,))

    conn.commit()
    conn.close()

# --- Email Header Decoder -----------------------------------------------------

def decode_header_value(value):
    if not value:
        return ""
    decoded_parts = email.header.decode_header(value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(part)
    return " ".join(result)

def parse_email_address(addr_str):
    if not addr_str:
        return "", ""
    decoded = decode_header_value(addr_str)
    name, address = email.utils.parseaddr(decoded)
    return name, address

# --- Filter Engine -------------------------------------------------------------

class FilterEngine:
    def __init__(self, settings):
        self.settings = settings
        self.filter_keywords = settings.get("filter_keywords", {})

    def reload(self, settings):
        self.settings = settings
        self.filter_keywords = settings.get("filter_keywords", {})

    def classify_email(self, from_name, from_email, subject, body, attachment_names, is_contact):
        """Classify an email into a category based on keyword matching."""
        if is_contact:
            # Known contacts go to primary unless they match spam
            spam_score = self._match_score("spam", from_name, from_email, subject, body, attachment_names)
            if spam_score > 3:
                return "spam", f"spam:{spam_score}"
            return "primary", None

        text_pool = f"{from_name} {from_email} {subject} {body} {' '.join(attachment_names)}".lower()
        text_pool = unicodedata.normalize("NFKD", text_pool)

        best_cat = "primary"
        best_score = 0
        matched_kw = None

        # Check each category
        for cat_key, cat_data in self.filter_keywords.items():
            keywords = cat_data.get("keywords", [])
            score = 0
            matched = []
            for kw in keywords:
                kw_lower = kw.lower()
                if kw_lower in text_pool:
                    score += 1
                    matched.append(kw)
                    # Extra weight for subject matches
                    if kw_lower in subject.lower():
                        score += 2
                    # Extra weight for sender matches
                    if kw_lower in from_email.lower() or kw_lower in from_name.lower():
                        score += 1

            if score > best_score:
                best_score = score
                best_cat = cat_key
                matched_kw = ", ".join(matched[:5])

        # Map category keys to display categories
        cat_map = {
            "spam": "spam",
            "promotions": "promotions",
            "social": "social",
            "notifications": "notifications",
            "important": "primary",
            "custom": "primary"
        }
        final_cat = cat_map.get(best_cat, "primary")

        if best_score == 0:
            return "primary", None

        return final_cat, f"{best_cat}:{matched_kw}" if matched_kw else None

    def _match_score(self, category, from_name, from_email, subject, body, attachment_names):
        cat_data = self.filter_keywords.get(category, {})
        keywords = cat_data.get("keywords", [])
        text_pool = f"{from_name} {from_email} {subject} {body} {' '.join(attachment_names)}".lower()
        return sum(1 for kw in keywords if kw.lower() in text_pool)

# --- Attachment Scanner --------------------------------------------------------

class AttachmentScanner:
    def __init__(self, settings):
        sec = settings.get("attachment_security", {})
        self.enabled = sec.get("enabled", True)
        self.max_size = sec.get("max_size_mb", 25) * 1024 * 1024
        self.blocked_ext = set(sec.get("blocked_extensions", []))
        self.suspicious_ext = set(sec.get("suspicious_extensions", []))
        self.quarantine_unknown = sec.get("quarantine_unknown_sender_attachments", True)
        self.threshold = sec.get("trust_score_threshold", 50)

    def scan(self, filename, size, content_type, is_contact):
        """Returns (trust_score, is_blocked, is_quarantined, scan_result)"""
        if not self.enabled:
            return 100, False, False, "scanning_disabled"

        score = 100
        reasons = []
        ext = Path(filename).suffix.lower() if filename else ""

        # Blocked extension
        if ext in self.blocked_ext:
            return 0, True, False, f"blocked_extension:{ext}"

        # Suspicious extension
        if ext in self.suspicious_ext:
            score -= 30
            reasons.append(f"suspicious_extension:{ext}")

        # Size check
        if size > self.max_size:
            score -= 20
            reasons.append("oversized")

        # Double extension (e.g. document.pdf.exe)
        parts = filename.rsplit(".", 2) if filename else []
        if len(parts) > 2:
            score -= 40
            reasons.append("double_extension")

        # Unknown sender with attachment
        if not is_contact and self.quarantine_unknown:
            score -= 20
            reasons.append("unknown_sender")

        # Macro-enabled office docs
        if ext in (".docm", ".xlsm", ".pptm"):
            score -= 30
            reasons.append("macro_enabled")

        is_quarantined = score < self.threshold and not is_contact
        result = "; ".join(reasons) if reasons else "clean"
        return max(0, score), False, is_quarantined, result

# --- Contact Book --------------------------------------------------------------

class ContactBook:
    def __init__(self):
        self.db_path = str(DB_PATH)

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def add_contact(self, name, addr, phone="", company="", group="General", notes="", trusted=False):
        conn = self._conn()
        # nosec B324 - MD5 used purely to derive a deterministic 6-char avatar tint
        # from the email address. Not used for authentication or integrity.
        color = f"#{hashlib.md5(addr.encode(), usedforsecurity=False).hexdigest()[:6]}"
        try:
            conn.execute(
                """INSERT OR REPLACE INTO contacts
                   (name, email, phone, company, group_name, notes, is_trusted, avatar_color, date_added)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, addr.lower(), phone, company, group, notes, int(trusted), color, datetime.now().isoformat())
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"[!] Contact add error: {e}")
            return False
        finally:
            conn.close()

    def remove_contact(self, addr):
        conn = self._conn()
        conn.execute("DELETE FROM contacts WHERE email = ?", (addr.lower(),))
        conn.commit()
        conn.close()

    def search(self, query, limit=10):
        conn = self._conn()
        q = f"%{query.lower()}%"
        rows = conn.execute(
            """SELECT id, name, email, phone, company, group_name, is_trusted, avatar_color, frequency
               FROM contacts WHERE (LOWER(name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(company) LIKE ?)
               AND is_blocked = 0 ORDER BY frequency DESC, name ASC LIMIT ?""",
            (q, q, q, limit)
        ).fetchall()
        conn.close()
        return [{"id": r[0], "name": r[1], "email": r[2], "phone": r[3], "company": r[4],
                 "group": r[5], "trusted": bool(r[6]), "color": r[7], "frequency": r[8]} for r in rows]

    def get_all(self):
        conn = self._conn()
        rows = conn.execute(
            """SELECT id, name, email, phone, company, group_name, is_trusted, is_blocked,
                      avatar_color, frequency, notes, date_added, last_contact
               FROM contacts ORDER BY name ASC"""
        ).fetchall()
        conn.close()
        return [{"id": r[0], "name": r[1], "email": r[2], "phone": r[3], "company": r[4],
                 "group": r[5], "trusted": bool(r[6]), "blocked": bool(r[7]), "color": r[8],
                 "frequency": r[9], "notes": r[10], "date_added": r[11], "last_contact": r[12]} for r in rows]

    def get_groups(self):
        conn = self._conn()
        rows = conn.execute("SELECT id, name, color FROM contact_groups ORDER BY name").fetchall()
        conn.close()
        return [{"id": r[0], "name": r[1], "color": r[2]} for r in rows]

    def is_known(self, addr):
        conn = self._conn()
        row = conn.execute("SELECT id, is_trusted FROM contacts WHERE email = ?", (addr.lower(),)).fetchone()
        conn.close()
        return row is not None

    def is_trusted(self, addr):
        conn = self._conn()
        row = conn.execute("SELECT is_trusted FROM contacts WHERE email = ?", (addr.lower(),)).fetchone()
        conn.close()
        return bool(row[0]) if row else False

    def increment_frequency(self, addr):
        conn = self._conn()
        conn.execute("UPDATE contacts SET frequency = frequency + 1, last_contact = ? WHERE email = ?",
                      (datetime.now().isoformat(), addr.lower()))
        conn.commit()
        conn.close()

    def block_contact(self, addr, blocked=True):
        conn = self._conn()
        conn.execute("UPDATE contacts SET is_blocked = ? WHERE email = ?", (int(blocked), addr.lower()))
        conn.commit()
        conn.close()

    def update_contact(self, contact_id, data):
        conn = self._conn()
        fields = []
        values = []
        for key in ("name", "email", "phone", "company", "group_name", "notes", "is_trusted"):
            if key in data:
                fields.append(f"{key} = ?")
                values.append(data[key])
        if fields:
            values.append(contact_id)
            conn.execute(f"UPDATE contacts SET {', '.join(fields)} WHERE id = ?", values)
            conn.commit()
        conn.close()

# --- Provider Detector ---------------------------------------------------------

# Thunderbird public client ID - widely used by open-source email clients
MS_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
MS_AUTHORITY = "https://login.microsoftonline.com/consumers"
MS_SCOPES = ["https://outlook.office365.com/IMAP.AccessAsUser.All",
             "https://outlook.office365.com/SMTP.Send", "offline_access"]

MICROSOFT_DOMAINS = {"hotmail.com", "hotmail.fr", "hotmail.ca", "hotmail.co.uk",
                     "outlook.com", "outlook.fr", "outlook.ca",
                     "live.com", "live.fr", "live.ca", "msn.com"}

class ProviderDetector:
    """Auto-detects email provider and handles auth (app password or OAuth2)."""

    def __init__(self, settings):
        self.providers = settings.get("email_providers", {})

    def detect(self, email_address):
        if not email_address or "@" not in email_address:
            return None, None
        domain = email_address.split("@")[1].lower()
        for key, prov in self.providers.items():
            if domain in prov.get("domains", []):
                return key, prov
        return None, None

    def is_microsoft(self, email_address):
        if not email_address or "@" not in email_address:
            return False
        return email_address.split("@")[1].lower() in MICROSOFT_DOMAINS

    def get_all_providers(self):
        return {k: {"name": v["name"], "domains": v["domains"],
                     "help_text": v.get("help_text", ""), "help_url": v.get("help_url", ""),
                     "auth_method": "oauth2" if self.is_microsoft(next((d for d in v.get("domains", [])), "")) else "app_password"}
                for k, v in self.providers.items()}

    def get_account_config(self, email_address, password=""):
        """Build a full account config dict from email + password."""
        key, prov = self.detect(email_address)
        if not prov:
            return None, None
        is_ms = self.is_microsoft(email_address)
        config = {
            "name": prov["name"],
            "email": email_address,
            "imap_server": prov.get("imap_server", ""),
            "imap_port": prov.get("imap_port", 993),
            "smtp_server": prov.get("smtp_server", ""),
            "smtp_port": prov.get("smtp_port", 587),
            "username": email_address,
            "password": "" if is_ms else password,
            "use_ssl": True,
            "use_oauth2": is_ms,
            "oauth2_provider": "microsoft" if is_ms else "",
            "sync_interval_seconds": 60,
            "sync_days": 30
        }
        return config, prov


class MicrosoftOAuth:
    """Handles Microsoft OAuth2 flow for Hotmail/Outlook.com using MSAL."""

    def __init__(self):
        self._app = None
        self._token_cache = {}  # email -> {access_token, refresh_token, expiry}

    @property
    def app(self):
        """Lazy init - only connects to Microsoft when actually needed."""
        if self._app is None:
            self._app = msal.PublicClientApplication(
                MS_CLIENT_ID,
                authority=MS_AUTHORITY
            )
        return self._app

    def login_interactive(self, email_hint=""):
        """Open browser for Microsoft login. Returns (tokens_dict, error_msg)."""
        try:
            result = self.app.acquire_token_interactive(
                scopes=MS_SCOPES,
                login_hint=email_hint,
                prompt="select_account"
            )
            if "access_token" in result:
                email_addr = result.get("id_token_claims", {}).get("preferred_username", email_hint)
                token_data = {
                    "access_token": result["access_token"],
                    "refresh_token": result.get("refresh_token", ""),
                    "expiry": (datetime.now() + timedelta(seconds=result.get("expires_in", 3600))).isoformat(),
                    "email": email_addr
                }
                self._token_cache[email_addr.lower()] = token_data
                return token_data, None
            else:
                error = result.get("error_description", result.get("error", "Echec d'authentification Microsoft"))
                return None, error
        except Exception as e:
            return None, str(e)

    def get_token(self, email_address):
        """Get a valid access token for this email, refreshing if needed."""
        email_lower = email_address.lower()
        cached = self._token_cache.get(email_lower)

        if cached:
            try:
                expiry = datetime.fromisoformat(cached["expiry"])
                if datetime.now() < expiry - timedelta(minutes=5):
                    return cached["access_token"], None
            except:
                pass

        # Try silent token acquisition from MSAL cache
        accounts = self.app.get_accounts(username=email_address)
        if accounts:
            result = self.app.acquire_token_silent(MS_SCOPES, account=accounts[0])
            if result and "access_token" in result:
                token_data = {
                    "access_token": result["access_token"],
                    "refresh_token": result.get("refresh_token", ""),
                    "expiry": (datetime.now() + timedelta(seconds=result.get("expires_in", 3600))).isoformat(),
                    "email": email_address
                }
                self._token_cache[email_lower] = token_data
                return result["access_token"], None

        return None, "Token expire, reconnexion necessaire"

    def build_xoauth2_string(self, user, access_token):
        auth_string = f"user={user}\x01auth=Bearer {access_token}\x01\x01"
        return auth_string

# --- Blacklist Manager ---------------------------------------------------------

class BlacklistManager:
    """Manages email/domain blacklist."""

    def add(self, email_addr="", domain="", reason=""):
        conn = sqlite3.connect(str(DB_PATH))
        now = datetime.now().isoformat()
        if email_addr:
            conn.execute("INSERT OR REPLACE INTO blacklist (email, domain, reason, date_added) VALUES (?,?,?,?)",
                         (email_addr.lower(), "", reason, now))
        if domain:
            domain = domain.lower().lstrip("@")
            conn.execute("INSERT OR REPLACE INTO blacklist (email, domain, reason, date_added) VALUES (?,?,?,?)",
                         ("", domain, reason, now))
        conn.commit()
        conn.close()

    def remove(self, bl_id):
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("DELETE FROM blacklist WHERE id=?", (bl_id,))
        conn.commit()
        conn.close()

    def get_all(self):
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM blacklist WHERE is_active=1 ORDER BY date_added DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def is_blacklisted(self, email_addr):
        if not email_addr:
            return False
        email_lower = email_addr.lower()
        domain = email_lower.split("@")[-1] if "@" in email_lower else ""
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT id FROM blacklist WHERE is_active=1 AND (email=? OR (domain=? AND domain != ''))",
            (email_lower, domain)
        ).fetchone()
        conn.close()
        return row is not None

    def import_list(self, entries):
        """Import a list of email/domain strings."""
        count = 0
        for entry in entries:
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue
            if "@" in entry:
                self.add(email_addr=entry)
            else:
                self.add(domain=entry)
            count += 1
        return count

    def export_list(self):
        items = self.get_all()
        lines = []
        for item in items:
            if item["email"]:
                lines.append(item["email"])
            elif item["domain"]:
                lines.append(item["domain"])
        return "\n".join(lines)


# --- Threat Logger -------------------------------------------------------------

class ThreatLogger:
    """Logs and tracks security threats."""

    def log_threat(self, email_id=None, threat_type="unknown", severity="medium",
                   description="", from_email="", subject="", details=None, action="blocked"):
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""INSERT INTO threats
            (email_id, threat_type, severity, description, from_email, subject, details, action_taken, date_detected)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (email_id, threat_type, severity, description, from_email, subject,
             json.dumps(details or {}), action, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def get_threats(self, limit=100, severity=None):
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        q = "SELECT * FROM threats"
        params = []
        if severity:
            q += " WHERE severity=?"
            params.append(severity)
        q += " ORDER BY date_detected DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self):
        conn = sqlite3.connect(str(DB_PATH))
        stats = {}
        for row in conn.execute("SELECT threat_type, COUNT(*) as cnt FROM threats GROUP BY threat_type"):
            stats[row[0]] = row[1]
        for row in conn.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity"):
            stats[f"severity_{row[0]}"] = row[1]
        total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        stats["total"] = total
        recent = conn.execute("SELECT COUNT(*) FROM threats WHERE date_detected > ?",
                              ((datetime.now() - timedelta(days=7)).isoformat(),)).fetchone()[0]
        stats["recent_7d"] = recent
        conn.close()
        return stats

    def clear_old(self, days=90):
        conn = sqlite3.connect(str(DB_PATH))
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        conn.execute("DELETE FROM threats WHERE date_detected < ?", (cutoff,))
        conn.commit()
        conn.close()


# --- Phishing Detector --------------------------------------------------------

class PhishingDetector:
    """Advanced phishing and fraud detection."""

    SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click", ".loan", ".work"}
    PHISHING_KEYWORDS = [
        "verify your account", "verifiez votre compte", "confirm your identity",
        "confirmez votre identite", "update your payment", "mise a jour de paiement",
        "your account has been suspended", "votre compte a ete suspendu",
        "click here immediately", "cliquez ici immediatement", "urgent action required",
        "action urgente requise", "you have won", "vous avez gagne",
        "reset your password now", "reinitialisez votre mot de passe",
        "invoice attached", "facture ci-jointe", "wire transfer", "virement bancaire",
        "bitcoin", "cryptocurrency", "crypto-monnaie", "lottery", "loterie",
        "inherit", "heritage", "prince", "beneficiary", "beneficiaire",
        "social security", "numero de securite sociale", "tax refund", "remboursement",
        "apple id", "paypal", "netflix", "amazon", "bank of", "banque de"
    ]
    SPOOF_DOMAINS = {
        "paypal": ["paypa1", "paypaI", "paypall", "pay-pal", "paypal-secure"],
        "google": ["g00gle", "googIe", "gogle", "google-verify"],
        "microsoft": ["micros0ft", "micosoft", "microsoft-verify", "ms-login"],
        "apple": ["app1e", "appIe", "apple-id-verify"],
        "amazon": ["amaz0n", "arnazon", "amazon-delivery"],
        "netflix": ["netf1ix", "netfIix", "netflix-billing"],
        "facebook": ["faceb00k", "facebok", "facebook-security"],
    }

    def analyze(self, from_email, from_name, subject, body_text, body_html, headers_raw=""):
        """Analyze email for phishing indicators. Returns dict with score and flags."""
        threats = []
        score = 0  # 0=safe, 100=definitely phishing

        if not from_email:
            return {"score": 0, "threats": [], "is_phishing": False}

        domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
        content = f"{subject} {body_text}".lower()

        # 1. Check suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 15
                threats.append({"type": "suspicious_tld", "detail": f"Domaine suspect: .{tld}"})
                break

        # 2. Check phishing keywords
        kw_hits = 0
        for kw in self.PHISHING_KEYWORDS:
            if kw.lower() in content:
                kw_hits += 1
        if kw_hits >= 3:
            score += 30
            threats.append({"type": "phishing_keywords", "detail": f"{kw_hits} mots-cles de phishing detectes"})
        elif kw_hits >= 1:
            score += 10 * kw_hits
            threats.append({"type": "phishing_keywords", "detail": f"{kw_hits} mot(s)-cle(s) suspect(s)"})

        # 3. Check domain spoofing
        for legit, spoofs in self.SPOOF_DOMAINS.items():
            for spoof in spoofs:
                if spoof in domain:
                    score += 40
                    threats.append({"type": "domain_spoof", "detail": f"Usurpation possible de {legit} ({domain})"})
                    break

        # 4. Check mismatched display name vs email domain
        if from_name:
            name_lower = from_name.lower()
            for brand in self.SPOOF_DOMAINS:
                if brand in name_lower and brand not in domain:
                    score += 25
                    threats.append({"type": "name_mismatch", "detail": f"Nom affiche '{from_name}' ne correspond pas au domaine {domain}"})
                    break

        # 5. Check for suspicious URLs in body
        if body_html:
            import re as _re
            urls = _re.findall(r'href=["\']([^"\']+)["\']', body_html)
            suspicious_urls = [u for u in urls if any(s in u.lower() for s in
                              ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd",
                               "login", "signin", "verify", "secure", "account", "update"])]
            if suspicious_urls:
                score += min(len(suspicious_urls) * 5, 20)
                threats.append({"type": "suspicious_urls", "detail": f"{len(suspicious_urls)} lien(s) suspect(s)"})

        # 6. Check for urgency language
        urgency_words = ["urgent", "immediately", "immediatement", "asap", "right now",
                         "act now", "agissez maintenant", "expire", "24 hours", "24 heures",
                         "limited time", "temps limite", "deadline", "last chance", "derniere chance"]
        urgency_hits = sum(1 for w in urgency_words if w in content)
        if urgency_hits >= 2:
            score += 15
            threats.append({"type": "urgency", "detail": "Langage d'urgence suspect"})

        # 7. Excessive use of CAPS in subject
        if subject and sum(1 for c in subject if c.isupper()) > len(subject) * 0.6 and len(subject) > 10:
            score += 10
            threats.append({"type": "caps_subject", "detail": "Sujet en majuscules (technique de spam)"})

        score = min(score, 100)
        return {
            "score": score,
            "threats": threats,
            "is_phishing": score >= 50,
            "severity": "critical" if score >= 70 else "high" if score >= 50 else "medium" if score >= 30 else "low"
        }


# --- Internationalization -----------------------------------------------------

I18N = {
    "fr": {
        "app_name": "MailShield Pro",
        "inbox": "Boite de reception",
        "all_emails": "Tous les emails",
        "primary": "Principal",
        "social": "Social",
        "promotions": "Promotions",
        "notifications": "Notifications",
        "starred": "Favoris",
        "spam": "Spam",
        "trash": "Corbeille",
        "junk": "Indesirables",
        "drafts": "Brouillons",
        "reply": "Repondre",
        "reply_all": "Repondre a tous",
        "forward": "Transferer",
        "save_draft": "Sauvegarder brouillon",
        "privacy_local": "100% LOCAL",
        "privacy_desc": "Aucune donnee ne quitte votre ordinateur. Zero cloud, zero tracking.",
        "blacklist": "Liste noire",
        "threats": "Menaces",
        "contacts": "Contacts",
        "filters": "Filtres",
        "settings": "Parametres",
        "compose": "Nouveau message",
        "sync": "Synchroniser",
        "refresh": "Actualiser",
        "search": "Rechercher des emails, contacts...",
        "send": "Envoyer",
        "cancel": "Annuler",
        "save": "Sauvegarder",
        "delete": "Supprimer",
        "block": "Bloquer",
        "unblock": "Debloquer",
        "import": "Importer",
        "export": "Exporter",
        "add_contact": "Ajouter un contact",
        "import_contacts": "Importer contacts",
        "export_contacts": "Exporter contacts",
        "safe": "Securise",
        "warning": "Attention",
        "danger": "Suspect",
        "known_contact": "Contact connu",
        "dangerous_attachment": "PJ dangereuse !",
        "open_virtual": "Ouvrir en mode protege",
        "virtual_mode": "Mode protege",
        "virtual_desc": "Email ouvert en sandbox - liens et scripts desactives",
        "connection_cut": "Connexion coupee - mode hors ligne de securite",
        "threats_detected": "Menaces detectees",
        "threats_blocked": "Menaces bloquees",
        "threats_recent": "Menaces recentes (7j)",
        "phishing": "Phishing",
        "malware": "Malware",
        "blacklisted": "Expediteur bloque",
        "add_to_blacklist": "Ajouter a la liste noire",
        "remove_from_blacklist": "Retirer de la liste noire",
        "no_threats": "Aucune menace detectee",
        "select_email": "Selectionnez un email pour le lire",
        "or_compose": 'Ou cliquez sur "Nouveau message" pour composer',
        "no_emails": "Aucun email dans cette categorie",
        "click_sync": "Cliquez sur Actualiser pour verifier les nouveaux messages",
        "language": "Langue",
    },
    "en": {
        "app_name": "MailShield Pro",
        "inbox": "Inbox",
        "all_emails": "All Emails",
        "primary": "Primary",
        "social": "Social",
        "promotions": "Promotions",
        "notifications": "Notifications",
        "starred": "Starred",
        "spam": "Spam",
        "trash": "Trash",
        "junk": "Junk",
        "drafts": "Drafts",
        "reply": "Reply",
        "reply_all": "Reply All",
        "forward": "Forward",
        "save_draft": "Save Draft",
        "privacy_local": "100% LOCAL",
        "privacy_desc": "No data ever leaves your computer. Zero cloud, zero tracking.",
        "blacklist": "Blacklist",
        "threats": "Threats",
        "contacts": "Contacts",
        "filters": "Filters",
        "settings": "Settings",
        "compose": "New Message",
        "sync": "Sync",
        "refresh": "Refresh",
        "search": "Search emails, contacts...",
        "send": "Send",
        "cancel": "Cancel",
        "save": "Save",
        "delete": "Delete",
        "block": "Block",
        "unblock": "Unblock",
        "import": "Import",
        "export": "Export",
        "add_contact": "Add Contact",
        "import_contacts": "Import Contacts",
        "export_contacts": "Export Contacts",
        "safe": "Safe",
        "warning": "Warning",
        "danger": "Suspect",
        "known_contact": "Known Contact",
        "dangerous_attachment": "Dangerous Attachment!",
        "open_virtual": "Open in Protected Mode",
        "virtual_mode": "Protected Mode",
        "virtual_desc": "Email opened in sandbox - links and scripts disabled",
        "connection_cut": "Connection cut - safety offline mode",
        "threats_detected": "Threats Detected",
        "threats_blocked": "Threats Blocked",
        "threats_recent": "Recent Threats (7d)",
        "phishing": "Phishing",
        "malware": "Malware",
        "blacklisted": "Blocked Sender",
        "add_to_blacklist": "Add to Blacklist",
        "remove_from_blacklist": "Remove from Blacklist",
        "no_threats": "No threats detected",
        "select_email": "Select an email to read",
        "or_compose": 'Or click "New Message" to compose',
        "no_emails": "No emails in this category",
        "click_sync": "Click Refresh to check for new messages",
        "language": "Language",
    }
}


# --- Mail Engine ---------------------------------------------------------------

class MailShieldEngine:
    def __init__(self):
        self.settings = load_settings()
        self.filter_engine = FilterEngine(self.settings)
        self.attachment_scanner = AttachmentScanner(self.settings)
        self.contacts = ContactBook()
        self.provider_detector = ProviderDetector(self.settings)
        self.ms_oauth = MicrosoftOAuth()
        self.blacklist = BlacklistManager()
        self.threat_logger = ThreatLogger()
        self.phishing_detector = PhishingDetector()
        self.imap_conn = None
        self.smtp_conn = None
        self.running = False
        self.ws_clients = set()
        self.sandbox_mode = False  # Virtual/sandbox email viewing
        init_database()
        QUARANTINE_DIR.mkdir(exist_ok=True)

    def reload_settings(self):
        self.settings = load_settings()
        self.filter_engine.reload(self.settings)
        self.attachment_scanner = AttachmentScanner(self.settings)
        self.provider_detector = ProviderDetector(self.settings)

    # -- IMAP Connection ----------------------------------------------------

    def connect_imap(self, account=None):
        acc = account or (self.settings.get("accounts", [{}])[0] if self.settings.get("accounts") else {})
        server = acc.get("imap_server", "")
        port = acc.get("imap_port", 993)
        user = acc.get("username", "") or acc.get("email", "")
        pwd_raw = acc.get("password", "")
        pwd = password_vault.decrypt(pwd_raw)  # Decrypt password
        use_ssl = acc.get("use_ssl", True)
        use_oauth2 = acc.get("use_oauth2", False)

        if not server or not user:
            return False, "Configuration IMAP incomplete"

        # Microsoft OAuth2 (XOAUTH2)
        if use_oauth2 or self.provider_detector.is_microsoft(user):
            token, err = self.ms_oauth.get_token(user)
            if not token:
                return False, f"Token Microsoft expire. {err or 'Reconnectez-vous via OAuth.'}"
            try:
                self.imap_conn = imaplib.IMAP4_SSL(server, port)
                auth_string = self.ms_oauth.build_xoauth2_string(user, token)
                self.imap_conn.authenticate("XOAUTH2", lambda x: auth_string.encode())
                logger.info(f"Connected to {server} via OAuth2 for {user}")
                return True, "Connecte (OAuth2 Microsoft)"
            except imaplib.IMAP4.error as e:
                logger.error(f"XOAUTH2 failed for {user}: {e}")
                return False, f"Echec XOAUTH2 IMAP: {e}"
            except Exception as e:
                return False, str(e)

        # Standard password login (Gmail app password, Yahoo, etc.)
        if not pwd:
            return False, "Mot de passe requis"

        try:
            if use_ssl:
                self.imap_conn = imaplib.IMAP4_SSL(server, port)
            else:
                self.imap_conn = imaplib.IMAP4(server, port)
            self.imap_conn.login(user, pwd)
            logger.info(f"Connected to {server} for {user}")
            return True, "Connecte"
        except imaplib.IMAP4.error as e:
            err = str(e)
            if "AUTHENTICATIONFAILED" in err.upper() or "LOGIN" in err.upper():
                provider_key, prov = self.provider_detector.detect(user)
                if prov:
                    return False, f"Echec d'authentification. {prov.get('help_text', 'Verifiez votre mot de passe.')}"
                return False, "Echec d'authentification. Verifiez votre email et mot de passe."
            return False, err
        except Exception as e:
            return False, str(e)

    def disconnect_imap(self):
        if self.imap_conn:
            try:
                self.imap_conn.logout()
            except:
                pass
            self.imap_conn = None

    # -- Fetch Emails -------------------------------------------------------

    def fetch_emails(self, folder="INBOX", limit=50, since_days=30):
        if not self.imap_conn:
            return []

        try:
            self.imap_conn.select(folder, readonly=True)
        except Exception as e:
            print(f"[!] Select folder error: {e}")
            return []

        since_date = (datetime.now() - timedelta(days=since_days)).strftime("%d-%b-%Y")
        try:
            _, msg_ids = self.imap_conn.search(None, f'(SINCE {since_date})')
        except:
            _, msg_ids = self.imap_conn.search(None, "ALL")

        id_list = msg_ids[0].split()
        if not id_list:
            return []

        # Get latest emails first
        id_list = id_list[-limit:]
        id_list.reverse()

        emails = []
        conn = sqlite3.connect(str(DB_PATH))

        for uid in id_list:
            try:
                _, msg_data = self.imap_conn.fetch(uid, "(RFC822)")
                if not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                msg = email.message_from_bytes(raw)

                # nosec B324 - synthetic Message-ID fallback; MD5 used as
                # non-cryptographic dedup key when the mail server omits the header.
                message_id = msg.get("Message-ID", f"<{hashlib.md5(raw[:500], usedforsecurity=False).hexdigest()}>")

                # Check if already in DB
                existing = conn.execute("SELECT id FROM emails WHERE message_id = ?", (message_id,)).fetchone()
                if existing:
                    continue

                from_name, from_email_addr = parse_email_address(msg.get("From", ""))
                to_name, to_email_addr = parse_email_address(msg.get("To", ""))
                cc = decode_header_value(msg.get("Cc", ""))
                subject = decode_header_value(msg.get("Subject", "(Sans sujet)"))

                date_str = msg.get("Date", "")
                try:
                    date_tuple = email.utils.parsedate_to_datetime(date_str)
                    date_sent = date_tuple.isoformat()
                except:
                    date_sent = datetime.now().isoformat()

                # Extract body
                body_text, body_html = self._extract_body(msg)

                # Extract attachments
                attachments = self._extract_attachments(msg)
                att_names = [a["filename"] for a in attachments]

                # Classify
                is_contact = self.contacts.is_known(from_email_addr)
                category, filter_matched = self.filter_engine.classify_email(
                    from_name, from_email_addr, subject, body_text, att_names, is_contact
                )

                # Calculate trust score
                trust_score = self._calculate_trust_score(from_email_addr, is_contact, attachments, category)

                # Security flags
                security_flags = {
                    "is_contact": is_contact,
                    "has_dangerous_attachments": any(a.get("blocked") for a in attachments),
                    "attachment_count": len(attachments)
                }

                # Insert email
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO emails
                       (message_id, account, folder, from_name, from_email, to_email, cc,
                        subject, body_text, body_html, date_sent, date_received, category,
                        trust_score, security_flags, has_attachments, filter_matched, uid)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (message_id, "", folder, from_name, from_email_addr, to_email_addr, cc,
                     subject, body_text, body_html, date_sent, datetime.now().isoformat(),
                     category, trust_score, json.dumps(security_flags),
                     1 if attachments else 0, filter_matched, int(uid))
                )
                email_db_id = cursor.lastrowid

                # Insert attachments
                for att in attachments:
                    is_contact_trusted = self.contacts.is_trusted(from_email_addr)
                    score, blocked, quarantined, result = self.attachment_scanner.scan(
                        att["filename"], att["size"], att["content_type"], is_contact_trusted
                    )
                    att_data = att.get("data")

                    if quarantined and att_data:
                        q_path = QUARANTINE_DIR / f"{email_db_id}_{att['filename']}"
                        q_path.write_bytes(att_data)
                        att_data = None  # Don't store in DB if quarantined

                    conn.execute(
                        """INSERT INTO attachments
                           (email_id, filename, content_type, size_bytes, extension,
                            is_blocked, is_quarantined, quarantine_path, trust_score, scan_result, data)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (email_db_id, att["filename"], att["content_type"], att["size"],
                         att["extension"], int(blocked), int(quarantined),
                         str(QUARANTINE_DIR / f"{email_db_id}_{att['filename']}") if quarantined else None,
                         score, result, att_data if not blocked else None)
                    )

                # Auto-learn contacts
                if is_contact:
                    self.contacts.increment_frequency(from_email_addr)

                emails.append({
                    "id": email_db_id,
                    "subject": subject,
                    "from_name": from_name,
                    "from_email": from_email_addr,
                    "category": category,
                    "trust_score": trust_score
                })

            except Exception as e:
                print(f"[!] Email parse error: {e}")
                continue

        conn.commit()
        conn.close()
        return emails

    def _extract_body(self, msg):
        body_text = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if "attachment" in disp:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")
                    if ct == "text/plain":
                        body_text = text
                    elif ct == "text/html":
                        body_html = text
                except:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace") if payload else ""
                if msg.get_content_type() == "text/html":
                    body_html = text
                else:
                    body_text = text
            except:
                pass
        return body_text, body_html

    def _extract_attachments(self, msg):
        attachments = []
        if not msg.is_multipart():
            return attachments
        for part in msg.walk():
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" not in disp and "inline" not in disp:
                continue
            filename = part.get_filename()
            if not filename:
                continue
            filename = decode_header_value(filename)
            data = part.get_payload(decode=True)
            ext = Path(filename).suffix.lower()
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(data) if data else 0,
                "extension": ext,
                "data": data
            })
        return attachments

    def _calculate_trust_score(self, from_addr, is_contact, attachments, category):
        score = 50
        if is_contact:
            score += 30
        if self.contacts.is_trusted(from_addr):
            score += 20
        if category == "spam":
            score -= 40
        if any(a.get("blocked") for a in attachments):
            score -= 30
        has_suspicious = any(
            Path(a["filename"]).suffix.lower() in self.attachment_scanner.suspicious_ext
            for a in attachments if a.get("filename")
        )
        if has_suspicious:
            score -= 15
        return max(0, min(100, score))

    # -- Send Email ---------------------------------------------------------

    def send_email(self, to, subject, body_html, cc="", bcc="", attachments=None, account=None):
        acc = account or (self.settings.get("accounts", [{}])[0] if self.settings.get("accounts") else {})
        server = acc.get("smtp_server", "")
        port = acc.get("smtp_port", 587)
        user = acc.get("username", "")
        pwd = password_vault.decrypt(acc.get("password", ""))
        from_email = acc.get("email", user)

        if not server or not user:
            return False, "Configuration SMTP incomplete"

        msg = MIMEMultipart("alternative")
        msg["From"] = from_email
        msg["To"] = to
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid()

        if cc:
            msg["Cc"] = cc
        if bcc:
            msg["Bcc"] = bcc

        msg.attach(MIMEText(body_html, "html", "utf-8"))

        if attachments:
            for att_path in attachments:
                p = Path(att_path)
                if p.exists():
                    ct, _ = mimetypes.guess_type(str(p))
                    maintype, subtype = (ct or "application/octet-stream").split("/", 1)
                    part = MIMEBase(maintype, subtype)
                    part.set_payload(p.read_bytes())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", "attachment", filename=p.name)
                    msg.attach(part)

        use_oauth2 = acc.get("use_oauth2", False)
        recipients = [to]
        if cc:
            recipients.extend(a.strip() for a in cc.split(","))
        if bcc:
            recipients.extend(a.strip() for a in bcc.split(","))

        try:
            with smtplib.SMTP(server, port) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()

                if use_oauth2 or self.provider_detector.is_microsoft(user):
                    # Microsoft XOAUTH2 SMTP
                    token, err = self.ms_oauth.get_token(user)
                    if not token:
                        return False, f"Token Microsoft expire. {err or 'Reconnectez-vous.'}"
                    auth_string = self.ms_oauth.build_xoauth2_string(user, token)
                    smtp.auth("XOAUTH2", lambda challenge=None: auth_string)
                else:
                    smtp.login(user, pwd)

                smtp.sendmail(from_email, recipients, msg.as_string())
            return True, "Email envoye"
        except Exception as e:
            return False, str(e)

    # -- Database Queries ---------------------------------------------------

    def get_emails(self, category=None, folder="INBOX", search=None, page=1, per_page=50):
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        where = ["is_deleted = 0"]
        params = []

        if category and category != "all":
            if category == "trash":
                where = ["is_deleted = 1"]
            elif category == "starred":
                where.append("is_starred = 1")
            elif category == "junk":
                where.append("(category = 'spam' OR is_spam = 1)")
            else:
                where.append("category = ?")
                params.append(category)

        if search:
            where.append("(subject LIKE ? OR from_name LIKE ? OR from_email LIKE ? OR body_text LIKE ?)")
            sq = f"%{search}%"
            params.extend([sq, sq, sq, sq])

        offset = (page - 1) * per_page
        where_clause = ' AND '.join(where) if where else '1=1'
        query = f"""SELECT id, message_id, from_name, from_email, to_email, subject,
                           SUBSTR(body_text, 1, 200) as preview, date_sent, date_received,
                           category, is_read, is_starred, trust_score, has_attachments,
                           filter_matched, security_flags
                    FROM emails WHERE {where_clause}
                    ORDER BY date_received DESC LIMIT ? OFFSET ?"""

        count_params = list(params)  # copy params before adding limit/offset
        params.extend([per_page, offset])

        rows = conn.execute(query, params).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM emails WHERE {where_clause}", count_params).fetchone()[0]
        conn.close()

        return {
            "emails": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page
        }

    def get_email(self, email_id):
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM emails WHERE id = ?", (email_id,)).fetchone()
        if not row:
            conn.close()
            return None

        result = dict(row)
        # Get attachments
        atts = conn.execute(
            """SELECT id, filename, content_type, size_bytes, extension,
                      is_blocked, is_quarantined, trust_score, scan_result
               FROM attachments WHERE email_id = ?""", (email_id,)
        ).fetchall()
        result["attachments"] = [dict(a) for a in atts]

        # Mark as read
        conn.execute("UPDATE emails SET is_read = 1 WHERE id = ?", (email_id,))
        conn.commit()
        conn.close()
        return result

    def delete_email(self, email_id, permanent=False):
        conn = sqlite3.connect(str(DB_PATH))
        if permanent:
            conn.execute("DELETE FROM emails WHERE id = ?", (email_id,))
        else:
            conn.execute("UPDATE emails SET is_deleted = 1 WHERE id = ?", (email_id,))
        conn.commit()
        conn.close()

    def toggle_star(self, email_id):
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("UPDATE emails SET is_starred = CASE WHEN is_starred = 1 THEN 0 ELSE 1 END WHERE id = ?", (email_id,))
        conn.commit()
        conn.close()

    def move_to_category(self, email_id, category):
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("UPDATE emails SET category = ? WHERE id = ?", (category, email_id))
        conn.commit()
        conn.close()

    def get_category_counts(self):
        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute(
            """SELECT category, COUNT(*) as total,
                      SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread
               FROM emails WHERE is_deleted = 0 GROUP BY category"""
        ).fetchall()
        counts = {r[0]: {"total": r[1], "unread": r[2]} for r in rows}
        # Add trash count
        trash = conn.execute("SELECT COUNT(*) FROM emails WHERE is_deleted = 1").fetchone()
        counts["trash"] = {"total": trash[0], "unread": 0}
        # Starred
        starred = conn.execute("SELECT COUNT(*) FROM emails WHERE is_starred = 1 AND is_deleted = 0").fetchone()
        counts["starred"] = {"total": starred[0], "unread": 0}
        # Junk = spam + is_spam combined
        junk = conn.execute(
            "SELECT COUNT(*), SUM(CASE WHEN is_read=0 THEN 1 ELSE 0 END) FROM emails WHERE is_deleted=0 AND (category='spam' OR is_spam=1)"
        ).fetchone()
        counts["junk"] = {"total": junk[0] or 0, "unread": junk[1] or 0}
        conn.close()
        return counts

    def get_attachment_data(self, att_id):
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute("SELECT filename, content_type, data, is_blocked, is_quarantined FROM attachments WHERE id = ?", (att_id,)).fetchone()
        conn.close()
        if row and row[3] == 0:  # Not blocked
            return {"filename": row[0], "content_type": row[1], "data": row[2]}
        return None

# --- HTTP Server ---------------------------------------------------------------

engine = None

class MailShieldHTTPHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default access logging (use structured logger instead)

    def log_error(self, format, *args):
        logger.error(f"[HTTP] {format % args}")

    def _check_auth(self):
        """Check API token for non-dashboard requests."""
        if self.path == "/" or self.path == "/dashboard" or self.path.startswith("/api/i18n"):
            return True  # Public endpoints
        # Token can be in header or query param
        auth = self.headers.get("X-API-Token", "")
        if auth == API_TOKEN:
            return True
        # Check query param (for browser-opened URLs like attachments)
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if params.get("token", [""])[0] == API_TOKEN:
            return True
        return False

    def do_GET(self):
      try:
        if not self._check_auth():
            self.json_response({"error": "Unauthorized"}, 401)
            return

        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/" or path == "/dashboard":
            self.serve_file("mailshield_dashboard.html")
        elif path == "/api/token":
            # Return token for dashboard init (only accessible from localhost)
            self.json_response({"token": API_TOKEN})
        elif path == "/api/emails":
            category = params.get("category", [None])[0]
            search = params.get("search", [None])[0]
            page = int(params.get("page", [1])[0])
            data = engine.get_emails(category=category, search=search, page=page)
            self.json_response(data)
        elif path.startswith("/api/email/"):
            eid = int(path.split("/")[-1])
            data = engine.get_email(eid)
            self.json_response(data or {"error": "not found"})
        elif path == "/api/contacts":
            q = params.get("q", [None])[0]
            if q:
                data = engine.contacts.search(q)
            else:
                data = engine.contacts.get_all()
            self.json_response(data)
        elif path == "/api/contacts/groups":
            self.json_response(engine.contacts.get_groups())
        elif path == "/api/categories/counts":
            self.json_response(engine.get_category_counts())
        elif path == "/api/settings":
            # Return settings with passwords masked
            safe = json.loads(json.dumps(engine.settings))
            for acc in safe.get("accounts", []):
                if acc.get("password"):
                    acc["password"] = "********"  # Never expose passwords
            self.json_response(safe)
        elif path == "/api/settings/filters":
            self.json_response(engine.settings.get("filter_keywords", {}))
        elif path == "/api/account/status":
            accounts = engine.settings.get("accounts", [])
            statuses = []
            for acc in accounts:
                if acc.get("email") and acc.get("imap_server"):
                    prov_key, prov = engine.provider_detector.detect(acc.get("email", ""))
                    statuses.append({
                        "connected": True,
                        "provider": prov_key or "custom",
                        "provider_name": prov["name"] if prov else "Autre",
                        "email": acc.get("email", "")
                    })
                else:
                    statuses.append({"connected": False, "email": ""})
            self.json_response(statuses)
        elif path == "/api/providers":
            self.json_response(engine.provider_detector.get_all_providers())
        elif path.startswith("/api/provider/detect"):
            email_addr = params.get("email", [""])[0]
            prov_key, prov = engine.provider_detector.detect(email_addr)
            is_ms = engine.provider_detector.is_microsoft(email_addr)
            if prov:
                self.json_response({
                    "found": True, "provider": prov_key, "name": prov["name"],
                    "help_text": prov.get("help_text", ""), "help_url": prov.get("help_url", ""),
                    "auth_method": "oauth2" if is_ms else "app_password",
                    "needs_oauth": is_ms
                })
            else:
                self.json_response({"found": False})
        elif path.startswith("/api/attachment/"):
            att_id = int(path.split("/")[-1])
            data = engine.get_attachment_data(att_id)
            if data and data["data"]:
                self.send_response(200)
                self.send_header("Content-Type", data["content_type"])
                self.send_header("Content-Disposition", f'attachment; filename="{data["filename"]}"')
                self.end_headers()
                self.wfile.write(data["data"])
            else:
                self.json_response({"error": "blocked or not found"}, 403)
        elif path == "/api/blacklist":
            self.json_response(engine.blacklist.get_all())
        elif path == "/api/threats":
            limit = int(params.get("limit", [100])[0])
            sev = params.get("severity", [None])[0]
            self.json_response(engine.threat_logger.get_threats(limit=limit, severity=sev))
        elif path == "/api/threats/stats":
            self.json_response(engine.threat_logger.get_stats())
        elif path == "/api/i18n":
            lang = params.get("lang", ["fr"])[0]
            self.json_response(I18N.get(lang, I18N["fr"]))
        elif path == "/api/i18n/all":
            self.json_response(I18N)
        elif path == "/api/contacts/export":
            contacts = engine.contacts.get_all()
            csv_lines = ["name,email,phone,company,group,trusted"]
            for c in contacts:
                csv_lines.append(f'"{c.get("name","")}","{c.get("email","")}","{c.get("phone","")}","{c.get("company","")}","{c.get("group","")}","{c.get("trusted",False)}"')
            csv_data = "\n".join(csv_lines)
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="mailshield_contacts.csv"')
            self.end_headers()
            self.wfile.write(csv_data.encode("utf-8"))
        elif path == "/api/drafts":
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM drafts ORDER BY date_modified DESC").fetchall()
            conn.close()
            self.json_response([dict(r) for r in rows])
        elif path.startswith("/api/draft/"):
            did = int(path.split("/")[-1])
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM drafts WHERE id=?", (did,)).fetchone()
            conn.close()
            self.json_response(dict(row) if row else {"error": "not found"})
        elif path == "/api/blacklist/export":
            data = engine.blacklist.export_list()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="mailshield_blacklist.txt"')
            self.end_headers()
            self.wfile.write(data.encode("utf-8"))
        elif path == "/api/startup/state":
            if HAS_STARTUP_UTILS:
                self.json_response({"enabled": is_startup_enabled("MailShield Pro"), "available": True})
            else:
                self.json_response({"enabled": False, "available": False})
        else:
            self.send_error(404)
      except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            self.json_response({"error": str(e)}, 500)
        except:
            pass

    def do_POST(self):
      try:
        if not self._check_auth():
            self.json_response({"error": "Unauthorized"}, 401)
            return

        parsed = urlparse(self.path)
        path = parsed.path
        content_len = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_len)) if content_len > 0 else {}

        if path == "/api/email/reply":
            # Reply to an email
            original_id = body.get("original_id", 0)
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            orig = conn.execute("SELECT * FROM emails WHERE id=?", (original_id,)).fetchone()
            conn.close()
            if not orig:
                self.json_response({"success": False, "message": "Email original introuvable"})
                return
            reply_body = body.get("body", "")
            reply_all = body.get("reply_all", False)
            to = orig["from_email"]
            cc = ""
            if reply_all and orig["cc"]:
                cc = orig["cc"]
            subject = orig["subject"]
            if not subject.lower().startswith("re:"):
                subject = f"Re: {subject}"
            # Build reply HTML with quote
            quote_date = orig["date_sent"] or orig["date_received"] or ""
            quoted = f"""<div style="font-family:sans-serif;font-size:14px">{reply_body}</div>
<br><hr style="border:none;border-top:1px solid #ccc;margin:16px 0">
<div style="color:#666;font-size:12px;margin-bottom:8px">Le {quote_date}, {orig['from_name'] or orig['from_email']} a ecrit :</div>
<blockquote style="margin:0 0 0 12px;padding:0 0 0 12px;border-left:3px solid #ccc;color:#555">
{orig['body_html'] or '<pre>' + (orig['body_text'] or '') + '</pre>'}
</blockquote>"""
            ok, msg = engine.send_email(to=to, subject=subject, body_html=quoted, cc=cc)
            self.json_response({"success": ok, "message": msg})

        elif path == "/api/email/forward":
            # Forward an email
            original_id = body.get("original_id", 0)
            forward_to = body.get("to", "")
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            orig = conn.execute("SELECT * FROM emails WHERE id=?", (original_id,)).fetchone()
            conn.close()
            if not orig:
                self.json_response({"success": False, "message": "Email original introuvable"})
                return
            if not forward_to:
                self.json_response({"success": False, "message": "Destinataire requis"})
                return
            fwd_note = body.get("body", "")
            subject = orig["subject"]
            if not subject.lower().startswith("fwd:") and not subject.lower().startswith("tr:"):
                subject = f"Fwd: {subject}"
            fwd_html = f"""<div style="font-family:sans-serif;font-size:14px">{fwd_note}</div>
<br><hr style="border:none;border-top:1px solid #ccc;margin:16px 0">
<div style="color:#666;font-size:12px;margin-bottom:8px">
---------- Message transfere ----------<br>
De : {orig['from_name'] or ''} &lt;{orig['from_email']}&gt;<br>
Date : {orig['date_sent'] or orig['date_received'] or ''}<br>
Objet : {orig['subject']}<br>
A : {orig['to_email']}<br>
</div>
<div>{orig['body_html'] or '<pre>' + (orig['body_text'] or '') + '</pre>'}</div>"""
            ok, msg = engine.send_email(to=forward_to, subject=subject, body_html=fwd_html)
            self.json_response({"success": ok, "message": msg})

        elif path == "/api/send":
            ok, msg = engine.send_email(
                to=body.get("to", ""),
                subject=body.get("subject", ""),
                body_html=body.get("body", ""),
                cc=body.get("cc", ""),
                bcc=body.get("bcc", "")
            )
            self.json_response({"success": ok, "message": msg})
        elif path == "/api/sync":
            acc_idx = body.get("account_index", 0)
            accounts = engine.settings.get("accounts", [])
            if acc_idx < len(accounts):
                ok, msg = engine.connect_imap(accounts[acc_idx])
                if ok:
                    emails = engine.fetch_emails()
                    engine.disconnect_imap()
                    self.json_response({"success": True, "fetched": len(emails)})
                else:
                    self.json_response({"success": False, "message": msg})
            else:
                self.json_response({"success": False, "message": "Compte non trouve"})
        elif path == "/api/email/delete":
            engine.delete_email(body.get("id", 0), permanent=body.get("permanent", False))
            self.json_response({"success": True})
        elif path == "/api/email/star":
            engine.toggle_star(body.get("id", 0))
            self.json_response({"success": True})
        elif path == "/api/email/move":
            engine.move_to_category(body.get("id", 0), body.get("category", "primary"))
            self.json_response({"success": True})
        elif path == "/api/contacts/add":
            ok = engine.contacts.add_contact(
                name=body.get("name", ""),
                addr=body.get("email", ""),
                phone=body.get("phone", ""),
                company=body.get("company", ""),
                group=body.get("group", "General"),
                notes=body.get("notes", ""),
                trusted=body.get("trusted", False)
            )
            self.json_response({"success": ok})
        elif path == "/api/contacts/update":
            engine.contacts.update_contact(body.get("id"), body)
            self.json_response({"success": True})
        elif path == "/api/contacts/delete":
            engine.contacts.remove_contact(body.get("email", ""))
            self.json_response({"success": True})
        elif path == "/api/contacts/block":
            engine.contacts.block_contact(body.get("email", ""), body.get("blocked", True))
            self.json_response({"success": True})
        elif path == "/api/settings/update":
            settings = engine.settings
            # Deep merge
            for key, value in body.items():
                if isinstance(value, dict) and isinstance(settings.get(key), dict):
                    settings[key].update(value)
                else:
                    settings[key] = value
            save_settings(settings)
            engine.reload_settings()
            self.json_response({"success": True})
        elif path == "/api/settings/filters/update":
            engine.settings["filter_keywords"] = body
            save_settings(engine.settings)
            engine.reload_settings()
            self.json_response({"success": True})
        elif path == "/api/account/save":
            accounts = engine.settings.get("accounts", [])
            idx = body.get("index", -1)
            acc_data = body.get("account", {})
            if idx >= 0 and idx < len(accounts):
                accounts[idx].update(acc_data)
            else:
                accounts.append(acc_data)
            engine.settings["accounts"] = accounts
            save_settings(engine.settings)
            self.json_response({"success": True})
        elif path == "/api/account/test":
            acc = body.get("account", {})
            ok, msg = engine.connect_imap(acc)
            if ok:
                engine.disconnect_imap()
            self.json_response({"success": ok, "message": msg})
        elif path == "/api/quickconnect":
            email_addr = body.get("email", "").strip()
            password = body.get("password", "").strip()

            if not email_addr:
                self.json_response({"success": False, "message": "Adresse email requise"})
                return

            # Check if Microsoft account -> redirect to OAuth
            if engine.provider_detector.is_microsoft(email_addr):
                self.json_response({
                    "success": False,
                    "needs_oauth": True,
                    "provider": "microsoft",
                    "message": "Les comptes Microsoft necessitent une connexion OAuth2. Cliquez sur 'Se connecter avec Microsoft'."
                })
                return

            if not password:
                self.json_response({"success": False, "message": "Mot de passe d'application requis"})
                return

            # Auto-detect provider and build config
            acc_config, prov = engine.provider_detector.get_account_config(email_addr, password)

            if not prov:
                self.json_response({
                    "success": False,
                    "message": "Provider non reconnu. Utilisez la configuration manuelle.",
                    "manual_required": True
                })
                return

            # Test the connection
            ok, msg = engine.connect_imap(acc_config)
            if ok:
                engine.disconnect_imap()
                # Save account
                self._save_account(acc_config, email_addr)
                print(f"  [+] Compte {email_addr} connecte via {prov['name']}")
                self.json_response({
                    "success": True,
                    "email": email_addr,
                    "provider": prov["name"],
                    "message": f"Connecte a {prov['name']} avec succes !"
                })
            else:
                self.json_response({
                    "success": False,
                    "message": msg,
                    "help_url": prov.get("help_url", ""),
                    "help_text": prov.get("help_text", "")
                })

        elif path == "/api/ms-oauth/connect":
            # Microsoft OAuth2 interactive login
            email_hint = body.get("email", "").strip()
            def do_oauth():
                token_data, err = engine.ms_oauth.login_interactive(email_hint)
                return token_data, err
            # Run in thread to not block (MSAL opens browser)
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(do_oauth)
                token_data, err = future.result(timeout=120)

            if token_data:
                email_addr = token_data["email"]
                # Build Microsoft account config
                acc_config = {
                    "name": "Hotmail / Outlook",
                    "email": email_addr,
                    "imap_server": "outlook.office365.com",
                    "imap_port": 993,
                    "smtp_server": "smtp.office365.com",
                    "smtp_port": 587,
                    "username": email_addr,
                    "password": "",
                    "use_ssl": True,
                    "use_oauth2": True,
                    "oauth2_provider": "microsoft",
                    "sync_interval_seconds": 60,
                    "sync_days": 30
                }
                # Test connection
                ok, msg = engine.connect_imap(acc_config)
                if ok:
                    engine.disconnect_imap()
                    self._save_account(acc_config, email_addr)
                    print(f"  [+] Compte Microsoft {email_addr} connecte via OAuth2")
                    self.json_response({
                        "success": True,
                        "email": email_addr,
                        "provider": "Microsoft (OAuth2)",
                        "message": f"Connecte a Microsoft avec succes !"
                    })
                else:
                    self.json_response({"success": False, "message": f"OAuth OK mais IMAP echoue: {msg}"})
            else:
                self.json_response({"success": False, "message": err or "Echec de connexion Microsoft"})

        elif path == "/api/ms-oauth/status":
            accounts = engine.settings.get("accounts", [])
            ms_accounts = [a for a in accounts if a.get("use_oauth2") and a.get("oauth2_provider") == "microsoft"]
            if ms_accounts:
                acc = ms_accounts[0]
                token, _ = engine.ms_oauth.get_token(acc["email"])
                self.json_response({
                    "connected": True,
                    "email": acc["email"],
                    "token_valid": token is not None
                })
            else:
                self.json_response({"connected": False})

        elif path == "/api/providers":
            self.json_response(engine.provider_detector.get_all_providers())

        elif path == "/api/blacklist/add":
            engine.blacklist.add(
                email_addr=body.get("email", ""),
                domain=body.get("domain", ""),
                reason=body.get("reason", "Manually blocked")
            )
            # Log as threat
            engine.threat_logger.log_threat(
                threat_type="blacklisted",
                severity="low",
                description=f"Added to blacklist: {body.get('email', '') or body.get('domain', '')}",
                from_email=body.get("email", ""),
                action="blacklisted"
            )
            self.json_response({"success": True})
        elif path == "/api/blacklist/remove":
            engine.blacklist.remove(body.get("id", 0))
            self.json_response({"success": True})
        elif path == "/api/blacklist/import":
            entries = body.get("entries", [])
            if isinstance(entries, str):
                entries = [e.strip() for e in entries.split("\n") if e.strip()]
            count = engine.blacklist.import_list(entries)
            self.json_response({"success": True, "imported": count})
        elif path == "/api/blacklist/check":
            email_addr = body.get("email", "")
            self.json_response({"blacklisted": engine.blacklist.is_blacklisted(email_addr)})
        elif path == "/api/threats/clear":
            engine.threat_logger.clear_old(days=body.get("days", 90))
            self.json_response({"success": True})
        elif path == "/api/phishing/scan":
            result = engine.phishing_detector.analyze(
                from_email=body.get("from_email", ""),
                from_name=body.get("from_name", ""),
                subject=body.get("subject", ""),
                body_text=body.get("body_text", ""),
                body_html=body.get("body_html", ""),
                headers_raw=body.get("headers", "")
            )
            self.json_response(result)
        elif path == "/api/sandbox/toggle":
            engine.sandbox_mode = body.get("enabled", not engine.sandbox_mode)
            self.json_response({"success": True, "sandbox_mode": engine.sandbox_mode})
        elif path == "/api/contacts/import":
            imported = 0
            contacts_list = body.get("contacts", [])
            for c in contacts_list:
                try:
                    engine.contacts.add_contact(
                        name=c.get("name", ""),
                        addr=c.get("email", ""),
                        phone=c.get("phone", ""),
                        company=c.get("company", ""),
                        group=c.get("group", "General"),
                        notes=c.get("notes", ""),
                        trusted=c.get("trusted", False)
                    )
                    imported += 1
                except:
                    pass
            self.json_response({"success": True, "imported": imported})
        elif path == "/api/email/report-spam":
            eid = body.get("id", 0)
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT from_email, subject FROM emails WHERE id=?", (eid,)).fetchone()
            if row:
                engine.blacklist.add(email_addr=row["from_email"], reason="Reported as spam")
                conn.execute("UPDATE emails SET category='spam', is_spam=1 WHERE id=?", (eid,))
                conn.commit()
                engine.threat_logger.log_threat(
                    email_id=eid, threat_type="spam_report", severity="low",
                    description=f"Reported as spam by user",
                    from_email=row["from_email"], subject=row["subject"], action="blocked"
                )
            conn.close()
            self.json_response({"success": True})
        elif path == "/api/account/disconnect":
            idx = body.get("index", 0)
            accounts = engine.settings.get("accounts", [])
            if idx < len(accounts):
                accounts[idx] = {
                    "name": "Mon Compte", "email": "", "imap_server": "", "imap_port": 993,
                    "smtp_server": "", "smtp_port": 587, "username": "", "password": "",
                    "use_ssl": True, "use_oauth2": False, "sync_interval_seconds": 60, "sync_days": 30
                }
                engine.settings["accounts"] = accounts
                save_settings(engine.settings)
                engine.reload_settings()
            self.json_response({"success": True})
        elif path == "/api/drafts/save":
            now = datetime.now().isoformat()
            draft_id = body.get("id")
            conn = sqlite3.connect(str(DB_PATH))
            if draft_id:
                conn.execute("""UPDATE drafts SET to_email=?, cc=?, bcc=?, subject=?, body_html=?, date_modified=? WHERE id=?""",
                    (body.get("to", ""), body.get("cc", ""), body.get("bcc", ""), body.get("subject", ""),
                     body.get("body", ""), now, draft_id))
            else:
                cursor = conn.execute("""INSERT INTO drafts (to_email, cc, bcc, subject, body_html, original_id, draft_type, date_created, date_modified)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (body.get("to", ""), body.get("cc", ""), body.get("bcc", ""), body.get("subject", ""),
                     body.get("body", ""), body.get("original_id"), body.get("draft_type", "new"), now, now))
                draft_id = cursor.lastrowid
            conn.commit()
            conn.close()
            self.json_response({"success": True, "id": draft_id})
        elif path == "/api/drafts/delete":
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute("DELETE FROM drafts WHERE id=?", (body.get("id", 0),))
            conn.commit()
            conn.close()
            self.json_response({"success": True})
        elif path == "/api/startup/toggle":
            if HAS_STARTUP_UTILS:
                bat_path = str(SCRIPT_DIR.parent / "LANCER_MAILSHIELD.bat")
                new_state = toggle_startup_reg("MailShield Pro", bat_path)
                self.json_response({"enabled": new_state, "available": True})
            else:
                self.json_response({"enabled": False, "available": False})
        else:
            self.send_error(404)
      except Exception as e:
        import traceback
        traceback.print_exc()
        logger.error(f"POST {self.path} error: {e}")
        try:
            self.json_response({"error": "Internal server error"}, 500)
        except:
            pass

    def _save_account(self, acc_config, email_addr):
        """Save or update account in settings."""
        accounts = engine.settings.get("accounts", [])
        if accounts and not accounts[0].get("email"):
            accounts[0] = acc_config
        else:
            replaced = False
            for i, existing in enumerate(accounts):
                if existing.get("email") == email_addr:
                    accounts[i] = acc_config
                    replaced = True
                    break
            if not replaced:
                accounts.append(acc_config)
        engine.settings["accounts"] = accounts
        save_settings(engine.settings)
        engine.reload_settings()

    def serve_file(self, filename):
        fpath = SCRIPT_DIR / filename
        if fpath.exists():
            self.send_response(200)
            ct = "text/html" if filename.endswith(".html") else "application/octet-stream"
            self.send_header("Content-Type", f"{ct}; charset=utf-8")
            self.end_headers()
            self.wfile.write(fpath.read_bytes())
        else:
            self.send_error(404)

    def json_response(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8800")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8800")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Token")
        self.end_headers()

# --- WebSocket Server ----------------------------------------------------------

async def ws_handler(websocket):
    engine.ws_clients.add(websocket)
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                cmd = data.get("cmd")
                resp = {"cmd": cmd, "success": True}

                if cmd == "sync":
                    accounts = engine.settings.get("accounts", [])
                    if accounts:
                        ok, msg = engine.connect_imap(accounts[0])
                        if ok:
                            emails = engine.fetch_emails()
                            engine.disconnect_imap()
                            resp["fetched"] = len(emails)
                            resp["message"] = f"{len(emails)} nouveaux emails"
                        else:
                            resp["success"] = False
                            resp["message"] = msg

                elif cmd == "get_counts":
                    resp["counts"] = engine.get_category_counts()

                elif cmd == "search_contacts":
                    resp["contacts"] = engine.contacts.search(data.get("query", ""), limit=8)

                await websocket.send(json.dumps(resp, ensure_ascii=False, default=str))
            except Exception as e:
                await websocket.send(json.dumps({"error": str(e)}))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        engine.ws_clients.discard(websocket)

async def broadcast(data):
    if engine.ws_clients:
        msg = json.dumps(data, ensure_ascii=False, default=str)
        await asyncio.gather(*(c.send(msg) for c in engine.ws_clients), return_exceptions=True)

# --- Auto Sync Thread ---------------------------------------------------------

def auto_sync_loop():
    while engine.running:
        interval = engine.settings.get("accounts", [{}])[0].get("sync_interval_seconds", 60) if engine.settings.get("accounts") else 60
        time.sleep(interval)
        if not engine.running:
            break
        accounts = engine.settings.get("accounts", [])
        if accounts and accounts[0].get("imap_server"):
            try:
                ok, _ = engine.connect_imap(accounts[0])
                if ok:
                    engine.fetch_emails()
                    engine.disconnect_imap()
            except:
                pass

# --- Main ----------------------------------------------------------------------

def _common_init():
    """Common initialization for both pywebview and browser modes"""
    global engine
    engine = MailShieldEngine()

    settings = engine.settings
    host = settings.get("server", {}).get("host", "127.0.0.1")
    http_port = settings.get("server", {}).get("http_port", 8800)
    ws_port = settings.get("server", {}).get("ws_port", 8801)

    engine.running = True

    # Start auto-sync thread
    threading.Thread(target=auto_sync_loop, daemon=True).start()

    # Start WebSocket server (with port fallback)
    actual_ws_port = ws_port

    async def start_ws(port):
        try:
            async with websockets.serve(ws_handler, host, port):
                await asyncio.Future()
        except OSError:
            raise

    def try_ws():
        nonlocal actual_ws_port
        for attempt_port in range(ws_port, ws_port + 10):
            try:
                actual_ws_port = attempt_port
                asyncio.run(start_ws(attempt_port))
                break
            except OSError:
                logger.warning(f"WebSocket port {attempt_port} occupe, essai suivant...")
                continue

    ws_thread = threading.Thread(target=try_ws, daemon=True)
    ws_thread.start()
    time.sleep(0.5)
    print(f"  [+] WebSocket serveur demarre sur le port {actual_ws_port}")

    # Start HTTP server in background thread
    httpd = HTTPServer((host, http_port), MailShieldHTTPHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"  [+] HTTP serveur demarre sur le port {http_port}")

    return host, http_port, ws_port, httpd


def main_webview():
    """Launch with pywebview — native window, HTTP API still runs in background"""
    host, http_port, ws_port, httpd = _common_init()

    print("""
    ==========================================================
    |           MailShield Pro v2.0.0                         |
    |           Fenetre native (pywebview)                    |
    |           Filtrage Intelligent + Protection Avancee     |
    ==========================================================
    """)
    print(f"  [*] API HTTP : http://{host}:{http_port}")
    print(f"  [*] Base de donnees : {DB_PATH}")
    print(f"  [*] Quarantaine : {QUARANTINE_DIR}")
    print()

    window = webview.create_window(
        f"MailShield Pro v{VERSION}",
        f"http://{host}:{http_port}",
        width=1360,
        height=860,
        min_size=(1000, 650),
        background_color="#0f0f13",
    )

    def on_loaded():
        print("  [+] Dashboard charge dans la fenetre native")

    window.events.loaded += on_loaded

    try:
        webview.start(debug=False)
    finally:
        engine.running = False
        httpd.shutdown()
        print("  [*] MailShield Pro ferme.")


def main():
    headless = "--headless" in sys.argv
    if headless:
        sys.argv.remove("--headless")

    if not headless and HAS_WEBVIEW:
        print("  [*] pywebview detecte -- lancement en mode fenetre native")
        main_webview()
    else:
        host, http_port, ws_port, httpd = _common_init()

        print("""
    ==========================================================
    |           MailShield Pro v2.0.0                         |
    |           Client Email Securise                         |
    |           Filtrage Intelligent + Protection Avancee     |
    ==========================================================
        """)
        print(f"  [*] Dashboard : http://{host}:{http_port}")
        print(f"  [*] Base de donnees : {DB_PATH}")
        print(f"  [*] Quarantaine : {QUARANTINE_DIR}")
        print(f"  [*] Log : {LOG_PATH}")
        print()

        if not headless:
            webbrowser.open(f"http://{host}:{http_port}")

        try:
            # Keep main thread alive
            while engine.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  [*] Arret de MailShield Pro...")
            engine.running = False
            httpd.shutdown()

if __name__ == "__main__":
    main()
