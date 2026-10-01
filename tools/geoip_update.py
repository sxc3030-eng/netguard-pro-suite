"""
NetGuard MaxMind GeoLite2 downloader / updater.

Downloads the City + ASN .mmdb files from MaxMind using your license key
and places them in netguard-pro-suite/geoip/.

Usage:
    # First-time setup (gives you a license key from maxmind.com dashboard):
    python tools/geoip_update.py --key YOUR_LICENSE_KEY

    # Subsequent monthly refresh — key persists in geoip/.maxmind_license:
    python tools/geoip_update.py
"""
import argparse
import base64
import io
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEOIP_DIR = ROOT / "geoip"
KEY_FILE = GEOIP_DIR / ".maxmind_license"
ACCOUNT_FILE = GEOIP_DIR / ".maxmind_account_id"

# Editions we want — City for country/city/lat/lon, ASN for org/AS#
EDITIONS = [
    ("GeoLite2-City", "GeoLite2-City.mmdb"),
    ("GeoLite2-ASN",  "GeoLite2-ASN.mmdb"),
]


def _read_file(path: Path) -> str:
    if path.exists():
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return ""


def _save_file(path: Path, value: str):
    GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _download_edition(edition_id: str, out_filename: str, key: str, account_id: str = "") -> bool:
    """Try the direct-download URL first (license_key only). If 401, fall back to
    HTTP Basic Auth with account_id:license_key — MaxMind enforces this when the
    key was generated with the 'GeoIP Update' option enabled."""
    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id={edition_id}&license_key={key}&suffix=tar.gz"
    )
    print(f"  fetch  {edition_id} ...", end=" ", flush=True)

    def _try(use_basic_auth: bool):
        headers = {"User-Agent": "NetGuardAI/1.9 (geoip-update)"}
        if use_basic_auth and account_id:
            creds = base64.b64encode(f"{account_id}:{key}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()

    payload = None
    try:
        payload = _try(use_basic_auth=False)
    except urllib.error.HTTPError as e:
        if e.code == 401 and account_id:
            try:
                payload = _try(use_basic_auth=True)
                print("(basic auth)", end=" ", flush=True)
            except urllib.error.HTTPError as e2:
                if e2.code == 401:
                    print("FAIL (401 with basic auth — check account_id + key)")
                else:
                    print(f"FAIL (HTTP {e2.code})")
                return False
            except Exception as e2:
                print(f"FAIL ({type(e2).__name__}: {e2})")
                return False
        elif e.code == 401:
            print("FAIL (401 — pass --account-id if your key has 'GeoIP Update' enabled)")
            return False
        else:
            print(f"FAIL (HTTP {e.code})")
            return False
    except Exception as e:
        print(f"FAIL ({type(e).__name__}: {e})")
        return False

    print(f"{len(payload)//1024} KB", end=" ", flush=True)

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            mmdb_member = next(
                (m for m in tar.getmembers() if m.name.endswith(out_filename)),
                None,
            )
            if not mmdb_member:
                print("FAIL (no .mmdb in tarball)")
                return False
            f = tar.extractfile(mmdb_member)
            if not f:
                print("FAIL (extract failed)")
                return False
            mmdb_bytes = f.read()
    except Exception as e:
        print(f"FAIL (tar parse: {e})")
        return False

    out_path = GEOIP_DIR / out_filename
    out_path.write_bytes(mmdb_bytes)
    try:
        os.chmod(out_path, 0o644)  # readable, world-readable not sensitive (it's a public DB)
    except OSError:
        pass
    print(f"-> {out_path} ({len(mmdb_bytes)//(1024*1024)} MB)")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Download/update MaxMind GeoLite2 databases")
    parser.add_argument("--key", default=None,
                        help="MaxMind license key (saved to geoip/.maxmind_license for future runs)")
    parser.add_argument("--account-id", default=None,
                        help="MaxMind Account ID (numeric). Required if your license key was generated "
                             "with 'Will this key be used for GeoIP Update?' = Yes.")
    args = parser.parse_args()

    key = (args.key or os.environ.get("MAXMIND_LICENSE_KEY") or _read_file(KEY_FILE) or "").strip()
    account_id = (args.account_id or os.environ.get("MAXMIND_ACCOUNT_ID") or _read_file(ACCOUNT_FILE) or "").strip()

    if not key:
        print("ERROR: no MaxMind license key.")
        print("  Get one free at https://www.maxmind.com/en/geolite2/signup")
        print("  Then run:  python tools/geoip_update.py --key YOUR_LICENSE_KEY [--account-id NNNNNN]")
        return 1

    if args.key:
        _save_file(KEY_FILE, args.key)
        print(f"License key saved -> {KEY_FILE}")
    if args.account_id:
        _save_file(ACCOUNT_FILE, args.account_id)
        print(f"Account ID saved -> {ACCOUNT_FILE}")

    GEOIP_DIR.mkdir(parents=True, exist_ok=True)

    ok_count = 0
    for edition_id, out_filename in EDITIONS:
        if _download_edition(edition_id, out_filename, key, account_id):
            ok_count += 1

    if ok_count == len(EDITIONS):
        print(f"\nOK. {ok_count}/{len(EDITIONS)} databases updated. Restart NetGuard to pick them up.")
        return 0
    else:
        print(f"\nPARTIAL. {ok_count}/{len(EDITIONS)} downloaded.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
