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
import io
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEOIP_DIR = ROOT / "geoip"
KEY_FILE = GEOIP_DIR / ".maxmind_license"

# Editions we want — City for country/city/lat/lon, ASN for org/AS#
EDITIONS = [
    ("GeoLite2-City", "GeoLite2-City.mmdb"),
    ("GeoLite2-ASN",  "GeoLite2-ASN.mmdb"),
]


def _read_key() -> str:
    if KEY_FILE.exists():
        try:
            return KEY_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return ""


def _save_key(key: str):
    GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_text(key, encoding="utf-8")
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass


def _download_edition(edition_id: str, out_filename: str, key: str) -> bool:
    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id={edition_id}&license_key={key}&suffix=tar.gz"
    )
    print(f"  fetch  {edition_id} ...", end=" ", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/1.9 (geoip-update)"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("FAIL (401 Unauthorized — license key invalid)")
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
    args = parser.parse_args()

    key = (args.key or os.environ.get("MAXMIND_LICENSE_KEY") or _read_key() or "").strip()
    if not key:
        print("ERROR: no MaxMind license key.")
        print("  Get one free at https://www.maxmind.com/en/geolite2/signup")
        print("  Then run:  python tools/geoip_update.py --key YOUR_LICENSE_KEY")
        return 1

    if args.key:
        _save_key(args.key)
        print(f"License key saved -> {KEY_FILE}")

    GEOIP_DIR.mkdir(parents=True, exist_ok=True)

    ok_count = 0
    for edition_id, out_filename in EDITIONS:
        if _download_edition(edition_id, out_filename, key):
            ok_count += 1

    if ok_count == len(EDITIONS):
        print(f"\nOK. {ok_count}/{len(EDITIONS)} databases updated. Restart NetGuard to pick them up.")
        return 0
    else:
        print(f"\nPARTIAL. {ok_count}/{len(EDITIONS)} downloaded.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
