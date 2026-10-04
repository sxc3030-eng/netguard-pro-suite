# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""
Argus Updater V1 — privacy-respecting GitHub Releases checker.

Design contract
---------------
* User-OPT-IN. Default ON for V1, but a single setting flips it off.
* The check ONLY hits ``api.github.com`` for one public endpoint
  (``/repos/<owner>/<repo>/releases/latest``). No telemetry, no install
  ID, no OS version, no IP fingerprinting beyond what the GitHub API
  already sees from any HTTP client.
* No automatic replacement of the running binary. The downloader only
  fetches the asset to ``argus_data/updates/`` and verifies SHA-256 if a
  digest was published; the user is told to quit Argus and run the
  installer themselves. Live binary replacement on Windows is permission-
  fraught (file in use), antivirus-touchy, and exactly the kind of
  behaviour a cybersecurity browser must NOT exhibit.
* Cooldown: once per launch is the policy enforced by the caller, but we
  also persist the last-check timestamp so that successive launches in a
  short window don't hammer the GitHub API. Default cooldown is 6h.

Public API (the names argus_pyqt.py is meant to import)
-------------------------------------------------------
``UpdateInfo``, ``ARGUS_VERSION``, ``check_for_update``,
``is_check_enabled``, ``set_check_enabled``, ``download_update``,
``verify_update``, ``install_update_hint``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

#: Current installed version. Bump this when shipping a release.
ARGUS_VERSION = "3.0.0"

#: GitHub repo coordinates. Public endpoint only.
GITHUB_OWNER = "sxc3030-eng"
GITHUB_REPO = "netguard-pro-suite"
GITHUB_API_URL = (
    f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
)

#: User-Agent. GitHub requires one; this string is intentionally non-unique
#: (no install ID) but identifies the project for politeness.
USER_AGENT = (
    f"Argus/{ARGUS_VERSION} "
    f"(+https://github.com/{GITHUB_OWNER}/{GITHUB_REPO})"
)

#: Cooldown between checks. Six hours is enough that a heavy user opening
#: Argus a dozen times a day still hits GitHub at most ~4 times.
DEFAULT_COOLDOWN_SECONDS = 6 * 60 * 60

#: Storage paths (relative to repo root by default; tests redirect via
#: ``ARGUS_UPDATER_DATA_DIR`` env var).
_ROOT = Path(__file__).resolve().parent
_DEFAULT_DATA_DIR = _ROOT / "argus_data"


def _data_dir() -> Path:
    """Return the active data dir, honouring ``ARGUS_UPDATER_DATA_DIR``."""
    override = os.environ.get("ARGUS_UPDATER_DATA_DIR")
    return Path(override) if override else _DEFAULT_DATA_DIR


def _settings_file() -> Path:
    return _data_dir() / "settings.json"


def _last_check_file() -> Path:
    return _data_dir() / "last_update_check.json"


def _updates_dir() -> Path:
    return _data_dir() / "updates"


_LOGGER = logging.getLogger("argus.updater")


# ─────────────────────────────────────────────────────────────────────────────
# Data class
# ─────────────────────────────────────────────────────────────────────────────


class UpdateInfo(NamedTuple):
    """A newer release found on GitHub."""

    version: str
    published_at: str
    changelog: str
    download_url: str
    sha256: Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# Settings persistence (light wrapper, doesn't fight argus_pyqt.SettingsManager)
# ─────────────────────────────────────────────────────────────────────────────


_SETTING_KEY = "update_check_enabled"


def _read_settings() -> dict:
    path = _settings_file()
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except Exception:  # noqa: BLE001 — corrupt settings shouldn't crash app
        return {}


def _write_settings(data: dict) -> None:
    path = _settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def is_check_enabled() -> bool:
    """Return True if the user has opted in (default True for V1)."""
    return bool(_read_settings().get(_SETTING_KEY, True))


def set_check_enabled(enabled: bool) -> None:
    """Persist the opt-in preference."""
    data = _read_settings()
    data[_SETTING_KEY] = bool(enabled)
    _write_settings(data)


# ─────────────────────────────────────────────────────────────────────────────
# Cooldown
# ─────────────────────────────────────────────────────────────────────────────


def _read_last_check() -> dict:
    path = _last_check_file()
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _write_last_check(payload: dict) -> None:
    path = _last_check_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _cooldown_active(cooldown_s: int) -> bool:
    last = _read_last_check()
    ts = last.get("ts")
    if not isinstance(ts, (int, float)):
        return False
    return (time.time() - ts) < cooldown_s


def _cached_update_info() -> Optional[UpdateInfo]:
    last = _read_last_check()
    cached = last.get("update_info")
    if not isinstance(cached, dict):
        return None
    try:
        return UpdateInfo(
            version=cached["version"],
            published_at=cached["published_at"],
            changelog=cached["changelog"],
            download_url=cached["download_url"],
            sha256=cached.get("sha256"),
        )
    except (KeyError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Surveillance hook (best-effort, never fatal)
# ─────────────────────────────────────────────────────────────────────────────


def _log_check(result: str) -> None:
    """Best-effort surveillance event. Never raises."""
    try:
        from argus_surveillance import surveil_log_event  # local import

        surveil_log_event(
            "user_action",
            {"type": "update_check", "result": result},
        )
    except Exception:  # noqa: BLE001 — surveillance is optional here
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Version comparison
# ─────────────────────────────────────────────────────────────────────────────

# Matches ``v3.0.1``, ``3.0.1-beta``, ``3.0.1+build.5`` etc. We extract just
# the leading dotted-numeric segment for comparison; suffix is treated as a
# pre-release marker (sorts BEFORE the bare version).
_VERSION_RE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)([-+].*)?\s*$")


def _parse_version(s: str) -> tuple[tuple[int, ...], int]:
    """Parse a version string into ``((major, minor, patch, ...), pre_flag)``.

    ``pre_flag`` is ``0`` for a pre-release (``-beta``, ``+build.5``...) and
    ``1`` for a final release. Tuples compare lexicographically, so a
    pre-release of the same numeric tuple sorts before its final.
    """
    m = _VERSION_RE.match(s or "")
    if not m:
        return ((0,), 0)
    nums = tuple(int(p) for p in m.group(1).split("."))
    pre = 0 if m.group(2) else 1
    return (nums, pre)


def _is_newer(remote: str, local: str) -> bool:
    return _parse_version(remote) > _parse_version(local)


# ─────────────────────────────────────────────────────────────────────────────
# Asset / SHA-256 extraction
# ─────────────────────────────────────────────────────────────────────────────

# Match ``SHA256: abc123…`` or ``sha256: abc…`` in the release body.
_SHA256_RE = re.compile(r"sha-?256[^\w]*([0-9a-f]{64})", re.IGNORECASE)


def _pick_asset(assets: list) -> tuple[Optional[str], Optional[str]]:
    """Return (download_url, sha256_from_asset_label) for the best asset.

    Preference order:
    1. an ``.exe`` (Windows installer, the V1 target)
    2. a ``.msi``
    3. anything not labelled ``.txt`` / ``.sha256``
    """
    if not isinstance(assets, list):
        return None, None
    exe, msi, other = None, None, None
    sha_companion: Optional[str] = None
    for a in assets:
        if not isinstance(a, dict):
            continue
        name = (a.get("name") or "").lower()
        url = a.get("browser_download_url")
        if not url:
            continue
        if name.endswith(".sha256"):
            # Could be a companion text file; we don't fetch it, but the
            # release body normally embeds the digest too.
            continue
        if name.endswith(".exe") and exe is None:
            exe = url
        elif name.endswith(".msi") and msi is None:
            msi = url
        elif other is None and not name.endswith((".txt", ".asc", ".sig")):
            other = url
    chosen = exe or msi or other
    return chosen, sha_companion


def _extract_sha256(body: str) -> Optional[str]:
    if not isinstance(body, str):
        return None
    m = _SHA256_RE.search(body)
    return m.group(1).lower() if m else None


# ─────────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────────


def _http_get_json(url: str, timeout_s: float) -> Optional[dict]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        _LOGGER.debug("update check: network error: %s", exc)
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _LOGGER.debug("update check: bad JSON: %s", exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public: check_for_update
# ─────────────────────────────────────────────────────────────────────────────


def check_for_update(
    timeout_s: float = 5.0,
    cooldown_s: int = DEFAULT_COOLDOWN_SECONDS,
) -> Optional[UpdateInfo]:
    """Return an :class:`UpdateInfo` if a newer version exists.

    Returns ``None`` when:
    * the user opted out,
    * we're inside the cooldown window AND no update was previously found,
    * the current installed version is up to date,
    * the network call failed for any reason.

    Never raises — failures are silent so they cannot crash app startup.
    """
    if not is_check_enabled():
        _LOGGER.debug("update check: disabled by user")
        return None

    if _cooldown_active(cooldown_s):
        cached = _cached_update_info()
        if cached is not None and _is_newer(cached.version, ARGUS_VERSION):
            _LOGGER.debug(
                "update check: cooldown active, returning cached info"
            )
            return cached
        _LOGGER.debug("update check: cooldown active, no cached update")
        return None

    payload = _http_get_json(GITHUB_API_URL, timeout_s=timeout_s)
    if payload is None:
        _log_check("failed")
        # Persist a check timestamp anyway so we don't hammer GitHub during
        # an outage. We do NOT cache an update_info on failure.
        _write_last_check({"ts": time.time(), "result": "failed"})
        return None

    tag = payload.get("tag_name") or payload.get("name") or ""
    body = payload.get("body") or ""
    published = payload.get("published_at") or ""
    assets = payload.get("assets") or []

    download_url, _ = _pick_asset(assets)
    sha256 = _extract_sha256(body)

    if not _is_newer(tag, ARGUS_VERSION):
        _log_check("up_to_date")
        _write_last_check({"ts": time.time(), "result": "up_to_date"})
        return None

    if not download_url:
        # Tag is newer, but the release has no usable asset attached.
        # Treat as a soft failure — there's nothing to download.
        _log_check("failed")
        _write_last_check({"ts": time.time(), "result": "failed"})
        return None

    info = UpdateInfo(
        version=tag.lstrip("v"),
        published_at=published,
        changelog=body,
        download_url=download_url,
        sha256=sha256,
    )
    _log_check("found_update")
    _write_last_check(
        {
            "ts": time.time(),
            "result": "found_update",
            "update_info": info._asdict(),
        }
    )
    return info


# ─────────────────────────────────────────────────────────────────────────────
# Public: download + verify
# ─────────────────────────────────────────────────────────────────────────────


def verify_update(file_path: Path, expected_sha256: str) -> bool:
    """Recompute SHA-256 of ``file_path`` and constant-time compare."""
    if not isinstance(file_path, Path):
        file_path = Path(file_path)
    if not file_path.exists():
        return False
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        return False
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return hmac.compare_digest(h.hexdigest().lower(), expected_sha256.lower())


def download_update(
    info: UpdateInfo,
    dest_dir: Optional[Path] = None,
    timeout_s: float = 60.0,
) -> Path:
    """Download the asset referenced by ``info`` to ``dest_dir``.

    If ``info.sha256`` is set, the downloaded bytes are verified; on
    mismatch the partial file is deleted and ``ValueError`` is raised.
    """
    target_dir = Path(dest_dir) if dest_dir else _updates_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    url = info.download_url
    # Filename derived from URL path; fall back to the version.
    name = url.rsplit("/", 1)[-1] or f"argus-{info.version}.bin"
    out = target_dir / name

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp, out.open(
        "wb"
    ) as f:
        while True:
            chunk = resp.read(1024 * 64)
            if not chunk:
                break
            f.write(chunk)

    if info.sha256:
        if not verify_update(out, info.sha256):
            try:
                out.unlink()
            except OSError:
                pass
            raise ValueError(
                f"SHA-256 mismatch for downloaded asset {name!r}; refusing "
                "to keep an unverified file."
            )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Public: install hint (NEVER replaces running binary)
# ─────────────────────────────────────────────────────────────────────────────


def install_update_hint(downloaded_file: Path) -> str:
    """Return a user-facing instruction. Does NOT touch the running process.

    Live binary replacement on Windows is unsafe (file in use, AV warnings,
    permission elevation prompts). Argus delegates installation to the
    user, who runs the downloaded installer after closing the browser.
    """
    if not isinstance(downloaded_file, Path):
        downloaded_file = Path(downloaded_file)
    return (
        "Mise à jour téléchargée. Quittez Argus, puis exécutez :\n"
        f"  {downloaded_file}\n"
        "Argus ne remplace JAMAIS automatiquement son propre binaire."
    )
