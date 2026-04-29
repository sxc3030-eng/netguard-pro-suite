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
release_check — manual dry-run for the Argus updater.

Examples
--------
  python tools/release_check.py            # check + print result
  python tools/release_check.py --download  # also download if available
  python tools/release_check.py --verbose   # debug logging
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Make the repo root importable when the script is run directly.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_updater  # noqa: E402


def _format_info(info: argus_updater.UpdateInfo) -> str:
    head = (
        f"Update available: Argus {info.version} "
        f"(published {info.published_at})"
    )
    sha = f"  sha256:   {info.sha256}" if info.sha256 else "  sha256:   (none published)"
    body = (info.changelog or "").strip()
    if len(body) > 600:
        body = body[:600] + "  …"
    return "\n".join(
        [
            head,
            f"  download: {info.download_url}",
            sha,
            "  changelog:",
            "    " + body.replace("\n", "\n    ") if body else "    (empty)",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argus updater dry-run.")
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download the update asset if a newer release is available.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose logging."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout for the GitHub API call (seconds).",
    )
    parser.add_argument(
        "--no-cooldown",
        action="store_true",
        help="Bypass the 6h cooldown (always hit GitHub).",
    )
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        )

    print(f"Argus current version: {argus_updater.ARGUS_VERSION}")
    print(f"GitHub endpoint:       {argus_updater.GITHUB_API_URL}")

    cooldown = 0 if args.no_cooldown else argus_updater.DEFAULT_COOLDOWN_SECONDS
    try:
        info = argus_updater.check_for_update(
            timeout_s=args.timeout, cooldown_s=cooldown
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Check failed: {exc}", file=sys.stderr)
        return 2

    if info is None:
        print("Up to date (or check skipped: opted out / cooldown / network).")
        return 0

    print(_format_info(info))

    if args.download:
        print("\nDownloading…")
        try:
            path = argus_updater.download_update(info)
        except Exception as exc:  # noqa: BLE001
            print(f"Download failed: {exc}", file=sys.stderr)
            return 3
        print(f"Saved to: {path}")
        print(argus_updater.install_update_hint(path))

    return 0


if __name__ == "__main__":
    sys.exit(main())
