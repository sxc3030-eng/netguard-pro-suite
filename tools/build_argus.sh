#!/usr/bin/env bash
# =============================================================================
# Argus build script — Linux / macOS
# =============================================================================
#
# Requires:  pip install pyinstaller    (already in requirements-dev.txt)
#
# Usage:
#     tools/build_argus.sh
#
# Output:
#     build/dist/Argus/Argus              (Linux ELF / macOS Mach-O)
#     build/dist/Argus-portable.tar.gz    (portable tarball)
#
# V1 does NOT sign the macOS or Linux binaries — codesigning on macOS
# requires an Apple Developer ID + notarisation flow that is out of scope
# for the initial release. Add it later if/when we ship outside Windows.
# =============================================================================

set -euo pipefail

# --- Resolve repo root: this script lives in <repo>/tools/ -------------------
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
cd "${REPO_ROOT}"

OS_NAME="$(uname -s)"
echo
echo "=== Argus build — one-folder bundle (${OS_NAME}) ==="
echo "Repo root: ${REPO_ROOT}"
echo

# --- Sanity: PyInstaller present? -------------------------------------------
# Prefer `python -m PyInstaller` over the bare CLI: in CI runners and venvs,
# the `Scripts`/`bin` dir isn't always on PATH but `python` is.
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi
if ! "${PYTHON_BIN}" -m PyInstaller --version >/dev/null 2>&1; then
    echo "[ERROR] PyInstaller not installed in '${PYTHON_BIN}'." >&2
    echo "        Install with:  ${PYTHON_BIN} -m pip install pyinstaller" >&2
    exit 1
fi

# --- Clean previous build artefacts ------------------------------------------
if [ -d "build/build" ]; then
    echo "[INFO] Removing build/build ..."
    rm -rf "build/build"
fi
if [ -d "build/dist" ]; then
    echo "[INFO] Removing build/dist ..."
    rm -rf "build/dist"
fi

# --- Run PyInstaller ---------------------------------------------------------
echo "[INFO] Running PyInstaller ..."
"${PYTHON_BIN}" -m PyInstaller --clean --noconfirm \
    --workpath "build/build" \
    --distpath "build/dist" \
    "build/Argus.spec"

# --- Copy top-level docs into the dist folder --------------------------------
for f in README.md LICENSE SECURITY.md; do
    if [ -f "${f}" ]; then
        cp -f "${f}" "build/dist/Argus/"
    fi
done

# --- Create a portable archive -----------------------------------------------
echo "[INFO] Creating portable archive ..."
( cd "build/dist" && tar -czf "Argus-portable.tar.gz" "Argus" )

cat <<EOF

=============================================================================
 Build complete.
 Bundle folder : build/dist/Argus/Argus
 Portable arch : build/dist/Argus-portable.tar.gz
=============================================================================
EOF

if [ "${OS_NAME}" = "Darwin" ]; then
    cat <<EOF
Optional next step — sign and notarise on macOS:
  codesign --deep --force --options runtime \\
           --sign "Developer ID Application: <Your Name> (<TEAMID>)" \\
           build/dist/Argus/Argus
  xcrun notarytool submit build/dist/Argus-portable.tar.gz \\
           --apple-id <id> --team-id <TEAMID> --keychain-profile <profile> --wait

EOF
fi
