# Build Guide — Argus

This document covers how to package the Argus PyQt6 / QtWebEngine
browser into a self-contained, redistributable `.exe` (Windows) or
`./Argus` (Linux/macOS) using PyInstaller.

For the *signing* side of the story (Authenticode, SmartScreen, MSIX
packaging) see [AUTHENTICODE.md](AUTHENTICODE.md). For *running* an
already-built bundle, see the top-level `README.md`.

---

## 1. Why one-folder, not one-file?

PyInstaller offers `--onefile` for a single `.exe` that self-extracts at
launch. **We deliberately do NOT use it.** QtWebEngine ships its own
helper process (`QtWebEngineProcess.exe`) that Chromium spawns for the
sandbox + GPU; the helper resolves its path before re-exec, which
collides with the temp-extract location of `--onefile` and produces
either a startup crash or stale-helper bugs on the second launch.

The official Qt + PyInstaller recommendation is **one-folder** — a
single `dist/Argus/` directory containing `Argus.exe`, every Qt DLL,
the WebEngine helper, ICU data, locale `.pak` files, and the bundled
Python interpreter. We then ship that folder as a portable `.zip`
(or `.tar.gz` on Linux/macOS).

---

## 2. Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ (CI tests 3.10, 3.11, 3.12; local 3.13 also works) | 64-bit |
| PyQt6 | 6.6+ | from `requirements.txt` |
| PyQt6-WebEngine | 6.6+ | Chromium-based engine |
| PyInstaller | 6.x | from `requirements-dev.txt` |
| Pillow | 10+ | icon / branding rendering |
| Windows SDK (optional) | latest | only if you intend to run `signtool` afterwards |

Install everything in one shot:

```bash
pip install -r requirements.txt -r requirements-dev.txt pyinstaller
```

---

## 3. Building

### Windows

```bat
tools\build_argus.bat
```

Outputs:

```
build\dist\Argus\Argus.exe          (the binary)
build\dist\Argus\...                (~150 MB of Qt DLLs + helper + assets)
build\dist\Argus-portable.zip       (zipped folder for distribution)
```

### Linux / macOS

```bash
chmod +x tools/build_argus.sh
tools/build_argus.sh
```

Outputs:

```
build/dist/Argus/Argus              (the binary)
build/dist/Argus-portable.tar.gz
```

### What the scripts actually do

1. Wipe `build/build/` (PyInstaller scratch dir) and `build/dist/`.
2. Invoke `pyinstaller --clean --noconfirm build/Argus.spec`.
3. Copy `README.md`, `LICENSE`, `SECURITY.md` into the dist folder so
   end-users see the legal context next to the binary.
4. Compress the dist folder into a portable archive.

The spec file (`build/Argus.spec`) is the source of truth — every
hidden import, every excluded Qt module, every bundled data file is
declared there with comments.

---

## 4. Verifying the build

Quick smoke test — launch and kill after 3 s. The window should appear
with no console popup and no missing-DLL errors.

**Windows (cmd):**

```bat
start "" build\dist\Argus\Argus.exe
timeout /t 3 /nobreak >nul
taskkill /im Argus.exe /f
```

**Linux/macOS:**

```bash
./build/dist/Argus/Argus &
sleep 3
kill %1
```

If the window paints, the bundle is good. Common signs of a broken
bundle:

- Window opens but every page shows "Web engine not initialised" →
  `QtWebEngineProcess.exe` not collected. Check `collect_all` block in
  the spec.
- Crash with `ImportError: No module named argus_<x>` → that module
  fell out of the `hidden_argus_modules` list in the spec. Add it
  back.
- White window, no chrome → `Pillow` plugins not picked up. Run
  `pyinstaller --collect-all PIL` to confirm.

---

## 5. Code-signing the result

The build script intentionally does NOT sign. Sign the bundle as a
separate step on a machine that has access to your signing cert:

```bat
REM Trusted Signing (Azure-hosted HSM, recommended for indie / OSS)
signtool sign /a /tr http://timestamp.acs.microsoft.com /td sha256 /fd sha256 ^
        build\dist\Argus\Argus.exe

REM Sectigo / DigiCert OV cert on a physical USB token
signtool sign /a /n "Your Legal Name" /tr http://timestamp.sectigo.com ^
        /td sha256 /fd sha256 build\dist\Argus\Argus.exe
```

After signing, *re-create* the portable zip so the signed binary is
the one users download:

```bat
powershell -Command "Compress-Archive -Path 'build\dist\Argus\*' ^
        -DestinationPath 'build\dist\Argus-portable.zip' -Force"
```

Full step-by-step instructions, cost comparison, and Microsoft Store
(MSIX) re-packaging guidance live in
[AUTHENTICODE.md](AUTHENTICODE.md).

---

## 6. Creating a portable zip manually

If you want a zip without re-running the full build:

**Windows (PowerShell):**

```powershell
Compress-Archive -Path build\dist\Argus\* `
                 -DestinationPath build\dist\Argus-portable.zip -Force
```

**Linux/macOS:**

```bash
( cd build/dist && tar -czf Argus-portable.tar.gz Argus )
# or zip:
( cd build/dist && zip -r Argus-portable.zip Argus )
```

The portable archive is fully self-contained: a user only needs to
unzip it and double-click `Argus.exe` — no Python, no `pip install`,
no admin rights.

---

## 6.5. A note on `.gitignore`

The repo's root `.gitignore` ignores `build/` and `dist/` wholesale.
The build spec lives in `build/Argus.spec` — to keep it under version
control you have two clean options:

1. **Add a negation rule** to the root `.gitignore`:

   ```gitignore
   build/
   !build/Argus.spec
   ```

2. **Track the spec from a different folder** (e.g. `tools/Argus.spec`)
   and update both build scripts + the workflow to reference the new
   path.

This guide assumes option 1 — adjust before the first commit that
touches the build pipeline.

---

## 7. Continuous integration

`.github/workflows/build.yml` runs the Windows build on every push to
`main` and on every `v*` tag, and uploads `Argus-portable.zip` as an
artifact. The CI build is **unsigned** — signing is intentionally a
manual step that requires access to the production signing identity.

Workflow behaviour summary:

| Trigger | Builds | Uploads artifact | Signs |
|---|---|---|---|
| Push to `main` | yes | yes (90-day retention) | no |
| Tag `v*` | yes | yes (90-day retention) | no |
| `workflow_dispatch` | yes | yes | no |

Promoting an artifact to a release is a manual step (the sign-and-zip
flow above, then `gh release upload`).

---

## 8. Troubleshooting

### `ImportError: DLL load failed while importing QtWebEngineCore`

You are running the bundle on a machine that lacks the
**Microsoft Visual C++ 2015–2022 Redistributable**. PyInstaller does
not redistribute it (Qt links against system `vcruntime140.dll`).
Either install the redistributable or instruct end-users to do so via
the README.

### `Could not find QtWebEngineProcess.exe`

The `collect_all("PyQt6.QtWebEngineCore")` call in the spec failed
silently — usually because PyInstaller is older than 6.0 and does not
recognise PyQt6 as a Qt binding. Update PyInstaller:

```bash
pip install -U pyinstaller
```

### Bundle is huge (> 250 MB)

The `excludes=` list in the spec drops every Qt module Argus does not
use (Bluetooth, Designer, Quick, etc.). Verify the excludes are
honoured by inspecting `build/dist/Argus/PyQt6/Qt6/bin/` — if you see
`Qt6Quick.dll` or `Qt6Multimedia.dll`, the exclude list is not being
applied. Common cause: a transitive import in your code accidentally
references the excluded module.

### "Argus.exe is not a recognised application" on user's PC

That is the **unsigned-binary SmartScreen warning**. It is NOT a build
problem. Sign the binary (see §5) or document the "More info → Run
anyway" workaround in your release notes.

### `pywin32` postinstall not run

`pywin32` ships some COM registrations that are only set up by a
postinstall script. PyInstaller does not run it. If you observe
`ModuleNotFoundError: No module named 'pywintypes'` at launch, add a
runtime hook:

```python
# In the spec file, add to runtime_hooks=[]:
runtime_hooks=["build/hooks/rt_pywin32.py"],
```

with `build/hooks/rt_pywin32.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(sys._MEIPASS, "win32"))
sys.path.insert(0, os.path.join(sys._MEIPASS, "win32", "lib"))
sys.path.insert(0, os.path.join(sys._MEIPASS, "Pythonwin"))
```

Argus does not currently need this — the only direct `pywin32` use is
in `cleanguard/` and `vpnguard/`, which are separate processes — but
the hook is here for future reference.

---

## 9. Next steps

- **Microsoft Store (MSIX)** — see [AUTHENTICODE.md §6](AUTHENTICODE.md).
  Wraps the one-folder bundle in an MSIX package suitable for Store
  submission. Required for re-submission after the 2026-04-03
  rejection under policy 10.2.9.
- **Inno Setup / NSIS installer** — for users who prefer a guided
  install over an unzip. Out of scope for V1; the portable zip covers
  the same use case.
- **Auto-update** — Sparkle / WinSparkle integration. Not yet wired.
