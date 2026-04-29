# Authenticode Code-Signing Guide

> Status: **planning document**. The Argus / NetGuard suite is currently
> distributed as unsigned `.exe` and source. This file describes the
> options, costs, and step-by-step procedure to ship a signed binary
> that escapes Windows SmartScreen and qualifies for the Microsoft
> Store.

---

## 1. Why sign at all?

Three concrete reasons, in order of pain:

1. **SmartScreen warning on first run.** When a user double-clicks an
   unsigned `.exe` downloaded from the internet, Windows shows a blue
   "Windows protected your PC" panel. The user has to click `More info`
   then `Run anyway`. In practice, ~95 % of users abort at this point.
   Signing with a valid Authenticode certificate that has built up
   reputation removes the warning entirely.

2. **Microsoft Store rejection.** The Store reviewers refused
   `NetGuard Pro` on 2026-04-03 under policy 10.2.9 because the
   submitted package was not signed. Re-submission requires a signed
   MSIX bundle (see §6).

3. **Trust on the first run.** A signed binary surfaces the publisher
   name (`Verified publisher: <Your Legal Name>`) in the UAC prompt
   when the app needs admin rights. Unsigned binaries show the generic
   `Publisher: Unknown` red banner, which scares users away and
   correlates with low installation completion rates.

---

## 2. The three realistic options

| Option | Cost | Hardware | Time to first sign | Notes |
|---|---|---|---|---|
| **Trusted Signing (Azure)** | ~$10 USD / month flat | None — cloud HSM | 1–2 weeks (identity check) | Microsoft's 2024+ replacement for the old expensive model. **Recommended for indie devs.** No USB token to lose. |
| **OV Authenticode cert (Sectigo / DigiCert / SSL.com)** | $70–300 / year | USB FIPS 140-2 token shipped to you | 1–2 weeks (identity check) | Standard option. Loses SmartScreen reputation if the token is replaced. |
| **EV Authenticode cert** | $300–700 / year | USB FIPS 140-2 token | 2–4 weeks (extended validation) | **Instant** SmartScreen reputation — no waiting period. Hardest to obtain (DUNS number, phone verification). Justified only for paid commercial software. |
| _Self-signed_ | Free | None | Minutes | NOT trusted by default. The user has to manually install your cert into the `Trusted Root` store. Useful only for internal corporate deployments. |

The recommended path for a free OSS project like Argus is
**Trusted Signing**. Cost is predictable, no token to physically secure,
and the reputation builds over time on Microsoft's side.

---

## 3. Step-by-step: Trusted Signing (recommended)

### 3.1 Prerequisites

- Active Azure subscription (free tier works — Trusted Signing has its
  own metered cost outside the free credits).
- A government-issued ID and a recent utility bill or bank statement
  (used during identity validation).
- Admin access to the build machine running PowerShell 7+.

### 3.2 Identity validation

1. Sign into the Azure portal and search for `Trusted Signing`.
2. Create a new **Trusted Signing Account**. Pick the closest region.
3. Create an **Identity Validation** record. Select
   `Individual` (for an indie dev) or `Organization` (LLC / inc.).
4. Upload the requested documents. Microsoft's review SLA is typically
   1–7 business days. You will receive an email when the validation
   passes.

### 3.3 Provisioning the certificate profile

Once validated:

1. Inside the Trusted Signing Account, create a **Certificate Profile**
   of type `Public Trust`. This is the profile used for
   end-user-facing software.
2. Note the **profile name** and **endpoint URI**. You will need both
   in the signing command.
3. Create an Azure RBAC role assignment so the user / service principal
   running the build pipeline has the
   `Trusted Signing Certificate Profile Signer` role on the profile.

### 3.4 Signing the binary

The actual sign call uses the standard `signtool.exe` from the Windows
SDK with the Trusted Signing dlib plug-in:

```bat
signtool.exe sign ^
    /v ^
    /fd SHA256 ^
    /tr http://timestamp.acs.microsoft.com ^
    /td SHA256 ^
    /dlib "C:\Program Files\TrustedSigning\Azure.CodeSigning.Dlib.dll" ^
    /dmdf signing-config.json ^
    target\argus_pyqt.exe
```

Where `signing-config.json` contains:

```json
{
  "Endpoint":            "https://<region>.codesigning.azure.net/",
  "CodeSigningAccountName": "<your-account>",
  "CertificateProfileName": "<your-profile>",
  "ExcludeCredentials":     ["ManagedIdentityCredential"]
}
```

After signing, **always verify**:

```bat
signtool.exe verify /pa /v target\argus_pyqt.exe
```

A successful verification ends with
`Successfully verified: target\argus_pyqt.exe`.

### 3.5 CI integration (GitHub Actions)

Use the official `azure/login@v2` action with a federated identity
(no client secrets in repo). Then call `signtool` exactly as above.
Documentation:
[Trusted Signing in GitHub Actions](https://learn.microsoft.com/azure/trusted-signing/quickstart-github-actions).

---

## 4. Build script template — `tools/build_signed.bat`

> Not committed to the repo yet. Here is the template the maintainer
> would drop into `tools/` once a cert is provisioned.

```bat
@echo off
setlocal

REM 1. Bundle the PyQt6 / QtWebEngine app with PyInstaller.
pyinstaller --noconfirm --onefile --windowed ^
    --name argus_pyqt ^
    --icon branding\argus\argus.ico ^
    --add-data "argus_data\;argus_data" ^
    --collect-all PyQt6 ^
    argus_pyqt.py

REM 2. Sign the produced binary with Trusted Signing.
signtool sign /v /fd SHA256 ^
    /tr http://timestamp.acs.microsoft.com /td SHA256 ^
    /dlib "%TRUSTED_SIGNING_DLIB%" ^
    /dmdf signing-config.json ^
    dist\argus_pyqt.exe

REM 3. Verify the signature is well-formed.
signtool verify /pa /v dist\argus_pyqt.exe || exit /b 1

echo.
echo Signed binary at: dist\argus_pyqt.exe
endlocal
```

---

## 5. PyInstaller `.spec` template

For full control over the QtWebEngine resources (without which the
embedded Chromium is broken at runtime), prefer a `.spec` file over
the one-shot CLI:

```python
# argus_pyqt.spec
block_cipher = None

a = Analysis(
    ['argus_pyqt.py'],
    pathex=['.'],
    datas=[
        ('branding/argus', 'branding/argus'),
    ],
    hiddenimports=[
        'PyQt6.QtWebEngineCore',
        'PyQt6.QtWebEngineWidgets',
    ],
    hookspath=[],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas,
    name='argus_pyqt',
    icon='branding/argus/argus.ico',
    console=False,
    debug=False,
    upx=False,
)
```

Build with `pyinstaller argus_pyqt.spec`.

---

## 6. Microsoft Store resubmission checklist

To recover from the 2026-04-03 rejection:

- [ ] Sign `argus_pyqt.exe` and `netguard.exe` with the Trusted Signing
      cert (or any valid OV/EV cert) following §3.4.
- [ ] Repackage as MSIX using the
      [Microsoft MSIX Packaging Tool](https://learn.microsoft.com/windows/msix/packaging-tool/tool-overview).
      Manual repack from a directory works fine — no need to recapture
      an installer.
- [ ] In the MSIX manifest, set `Publisher` to **exactly** the CN of
      your code-signing certificate — Store reviewers reject any
      mismatch.
- [ ] Sign the MSIX itself (`signtool sign … target.msix`) with the
      same cert.
- [ ] Re-submit through Partner Center, citing the previous rejection
      ID in the notes.
- [ ] Expect a 1–3 business day re-review SLA.

---

## 7. FAQ — should I get a cert *now*?

**Q. We are a free, open-source project. Is signing strictly required?**

A. Strictly, no. Anyone can build the source themselves and run it
without any SmartScreen warning. Distribution of an unsigned `.exe`
download is functional — users just have to click through the
`More info → Run anyway` button. Adoption rate, however, drops
dramatically. Industry estimates put the gap at roughly
**5 % adoption unsigned vs. 50 %+ signed** for downloads of unknown
publishers.

**Q. Trusted Signing vs. OV cert?**

A. Trusted Signing is cheaper, has no physical token to lose, and is
backed by Microsoft's own infrastructure — easier to keep working
in CI. Pick OV only if you specifically need a cert that is recognized
outside Microsoft's ecosystem (rare).

**Q. Should I get EV?**

A. Only if you sell paid commercial licenses and need zero-warning
first-run behaviour from day one. For free / OSS, the wait for
SmartScreen reputation to build up after Trusted Signing (~30 days
of installs) is acceptable.

**Q. How do I store the cert credentials securely?**

A. Trusted Signing uses Azure RBAC + federated identity — there is no
secret to leak. For OV/EV, the USB token is the only key material;
keep it in a locked drawer and **never** plug it into a CI agent
without HSM access controls.

---

> Copyright © 2026 NetGuard Pro Suite contributors
> This documentation file is part of the suite and is licensed under
> the GNU General Public License v3.0. See the `LICENSE` file at the
> repository root for the full text.
