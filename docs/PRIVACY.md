# Argus — Privacy Policy

_Last updated: 2026-04-28_

Argus is built around a simple, hard rule: **the browser does not phone home.**
This document lists the only network requests Argus makes on its own behalf
(i.e. requests not initiated by the user navigating to a page), what data is
sent, and how to disable them.

## 1. What Argus does NOT collect

* No install ID, device fingerprint, MAC address, or hardware UUID.
* No OS version, CPU model, RAM size, or screen resolution.
* No usage analytics, click tracking, or session telemetry.
* No "anonymous" event reporting via a third party (Sentry, GA, Mixpanel,
  PostHog, etc. are NOT integrated).
* No automatic crash reports — if Argus crashes, the stack trace stays
  on your disk.

## 2. The auto-update check

If you have it enabled (default ON, see §4 to disable):

* Argus issues **one HTTPS GET** to
  `https://api.github.com/repos/sxc3030-eng/netguard-pro-suite/releases/latest`
  on launch, at most every 6 hours (cooldown), with a `User-Agent` of
  `Argus/<version> (+https://github.com/sxc3030-eng/netguard-pro-suite)`.
* What GitHub sees: your IP address, the request timestamp, and the
  User-Agent above. That is the same information any unauthenticated
  visitor of `api.github.com` reveals — Argus adds nothing.
* What GitHub does **not** see: who you are, what page you were on, what
  features you use, anything specific to your install.
* If a newer release is found, the version, changelog, and download URL
  are cached locally in `argus_data/last_update_check.json` so that
  successive launches inside the cooldown window don't re-query GitHub.
* No update is auto-downloaded. The user clicks an explicit button.
* No update auto-replaces the running binary. The user closes Argus and
  runs the installer themselves.

## 3. Surveillance log

Argus keeps an **encrypted, local-only** forensic log under
`argus_data/surveillance/` (AES-256-GCM, HMAC-chained). When the update
checker runs, it appends one event of type `user_action` with payload
`{"type": "update_check", "result": "<found_update|up_to_date|failed>"}`.
That event never leaves your machine. See `argus_surveillance.py` for the
storage format and retention policy (default 7 days).

## 4. How to disable the update check

Either:

* In Argus, open Settings and uncheck "Vérifier automatiquement les
  mises à jour" (TODO V2 wiring), **or**
* From a terminal:

```
python -c "import argus_updater; argus_updater.set_check_enabled(False)"
```

Verify with:

```
python -c "import argus_updater; print(argus_updater.is_check_enabled())"
```

When disabled, Argus makes **zero** outbound requests on its own behalf.

## 5. Source code

Argus is GPL v3. The full implementation of the updater is in
`argus_updater.py`. Audit it. If you find a request not documented here,
that is a bug — please open an issue.
