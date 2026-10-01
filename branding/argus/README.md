# Argus Browser - Brand Assets

Visual identity for the **Argus Panoptes** browser, the privacy-first
cybersecurity workbench in the NetGuard AI Suite.

> *Argus Panoptes (Greek: Ἄργος Πανόπτης, "the all-seeing")* — the hundred-eyed
> giant of myth, never asleep, charged with watching what others would harm.
> The browser is named for him: every tab is a watched eye.

---

## Concept

**Sigil, not corporate logo.** The mark is a magical seal, not a SaaS roundel.

- **Central iris** — the master eye, watcher in chief.
- **Twelve satellite eyes** — stylized rendering of the 100 eyes of Argus,
  arranged on a sacred-geometry dodecagon (one eye per 30°).
- **Hexagram seal lines** — the Watcher's seal, faintly etched behind the iris.
- **Mint scan-tick** — a horizontal scan line crossing the iris, signalling
  *live watching* (matches NetGuard module language: green = active).
- **Catchlight** — small white gleam off the iris, gives the eye life.

The dodecagon and seal lines reference occult/alchemical sigils rather than
modern UI; the mark should feel like a glyph carved in dark glass, not a
corporate badge.

---

## Palette

| Role               | Hex        | RGB              | Used in                                |
|--------------------|------------|------------------|----------------------------------------|
| Cyber dark         | `#0a0e14`  | `10, 14, 20`     | Backdrop disc, almond fill             |
| Deep void          | `#05070b`  | `5, 7, 11`       | Pupil, vignette far edge               |
| Primary blue       | `#4d9fff`  | `77, 159, 255`   | **Normal mode** iris, satellite eyes   |
| Primary light      | `#9bd0ff`  | `155, 208, 255`  | Iris highlight stop, catchlight        |
| Secondary purple   | `#b47dff`  | `180, 125, 255`  | Outer-ring gradient terminus, wordmark |
| Privé deep blue    | `#1e40af`  | `30, 64, 175`    | **Privé mode** iris core               |
| Vault gold         | `#d4af37`  | `212, 175, 55`   | **Vault mode** iris, ring              |
| Mint accent        | `#3dffb4`  | `61, 255, 180`   | Live scan-tick, "active" signal        |
| Cyan inner         | `#6ef0ff`  | `110, 240, 255`  | Inner containment ring, taglines       |
| Text light         | `#dcefff`  | `220, 239, 255`  | Wordmark left stop                     |

Gradients run **blue → purple** for Normal, **deep blue → indigo** for Privé,
**gold → light gold** for Vault. The mint accent is a *signal* color — never
the dominant hue.

---

## Variants

Three mode variants share the same composition. The iris color and outer-ring
gradient swap; everything else is identical.

| File                | Mode    | Iris           | Ring gradient           | Use                           |
|---------------------|---------|----------------|-------------------------|-------------------------------|
| `argus_normal.png`  | Normal  | Electric blue  | Blue → Purple           | Default browsing chrome       |
| `argus_private.png` | Privé   | Deep blue      | Deep blue → Indigo      | Private/incognito mode        |
| `argus_vault.png`   | Vault   | Gold           | Gold → Light gold       | Coffre / encrypted-vault mode |

Each ships at **1024×1024 PNG** plus a multi-resolution **`.ico`**
(16/32/48/64/128/256). At ≤48px the ICO falls back to a *simplified mark*
(bold ring + iris + pupil + catchlight, no satellite eyes) so the favicon
remains readable. From 64px upward the full sigil renders.

---

## Files

| File                  | Size               | Description                                    |
|-----------------------|--------------------|------------------------------------------------|
| `argus_mark.svg`      | vector, 1024 vb    | Master mark, hand-written SVG primitives       |
| `argus_mark.png`      | 1024×1024          | Master mark raster (= `argus_normal.png`)      |
| `argus_mark_64.png`   | 64×64              | Pre-rendered web-icon size                     |
| `argus_mark_256.png`  | 256×256            | Pre-rendered window-icon size                  |
| `argus_normal.png`    | 1024×1024          | Normal mode (electric blue iris)               |
| `argus_private.png`   | 1024×1024          | Privé mode (deep blue iris)                    |
| `argus_vault.png`     | 1024×1024          | Vault mode (gold iris)                         |
| `argus_normal.ico`    | 16/32/48/64/128/256| Multi-res Windows icon, Normal                 |
| `argus_private.ico`   | 16/32/48/64/128/256| Multi-res Windows icon, Privé                  |
| `argus_vault.ico`     | 16/32/48/64/128/256| Multi-res Windows icon, Vault                  |
| `argus_wordmark.svg`  | vector, 800×200    | Mark + "ARGUS" wordmark + tagline              |
| `argus_wordmark.png`  | 800×200            | Wordmark raster                                |
| `argus_splash.png`    | 800×500            | Splash screen with mark, wordmark, tagline     |
| `_generate_argus.py`  | source             | Pillow-based generator for all PNG/ICO outputs |

The two SVGs are the canonical source; PNGs are rendered to match the SVG
design. If you change one you should regenerate the matching PNG.

---

## Typography

The wordmark uses a **geometric monospace** with wide letter-spacing:

- Primary: **JetBrains Mono Bold** (Google Fonts, OFL-1.1)
- Fallbacks: Fira Code, Consolas, Courier New
- "ARGUS": 78px · letter-spacing 14px · gradient blue→purple
- Tagline "CYBERSECURITY  WORKBENCH": 16px · letter-spacing 6px · cyan

The double-space inside "CYBERSECURITY  WORKBENCH" is intentional — it gives
the tagline a deliberate, telegraphic cadence consistent with monospace
formatting.

---

## Variant usage

| When                                   | Use                  |
|----------------------------------------|----------------------|
| Default app icon, taskbar, Start menu  | `argus_normal.ico`   |
| Private window chrome / system tray    | `argus_private.ico`  |
| Vault unlock screen / encrypted tab    | `argus_vault.ico`    |
| Splash screen on launch                | `argus_splash.png`   |
| Header / about box / docs cover        | `argus_wordmark.png` |
| Single mark on a dark UI panel         | `argus_mark.png`     |
| Tab favicon / small-context icon       | `argus_mark_64.png` or 16/32/48 frame from `.ico` |

Always render the mark on **dark** backgrounds (≤ `#1a2030`). The mark is
designed for cyber-dark UI; on light backgrounds the inner cyan
containment ring and the dark almond fill lose contrast.

---

## Regenerating assets

```sh
cd branding/argus
python _generate_argus.py
```

Requires only **Pillow ≥ 10**. No `cairo`, no `cairosvg` — all raster output
comes from Pillow primitives, which keeps the generator portable across
Windows / Linux / macOS without native-library headaches.

The SVGs are hand-authored and are *not* rebuilt by the generator; the
generator's PNG output mirrors the SVG design but is independently composed.
If you edit the SVG, eyeball the PNG against it.

---

## License & attribution

- All artwork: **GPL v3**, © 2026 sxc3030-eng.
- All design elements (iris, satellite eyes, dodecagon frame, hexagram seal,
  almond eye outline, scan-tick) are **original**, hand-composed from
  geometric primitives in SVG and Pillow.
- **No AI image generation was used.** The mark is rendered programmatically
  from circles, polygons, and lines, so it carries no training-data
  provenance risk for a public GPL repository.
- "ARGUS PANOPTES" is the name of a figure in Greek mythology and is in the
  public domain.

If you fork or modify, retain the GPL v3 notice and credit `sxc3030-eng` /
the NetGuard AI Suite project.

---

## Naming

Argus is the **sister product** to Mythos in the NetGuard suite — both draw
on Greek mythology of watchers and beasts. Argus *watches*; Mythos *acts*.
The two-mark system reflects this: Argus eye versus Mythos sigil.
