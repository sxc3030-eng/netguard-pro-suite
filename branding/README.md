# NetGuard AI - Brand Mark

A shield with a bold center lettermark, framed by a tri-color gradient ring
and an inner containment line. Designed to swap a single character for each
module in the suite while keeping the silhouette and color system constant.

## Files

| File | Purpose |
|---|---|
| `netguard_logo.svg` | Vector source of truth. ViewBox 0 0 100 100. Use this to derive any raster size or build the favicon set. |
| `netguard_logo_master.png` | 1024x1024 hero render with transparent background. Drop into marketing surfaces, GitHub social card, app store hero, etc. |
| `netguard_logo_variants.png` | Reference sheet: all 6 module variants + a scale-resilience strip showing the mark at 256/128/64/32/16 px. |
| `_generate_brand.py` | Generator. Run `python _generate_brand.py` from this directory to rebuild every asset. The PNG renders are produced through PIL (no cairo dependency); the SVG is hand-templated. |

## Why this works at scale

**Silhouette first.** The shield is a rounded-crown / single-point silhouette
with strong negative space. At 16x16 the silhouette alone is recognizable;
at 1024x1024 the inner architecture (mesh, scan line, intersection dots,
sheen) rewards close inspection. This is the same design instinct behind
Cloudflare, Linear, Stripe -- the mark works at favicon scale because every
detail beyond the silhouette is treated as a "level of detail" that the
generator sheds at small sizes.

**Lettermark, not symbol.** Suite identity is encoded in a single character
(N for NetGuard, S for Sentinel, ...). This trades clever iconography for
something more robust: at 32px the user does not need to decode a tiny
metaphor, they just read a letter. Segoe UI Black is the actual rendered
font (universally available on Windows, with `Helvetica Neue` / `Arial Black`
fallbacks in the SVG).

**Gradient as identity, not decoration.** The violet -> blue -> cyan ring is
diagonal: violet at upper-left, blue at the bottom point, cyan at upper-right.
This asymmetry makes the mark feel directional and lit, rather than
symmetric and decal-like. The gradient is reproduced identically in vector
(SVG `<linearGradient>`) and raster (per-segment color interpolation along
the perimeter), so the brand reads consistently across both pipelines.

**Mint pulse, not notification badge.** A thin mint scan-line crosses the
shield at ~36% height, with two small luminous LED markers where it meets
the inner ring. This signals "active monitoring" without becoming a
notification dot (which would be ambiguous against a real notification dot
in OS surfaces). The scan-line is dropped at <96px to avoid clutter.

## Variant rules

Same shield, same colors, same gradient. Only the center character changes.

| Letter | Module | Slug |
|---|---|---|
| **N** | NetGuard       | `netguard-n` (the master mark, also the suite mark) |
| **S** | Sentinel       | `netguard-s` |
| **C** | CleanGuard     | `netguard-c` |
| **F** | FIM            | `netguard-f` |
| **M** | MailShield     | `netguard-m` |
| **V** | VPNGuard       | `netguard-v` |

Two additional letters are reserved for future modules:
- **H** for HoneyPot (already in the suite)
- **R** for Reports / Reporter

To add a new variant: open `netguard_logo.svg`, change the `<text>` content
on the last `<text>` element, and re-export. Or pass `letter='X'` to
`render_logo_png()` in the generator.

**Per-module accent (optional, future):** if we ever want to color-code
modules beyond the lettermark, the gradient stops can shift hue while
keeping value/saturation locked. For example:
- Sentinel: shift cyan -> teal (active scanning)
- VPNGuard: shift violet -> indigo (private tunnel)
- MailShield: shift cyan -> mint (clean inbox)

The current spec says "do not do this yet" -- one consistent gradient across
the suite is more recognizable than six bespoke palettes. Revisit only if
user research demands it.

## Color tokens

| Token | Hex | Use |
|---|---|---|
| `--ng-navy-deep`    | `#080A16` | Shield body, deep stop |
| `--ng-navy-mid`     | `#10152E` | Shield body, mid stop |
| `--ng-indigo-deep`  | `#1C1C4E` | Shield body, highlight stop |
| `--ng-violet`       | `#7A50F0` | Ring gradient, upper-left |
| `--ng-blue`         | `#3478F6` | Ring gradient, mid / shield bottom point |
| `--ng-cyan`         | `#34D2F6` | Ring gradient, upper-right |
| `--ng-cyan-bright`  | `#6EF0FF` | Inner ring, mesh grid, intersection dots |
| `--ng-active-green` | `#34E6A8` | Scan line, LED markers ("monitoring" cue) |

Backgrounds the mark is tested against:
- `#0F0F13` (NetGuard dashboard dark) - primary target
- pure white - acceptable, the dark shield body provides contrast
- pure black - good
- `#0A0E1A` (alt enterprise dark) - good

## Scale-of-detail (LOD) ladder

The generator drops detail as size shrinks. This is intentional and matches
how real brand systems work (compare Cloudflare's mark at 1024px vs. their
favicon).

| Output size | Halo | Mesh grid | Inner ring | Scan line | Letter glow |
|---|---|---|---|---|---|
| **>= 96px**  | yes | yes | yes | yes | yes |
| **>= 64px**  | yes | -   | yes | -   | -   |
| **>= 48px**  | yes | -   | -   | -   | -   |
| **<= 32px**  | -   | -   | -   | -   | -   |

At small sizes the outer ring also gets proportionally thicker (0.045 of
canvas at 32px, vs. 0.022 at 1024px) and the lettermark grows
proportionally (0.55 of canvas at 32px, vs. 0.42 at 1024px) to compensate
for antialiasing.

## Regeneration

```bash
cd D:/ComfyUI-Intel/netguard-pro-suite/branding
python _generate_brand.py
```

Requirements: Python 3.10+, Pillow (>= 10), NumPy. No cairo.

Windows-only font lookup is hardcoded to `C:/Windows/Fonts/seguibl.ttf`
(Segoe UI Black). Falls back to `arialbd.ttf`. To run on macOS/Linux,
edit the `font_path` strings in `render_logo_png` and `render_variants_grid`.

## Relationship to existing PIL pipeline

`create_brand_icons.py` and the existing `.ico` files are **not modified**.
That pipeline still produces the v1 hexagonal mark used in shipped binaries.
When ready to switch:

1. Re-target `create_brand_icons.py` to import `render_logo_png` from this
   module, or
2. Use `netguard_logo.svg` + ImageMagick / Inkscape to produce the full
   `.ico` chain (16, 32, 48, 64, 128, 256), or
3. Use `netguard_logo_master.png` as the source for a one-shot `.ico` build
   with PIL.

The SVG is the canonical source. Both PNGs are derived.
