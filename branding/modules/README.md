# NetGuard AI Suite - Module Marks

Per-module brand marks. Same shield silhouette and color system as the master
mark in `branding/`, but each module carries its own pictorial metaphor
instead of a swapped letter.

This is the design language used by Cloudflare (Workers / R2 / Pages), Linear
(Cycles / Triage / Insights), and JetBrains (one frame, one accent, one
distinctive glyph per product). Each program reads as its own product while
still belonging unmistakably to the same family.

## Files

| File | Purpose |
|---|---|
| `_generate_modules.py` | Generator. Imports the master shield/ring/halo from `branding/_generate_brand.py` and adds a `render_module_icon(slug, size)` API plus 13 small metaphor drawers. |
| `<slug>.svg` | Vector source per module. ViewBox `0 0 100 100`, hand-templated, human-editable. |
| `<slug>.png` | 512x512 hero render per module. Transparent background. |
| `_overview.png` | 13-up grid + 32-px favicon strip to check brand cohesion and small-scale legibility. |

Run from this directory:

```bash
python _generate_modules.py
```

Same Pillow + NumPy requirements as the master generator. Windows-only font
path (Segoe UI Black at `C:/Windows/Fonts/seguibl.ttf`). To run on other
platforms, edit the two `font_path` strings.

## What stays constant across all 13 marks (cohesion)

- **Shield silhouette** - identical pentagonal crown/point geometry from
  `shield_path_units()` in the master generator. Every module is the same
  outer shape.
- **Body fill** - radial indigo -> navy gradient. Identical numerics.
- **Outer ring gradient** - violet (upper-left) -> blue (mid) -> cyan
  (upper-right). The dominant brand signature; never altered per module.
- **Inner containment ring** - thin cyan keyline, identical inset of 4 units.
- **Halo + sheen** - same blur radii, same alphas, same upper-left specular
  bloom.
- **Mesh grid** - same triangular lattice clipped to the body, same alphas,
  same LOD threshold (drops at <96 px).
- **Scan line** - same y-position (35.5%), same node geometry. The pulse
  *colour* is the only thing the module is allowed to tint.

## What changes per module (distinction)

1. **Centre glyph** - one bespoke metaphor each.
2. **Single accent shift** - at most one of `mint / amber / violet / red` for
   the scan line + glyph highlights. The ring gradient never moves.

That's it. Two degrees of freedom. The result is exactly the Cloudflare-suite
behaviour: a glance tells you "NetGuard family"; a beat later tells you
*which* product.

## Per-module rationale

| Slug | Metaphor | Why this glyph |
|---|---|---|
| **netguard** | Bold "N" lettermark | The master keeps the original anchor letter. Everyone in the suite knows where they came from. |
| **netguard-tray** | Stamped mini-shield with "N" | Designed for system-tray rendering. The inset white shield + dark navy N stays legible at 16/24/32 px when nothing else can. Mesh and inner ring are dropped to keep the silhouette clean at tray sizes. |
| **netguard-ai** | 4-point sparkles | The universal "generative / intelligent" mark across modern UI (Linear AI, Notion AI, ChatGPT, Figma AI). Three sparkles - one large, two satellites - read as "AI presence." |
| **mailshield** | Envelope behind shield | Linework envelope with a triangular flap whose apex echoes the shield's bottom point. The accent dot at the seal hints at "scanned mail," not just inbox. |
| **cleanguard** | Broom sweep + trailing sparkles | The clean handle/ferrule/bristle silhouette is universally recognisable as "clean." Three trailing mint sparkles communicate "after the sweep, the system shines." |
| **sandbox** | Isometric wireframe cube | The exact visual language used by every malware-sandbox vendor (Cuckoo, Joe, ANY.RUN). The single accent dot inside is "the suspect sample, contained." |
| **sentinel-os** | Radar dial with sweeping wedge | A watchtower would be too literal and too dense at small sizes. Concentric rings + sweep wedge + crosshair is the universal SOC vocabulary for "we are watching." |
| **siem** | ECG / event-pulse line | An ECG-style polyline with two terminal nodes. SOC analysts live in event timelines and dashboards - this glyph is what their day looks like. The line tints mint to keep "active monitoring" energy. |
| **vpnguard** | Tunnel arch with chain link | A two-ring tunnel arch (foreground + background depth cue) with two interlocking violet rings inside. The chain link is the universal "encrypted / locked passage" marker. |
| **recorder** | Red record dot + concentric capture ring | Anyone who has ever clicked record knows this glyph in <100 ms. The outer thin ring frames it as a capture target rather than just a notification dot. |
| **honeypot** | Hexagonal honeycomb cell + drop | A single flat-top honeycomb cell (with a comb-hint inner hex) and a hanging amber drop. Cleaner than a literal jar, instantly readable, scales beautifully to favicon size. |
| **fim** | Document with hash signature wave | Document silhouette with folded corner, two text-line bars, and a sine-wave "hash signature" running across. Reads as "file content + integrity fingerprint" - the literal job of FIM. |
| **strikeback** | Lightning bolt through reticle | Crosshair reticle + cardinal ticks + a glowing red lightning bolt punching through. Red-team aggression in a single glance: "we can hit back, here is the target." |

## Accent shifts (one per module max)

| Module | Accent | Effect |
|---|---|---|
| netguard, netguard-tray, mailshield, sandbox, sentinel-os, recorder (ring only), fim | none | Default cyan/mint pulse. |
| netguard-ai | violet | Glyph highlights pull violet for "generative / intelligent." |
| cleanguard | mint | Sparkles render in a brighter mint. |
| siem | mint | ECG line picks up mint to read as "active heartbeat." |
| vpnguard | violet | Chain links render in violet to read as "private tunnel." |
| recorder | red | Record-dot uses brand red, not pulse green. |
| honeypot | amber | Honeycomb fill + drop shift to amber/gold. |
| strikeback | red | Bolt is the brand-red threat colour. |

## Scale-of-detail (LOD) ladder

Identical to the master mark. Every module's glyph is sized to survive the
inner-ring envelope at all output sizes. The favicon strip in
`_overview.png` shows every module at 32 px against the brand-dark
background.

| Output size | Halo | Mesh | Inner ring | Scan line | Glyph glow |
|---|---|---|---|---|---|
| >= 96 px | yes | yes | yes | yes | yes (where applicable) |
| >= 64 px | yes |  -  | yes |  -  | partial |
| >= 48 px | yes |  -  |  -  |  -  | core only |
| <= 32 px |  -  |  -  |  -  |  -  | core only |

Because the chassis sheds detail at small sizes, the glyph is what carries
the module identity below 64 px. Each glyph was sketched to survive a
2-line, single-colour fallback (try the favicon strip - the broom, the
sparkle, the cube, the radar, the pulse, the chain, the dot, the comb, the
doc, the bolt are all individually distinguishable at 32 px against
dashboard dark).

## Adding a 14th module

1. Pick a slug. Append to `MODULES` in `_generate_modules.py` with
   `(slug, "Display Name", "tagline", accent_or_None)`.
2. Pick an accent: `None`, `"mint"`, `"violet"`, `"amber"`, or `"red"`. If
   none of those fit your module, add a new entry to `ACCENTS` with a
   `pulse` and `glyph` colour. Keep saturation in the same band as the
   others - high but not neon.
3. Write a `draw_<slug>(draw, W, H, SS, accent)` that returns a list of
   RGBA layers to alpha-composite over the chassis. The unit space is
   `0..100`; the optical centre of the shield is at `(50, 53)`. Keep
   glyphs inside roughly a `50x44` cell centred there so they sit cleanly
   inside the inner containment ring.
4. Add an entry to `GLYPH_DRAWERS`.
5. Add a corresponding clause to `_svg_glyph_for(slug, accent)` so the
   vector source matches the raster.
6. Re-run `python _generate_modules.py`. The overview grid auto-rebuilds.

## Relationship to `branding/`

This directory imports from `branding/_generate_brand.py` for the shared
chassis (shield path, palette, ring colour math). It does **not** modify the
master generator, the master SVG, or `create_brand_icons.py`. The wiring
layer that maps these PNGs into Windows `.ico` chains and shipped binaries
is intentionally left untouched - that lives one floor up.
