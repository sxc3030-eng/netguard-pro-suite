# Argus &mdash; Internal Pitch Deck

> Working document. Not for public distribution.
> Last updated: 2026-04-28.

---

## Problem

The web has become hostile to professional users in three converging ways.
Browser vendors have responded to the tracking-economy backlash by enabling
aggressive cross-site isolation (Edge Tracking Prevention, Firefox Total
Cookie Protection, Safari ITP) that quietly breaks the SSO and dashboard
flows cybersecurity analysts actually depend on. AI is being bolted onto
browsers as an upsell SaaS &mdash; your prompts and pasted context routed
through someone else's billing department. And there is no general-purpose
browser that exposes a tamper-evident audit trail of what you did, what
loaded, what fired off; forensic browsers exist but cost five figures and
lock the data inside vendor formats.

## Why now?

Three tailwinds converge in 2026.

1. **Edge Tracking Prevention is breaking productivity tooling.** Analysts
   are flipping it off site-by-site, opening more attack surface than the
   ETP was meant to close. The market wants the granular control without
   the productivity hit.
2. **Surveillance capitalism fatigue.** Mullvad Browser, Brave's Tor mode,
   and Mozilla's containers were the first wave; the next is structural,
   not cosmetic.
3. **BYOK AI is the new normal.** Developers and security pros are
   already paying for direct Anthropic / OpenAI / Gemini keys. They
   want to *use* those keys in the tools they live in &mdash; without
   handing them to another vendor.

The combined slope makes 2026 a viable launch window for a niche browser
positioned at the intersection of forensic transparency + AI-native +
privacy-by-default.

## Solution: Argus

Argus is a privacy-first cybersecurity workbench browser. Three pillars,
documented in `argus_README.md` and the source tree:

- **Sandbox.** Per-mode profile isolation, scoped storage, mode-specific
  badges (Normal / Priv&eacute; / Coffre).
- **Surveillance.** HMAC-SHA256 chain over every event, JSONL audit log,
  offline chain-verify CLI &mdash; the forensic surface a $20K/seat
  competitor sells.
- **Arbitrage.** BYOK AI (Claude, GPT, Gemini, Ollama) classifying
  traffic in flight, decisions written to the same audit chain.

Plus two infrastructure pieces nobody else has: the **Mythos Bus +
Gateway** (a versioned, audit-logged plug-port for autonomous agents)
and the **Vault Gateway** (cross-process secret broker with live
binary-hash verification).

## Competitive matrix

Honest reads on each competitor &mdash; we lose on some axes.

|                              | **Argus**                | **Brave**                | **Chrome + uBlock**     | **Firefox + Containers** | **Mullvad Browser**      | **Tor Browser**          |
|------------------------------|--------------------------|--------------------------|-------------------------|--------------------------|--------------------------|--------------------------|
| Open source                  | Yes (GPL v3)             | Yes (MPL 2.0 mostly)     | Engine yes, profile no  | Yes (MPL 2.0)            | Yes (MPL 2.0)            | Yes (BSD-3 / MPL)        |
| Cyber-forensic audit trail   | **Yes, HMAC-anchored**   | No                       | No                      | No                       | No                       | No                       |
| BYOK AI in browser           | **Yes, native**          | Leo (Brave-hosted only)  | Via extensions, leaky   | Via extensions, leaky    | No                       | No                       |
| Per-mode strict isolation    | Roadmap V3               | Tor mode (V1 today)      | Incognito only          | Containers (best class)  | Strict by default        | Strict by default        |
| Tamper-evident vault         | **Yes (V2 gateway)**     | No                       | No                      | No                       | No                       | No                       |
| Plug-port for AI agents      | **Yes (Mythos protocol)**| No                       | No                      | No                       | No                       | No                       |
| Network-level anonymisation  | Out of scope V1          | Tor mode                 | No                      | No                       | No (uses VPN externally) | **Yes**                  |
| Fingerprint resistance       | Roadmap V3               | Strong                   | Weak                    | Medium                   | Strong                   | **Best in class**        |
| Productivity (dashboards/SSO)| **Strong**               | Strong                   | Strong                  | Strong                   | Medium                   | **Poor by design**       |

We are not trying to beat Tor on anonymity or Firefox containers on per-tab
identity gymnastics. We win on the orthogonal axes: forensic transparency,
AI-native BYOK, and the agent plug-port. That is a niche &mdash; on
purpose.

## Differentiation &mdash; three USPs

1. **Forensic browser at GPL v3 price point.** A signed, tamper-evident
   HMAC chain over your browsing events. Today this capability is sold by
   Magnet Forensics / Cellebrite / Hunchly at $5K&ndash;$20K/seat with
   proprietary export formats. Argus emits open JSONL with a documented
   chain.
2. **Agent-native cage.** The Mythos Bus + Tool Gateway protocol is
   already implemented and tested before Mythos itself exists. Anyone can
   build an agent against the spec. We are the first browser shipping a
   stable, versioned, audit-logged interface for autonomous agents to
   read and act on the browsing surface.
3. **Cross-process secret vault with live binary-hash verification.**
   The vault gateway authenticates callers by re-hashing their on-disk
   binary at every request, not by a shared passphrase or filesystem
   ACL. This is the level of identity rigour usually associated with
   HSMs &mdash; ported to a single-machine open-source product.

## Target user personas

**1. The professional cybersecurity analyst.**
Has a dual-monitor setup, runs Wireshark and Burp Suite, takes screenshots
into Hunchly or KeepNote for case files. Spends $200&ndash;$500/month on
licensed tooling already. Wants a browser whose log she can subpoena
without waving an EULA. Pays Pro tier without hesitation; her firm pays
Enterprise.

**2. The privacy-conscious developer.**
Maintains side projects, runs a self-hosted vault (Vaultwarden /
Bitwarden), and uses Claude / Codex daily. Hates that ChatGPT plugin lives
in OpenAI's session. Will use the Free tier indefinitely; will pay Pro if
the AI session-summary report is good enough to replace his current
manual journaling.

**3. The banking power user / finance professional.**
Has a primary account at a bank, a brokerage, and one or two crypto
exchanges. Has been phished or near-phished at least once. Already runs a
hardware key (YubiKey, Titan) and a separate VM for banking. Will pay Pro
for Mode Coffre as soon as it ships real isolation in V3 &mdash; which is
why V3 is on the roadmap, not V8.

## Pricing tiers + revenue model

The HTML one-pager has the canonical layout; in short:

- **Free** &mdash; GPL v3, Mode Normal + Priv&eacute;, BYOK AI, audit
  chain, GitHub community support. The feature ceiling is generous on
  purpose: distribution and trust come first.
- **Pro &mdash; $9&ndash;15/month placeholder** &mdash; real Mode Coffre,
  forensic export, AI session summary, vault gateway with binary
  whitelist, priority response. Single seat. Self-serve.
- **Enterprise &mdash; custom** &mdash; SAML/SSO, central whitelist
  management, SIEM integration, custom retention, named SLA,
  on-premise deployment guidance, compliance attestations on request.
  Sales-led. Floor in the $20K/year/team range, ceiling on volume.

Revenue model is hybrid open-core: the engine is GPL v3 forever, the
opinionated configurations + central management + signed report
templates + first-party Mythos tools live on the paid tiers. The
hard line: nothing on the paid tier hides a security primitive from
the open-source codebase. Paid customers get *operational
convenience*, not *security exclusivity*.

> **Pricing needs validation.** $9&ndash;15/month is currently a
> placeholder. We need 30+ user-interview signals + a willingness-to-pay
> survey before locking it.

## Roadmap

| Version | Status | Major contents |
|---|---|---|
| **V1**  | Shipped 2026-04-27 | PyQt6 multi-tab, sessions, NetGuard launcher, settings dialog, mode badges (cosmetic), in-process vault, Mythos bus + gateway (stubs), surveillance HMAC chain, BYOK arbiter, three brand variants. |
| **V2**  | In progress       | Vault Gateway (cross-process broker, V2 secure REST), AI session summary, signed forensic export, Code Sandbox tab, Reader mode, Argus side panel polish. |
| **V3**  | Specced           | Real Mode Priv&eacute; / Coffre isolation, certificate pinning, download sandbox, fingerprint resistance, themes, print, snip-inline. |
| **Mythos** | Specced (protocol live) | Autonomous agent that reads the bus, requests actions through the gateway, runs in a separate process with semi-trust. Argus is the cage; Mythos is the beast. |

## Risks + mitigations

**Chromium upstream churn.** PyQt6's QtWebEngine ships behind the latest
Chromium release; security CVEs may land days late. *Mitigation:* track
PyQt6/Qt6 releases, surface lag in `SECURITY.md`, document a manual
override path for users who need today's Chrome.

**Crypto missteps.** Forensic claims live or die on the chain integrity.
*Mitigation:* every primitive comes from `cryptography` /
`pycryptodome` / OS DPAPI. We design no protocols; we glue vetted ones.
The chain-verify CLI runs in CI on every push.

**Pricing mismatch.** $9&ndash;15/month may be too low (analysts pay
much more for Hunchly) or too high (devs are price-sensitive).
*Mitigation:* run the willingness-to-pay survey before V2 launch; be
willing to ship a $5/month Lite and a $25/month Pro+ if signals
demand it.

**MS Store rejection.** NetGuard hit a Store policy 10.2.9 rejection
(unsigned binary). Argus is on the same path. *Mitigation:* either MSIX
repackage with code-signing, Microsoft Trusted Signing programme, or
own EV cert. The AUTHENTICODE.md doc covers all three.

**GPL v3 chilling enterprise sales.** Some Fortune 500 procurement
treats AGPL/GPL v3 as untouchable. *Mitigation:* the engine stays GPL
v3; an Enterprise customer who needs a non-copyleft license can buy a
**dual-licensed commercial edition** for the modules they ship into
non-GPL products. This is the standard MySQL / Qt model.

**Mythos vapourware risk.** We pitch the Mythos plug-port as a
differentiator while Mythos itself is still spec. *Mitigation:* the
*protocol* and the *cage* are both shipped and tested; any third-party
agent can plug in. The pitch is "first browser with a stable agent
plug-port", not "first browser with a working agent". Frame it that way
in customer conversations.

---

> Internal document. Sourced from `argus_README.md`, `SECURITY.md`,
> `MYTHOS_PROTOCOL.md`, `VAULT_GATEWAY.md`, and the V1 codebase. All
> claims should be re-verified against the live tree before being used
> in customer-facing material.
