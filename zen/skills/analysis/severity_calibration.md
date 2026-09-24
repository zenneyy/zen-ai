---
name: severity-calibration
description: Qualitative rubric for what actually deserves high/critical severity, and an acceptance checklist to apply before rating a finding
---

# Severity Calibration

CVSS gives you a number once you have chosen the metrics. This skill is
about choosing them honestly — deciding what class of issue genuinely
belongs at each severity before you fill in the vector.

Calibrate severity **after** you have established reachability and run
the counterevidence pass, never before. Severity is a conclusion, not an
opening position.

## The Test That Matters

Before rating anything high or critical, ask:

> Would this be accepted as high/critical in serious audit or bug bounty
> triage, by a firm putting its reputation on the line?

If the honest answer is "only if you accept a chain of assumptions", it
is not high. Rate the weakness you proved, not the worst case you can
imagine reaching from it.

## Critical

Reserve for findings where a realistic attacker gets decisive control or
mass data access, with evidence:

- Unauthenticated remote code execution, or command/code execution
  reachable by any user on internet-exposed surface.
- Full authentication bypass, or trivially forgeable authentication
  (accepted unsigned tokens, `alg: none`, signature not verified).
- Mass extraction of other users' or other tenants' sensitive data.
- Compromise of signing keys, control-plane credentials, or credentials
  granting broad infrastructure access.
- Complete cross-tenant isolation failure in a multi-tenant system.

Factors that push a high up to critical: no authentication required,
internet reachable, zero user interaction, wormable/self-propagating,
or the impact spans all tenants rather than one.

## High

- Authenticated RCE, or RCE requiring a common non-privileged role.
- Privilege escalation crossing a real trust boundary (user → admin,
  tenant → tenant, read → write on protected objects).
- Object-level authorization failures exposing or modifying other users'
  sensitive data at scale.
- SQL injection or equivalent injection reaching real data.
- SSRF that demonstrably reaches internal services, cloud metadata, or
  credentials.
- Sensitive credential or PII exposure that an attacker can actually
  reach.

## Medium

- Stored XSS in a limited context, or reflected XSS requiring user
  interaction.
- CSRF on a meaningful state-changing action.
- Authorization gaps on lower-value objects.
- Information disclosure that materially aids a further attack.
- Findings whose high-impact version is blocked by a real constraint you
  confirmed (internal-only exposure, a required privileged role, a
  narrow precondition).

## Low / Informational

- Missing security headers, cookie flag issues, verbose errors.
- Self-XSS, or XSS requiring the victim to paste a payload.
- Open redirect with no credential or token leakage.
- Rate-limiting and enumeration issues without a demonstrated impact.
- Defense-in-depth gaps with no reachable exploitation path.

## Mapping to Program Priority (Bugcrowd VRT)

Many programs — Bugcrowd-run VDPs and the NASA VDP this agent operates
under included — triage on the Vulnerability Rating Taxonomy's P1–P5
priority scale, not on a raw CVSS number. The VRT gives a *baseline* per
vulnerability class; the program brief, application context, and
demonstrated impact override it. Map the qualitative band you chose above
to a priority, then sanity-check the class against the VRT baseline:

| Priority | Band here | VRT definition | Typical classes |
|---|---|---|---|
| **P1** Critical | Critical | App unusable / immediate attention; unpriv→admin escalation, RCE, financial theft | Unauth RCE, SQLi reaching data, XXE, full auth bypass, hardcoded/privileged credential, private key exposure, OAuth→ATO, high-impact subdomain takeover |
| **P2** Severe/High | High | Not critical but significantly impacts the app's security and the processes it supports | Stored XSS hitting other users, internal SSRF, app-wide CSRF, 2FA bypass, IDOR exposing sensitive data at scale, authenticated RCE |
| **P3** Moderate/Medium | Medium | A real flaw that must be fixed; affects multiple users, little/no interaction | Reflected XSS (non-self), CSRF on a meaningful action, weaker IDOR, second-order or limited injection, meaningful information disclosure |
| **P4** Low | Low | Minor; affects a single user or needs interaction / significant prerequisites (e.g. MitM) | Self-XSS chains, open redirect alone, verbose errors, missing headers with a small demonstrated effect, low-value enumeration with impact |
| **P5** Informational | Informational | Non-rewardable: by-design, best-practice, or non-exploitable | Missing headers with no impact, version banners, theoretical or defence-in-depth gaps, no reachable exploitation path |

Two rules catch most mis-triage:

- **A program that runs P1–P4 treats P5 as non-rewardable and often
  non-reportable.** If your honest band is Informational, say so; do not
  inflate it into a P4 to get it accepted — that padding is exactly what
  triage rejects. Report it as informational or fold it into a chain that
  actually reaches P4 or above.
- **The VRT baseline is a starting point, not a verdict.** A class the VRT
  lists as P3 becomes P1 once you prove it reaches admin or cross-tenant
  data; a P2 class drops to P4 when the only path needs a privileged role
  or a MitM position you cannot obtain. Priority follows the *demonstrated*
  impact, the same way the CVSS metrics do — the VRT class is the anchor,
  your evidence is the score.

Where a program wants both a priority and a CVSS vector, the priority is
the headline and the vector is the justification; they must agree in
direction. A "P1 with a 5.3" or a "P4 with a 9.8" means one of them is
wrong — re-derive the metrics before filing.

## Usually NOT High or Critical

These are over-rated constantly. Each needs unusual, demonstrated
circumstances to exceed medium:

- Self-XSS and clickjacking on non-sensitive actions.
- Missing headers, cookie attributes, TLS configuration nits.
- Open redirect on its own.
- Theoretical memory-safety issues with no reachable attacker input.
- "Could matter if chained with several unproven assumptions."
- Anything already requiring admin, shell, or physical access — if the
  attacker already has that, the finding adds little.
- Session-management weaknesses that require the attacker to already
  hold a victim secret (a stolen cookie, an intercepted link). The
  acquisition of that secret is not free; unless the *same* finding shows
  how to obtain it, this is usually low/medium.
- Enumeration that only confirms an account, domain, or version exists.

## Downgrade, Don't Delete

A finding that turns out to be constrained gets a lower severity — not a
silent drop. Internal-only reachability, a required privileged role, or a
narrow precondition are all reasons to reduce severity and say so in the
report. They are not reasons to withhold the finding.

Equally: missing evidence about deployment or exposure lowers your
**confidence**, not the severity floor. Do not treat "I could not confirm
this is internet-facing" as if it were "this is internal-only".

## Acceptance Checklist for High / Critical

All of these must be true. If any is not, drop a level:

- [ ] The attack path is realistic and in scope — not a lab-only
      condition, not dependent on an unproven prior compromise.
- [ ] The attacker position required is one an attacker can actually
      obtain, and the CVSS `privileges_required` / `attack_complexity`
      reflect that honestly.
- [ ] The impact is material and demonstrated, not asserted — `C:H` /
      `I:H` mean proven broad or systemic read/write, not one record.
- [ ] The counterevidence pass found no constraint that meaningfully
      limits exploitation, or you have explained why the constraint does
      not hold.
- [ ] You have concrete evidence of reachability, not an assumption
      about how the application is deployed.
- [ ] You would defend this rating in a client debrief.

## CVSS 4.0

When the program scores on CVSS 4.0 (`CVSS:4.0/...`), do not hand it a 3.1
vector — the metric set changed and a mechanical port mis-scores. What
moved:

- **Scope is gone.** v3.1's single `S` is replaced by two impact triads:
  **Vulnerable System** `VC`/`VI`/`VA` and **Subsequent System**
  `SC`/`SI`/`SA`, each `H`/`L`/`N`. A container escape or an SSRF that
  pivots into other systems is now impact on the *subsequent* system
  (`SC:H`, `SI:H`, ...), not `S:C`. Rate the vulnerable component in the
  first triad and everything it reaches downstream in the second.
- **New Attack Requirements `AT` (`N`/`P`),** split out of the old Attack
  Complexity. `AT:P` (Present) is a required deployment, race, or
  configuration precondition; keep `AC:H` for attacker-side effort
  (defeating a mitigation, winning a computation). A TOCTOU/race bug that
  needs a timing window is `AC:L/AT:P`, not `AC:H` — do not spend the same
  precondition twice.
- **User Interaction is three-valued: `UI:N`/`UI:P`/`UI:A`.** `Passive` is
  incidental (a victim simply viewing the page that carries the payload —
  most stored XSS); `Active` is a conscious, specific action (importing a
  file, changing a setting, clicking a crafted link). Reflected XSS behind
  a link the victim must click is `UI:A`; stored XSS firing on a normal
  page view is `UI:P`.
- **Base is named by what you include:** Base only is **CVSS-B**; with
  Threat metrics **CVSS-BT**; with Environmental **CVSS-BE**; all three
  **CVSS-BTE**. State which you produced.
- **Threat: Exploit Maturity `E`** (`X` not defined = worst case, `A`
  Attacked, `P` Proof-of-Concept, `U` Unreported). A finding you have a
  working PoC for but no in-the-wild exploitation is `E:P`; leaving it `X`
  scores it as if attacks exist and over-rates most findings — set it.

Severity bands are unchanged in shape: **None 0.0, Low 0.1–3.9, Medium
4.0–6.9, High 7.0–8.9, Critical 9.0–10.0.** The rubric above is
version-agnostic; it decides which honest metric values to enter. The
common 4.0 mis-scores are the 3.1 three plus one: an optimistic impact
triad, `PR:N` where a role is actually required, `UI:N` where the victim
must act, and now `AT:N` where a real precondition exists. Fix the metric,
not the output.

### Two worked ratings

- **Reflected XSS; victim must click a crafted link; fires in their own
  session; no privileged data reached.** Band Medium → **P3**. A defensible
  base vector is
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
  (Medium band). `UI:A` (the click) and the self-context `L` impacts hold
  it at P3 rather than P2 — flip `UI:A`→`UI:N` or the impacts to `H` and
  you have rated it upward without evidence.
- **Unauthenticated SSRF returning cloud-metadata credentials that then
  read another tenant's bucket.** Band Critical → **P1**. Base vector
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`
  (Critical band). Credential theft on the reachable host is
  vulnerable-system confidentiality (`VC:H`); the cross-tenant read is the
  subsequent-system impact (`SC:H/SI:H`) that in 4.0 replaces the old
  `S:C`. Priority and vector agree in direction.

## Output

Severity still comes from the CVSS vector — this rubric decides which
vector is honest. When your intuitive rating and the computed CVSS
severity disagree, re-examine the metrics: usually one of
`privileges_required`, `attack_complexity`, or the impact triad was set
optimistically. Fix the metric, do not override the result.
