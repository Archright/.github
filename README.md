
## 2026-10-15 — Admission generation pinned at H₁
- Org rulesets 24233738/23943917 pin admission-gate.yml/landing-integrity.yml at sha e968b5c0 (generation tag admission-gen-h1-20261015).
- This commit deliberately advances main PAST the pinned generation: a canary proving the ruleset resolves the workflow from the pinned sha, not from main (see Archright/Axiom docs/spec/admission-generation.md §6 divergence test).

## 2026-10-16 — Divergence-test marker (generation pinned at 135644a302)
2026-10-16: divergence-test marker — main advances past the pinned admission generation; see Archright/Axiom docs/spec/admission-generation.md §6
- Org rulesets 24233738/23943917 pin admission-gate.yml/landing-integrity.yml at sha 135644a30291f2956e90b09a819fa7fe43371dd4 (H₃ generation, re-pin readback 2026-10-15T23:36:12+09:00).
- This commit deliberately advances main PAST that pinned generation; the next Axiom merge_group admission run must still execute the pinned pin-triple {admission-check@dc527994c, certificate-mint@689ff9eaf, runner-pool-acceptance@ba773d0631}.
