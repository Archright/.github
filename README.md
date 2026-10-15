
## 2026-10-15 — Admission generation pinned at H₁
- Org rulesets 24233738/23943917 pin admission-gate.yml/landing-integrity.yml at sha e968b5c0 (generation tag admission-gen-h1-20261015).
- This commit deliberately advances main PAST the pinned generation: a canary proving the ruleset resolves the workflow from the pinned sha, not from main (see Archright/Axiom docs/spec/admission-generation.md §6 divergence test).
