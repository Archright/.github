#!/usr/bin/env python3
"""Independent third-party replay verifier for Axiom PR Admission runs (v2).

v2 semantics: the admission verdict is decided against the DECLARED acceptance
class (contract v1.1.0, PR_ADMISSION_CONTRACT.md §2.7), not against the engine's
5-state label alone. Evidence tier is part of the verdict, never hidden.

Given a downloaded run artifact directory containing:
  - propositions/proposals.json
  - ax-verify-evidence-propositions-A/{verify-record.json, ax_proof_state.json, canonical-digest.txt, vault-manifest.json}
  - ax-verify-evidence-propositions-B/{...same...}
  - admission-integrity-report/admission-integrity-report.json
  - admission-verdict/admission-verdict.json

Missing evidence is reported as FAIL, never raised as an exception: a replay
that cannot inspect the evidence must not be able to look successful.

Independently recomputes:
  1. SHA-256 of proposals.json
  2. canonicalProjectionHash(ax_proof_state.json) for both legs A and B
     (per src/core/utils/canonical_projection.nim: stripVolatile + sorted JSON + SHA-256;
     floats are serialized like the engine — plain decimal expansion, e.g.
     0.000001 where Python's repr would emit 1e-06)
  3. all 7 admission guards (SUBJECT_IDENTITY, INPUT_EQUALITY, DETERMINISM,
     EVIDENCE_NON_VACUITY, ZERO_FOOTPRINT, ENVIRONMENT_EQUALITY,
     EVIDENCE_COHERENCE) and compares each status with the workflow's report
  4. green admission: exit 0 is admitted only when either the engine proved
     (verified>0, verificationComplete, verdict in CONTINUE/PROVED, gate != FAIL)
     or the declared law-conformance conjuncts hold at candidate tier

Additional admission-semantic checks, each reported independently as
PASS / FAIL / NOT_APPLICABLE:
  5. carrier coverage — state.declaredRequired (adopted claim) resolved against
     vault-manifest entries (modulePath + functionName); wave-facing renames are
     resolved by module-qualified match, not by trusting the engine's label
  6. A/B symmetry of checks 4-5 across legs A and B
  7. admission verdict consistency — admission-verdict.json against the
     independently recomputed classification and guard statuses

Local only — no network writes. `ax report --canonical-digest` is never
invoked (known non-determinism); every digest is recomputed in Python.

Output: human-readable summary per run plus a final "RESULT: PASS|FAIL" line.
RESULT: PASS means the recorded verdict (green or red) was reproduced from the
evidence; it does not mean the subject software passed.
Exit status: 0 iff every run reports RESULT: PASS.
"""
import hashlib
import json
import os
import re
import sys
from decimal import Decimal

HEX64 = re.compile(r"^[0-9a-f]{64}$")
VS_PAT = re.compile(r"(?P<v>n/a|[^/\s]+)/(?P<gv>n/a|[^/\s]+)/(?P<pv>n/a|[^/\s]+)", re.IGNORECASE)
TOOLCHAIN_KEYS = ("nim", "z3", "lean", "libpcre3")

VOLATILE_KEYS = {
    "timestamp",
    "startedAtMs", "endedAtMs", "elapsedMs", "solverElapsedMs",
    "parallelOverheadMs", "activeNodeCount", "availableMemoryBytes",
    "cpuLoadRatio", "recommendedWorkerCount",
    "totalWallTimeMs", "hotspotElapsedMs", "hotspotLabel",
    "runId", "generatedAt", "processId",
    "timedOut", "timeout", "timeoutCount", "timeoutNodes", "timeoutImpactNodes",
    "timeoutHotspots", "timeoutComplexityWeight", "wallElapsedMs",
    "vaultPath", "tmpPath", "absolutePath", "path", "sourcePath",
    "subjectRoot", "stateRoot", "repoRoot",
    "cacheHit", "cacheHitCount",
    "evidenceLogJson",
    "topologyScore", "complexityScore",
    "runtimeMeta",
}

FALLBACK_CARRIERS = ["bvSliceLenActual", "bvSliceLenControl"]
STRONG_CERT_STATUSES = ("certGreen", "certLeanVerified")
# Contract v1.1.0 §2.7: law-conformance evidence may be candidate-tier.
LAW_CONFORMANCE_STATUSES = ("certZ3Candidate", "certGreen", "certLeanVerified")
LEGS = ("A", "B")
EXPECTED_SUBJECT_REPO = "Archright/nim-libp2p"


def strip_volatile(n):
    if isinstance(n, dict):
        return {k: strip_volatile(v) for k, v in n.items() if k not in VOLATILE_KEYS}
    if isinstance(n, list):
        return [strip_volatile(v) for v in n]
    return n

def format_float_like_engine(f):
    # Nim's engine serializer (src/core/utils/canonical_projection.nim sortedCanonicalJson)
    # emits plain decimal expansions (e.g. 0.000001) where Python's repr switches to
    # exponent notation (1e-06). Reformat exponent forms to plain decimals so the
    # independent recomputation matches the engine's canonical form.
    r = repr(f)
    if "e" in r or "E" in r:
        return format(Decimal(r), "f")
    return r

def sorted_canonical_json(n):
    # Mirrors sortedCanonicalJson: object members in sorted key order, no spaces.
    if isinstance(n, bool):
        return "true" if n else "false"
    if n is None:
        return "null"
    if isinstance(n, int):
        return str(n)
    if isinstance(n, float):
        return format_float_like_engine(n)
    if isinstance(n, str):
        return json.dumps(n, ensure_ascii=False)
    if isinstance(n, list):
        return "[" + ",".join(sorted_canonical_json(v) for v in n) + "]"
    if isinstance(n, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + sorted_canonical_json(v)
            for k, v in sorted(n.items())
        ) + "}"
    raise TypeError(f"unserializable value {n!r}")

def canonical_projection_hash(state_obj):
    return hashlib.sha256(
        sorted_canonical_json(strip_volatile(state_obj)).encode("utf-8")
    ).hexdigest()


def load_json_optional(path):
    """Return (doc, error). Never raises: missing evidence is a finding."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except (OSError, ValueError) as exc:
        return None, f"{os.path.basename(path)}: {exc.__class__.__name__}"

def read_text_optional(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip(), None
    except OSError as exc:
        return "", f"{os.path.basename(path)}: {exc.__class__.__name__}"

def prove_exit_for_leg(report, leg):
    if not isinstance(report, dict):
        return None
    pe = report.get("prove_exit")
    if isinstance(pe, dict):
        return pe.get(leg)
    if isinstance(pe, int):
        return pe
    return None

def is_continue_proved_verdict(verdict):
    if not isinstance(verdict, str):
        return False
    v = verdict.strip().upper()
    return v.startswith("CONTINUE") or v.startswith("PROVED")

def is_strong_cert_status(status):
    return isinstance(status, str) and status.startswith(STRONG_CERT_STATUSES)


def declared_required(state):
    if not isinstance(state, dict):
        return []
    out = state.get("declaredRequired")
    if isinstance(out, list) and out:
        return [str(x) for x in out]
    census = state.get("census") or {}
    out = census.get("declaredRequired")
    return [str(x) for x in out] if isinstance(out, list) else []

def vault_entries(leg_dir):
    doc, err = load_json_optional(os.path.join(leg_dir, "vault-manifest.json"))
    if not isinstance(doc, dict):
        return [], err
    return [e for e in (doc.get("entries") or []) if isinstance(e, dict)], None

def match_vault_entry(declared, entries):
    """Resolve a declared obligation against vault entries.

    Accepts both "function" and "module/path.nim::function" forms. A
    module-qualified declaration must match on both module path suffix and
    function name, so a wave-facing rename cannot be mistaken for coverage.
    """
    if "::" in declared:
        module, fn = declared.split("::", 1)
        module = module.strip()
        fn = fn.strip()
        for e in entries:
            if not isinstance(e.get("functionName"), str):
                continue
            entry_mod = str(e.get("modulePath") or "").strip()
            if e["functionName"] != fn:
                continue
            if entry_mod == module or entry_mod.endswith("/" + module) or module.endswith("/" + entry_mod):
                return e
        return None
    for e in entries:
        if e.get("functionName") == declared:
            return e
    return None

def resolve_declared_carriers(state, run_dir):
    """Adopted obligations first, then a spec overlay copy, then the constant list."""
    required = declared_required(state)
    if required:
        return required, "state.declaredRequired (adopted claim)"
    for root, dirs, files in os.walk(run_dir):
        dirs.sort()
        for fn in sorted(files):
            if not fn.endswith(".json"):
                continue
            doc, _ = load_json_optional(os.path.join(root, fn))
            if not (isinstance(doc, dict) and isinstance(doc.get("carriers"), list)):
                continue
            names = [c.get("name") for c in doc["carriers"]
                     if isinstance(c, dict) and isinstance(c.get("name"), str)]
            if names:
                return names, f"spec overlay copy {os.path.relpath(os.path.join(root, fn), run_dir)}"
    return list(FALLBACK_CARRIERS), f"FALLBACK constant {FALLBACK_CARRIERS}"


def recompute_guards(run_dir, prop_sha256, prop_doc, rec, state, cd_txt, report, verdict_doc, declared):
    """Recompute the 7 admission guards from evidence alone.

    Returns (status_by_guard, detail_by_guard, digests).
    """
    details = {g: [] for g in (
        "SUBJECT_IDENTITY", "INPUT_EQUALITY", "DETERMINISM", "EVIDENCE_NON_VACUITY",
        "ZERO_FOOTPRINT", "ENVIRONMENT_EQUALITY", "EVIDENCE_COHERENCE")}

    def recv(leg, key):
        return (rec.get(leg) or {}).get(key)

    # SUBJECT_IDENTITY — every artifact names the same subject and PR.
    subject_commits = {
        "A": recv("A", "subject_commit"),
        "B": recv("B", "subject_commit"),
        "proposals": ((prop_doc or {}).get("subject") or {}).get("commit"),
        "report": ((report or {}).get("subject") or {}).get("commit"),
        "verdict": (verdict_doc or {}).get("subject_commit"),
    }
    repos = {recv("A", "subject_repository"), recv("B", "subject_repository"),
             ((prop_doc or {}).get("subject") or {}).get("repository")}
    if len(set(subject_commits.values())) != 1 or not all(subject_commits.values()):
        details["SUBJECT_IDENTITY"].append(f"subject commit disagreement: {subject_commits}")
    if set(repos) != {EXPECTED_SUBJECT_REPO}:
        details["SUBJECT_IDENTITY"].append(f"subject repository disagreement: {sorted(str(r) for r in repos)}")
    pr = (verdict_doc or {}).get("pr") or {}
    rpr = (report or {}).get("pr") or {}
    if pr and rpr and pr != rpr:
        details["SUBJECT_IDENTITY"].append(f"PR identity disagreement: verdict={pr} report={rpr}")
    if not (pr.get("head_sha") and pr.get("base_sha")):
        details["SUBJECT_IDENTITY"].append("PR head/base sha missing from verdict")

    # INPUT_EQUALITY — one input digest everywhere.
    input_shas = {
        "file": prop_sha256,
        "report": (report or {}).get("propositions_sha256"),
        "A": recv("A", "proposals_sha256"),
        "B": recv("B", "proposals_sha256"),
        "verdict": (verdict_doc or {}).get("propositions_sha256"),
    }
    if len(set(input_shas.values())) != 1 or not HEX64.fullmatch(str(prop_sha256)):
        details["INPUT_EQUALITY"].append(f"propositions digest disagreement: {input_shas}")

    # DETERMINISM — both legs report one 64-hex canonical digest.
    digests = {"A": "", "B": ""}
    reported = ((verdict_doc or {}).get("canonical_digest") or {})
    for leg in LEGS:
        rec_digest = recv(leg, "canonical_digest") or ""
        txt_digest = cd_txt.get(leg, "")
        digests[leg] = rec_digest
        if not HEX64.fullmatch(str(rec_digest)):
            details["DETERMINISM"].append(f"leg {leg}: canonical_digest {rec_digest!r} is not 64-hex")
        if txt_digest and txt_digest != rec_digest:
            details["DETERMINISM"].append(f"leg {leg}: canonical-digest.txt {txt_digest!r} != record {rec_digest!r}")
        if reported.get(leg) and reported.get(leg) != rec_digest:
            details["DETERMINISM"].append(f"leg {leg}: verdict digest {reported.get(leg)!r} != record {rec_digest!r}")
    if digests["A"] and digests["B"] and digests["A"] != digests["B"]:
        details["DETERMINISM"].append(f"A/B digest mismatch: {digests['A']} != {digests['B']}")

    # EVIDENCE_NON_VACUITY — an admissible exit code and a non-empty verdict.
    build_ids = set()
    for leg in LEGS:
        pe = prove_exit_for_leg(report, leg)
        vs = recv(leg, "verdict_summary") or ""
        bid = recv(leg, "engine_build_id") or ""
        build_ids.add(bid)
        if pe not in (0, 1, 3):
            details["EVIDENCE_NON_VACUITY"].append(f"leg {leg}: prove_exit {pe!r} is not one of 0/1/3")
        if not vs:
            details["EVIDENCE_NON_VACUITY"].append(f"leg {leg}: verdict_summary is missing or empty")
        else:
            m = VS_PAT.fullmatch(vs.strip())
            if not m or m.group("v").lower() == "n/a" or m.group("gv").lower() == "n/a":
                details["EVIDENCE_NON_VACUITY"].append(f"leg {leg}: vacuous verdict_summary {vs!r}")
        if not HEX64.fullmatch(str(bid)):
            details["EVIDENCE_NON_VACUITY"].append(f"leg {leg}: engine_build_id {bid!r} is not 64-hex")
    if len(build_ids) != 1:
        details["EVIDENCE_NON_VACUITY"].append(f"engine build id disagreement across legs: {sorted(build_ids)}")

    # ZERO_FOOTPRINT — the subject tree hash is unchanged.
    for leg in LEGS:
        zf = recv(leg, "zero_footprint_ok")
        pre, post = recv(leg, "pre_tree_hash"), recv(leg, "post_tree_hash")
        if str(zf).lower() != "true":
            details["ZERO_FOOTPRINT"].append(f"leg {leg}: zero_footprint_ok={zf!r}")
        if not pre or pre != post:
            details["ZERO_FOOTPRINT"].append(f"leg {leg}: tree hash changed {pre!r} -> {post!r}")

    # ENVIRONMENT_EQUALITY — same runner family, bundle, and toolchain.
    ra, rb = rec.get("A") or {}, rec.get("B") or {}
    if str(ra.get("runner_image", "")).split("/")[0] != str(rb.get("runner_image", "")).split("/")[0]:
        details["ENVIRONMENT_EQUALITY"].append(
            f"runner image family differs: {ra.get('runner_image')!r} vs {rb.get('runner_image')!r}")
    if ra.get("bundle_sha256") != rb.get("bundle_sha256"):
        details["ENVIRONMENT_EQUALITY"].append("bundle sha differs across legs")
    for key in TOOLCHAIN_KEYS:
        ta = (ra.get("toolchain") or {}).get(key)
        tb = (rb.get("toolchain") or {}).get(key)
        if ta != tb or ta is None:
            details["ENVIRONMENT_EQUALITY"].append(f"toolchain {key} differs: {ta!r} vs {tb!r}")

    # EVIDENCE_COHERENCE — every adopted obligation is covered by the vault,
    # and both legs recorded the same vault entry set.
    status_sets = {}
    vault_findings = {"A": [], "B": []}
    for leg, state_leg in (("A", state), ("B", state)):
        entries, err = vault_entries(os.path.join(run_dir, f"ax-verify-evidence-propositions-{leg}"))
        if err:
            details["EVIDENCE_COHERENCE"].append(f"leg {leg}: {err}")
            vault_findings[leg].append(err)
            continue
        status_sets[leg] = sorted((str(e.get("modulePath") or ""), str(e.get("functionName") or ""), str(e.get("status") or ""))
                                  for e in entries)
        for obligation in declared:
            entry = match_vault_entry(obligation, entries)
            if entry is None:
                vault_findings[leg].append(f"{obligation}: no vault entry")
                details["EVIDENCE_COHERENCE"].append(f"leg {leg}: adopted obligation {obligation!r} has no vault entry")
            elif entry.get("status") not in LAW_CONFORMANCE_STATUSES:
                vault_findings[leg].append(f"{obligation}: status {entry.get('status')!r}")
                details["EVIDENCE_COHERENCE"].append(
                    f"leg {leg}: {obligation!r} vault status {entry.get('status')!r} is not in {LAW_CONFORMANCE_STATUSES}")
    if len(status_sets) == 2 and status_sets["A"] != status_sets["B"]:
        details["EVIDENCE_COHERENCE"].append("A/B vault entry sets differ")

    status = {g: ("FAIL" if v else "PASS") for g, v in details.items()}
    return status, details, digests, vault_findings


def decide_green_admission(state, prove_exit, verdict_doc, declared, run_dir):
    """Independently decide whether an exit-0 observation is admissible."""
    if prove_exit != 0:
        return "NOT_APPLICABLE", f"prove_exit={prove_exit!r} (not a green exit)"
    summary = (state or {}).get("summary") or {}
    outcome = (state or {}).get("runOutcome") or {}
    census = (state or {}).get("census") or {}
    proved = (
        isinstance(summary.get("verified"), int) and summary.get("verified") > 0
        and outcome.get("verificationComplete") is True
        and is_continue_proved_verdict(outcome.get("verdict"))
        and str(outcome.get("gateVerdict") or "").upper() != "FAIL"
    )
    if proved:
        return "PROVED_REPRODUCIBLE", "engine verified >=1 obligation with a complete verdict"
    if (verdict_doc or {}).get("acceptance_class") != "law-conformance":
        return "VACUOUS_BLOCKED", "exit 0 without a proof and without a declared law-conformance class"
    failures = []
    if not declared:
        failures.append("declaredRequired is empty")
    if not isinstance(census.get("proofCandidateCount"), int) or census.get("proofCandidateCount") < 1:
        failures.append(f"proofCandidateCount={census.get('proofCandidateCount')!r} < 1")
    if not isinstance(census.get("obligationCount"), int) or census.get("obligationCount") < 1:
        failures.append(f"obligationCount={census.get('obligationCount')!r} < 1")
    if str(outcome.get("verdict") or "").upper() == "FAIL":
        failures.append(f"runOutcome.verdict={outcome.get('verdict')!r}")
    for obligation in declared:
        entry = match_vault_entry(obligation, vault_entries(os.path.join(run_dir, "ax-verify-evidence-propositions-A"))[0])
        if entry is None:
            failures.append(f"{obligation}: absent from leg A vault")
        elif entry.get("status") not in LAW_CONFORMANCE_STATUSES:
            failures.append(f"{obligation}: vault status {entry.get('status')!r} not in {LAW_CONFORMANCE_STATUSES}")
    if failures:
        return "VACUOUS_BLOCKED", "law-conformance conjunct(s) failed: " + "; ".join(failures)
    return "LAW_CONFORMANCE_ACCEPTED_REPRODUCIBLE", (
        "law-conformance conjuncts hold at candidate tier "
        f"(obligations={declared}, proofCandidateCount={census.get('proofCandidateCount')}, "
        f"obligationCount={census.get('obligationCount')}) — NOT a formal PROVED verdict"
    )


def classify_non_green(report, state, declared, run_dir):
    """Mirror the contract's non-green rows (DISPROVED / REFUSAL / UNCLASSIFIED)."""
    pe = prove_exit_for_leg(report, "A")
    if pe == 1:
        entries = vault_entries(os.path.join(run_dir, "ax-verify-evidence-propositions-A"))[0]
        for obligation in declared:
            entry = match_vault_entry(obligation, entries)
            if entry is not None and entry.get("status") == "certRed":
                return "DISPROVED_REPRODUCIBLE"
        return "FAILED_NO_DISPROOF"
    if pe == 3:
        return "REFUSAL_REPRODUCIBLE"
    return "UNCLASSIFIED"


def check_admission_verdict(verdict_doc, decision, recomputed_class, guard_status, guard_report, replay_failures):
    """Compare the workflow's verdict with the independent recomputation."""
    if not isinstance(verdict_doc, dict):
        return "FAIL", "admission-verdict.json missing or unreadable"
    problems = []
    sv = str(verdict_doc.get("subject_verdict") or "").strip().upper()
    green = decision in ("PROVED_REPRODUCIBLE", "LAW_CONFORMANCE_ACCEPTED_REPRODUCIBLE")
    expected_sv = "PASS" if green else "FAIL"
    if sv != expected_sv:
        problems.append(f"subject_verdict={sv!r} but recomputed decision {recomputed_class!r} implies {expected_sv!r}")
    if (verdict_doc.get("classification") or "") != recomputed_class:
        problems.append(f"classification={verdict_doc.get('classification')!r} but recomputed {recomputed_class!r}")
    reported = guard_report or {}
    for guard, status in guard_status.items():
        rep = (reported.get(guard) or {}).get("status")
        if rep != status:
            problems.append(f"guard {guard}: workflow reported {rep!r}, recomputed {status!r}")
    if replay_failures and expected_sv == "PASS":
        problems.append("replay could not reproduce the evidence but the workflow claims PASS")
    if problems:
        return "FAIL", "; ".join(problems)
    return "PASS", "workflow verdict and guard statuses agree with the independent recomputation"


def aggregate(status_a, status_b):
    statuses = {status_a, status_b}
    if "FAIL" in statuses:
        return "FAIL"
    if statuses == {"NOT_APPLICABLE"}:
        return "NOT_APPLICABLE"
    return "PASS"


def replay_run(run_dir):
    missing = []
    prop_path = os.path.join(run_dir, "propositions", "proposals.json")
    try:
        with open(prop_path, "rb") as f:
            prop_bytes = f.read()
        prop_sha256 = hashlib.sha256(prop_bytes).hexdigest()
        prop_doc = json.loads(prop_bytes.decode("utf-8"))
    except (OSError, ValueError) as exc:
        missing.append(f"propositions/proposals.json: {exc.__class__.__name__}")
        prop_sha256 = ""
        prop_doc = {}

    rec, state, cd_txt = {}, {}, {}
    state_missing = {"A": [], "B": []}
    for leg in LEGS:
        leg_dir = os.path.join(run_dir, f"ax-verify-evidence-propositions-{leg}")
        rec[leg], err = load_json_optional(os.path.join(leg_dir, "verify-record.json"))
        if err:
            missing.append(f"leg {leg}: {err}")
            rec[leg] = {}
        state[leg], err = load_json_optional(os.path.join(leg_dir, "ax_proof_state.json"))
        if err:
            state_missing[leg].append(err)
            state[leg] = {}
        cd_txt[leg], err = read_text_optional(os.path.join(leg_dir, "canonical-digest.txt"))
        if err:
            state_missing[leg].append(err)

    report, err = load_json_optional(os.path.join(run_dir, "admission-integrity-report", "admission-integrity-report.json"))
    if err:
        missing.append(err)
        report = {}
    verdict_doc, err = load_json_optional(os.path.join(run_dir, "admission-verdict", "admission-verdict.json"))
    if err:
        missing.append(err)
        verdict_doc = {}

    declared, carrier_source = resolve_declared_carriers(state["A"] or state["B"], run_dir)
    guard_status, guard_detail, digests, vault_findings = recompute_guards(
        run_dir, prop_sha256, prop_doc, rec, state["A"], cd_txt, report, verdict_doc, declared)

    recomputed, replay_failures = {}, list(missing)
    green_legs = {"A": prove_exit_for_leg(report, "A") == 0, "B": prove_exit_for_leg(report, "B") == 0}
    for leg in LEGS:
        # A non-green exit writes no digest/state by design; absence is only a
        # replay failure when the leg claims green.
        if green_legs[leg] and state_missing[leg]:
            replay_failures.extend(f"leg {leg}: {err}" for err in state_missing[leg])
        if state[leg]:
            recomputed[leg] = canonical_projection_hash(state[leg])
            if recomputed[leg] != digests.get(leg):
                replay_failures.append(
                    f"leg {leg}: recomputed digest {recomputed[leg]} != recorded {digests.get(leg)!r}")
    if len(recomputed) == 2 and recomputed["A"] != recomputed["B"]:
        replay_failures.append(f"A/B recomputed digest mismatch: {recomputed['A']} != {recomputed['B']}")

    decision_a, note_a = decide_green_admission(state["A"], prove_exit_for_leg(report, "A"), verdict_doc, declared, run_dir)
    decision_b, note_b = decide_green_admission(state["B"], prove_exit_for_leg(report, "B"), verdict_doc, declared, run_dir)
    green_status = aggregate(
        "NOT_APPLICABLE" if decision_a == "NOT_APPLICABLE" else ("PASS" if decision_a != "VACUOUS_BLOCKED" else "FAIL"),
        "NOT_APPLICABLE" if decision_b == "NOT_APPLICABLE" else ("PASS" if decision_b != "VACUOUS_BLOCKED" else "FAIL"),
    )
    claimed_green = decision_a != "NOT_APPLICABLE" or decision_b != "NOT_APPLICABLE"
    coverage_status = guard_status["EVIDENCE_COHERENCE"] if claimed_green else "NOT_APPLICABLE"

    recomputed_class = decision_a if decision_a != "NOT_APPLICABLE" else classify_non_green(
        report, state["A"], declared, run_dir)

    sym_fields = (
        ("prove_exit", prove_exit_for_leg(report, "A"), prove_exit_for_leg(report, "B")),
        ("green decision", decision_a, decision_b),
        ("canonical digest", digests["A"], digests["B"]),
        ("vault coverage violations", vault_findings["A"], vault_findings["B"]),
    )
    sym_diffs = [f"{label}: leg A={a!r} vs leg B={b!r}" for label, a, b in sym_fields if a != b]
    sym_status = "FAIL" if sym_diffs else "PASS"

    check4_status, check4_reason = check_admission_verdict(
        verdict_doc, decision_a, recomputed_class, guard_status, (report or {}).get("guards"), replay_failures)

    failed = sorted(name for name, st in (
        ("green_admission", green_status), ("carrier_coverage", coverage_status),
        ("ab_symmetry", sym_status), ("guard_agreement", check4_status)) if st == "FAIL")
    if replay_failures:
        failed.append("canonical_replay")
    run_ok = not failed

    print("=" * 72)
    print(f"RUN {os.path.basename(os.path.normpath(run_dir))}  ({run_dir})")
    print("=" * 72)
    print("[REPLAY] proposals SHA-256 + canonical digest (independent recomputation)")
    print(f"  subject_commit:               {(prop_doc.get('subject') or {}).get('commit', '<missing>')}")
    print(f"  propositions_sha256:          {prop_sha256 or '<missing>'}")
    print(f"  prove_exit:                   {{'A': {prove_exit_for_leg(report, 'A')!r}, 'B': {prove_exit_for_leg(report, 'B')!r}}}")
    print(f"  recomputed_canonical_digest_A: {recomputed.get('A', '<not recomputable>')}")
    print(f"  recomputed_canonical_digest_B: {recomputed.get('B', '<not recomputable>')}")
    print(f"  A/B digest equality:          {'OK' if digests['A'] and digests['A'] == digests['B'] else 'MISMATCH/MISSING'}")
    print(f"  workflow integrity:           {(report or {}).get('integrity', '<missing>')}")
    print(f"  workflow classification:      {(verdict_doc or {}).get('classification', '<missing>')}")
    print(f"  recomputed classification:    {recomputed_class}")
    print()

    print(f"[CHECK 1] green admission (acceptance class recomputed): {green_status}")
    print(f"  leg A: {decision_a} — {note_a}")
    print(f"  leg B: {decision_b} — {note_b}")
    print()

    print(f"[CHECK 2] adopted-obligation coverage in vault: {coverage_status}")
    print(f"  declared source: {carrier_source}")
    for obligation in declared:
        entry = match_vault_entry(obligation, vault_entries(os.path.join(run_dir, "ax-verify-evidence-propositions-A"))[0])
        if entry is None:
            print(f"    {obligation}: NOT in leg A vault")
        else:
            note = "" if entry.get("status") in STRONG_CERT_STATUSES else "  (candidate tier — not formally verified)"
            print(f"    {obligation}: in leg A vault, status={entry.get('status')!r}{note}")
    if guard_detail["EVIDENCE_COHERENCE"]:
        for line in guard_detail["EVIDENCE_COHERENCE"]:
            print(f"    violation: {line}")
    print()

    print(f"[REPLAY] 7 guards recomputed from evidence")
    for guard in ("SUBJECT_IDENTITY", "INPUT_EQUALITY", "DETERMINISM", "EVIDENCE_NON_VACUITY",
                  "ZERO_FOOTPRINT", "ENVIRONMENT_EQUALITY", "EVIDENCE_COHERENCE"):
        reported = ((report or {}).get("guards") or {}).get(guard, {}).get("status", "<missing>")
        agree = "agree" if reported == guard_status[guard] else f"DISAGREE (workflow {reported})"
        print(f"  {guard:<22} {guard_status[guard]:<5} {agree}")
        for line in guard_detail[guard][:3]:
            print(f"      {line}")
    print()

    print(f"[CHECK 3] A/B symmetry: {sym_status}")
    for diff in sym_diffs:
        print(f"  asymmetry: {diff}")
    if not sym_diffs:
        print("  legs agree on prove_exit, green decision, digest, and vault coverage")
    print()

    print(f"[CHECK 4] workflow verdict vs independent recomputation: {check4_status}")
    print(f"  {check4_reason}")
    print()
    if replay_failures:
        print("[REPLAY] evidence not fully reproducible:")
        for line in replay_failures:
            print(f"  - {line}")
        print()
    if run_ok:
        print(f"RESULT: PASS — replay reproduced the recorded verdict ({verdict_doc.get('subject_verdict')})")
    else:
        print(f"RESULT: FAIL — failed check(s): {', '.join(failed)}")
    print()
    return run_ok


def main(argv):
    if not argv:
        print(f"usage: {os.path.basename(sys.argv[0])} <run_dir> [<run_dir> ...]", file=sys.stderr)
        return 2
    all_ok = True
    for run_dir in argv:
        try:
            all_ok = replay_run(run_dir) and all_ok
        except Exception as exc:
            print("=" * 72)
            print(f"RUN {os.path.basename(os.path.normpath(run_dir))}  ({run_dir})")
            print("=" * 72)
            print(f"RESULT: FAIL — replay error: {exc!r}")
            print()
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))