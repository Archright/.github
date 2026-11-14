# PR Admission Contract — Archright/nim-libp2p

## 0. 서두

이 문서는 Archright/nim-libp2p PR에 대해 Axiom 검증 결과를 병합 허가(merge admission)에 결속하는 시스템의 **보안·실행 신뢰(제1장) · 판정 의미(제2장) · 병합 권한과 복구(제3장)** 계약을 규정한다.

| 항목 | 값 |
|---|---|
| 문서 버전 | v1.1.0 (2026-11-14) — v1.0.0 개정 |
| 정본 위치 (SSOT) | `Archright/.github` `.github/axiom-admission/PR_ADMISSION_CONTRACT.md` — **신뢰 저장소** |
| 비정본 사본 | `Archright/nim-libp2p` `.github/axiom-admission/PR_ADMISSION_CONTRACT.md` (v1.0.0, 역사 기록) |
| 대상 저장소 | `Archright/nim-libp2p` |
| 대상 브랜치 | 실험 `refs/heads/axiom-admission-probe` → 운영 `refs/heads/master` (제3장 §3.2) |
| 규정 대상 시스템 | ruleset이 실행하는 신뢰 워크플로 기반 PR Admission 게이트 (제1장 §1.2) |
| 채택 명제 집합 | 인간 채택 명제 — 1건 (제2장 §2.5) |
| 관측값 규칙 | 확정 실측값만 기입. 실행 시점 관측값은 «실행 시 채워짐»으로 표기하고 증거 문서에 원문 기록 (제3장 §3.6) |

### 0.1 이 계약이 규정하지 않는 것

- **정식 캠페인 계약은 이 문서의 규정 대상이 아니다.** `campaign-001.json`과 `axiom-verification.yml`은 이 계약과 무관하게 불변이며, 이 문서는 그 어느 것도 수정하지 않는다.
- Discovery(라이브 AI 발견)는 `workflow_dispatch` 전용이며 이 게이트 경로에 없다.

### 0.2 v1.1.0 개정 사유 (Fact)

v1.0.0 §2.3은 `exit 0`을 `PROVED_REPRODUCIBLE`로 매핑하면서, 같은 절의 불변식에 “exit 0은 전명제 증명이 아니다”라고 적었다 — **계약 내부 모순**. 실측(run `43547635750`, PR #11)에서 엔진 상태는 `summary.verified=0`, `runOutcome.verdict=INCONCLUSIVE`, `gateVerdict=FAIL`이었고, 같은 런의 spec 계약 §6은 이 결과를 적법한 **law-conformance 수용**으로 정의한다. 즉 증거는 유효하지만 라벨이 상위 주장이었다.

v1.1.0은 **라벨을 증거 등급에 결속**한다: `PROVED_REPRODUCIBLE`은 캠페인 계약 §2의 3개 조건을 모두 만족할 때만 쓰고, 그 외의 적법한 spec 수용은 별도 클래스로 기록한다.

---

## 제1장 Security & Execution Trust

### 1.1 검증 대상 신원 (Subject Identity)

**Authority**: 검증 대상 SHA의 단일 권위는 `github.sha`다.

| # | Invariant |
|---|---|
| I1 | 대상 신원은 `github.sha` 단일 권위로 결정된다. head SHA fallback은 금지한다. |
| I2 | `github.sha`가 40-hex가 아니거나 `head.sha`·`base.sha`와 같으면 **거절**한다 (합성 merge commit이 아님). |
| I3 | `pull_request.merge_commit_sha`는 synchronize 웹훅에서 stale할 수 있으므로 신원 권위로 쓰지 않는다. |
| I4 | merge conflict 상태의 PR은 워크플로 실행 자체가 불가능하다 → 체크 pending → 병합 불가 (플랫폼 수준 fail-closed). |

### 1.2 신뢰 사슬 (Chain of Trust)

| 단계 | 결속 | 관측값 |
|---|---|---|
| 1 | ruleset — 워크플로 신원 = repository_id `1182157951` (Archright/.github) + path `.github/workflows/nim-libp2p-pr-admission.yml` + 40-hex SHA | probes `27205573` · master `27208234` («실행 시 갱신») |
| 2 | 신뢰 워크플로 — 잡 구조(§1.5), 대상 신원(§1.1), 채택 명제(§2.5), 판정(§2.3) | 워크플로 SHA |
| 3 | 어댑터 — `Archright/axiom-cli/.github/workflows/ax-verify.yml@4ca1892a69abcdb9036ec8a69d7bcedc940507d1` | 확정 |
| 4 | 모든 `uses:` — 40-hex commit SHA 핀만 허용 (태그 핀 금지) | 워크플로 원문 |
| 5 | Axiom 릴리스 번들 — SHA256SUMS + manifest + attestation | `bundle_sha256` v0.6.4 `adc0d531…` |
| 6 | 도구체인 — Nim 2.2.10 / Z3 4.13.3 / Lean 4.33.0 | 확정 |
| 7 | 채택 명제 — `specId` + `acceptanceClass` + 명제 digest (§2.5, §2.7) | propositions sha256 |
| 8 | 대상 커밋 — §1.1의 단일 권위 | `github.sha` |

**Invariant T1**: 위 사슬의 어떤 고리도 PR 작성자가 수정할 수 없다. PR이 바꿀 수 있는 것은 검증 대상 커밋의 내용뿐이며, 그 변경은 곧 검증 대상이 된다.

**Invariant T2**: 상위 핀은 하위 의존성을 자동으로 고정하지 않는다 — 각 단계는 자기 `uses:`/다운로드를 40-hex 또는 sha256으로 고정한다.

### 1.3 권한 (Permissions & Zero-Footprint)

| 항목 | 계약 |
|---|---|
| 비밀키 | **0개** |
| 잡 권한 | `permissions: contents: read` 유일 |
| PR 코드의 지위 | 어댑터가 읽기 전용으로 checkout하는 **데이터** — 실행되지 않는다 |
| Zero-Footprint | `pre_tree_hash == post_tree_hash` + 작업 트리 오염 없음 (§2.2 ZERO_FOOTPRINT) |
| 저장소 가드 | 모든 잡에 `github.repository == 'Archright/nim-libp2p'` — 신뢰 워크플로 저장소 자체 PR에서 불활성 |

### 1.4 실행 제약 (Ruleset Workflow Execution Constraints)

| 제약 | 동작 | 귀결 |
|---|---|---|
| 트리거 | `pull_request` 기본 activity types(`opened`/`synchronize`/`reopened`) | 검증 트리거는 이 셋 |
| 필터 | `branches`/`paths`/`types` 필터 무시 | 모든 대상 PR이 전체 채택 명제 집합에 대해 검증됨 |
| 기존 PR | ruleset 생성 시점의 기존 PR은 자동 실행 없음 | 새 push/reopen으로 진입 |
| `GITHUB_TOKEN` 이벤트 | 후속 워크플로 미트리거 | 재귀 없음 |
| 직접 push | 차단 | `master` 변경은 PR 경유만 |
| 외부 fork PR | 실행 보장 없음 | **UNKNOWN** — 신뢰 주장 금지 |

### 1.5 잡 구조와 A/B 독립성

| 잡 | 책임 |
|---|---|
| `propositions` | 대상 신원(§1.1) + 채택 명제 결속(§2.5). AI 추론 없음. |
| `verify-a` / `verify-b` | **두 개의 별도 잡**으로 어댑터 실행. matrix를 쓰지 않는 이유: matrix reusable-workflow 출력은 마지막 성공 실행의 값으로 붕괴한다 — A/B는 독립 네임스페이스로 보존해야 한다. |
| `admission-integrity` | 7 불변식 검사 (§2.2) |
| `subject-verdict` | 판정 매핑 (§2.3) |

---

## 제2장 Subject Verdict Semantics

### 2.1 2축 분리

| 축 | 체크 | 질문 |
|---|---|---|
| 증거 무결성 | `admission-integrity` | 검증 파이프라인이 계약대로 실행됐는가 |
| 판정 | `subject-verdict` | 대상 소프트웨어가 채택 명제를 통과했는가 |

**Fact**: `DISPROVED_REPRODUCIBLE`은 무결성 PASS·판정 FAIL이다. 이 분리가 “검증 시스템의 성공”과 “소프트웨어의 합격”의 혼동을 차단한다.

**Invariant**: `subject-verdict`는 `admission-integrity`가 생산한 증거만 소비한다 — 자체 재판정 금지.

### 2.2 7 불변식 (`admission-integrity`)

| # | 불변식 | 조건 (모두 충족 시 PASS) |
|---|---|---|
| 1 | `SUBJECT_IDENTITY` | 선언된 대상 신원 == 양측 기록의 subject identity |
| 2 | `INPUT_EQUALITY` | 양측이 소비한 명제 문서의 sha256 동일 |
| 3 | `DETERMINISM` | 양측 `canonical_digest`가 실 64-hex이고 서로 동일 |
| 4 | `EVIDENCE_NON_VACUITY` | 기록 존재 · `verdict_summary` 유효 · `prove_exit` ∈ {0,1,3} |
| 5 | `ZERO_FOOTPRINT` | `pre_tree_hash == post_tree_hash` · 오염 없음 — 양측 |
| 6 | `ENVIRONMENT_EQUALITY` | 양측 runner OS family 동일 · 도구체인 4종 동일 · bundle/engine identity 동일 |
| 7 | `EVIDENCE_COHERENCE` | (a) A/B의 vault entry 집합 `(modulePath,functionName,status,solverMethod,irHash)` 동일 · (b) A/B의 `census`(`proofCandidates`,`obligationCount`,`candidateCount`) 동일 · (c) `declaredRequired`의 모든 unitId가 vault `functionName` 집합에 존재 |

**Failure**: 어느 하나라도 위반하면 `admission-integrity` = FAIL이며 `subject-verdict` FAIL의 전제가 된다.

**Note**: 이 7 불변식은 정식 캠페인의 5가드와 **동일하지 않고 PR Admission 전용 정의**다. 이름이 유사한 검사가 동일하다고 주장하지 않는다.

### 2.3 판정 매핑 (`subject-verdict`)

`acceptanceClass`는 **신뢰된 워크플로의 채택 테이블**(propositions job의 `ACCEPTANCE_CLASS` 상수)에 선언되며, 채택 시 인간이 고정한다(§2.7). 이 값은 엔진이 소비하는 `proposals.json`에 주입되지 않는다 — 엔진 입력 계약·스키마·`propositions_sha256` 의미를 변경하지 않기 위해서다. 분류는 **엔진이 영속한 증거 파일**(`ax_proof_state.json`, `vault-manifest.json`)을 입력으로 한다 — exit code 단독 판정은 금지한다.

| 조건 | 클래스 | `subject-verdict` | 기록 의무 |
|---|---|---|---|
| exit 0 · `acceptanceClass="proof"` · `verified>0` · `verificationComplete=true` · `verdict≠FAIL` · `gateVerdict≠FAIL` · 각 명제 `verdict≠DISPROVED` | `PROVED_REPRODUCIBLE` | **PASS** | 명제별 증명 기록 |
| exit 0 · `acceptanceClass="law-conformance"` · `verdict="INCONCLUSIVE"` · `declaredRequired≠∅` · 각 `declaredRequired`가 vault에 존재하고 status ∈ {`certZ3Candidate`,`certGreen`,`certLeanVerified`} · `proofCandidateCount≥1` · `obligationCount≥1` | `LAW_CONFORMANCE_ACCEPTED_REPRODUCIBLE` | **PASS** | `evidenceTier=candidate`, “형식적 PROVED 아님” 명시 |
| exit 0 · 위 두 조건 불충족 | `VACUOUS_BLOCKED` | **FAIL** | 부족한 증거 필드 명시 |
| exit 1 · `failedCount>0` · `declaredRequired` 중 ≥1이 vault `certRed` | `DISPROVED_REPRODUCIBLE` | **FAIL** | 반례 + 대상 SHA |
| exit 1 · 위 조건 불충족 | `FAILED_NO_DISPROOF` | **FAIL** | 관측값 명시 |
| exit 3 · 거절 사유 재현 | `REFUSAL_REPRODUCIBLE` | **FAIL (NOT READY)** | 사유 원문 |
| A/B exit·digest 불일치, `EVIDENCE_COHERENCE` 위반, 증거 누락 | `CONTRADICTION` / `UNCLASSIFIED` | **FAIL** | 불일치 관측값 |

**Invariant V1**: `exit 0`은 “모든 명제 증명됨”이 아니다. `PROVED_REPRODUCIBLE`은 §2.3 1행의 **전 조건**이 성립할 때만 쓰며, 그 밖의 green은 `VACUOUS_BLOCKED`다 (캠페인 계약 §2의 `VACUOUS_BLOCKED` 정의와 동일 관측).

**Invariant V2**: `LAW_CONFORMANCE_ACCEPTED_REPRODUCIBLE`은 **보증 등급 한정 라벨**이다 — “선언된 모델·법칙 아래 반례가 없다”이지 “명제가 형식 증명됐다”가 아니다. 체크 요약은 이 문구를 포함해야 한다.

**Invariant V3**: `PROVED_REPRODUCIBLE`은 캠페인 계약의 3조건(`exit 0` ∧ `NOT_DISPROVED` ∧ `verified>0`)을 그대로 요구한다. 현재 제품에서 `NOT_DISPROVED`는 도달 불가이므로(직렬화 갭), 이 클래스는 **예약 상태**다 — 도달 불가를 우회하는 어떤 변형도 금지한다.

### 2.4 CAPABLE 최소 요건

| # | Invariant |
|---|---|
| C1 | 필수 채택 집합은 ≥1개의 CAPABLE 명제를 포함해야 한다. |
| C2 | 채택 집합이 비었거나 전원 INCAPABLE이면 PASS 금지. |
| C3 | INCAPABLE 명제는 채택 대상에서 제외된다. |
| C4 | INCAPABLE은 증거에 정직 기록된다 — 판정을 지어내지 않는다. |

### 2.5 채택 절차와 기록 (Adoption)

**Authority**: 새 명제의 채택은 인간의 행위다.

**절차**: 채택 시 `specId`·명제 id·target·명제 digest·`acceptanceClass`·근거 캠페인(런 ID·분류·canonical digest)을 기록하고 버전을 상향한다. AI 생성 후보는 채택 없이 게이트에 들어올 수 없다 — **발견 ≠ 권한**.

현재 채택 기록 (v1.1.0):

| 항목 | 값 |
|---|---|
| specId | `SPEC-LIBP2P-BV-SLICE` (ruleVersion 1.1.0) |
| 명제 id | `bytesview-toOpenArray-bv-slice` |
| target | `libp2p/utils/bytesview.nim::toOpenArray` |
| acceptanceClass | `law-conformance` — spec 계약 §6(v1.1.0) 수용 기준 (워크플로 채택 테이블 상수) |
| 근거 캠페인 | `external-verification-campaign-001` 런 `43363278211` (2026-11-13) |
| 근거 분류 | `DISPROVED_REPRODUCIBLE` (v1.0.0 pre-fix subject) |
| PR Admission evidence | v0.6.4, run `43547635750`, vault `toOpenArray`=`certZ3Candidate`/smCLI, A/B digest `f7209f17…` |
| 명제 문서 sha256 | «실행 시 채워짐» |

### 2.6 보증 범위 (Warranty Scope)

**Invariant W1**: 판정은 **채택 명제별 보증**이다. “master가 PROVED 기준선”이라는 표현은 채택 집합·등급에 한정된 표현이며 저장소 전체 동작의 증명이 아니다.

**Invariant W2**: `LAW_CONFORMANCE_ACCEPTED_REPRODUCIBLE`의 보증은 (a) 선언된 모델·법칙, (b) 고정된 subject blob pin, (c) 두 독립 실행의 일치, (d) Zero-Footprint에 한정된다. 원본 template body의 추출·검증, 또는 명제 밖 동작의 정당성은 주장하지 않는다.

**Failure**: 채택 집합 밖 결함의 부재는 이 게이트의 주장이 아니다.

### 2.7 수용 클래스 선언 (Acceptance Class Declaration)

| # | Invariant |
|---|---|
| A1 | `acceptanceClass`는 신뢰된 워크플로의 채택 테이블에 명시되며, PR마다 선택할 수 없다 — 변경은 계약 개정이다. 엔진 입력(`proposals.json`)에는 주입하지 않는다. |
| A2 | `law-conformance`는 **spec 계약이 그 등급의 수용 기준을 명문화한 경우에만** 선언할 수 있다. |
| A3 | 클래스와 증거가 불일치하면 `VACUOUS_BLOCKED`다 — 라벨을 증거에 맞추지, 증거를 라벨에 맞추지 않는다. |

### 2.8 PR 스모크 ≠ 정식 캠페인

| 구분 | PR Admission | 정식 캠페인 (불변) |
|---|---|---|
| run_mode | `pr_admission` | 캠페인 |
| 명제 출처 | 인간 채택 명제만 | BYO AI 발견 또는 pinned fixture |
| 검사 어휘 | 7 불변식 + 판정 매핑 | 5가드 + 캠페인 11클래스 |
| SSOT | 이 문서 | 캠페인 SSOT |

---

## 제3장 GitHub Merge Authority + 복구

### 3.1 권한 구조

**Authority**: 병합 허용/거부의 최종 권한은 GitHub다 — ruleset의 required workflows 규칙.

| # | Fact |
|---|---|
| A1 | 워크플로 신원은 repository + path + 40-hex SHA 결속이며 체크 이름 기반이 아니다 → 동명 체크 스푸핑 불가. |
| A2 | 별도 GitHub App은 불필요하다. |
| A3 | Axiom은 판정만 소유한다 — 병합 권한은 없다. |

### 3.2 적용 대상

| 단계 | 대상 ref | ruleset ID | 상태 |
|---|---|---|---|
| 실험 (probe) | `refs/heads/axiom-admission-probe` | `27205573` | active |
| 운영 (production) | `refs/heads/master` | `27208234` | active |

**Invariant**: enforcement는 active다 (evaluate 의존 금지 — 플랜 가용성 UNKNOWN).

### 3.3 병합 거부 수용 기준

거부의 수용은 다음 4요건 모두 충족이다:

| # | 요건 |
|---|---|
| R1 | 거부 사유가 required workflow/ruleset임 (응답 본문·UI 확인) |
| R2 | PR `merged == false` |
| R3 | master SHA 불변 (거부 전후 동일) |
| R4 | 동일 계정·동일 게이트에서 **통과 PR의 병합 성공** (양성 대조) |

**Fact**: HTTP 코드(403/405/409/422) 자체는 증거가 아니다.

### 3.4 복구 계약

| 항목 | 계약 |
|---|---|
| 사전 기록 | ruleset ID·이전 상태(enforcement·조건·워크플로 핀)를 `ops-2026-11-14/ruleset-*-before-v2.json`으로 보존 |
| 비활성화 경로 | `gh api -X PUT /repos/Archright/nim-libp2p/rulesets/<id>` (enforcement=disabled) 또는 org-admin UI |
| 비상 시 | 사유·audit 기록 보존 |
| probe 오작동 | master 적용 없이 즉시 `disabled` |

### 3.5 미래 확장

| 항목 | 계약 |
|---|---|
| merge queue 도입 | 워크플로에 `merge_group` 추가 — **계약 개정 선행** |
| 관리자 bypass | `bypass_actors` = ∅ (우회 없음) |

### 3.6 운영 부록

| 항목 | 규칙 |
|---|---|
| 관측 값 | 런 ID·ruleset ID·체크 이름·응답 본문은 증거 문서에 원문 기록 |
| 신뢰 워크플로 갱신 | 새 SHA로 ruleset 핀 갱신 — probe 선실험 후 master 전환, 계약 버전 상향 |
| 계약 변경 | 버전 상향 + 변경 이력 |

### 변경 이력

| 버전 | 일자 | 내용 |
|---|---|---|
| v1.0.0 | 2026-11-13 | 최초 착지 — 3장 구성, 첫 채택 명제 |
| v1.1.0 | 2026-11-14 | 판정을 증거 등급에 결속: `LAW_CONFORMANCE_ACCEPTED_REPRODUCIBLE` 신설, `VACUOUS_BLOCKED` fail-closed 강제, `EVIDENCE_COHERENCE` 불변식 추가, SSOT를 신뢰 저장소로 이동 |