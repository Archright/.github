# 제3자 재현 절차 (PR Admission)

계약: [`PR_ADMISSION_CONTRACT.md`](./PR_ADMISSION_CONTRACT.md) v1.1.0.
검증기: [`verify_pr_admission_replay.py`](./verify_pr_admission_replay.py).

재현은 네트워크 쓰기를 하지 않는다. `ax report --canonical-digest`는 호출하지 않는다(비결정성).

## 1. 실행 기록 내려받기

```bash
gh run download <run-id> -R Archright/nim-libp2p -D ./run-<run-id>
```

필요 아티팩트:

```
propositions/proposals.json
ax-verify-evidence-propositions-A/{verify-record.json,ax_proof_state.json,canonical-digest.txt,vault-manifest.json}
ax-verify-evidence-propositions-B/{...동일...}
admission-integrity-report/admission-integrity-report.json
admission-verdict/admission-verdict.json
```

## 2. 검증기 실행

```bash
python3 verify_pr_admission_replay.py ./run-<run-id>
```

## 3. 판독

| 출력 | 의미 |
|---|---|
| `RESULT: PASS — replay reproduced the recorded verdict (PASS)` | green 판정이 증거로 재현됨 |
| `RESULT: PASS — replay reproduced the recorded verdict (FAIL)` | red 판정이 증거로 재현됨 |
| `RESULT: FAIL` | 기록된 판정과 증거가 불일치하거나 증거가 재현 불가 |

`RESULT: PASS`는 **대상 소프트웨어가 통과했다는 뜻이 아니다.** 기록된 판정이 재현됐다는 뜻이다.

검증기가 독립 재계산하는 것:

1. `proposals.json`의 SHA-256
2. `ax_proof_state.json`의 canonical projection hash (A/B 각각, `canonical_projection.nim` 규칙)
3. 7개 가드 전부와 워크플로 보고값의 일치
4. exit 0의 수용 여부 — 엔진 증명 또는 계약 §2.7의 law-conformance 접속사
5. 채택 의무(`declaredRequired`)의 vault 커버리지 (modulePath + functionName)
6. A/B 대칭성
7. `admission-verdict.json`과 독립 재계산의 일치

## 4. 실측 기준선

| 실행 | PR | 기록된 판정 | 재현 결과 |
|---|---|---|---|
| `43552724692` | #11 | PASS (`LAW_CONFORMANCE_ACCEPTED_REPRODUCIBLE`, tier=candidate) | `RESULT: PASS` |
| `43553077178` | #13 | FAIL (`UNCLASSIFIED`, pin 거절, exit 2) | `RESULT: PASS` |

## 5. 한계

- green의 적법성은 **선언된 acceptance class**에 한정된다. `law-conformance`는 고정된 subject blob pin과 Z3 후보 인증서를 근거로 하며, 형식적 `PROVED`가 아니다.
- 원본 template body 추출·재검증은 주장하지 않는다(계약 §2.7 Invariant W2).
- 비-green exit(1/3)에서는 엔진이 digest/state를 쓰지 않는 것이 정상이며, 검증기는 이를 결손으로 세지 않는다.
- `EVIDENCE_COHERENCE`가 FAIL인 런은 vault 커버리지를 요구하지 않는다(검사할 vault가 없다).