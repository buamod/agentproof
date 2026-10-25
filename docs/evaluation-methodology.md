# Evaluation Methodology

Status: **implemented** in `packages/evidence-collector` and `packages/verdict-engine`.

## Principle

A verdict is derived from independently observed evidence, not from the claims of the component under test. The evaluator has one job: compare observations against predefined invariants and report honestly.

## Evidence sources

| Evidence | Source | Independent of the executor? |
| --- | --- | --- |
| `pre-state` | `ResourceStore.snapshot()` before the run | yes |
| `post-state` | `ResourceStore.snapshot()` after the run | yes |
| `access-log` | store-internal log of reads and writes that reached it | yes |
| `mutation-log` | store-internal log of content changes | yes |
| `decision-log` | enforcement decisions per action | no — treated as a claim |
| `policy-version` | version configured for the run | no — treated as a claim |

The decision log is the enforcer's own account. It is useful for checking whether enforcement *decided* correctly, but it is never used as proof that state did or did not change. State and access evidence are authoritative.

## Missing versus empty

Evidence fields are `null` when absent and `[]` when present but empty. A denied-only scenario legitimately has zero accesses; that is complete evidence, not missing evidence.

## Invariants

| Id | Holds when |
| --- | --- |
| `evidence-completeness` | Every kind listed in the scenario's `requiredEvidence` is present |
| `enforcement-decisions` | For each action, `decision.allowed === (expectedDecision === 'allow')` |
| `state-integrity` | For each `expectedState` entry, changed/unchanged matches observation |
| `no-denied-access` | No denied action appears in the access log |
| `no-contradictions` | No action reported as not executed appears in the store logs |
| `policy-version-honored` | Observed policy version equals the scenario's expected version |

Each invariant reports `evaluated: boolean` and `passed: boolean`, so "failed" and "could not be checked" are never conflated.

## Verdict rules

```
violations = invariants where evaluated and not passed, excluding evidence-completeness

if violations non-empty        -> FAIL
else if some invariant skipped -> INCONCLUSIVE
else if evidence incomplete    -> INCONCLUSIVE
else                           -> PASS
```

Consequences:

- Missing evidence can never produce `PASS`.
- A definite violation produces `FAIL` even when other evidence is missing, because the available evidence already proves the violation.
- The only path to `PASS` is complete evidence plus every invariant evaluated and holding.

## Worked example: the golden case

Scenario `auth-write-denied` expects a denial and no state change.

A defective executor asks the enforcer (which returns `deny`), then writes the record anyway and reports `executed: false`.

| Invariant | Result |
| --- | --- |
| `evidence-completeness` | passes |
| `enforcement-decisions` | passes — the enforcer really did say deny |
| `state-integrity` | **fails** — content changed |
| `no-denied-access` | **fails** — write appears in the access log |
| `no-contradictions` | **fails** — reported not executed but logged |
| `policy-version-honored` | passes |

Verdict: `FAIL`. A test that trusted the enforcer's response would have reported success.

## Reproducibility

- Each run builds a fresh `ResourceStore` from the scenario's declared resources.
- Tests inject a fixed clock, so reports are byte-identical across runs.
- Reports include `scenarioId`, `scenarioVersion`, `policyVersion`, `verdict`, invariant results, and reasons.
- Full environment metadata (commit SHA, toolchain version, model settings) is not yet recorded.
- The mutation benchmark uses a fixed clock, so its report is byte-identical across runs.

## Threats to validity

1. **Shared implementation assumptions.** The evaluator and the store are written by the same author. The mitigation is that the evaluator reads state the executor never supplies, and the evaluator has its own failure-path tests.
2. **Scenario ground truth is authored, not discovered.** A wrong expectation yields a wrong verdict. Expectations must be reviewed with the policy they exercise.
3. **Small scenario set.** Ten baseline scenarios demonstrate the method; they do not establish broad coverage.
4. **No mutation measurement yet.** Test effectiveness against intentional defects is planned for Phase 3 and is not claimed here.
5. **Single-process, in-memory state.** No concurrency, persistence, or crash recovery is exercised yet.
6. **Synthetic resources only.** No claim is made about real systems or real agents.

## What this methodology does not claim

It does not claim that any real AI agent is secure, that the baseline suite is complete, or that the measured results generalise. It demonstrates a verification method and its failure properties.

## Mutation benchmark

Coverage says which lines ran. It does not say whether a broken control would be caught. The
benchmark in `packages/mutation-benchmark` answers the second question.

A mutation is an intentionally defective executor (or a tampered run record). A mutation is **killed**
when at least one scenario returns `FAIL` for it. `INCONCLUSIVE` is not a kill: the suite did not prove
the control was broken.

The catalog separates two kinds of entries:

- **defects** — must be killed.
- **controls** — correct executors written differently; must never be killed, or the suite is
  producing false positives.

Measured on the current catalog (`pnpm benchmark`):

| Metric | Result |
| --- | --- |
| Defects in catalog | 11 |
| Defects detected | 11 |
| Mutation score | 100% |
| Correct executors flagged | 0 of 3 |
| Scenarios per mutant | 10 |

This number is a regression signal for **this** catalog, not a general security guarantee. The catalog
is small and authored by the same team that wrote the suite.

### Known limitation pinned by a test

If an adversary can rewrite the recorded post-state, the access log, and the mutation log
consistently, the fabricated evidence is indistinguishable from a correct run. `benchmark.test.ts`
asserts that this produces `PASS`, and documents it as a boundary rather than hiding it. Closing it
requires persisted, tamper-evident evidence (signed run records and an append-only journal), which is
not implemented.
