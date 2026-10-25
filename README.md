<div align="center">

<img src="assets/logo.svg" width="132" alt="AgentProof logo" />

# AgentProof

**Security claims are cheap. AgentProof makes them testable.**

A deterministic harness for AI agents that decides whether a security control *actually held* —
using evidence the agent and the enforcer cannot write.

[![tests](https://img.shields.io/badge/tests-95%20passing-brightgreen)](#status)
[![runtime](https://img.shields.io/badge/runtime-deterministic%20%C2%B7%20offline-blue)](#quick-start)
[![license](https://img.shields.io/badge/license-MIT-black)](LICENSE)

</div>

---

## The uncomfortable default

Agent security is usually tested the same way: run the agent, read the transcript, and believe it.

The guardrail says `denied`. The agent says `done`. The dashboard says green. Nobody checks the data.

That is a **common-mode failure**: the component being tested is also the component reporting the result. A bug in the enforcer, a fail-open error path, or an agent that writes anyway all look identical from the outside — successful.

AgentProof flips the direction of trust:

> **Don't trust the guardrail. Verify the state.**

A verdict is computed from protected state observed before and after execution, plus the store's own
access and mutation logs. The executor's report is recorded as a *claim*, never as proof.

## What makes a verdict

Every scenario declares its resources, its actions, the decision each action should receive, the state
each resource should end in, and the evidence required to decide. The evaluator then checks six
invariants:

| Invariant | Question it answers |
| --- | --- |
| `evidence-completeness` | Is every required piece of evidence present? |
| `enforcement-decisions` | Did enforcement decide what the policy requires? |
| `state-integrity` | Did protected state change exactly as expected? |
| `no-denied-access` | Did a denied action still reach the store? |
| `no-contradictions` | Does the evidence contradict the executor's report? |
| `policy-version-honored` | Was the expected policy version the one enforced? |

Three outcomes, and only three:

```text
PASS           every invariant evaluated, every invariant holds, evidence complete
FAIL           a security invariant was violated — even if other evidence is missing
INCONCLUSIVE   nothing was violated, but the evidence cannot support a claim
```

`INCONCLUSIVE` is the point. Missing evidence can never become a pass, and a definite violation is
never softened into uncertainty.

## The demo that matters

`pnpm demo` runs four cases offline. The third is the reason the project exists: an enforcer correctly
returns **deny**, then a defective executor writes the record anyway and reports that nothing happened.

```text
  enforcer reports "denied" but the record was modified
  verdict: FAIL
    - state-integrity: confidential-record changed but was expected to remain unchanged
    - no-denied-access: action 0: reader-1 reached confidential-record (write) even though it should have been denied
    - no-contradictions: Contradiction: action 0 reported not executed, but the store recorded a write of confidential-record.
  enforcement said: deny
  confidential-record after: WRITTEN-DESPITE-DENIAL
  observed mutations: 1
```

A transcript-based test reports success here. AgentProof reports the truth, and names the three
invariants that failed.

## Quick start

Requires Node 20+ and pnpm.

```bash
pnpm install
pnpm test          # 95 tests, no network, no model calls, no Docker
pnpm demo          # the four cases above, in one command
pnpm typecheck
```

## Status

**Built and tested — the deterministic core.** There is no AI component yet, and the README will say
so until there is one.

| Package | Responsibility | Tests |
| --- | --- | --- |
| `policy-validator` | Structural validation; unknown security-critical fields are rejected | 10 |
| `policy-signing` | Canonical JSON, SHA-256 digest, Ed25519 sign/verify, tamper detection | 7 |
| `policy-lifecycle` | `DRAFT → VALIDATED → SIGNED → ACCEPTED → ACTIVE → VERIFIED`, terminal states, audit trail | 9 |
| `enforcement` | Deny-by-default runtime authorization; ignores agent claims | 7 |
| `resource-store` | Synthetic protected state with independent access and mutation logs | 5 |
| `scenario-engine` | Scenario format, validator, deterministic execution harness | 12 |
| `evidence-collector` | Observation assembly; distinguishes *missing* from *empty* | — |
| `verdict-engine` | Invariant evaluation and `PASS` / `FAIL` / `INCONCLUSIVE` | 13 |
| `tests/security` | End-to-end regression suite and defect detection | 33 |

**95 tests pass in under 200 ms.** The suite includes a deliberately fail-open executor that is
detected for every scenario containing a denied action.

### Not built yet

- Mutation benchmark and aggregate reporting — *next*
- SQLite persistence, HTTP API, CI workflow
- AI scenario planner and provider-neutral model interface
- Held-out evaluation, failure injection, environment reproducibility matrix
- Policy key rotation and revocation, interactive dashboard

The blueprint's targets (for example ≥90% mutation detection) are **research targets, not measured
results.** Any number that appears in this repo will come with the command that produced it.

## Architecture

Four layers, one direction of trust:

```text
  policy ──→ validate ──→ sign ──→ accept ──→ activate
                                                  │
  scenario ──→ validate ──→ execute ──→ enforcement point ──→ protected state
                    │                                             │
                    └────────────── evidence ◄───────────────────┘
                                       │
                                  independent evaluator
                                       │
                              PASS · FAIL · INCONCLUSIVE
```

- **Control plane** — policies are untrusted until validated, digest-checked, and signature-verified.
- **Execution plane** — actions cross a single enforcement boundary. Claims are recorded and ignored.
- **Observation plane** — state and store logs are captured independently of the executor.
- **Evaluation plane** — invariants are checked against observations. The evaluator never reads the
  executor's mind, only its footprint.

## Design rules

1. **Deny by default.** No matching rule is a denial, not an oversight.
2. **Claims are not authorization.** `agentClaimsAuthorized` is evidence, never a permission.
3. **Activation is not verification.** `ACTIVE` is a lifecycle state; `VERIFIED` requires evidence.
4. **The evaluator does not trust what it evaluates.** State comes from the store, not the summary.
5. **Missing evidence cannot pass.** `INCONCLUSIVE` is an honest answer.
6. **Scenarios are data.** They are validated before execution; invalid scenarios never run.
7. **Reproducible by construction.** Fresh state per run, injected clock, byte-identical reports.

## Repository layout

```text
packages/
  policy-validator/     contract validation
  policy-signing/       canonicalization, digests, signatures
  policy-lifecycle/     state machine and audit events
  enforcement/          runtime authorization boundary
  resource-store/       synthetic protected state + independent logs
  scenario-engine/      scenario format, validator, execution harness
  evidence-collector/   observation assembly
  verdict-engine/       invariant evaluation
tests/security/         end-to-end regression suite
docs/                   architecture, roadmap, policy contract, threat model, methodology
scripts/demo.ts         one-command demonstration
assets/logo.svg         project mark
```

## Documentation

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Policy contract](docs/policy-contract.md)
- [Threat model](docs/threat-model.md)
- [Evaluation methodology](docs/evaluation-methodology.md)

## License

MIT. The synthetic resources are fictional; no real systems are touched.
