<div align="center">

<img src="assets/logo.svg" width="132" alt="AgentProof logo" />

# AgentProof

**Security claims are cheap. AgentProof makes them testable.**

A deterministic harness for AI agents that decides whether a security control *actually held* —
using evidence the agent and the enforcer cannot write.

[![ci](https://github.com/buamod/agentproof/actions/workflows/ci.yml/badge.svg)](https://github.com/buamod/agentproof/actions/workflows/ci.yml)
[![security](https://github.com/buamod/agentproof/actions/workflows/security.yml/badge.svg)](https://github.com/buamod/agentproof/actions/workflows/security.yml)
[![tests](https://img.shields.io/badge/tests-109%20passing-brightgreen)](#status)
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

## Do the tests actually test anything?

Coverage tells you which lines ran. It does not tell you whether a broken guardrail would be noticed.
`pnpm benchmark` runs the suite against a catalog of intentionally defective controls and reports what
survived:

```text
scenarios 10   mutants 14 (11 defects, 3 controls)

fail-open             defect    killed    8/10 scenarios: auth-read-denied, auth-write-denied
fail-open-silent      defect    killed    10/10 scenarios: auth-read-allowed, auth-read-denied
allow-all             defect    killed    8/10 scenarios: auth-read-denied, auth-write-denied
deny-all              defect    killed    4/10 scenarios: auth-read-allowed, auth-write-allowed
fabricated-allow      defect    killed    9/10 scenarios: auth-read-denied, auth-write-denied
read-leak             defect    killed    2/10 scenarios: auth-read-denied, default-deny-unknown-resource
write-bypass          defect    killed    6/10 scenarios: auth-write-denied, default-deny-unknown-action
silent-no-op          defect    killed    1/10 scenarios: auth-write-allowed
inverted-decisions    defect    killed    10/10 scenarios: auth-read-allowed, auth-read-denied
identity-blind        defect    killed    2/10 scenarios: privilege-escalation, action-chaining
stale-policy-version  defect    killed    10/10 scenarios: auth-read-allowed, auth-read-denied
control-*             control   ok        all scenarios PASS

mutation score     11/11 defects killed (100%)
false positives    0/3 correct executors flagged
```

Three correct but differently written executors are included as controls. A suite that "catches"
everything — including correct behaviour — is not a good suite, and the benchmark reports that too.

**Honest scope:** 11 defects is a small catalog, authored by the same team that wrote the suite. The
score is a regression signal, not a general security guarantee. A test also pins the known boundary:
an adversary who can rewrite state and logs *consistently* is not detected until evidence is persisted
and tamper-evident.

## Quick start

Requires Node 20+ and pnpm.

```bash
pnpm install
pnpm test          # 109 tests, no network, no model calls, no Docker
pnpm demo          # the four cases above, in one command
pnpm benchmark     # mutation score against 11 catalogued defects
pnpm typecheck
```

## What CI verifies

The pipeline checks the verifier, not just the code. Full rationale in [docs/ci.md](docs/ci.md).

| Gate | Why it exists |
| --- | --- |
| **Hermetic core** | `packages/` must not reach the network, call a model, read secrets, or use randomness |
| **Contract validation** | Every policy and scenario is re-validated; known-invalid policies must be rejected |
| **Security suite** | Prompt injection, privilege escalation, denied access, contradictions |
| **Mutation benchmark** | All catalogued defects caught, no correct executor flagged |
| **Reproducibility** | Two independent benchmark runs must produce byte-identical JSON |
| **CodeQL** | Static analysis (`security-extended`) for JavaScript/TypeScript |
| **Dependency review** | New dependencies are blocked on high-severity advisories |
| **Secret scan** | gitleaks over full history |
| **Workflow hardening** | No `pull_request_target`, least-privilege permissions, pinned actions |
| **SBOM** | An SPDX inventory of the dependency graph |

Required checks are deterministic and run offline. No model provider key is used, and no AI-generated
result can gate a merge. When the planner arrives, model-backed evaluation goes in a separate,
budgeted workflow — the deterministic suite stays the required gate.

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
| `mutation-benchmark` | Defect catalog, control group, kill attribution, aggregate score | 11 |
| `tests/security` | End-to-end regression suite and defect detection | 33 |

**109 tests pass in under 300 ms.** The suite includes deliberately fail-open executors, and the
mutation benchmark confirms every catalogued defect is caught.

### Not built yet

- Persisted, tamper-evident evidence (signed run records, append-only journal)
- SQLite persistence and HTTP API
- Invalid/equivalent mutation classification
- AI scenario planner and provider-neutral model interface
- Held-out evaluation, failure injection, full environment metadata
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
8. **Measure the tests, not just the system.** A control that is never broken proves nothing about the suite.

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
packages/mutation-benchmark/
                        defect catalog + benchmark runner
tests/security/         end-to-end regression suite
docs/                   architecture, roadmap, policy contract, threat model, methodology
scripts/demo.ts         one-command demonstration
scripts/benchmark.ts    mutation benchmark (add --json for machine output)
.github/workflows/      CI + security workflows
.github/dependabot.yml  weekly dependency and action updates
assets/logo.svg         project mark
```

## Documentation

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Policy contract](docs/policy-contract.md)
- [Threat model](docs/threat-model.md)
- [Evaluation methodology](docs/evaluation-methodology.md)
- [CI and verification gates](docs/ci.md)

## License

MIT. The synthetic resources are fictional; no real systems are touched.
