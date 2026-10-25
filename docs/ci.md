# CI and Verification Gates

Status: implemented in `.github/workflows/`.

The pipeline is not "run the tests." For a project whose claim is *evidence over assertions*, CI has
to verify the evidence machinery itself. Each gate below exists because a specific failure mode would
otherwise go unnoticed.

## Gates

| Gate | Workflow | What it proves | Failure means |
| --- | --- | --- | --- |
| Hermetic core | `ci.yml` | No network, model SDK, secret access, or `Math.random` in `packages/` | The deterministic core has become non-reproducible or model-dependent |
| Contract validation | `ci.yml` | Every policy and scenario is valid; known-invalid policies are rejected | A malformed expectation could produce a confident, meaningless verdict |
| Typecheck | `ci.yml` | The TypeScript surface is consistent | Types and call sites have drifted |
| Security suite | `ci.yml` | Prompt injection, privilege escalation, denied access, contradictions still behave | A security invariant regressed |
| Full suite | `ci.yml` | All unit and integration tests pass on Node 22 and 24 | Behaviour or compatibility broke |
| Demo | `ci.yml` | The advertised walkthrough still runs end to end | The public claim no longer matches the artifact |
| Mutation benchmark | `ci.yml` | All catalogued defects are detected and no correct executor is flagged | The suite has gone blind, or is failing indiscriminately |
| Reproducibility | `ci.yml` | Two independent benchmark processes produce byte-identical JSON | The evaluator or harness is non-deterministic |
| CodeQL | `security.yml` | Static analysis for JavaScript/TypeScript (`security-extended`) | A code-level vulnerability pattern was found |
| Dependency review | `security.yml` | New dependencies do not introduce high-severity advisories | A risky dependency was added |
| Secret scan | `security.yml` | No credentials in the repository history | A secret was committed |
| OSSF Scorecard | `security.yml` | Supply-chain posture: pinned actions, permissions, branch protection | Repository hygiene regressed |
| SBOM | `security.yml` | An SPDX inventory of the dependency graph is produced | The shipped composition is unknown |

## Why these are the right gates for an agentic-AI project

Agentic systems fail differently from ordinary services. The dangerous failures are **silent**: a tool
call succeeds outside the policy, a guardrail is bypassed, or an evaluation reports success because the
component graded itself.

- **Hermetic core** keeps the evaluator off the network and away from model providers. If the judge can
  call a model, the judge is part of the attack surface. It also makes every verdict replayable offline.
- **Contract validation** treats scenarios and policies as code. An unknown action or an undeclared
  resource must be rejected before execution, not discovered in a report.
- **Mutation benchmark** measures the detector, not the system. A suite with 90% coverage and 0%
  mutation detection provides no security assurance.
- **Reproducibility diff** catches accidental time, ordering, or randomness dependence. Byte-identical
  reports are the minimum bar for a verdict someone else is expected to trust.
- **CodeQL and dependency review** cover the code and supply chain that the runtime evidence cannot see.
- **Secret scanning** matters more than usual here: agent projects tend to accumulate provider keys.

## Deliberately absent

- **No model calls in CI.** The repository has no AI component yet, and the required checks must never
  depend on a provider key. A fork PR cannot exfiltrate a secret that was never provided.
- **No deployment or publishing.** There are no releases yet.
- **No coverage percentage threshold.** Coverage is uploaded for inspection; the mutation score is the
  meaningful gate. A line-coverage target would reward tests that execute code without asserting
  anything.
- **No Windows/macOS matrix.** The core is in-memory and OS-independent; the cost is not justified
  until process isolation and persistence land.

## When the AI planner arrives (Phase 4)

Model-backed evaluation belongs in a separate, non-required workflow:

1. `workflow_dispatch` or a nightly schedule, never on `pull_request` from forks.
2. Provider key from an environment with required reviewers.
3. Hard budgets for tokens, cost, wall time, and scenario count.
4. Pinned model identifiers and recorded settings in the report.
5. The deterministic suite remains the required gate; AI-generated scenarios are additions, and the
   evaluator stays independent of the planner.

That split is the whole point: **the trustworthy part must be able to pass without the AI, and the AI
must never be able to make the trustworthy part pass.**
