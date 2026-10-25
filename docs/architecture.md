# AgentProof Architecture

## Current implementation

Layers 1, 3 (deterministic part), and 4 are implemented. Layer 2 is a controlled executor, not an
autonomous agent. The AI planner in layer 3 is planned, not built. See [roadmap](roadmap.md).

## High-level Design

The platform consists of four major layers:

**Layer 1 — Security control plane:** Validates, signs, accepts, and activates policies.

**Layer 2 — Agent execution plane:** Runs simulated agents and their permitted tools.

**Layer 3 — Test generation and execution:** Produces scenarios, validates them, and executes controlled experiments.

**Layer 4 — Independent evaluation:** Examines observed state changes and produces the final verdict.

```
                      AgentProof
                           |
             +-------------+-------------+
             |                           |
      Security Control Plane       Test Platform
             |                           |
      Policy Registry             Scenario Catalog
      Contract Validator          Deterministic Tests
      Signing / Trust             AI Scenario Planner
      Lifecycle Controller        Scenario Validator
             |                           |
             +-------------+-------------+
                           |
                   Controlled Runtime
                           |
                 Agent + Authorized Tools
                           |
                 Policy Enforcement Point
                           |
                 Synthetic Protected State
                           |
                 Independent Evidence Engine
                           |
                Verdicts + Benchmark Reports
```

The diagram is conceptual. Implementation should begin as a modular TypeScript application rather than a distributed microservices system. Separate deployment processes only when there is a demonstrated reason.

## Core Components

### 4.1 Policy Registry
Stores immutable policy versions and their metadata.

### 4.2 Policy Contract Validator
Checks that policies meet a formally defined contract.

### 4.3 Signing and Trust Service
Provides integrity and authenticity guarantees for policies.

### 4.4 Policy Lifecycle Controller
Implements an explicit lifecycle: `DRAFT → VALIDATED → SIGNED → ACCEPTED → ACTIVE → VERIFIED`

### 4.5 Enforcement Service
The runtime enforcement point checks every protected operation against the active policy.

### 4.6 Deterministic Scenario Engine
Executes known, repeatable security scenarios without requiring an LLM.

### 4.7 AI Scenario Planner
Uses an LLM to propose additional test scenarios.

### 4.8 Scenario Execution Controller
Acts as the boundary between generated scenarios and the test environment.

### 4.9 Independent Verdict Engine
This is the most important component. The evaluator must not simply trust the agent's response.

## Technology Stack

| Area | Initial choice | Reason |
| --- | --- | --- |
| Language | TypeScript | Strong fit for test automation and agent tooling |
| Runtime | Supported Node.js LTS | Mature ecosystem and deployment options |
| Package management | pnpm | Reproducible workspace management |
| API | Fastify | Lightweight service framework |
| Unit and integration tests | Vitest | Fast feedback and TypeScript support |
| Policy contracts | JSON Schema | Machine-verifiable policy structure |
| Persistence | SQLite | Simple local development and reproducible experiments |
| Cryptography | Node.js crypto APIs | Standard cryptographic primitives |
| Isolation | Docker | Reproducible, constrained execution environments |
| CI | GitHub Actions | Automated validation and regression testing |

## Security and Reliability Invariants

1. **No untrusted policy is activated.** Invalid signatures, untrusted signers, and invalid policy contracts must result in rejection.
2. **No silent policy mutation.** A change to the signed content must invalidate its integrity verification.
3. **No authorization based on agent claims.** Authorization is decided by the deterministic enforcement layer.
4. **No default allow on uncertainty.** If the system cannot establish authorization, the protected operation is denied.
5. **No direct execution of unvalidated AI proposals.** Every proposed scenario passes deterministic validation.
6. **No self-certified verdicts.** The component under test cannot decide whether its own security control passed.
7. **No hidden test state changes.** Relevant actions and synthetic resource mutations must be observable.
8. **No pass without evidence.** Missing or contradictory evidence produces a failure or inconclusive result according to predefined rules.
9. **No irreproducible benchmark claims.** Each run records its configuration, scenario version, policy version, and relevant model settings.
10. **No uncontrolled execution.** Tests operate only within the configured isolated environment and resource budgets.
11. **No ambiguous lifecycle status.** Deployment and activation success are separate from runtime security verification.
12. **No silent regression.** A previously passing security invariant must fail CI if a code change breaks it.
