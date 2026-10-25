# AgentProof Roadmap

## Phase 0 — Project Definition (Weeks 1–2)

**Objective:** Define the contracts before writing the agent.

**Tasks:**

- Create the repository and basic development tooling.
- Write the project README and scope.
- Define the threat model.
- Define the synthetic resource model.
- Specify the policy JSON contract.
- Specify the policy lifecycle state machine.
- Define the independent evaluator's inputs and outputs.
- Write the first ten security invariants.
- Define the initial scenario format.
- Write architecture decision records for significant choices.

**Exit criteria:** The policy format, lifecycle, scenario format, and verdict rules are documented and testable.

## Phase 1 — Deterministic policy engine (Weeks 3–5)

**Objective:** Build a working security system without an LLM.

**Tasks:**

- Implement policy schema validation.
- Implement canonicalization and policy hashing.
- Implement signing and signature verification.
- Implement lifecycle transition validation.
- Implement policy acceptance and activation.
- Implement the runtime enforcement point.
- Create synthetic identities and protected resources.
- Implement structured audit events.
- Add unit and integration tests.
- Verify that modified policies cannot be accepted as authentic.

**Exit criteria:** A valid policy can be signed, accepted, activated, and enforced. Invalid or tampered policies are rejected.

## Phase 2 — Scenario engine and independent evaluator (Weeks 6–8)

**Objective:** Prove that the system can detect broken controls.

**Tasks:**

- Implement deterministic scenario definitions.
- Build a controlled execution harness.
- Capture pre-execution and post-execution state.
- Implement independent verdict evaluation.
- Add explicit PASS, FAIL, and INCONCLUSIVE results.
- Implement the first security regression suite.
- Add deliberate policy and enforcement defects.
- Verify that the suite detects those defects.
- Produce machine-readable run reports.

**Exit criteria:** The test engine catches known defects using evidence independent of the agent's claims.

## Phase 3 — Mutation testing and benchmark (Weeks 9–11)

**Objective:** Measure the strength of the deterministic testing system.

**Tasks:**

- Create the mutation catalog.
- Define expected detection behavior for every mutation.
- Run the existing test suite against each mutation.
- Classify killed, surviving, invalid, and equivalent mutations.
- Implement benchmark result aggregation.
- Record reproducibility metadata.
- Add CI gates for critical security invariants.
- Document baseline limitations.

**Exit criteria:** The project can measure security-test effectiveness against a documented set of intentional defects.

## Phase 4 — AI-assisted scenario generation (Weeks 12–15)

**Objective:** Determine whether an LLM adds useful security-test coverage.

**Tasks:**

- Define a provider-neutral model interface.
- Implement structured scenario generation.
- Validate every proposal against a strict schema.
- Reject unsafe tools, unknown resources, and unsupported actions.
- Add scenario deduplication.
- Enforce execution budgets and isolation.
- Add prompt-injection scenarios against the synthetic agent.
- Compare AI-assisted tests with the deterministic baseline.
- Record model version, settings, token usage, and cost.
- Keep the evaluator independent from the planner.

**Exit criteria:** AI-generated scenarios can be safely validated, executed, evaluated, and compared with deterministic tests.

## Phase 5 — Hardening and fair evaluation (Weeks 16–18)

**Objective:** Make the results credible.

**Tasks:**

- Test missing and contradictory evidence.
- Test crashes and interrupted runs.
- Test stale policy versions and failed activations.
- Test enforcement-service failures.
- Test repeatability across fresh environments.
- Evaluate against a held-out scenario set.
- Compare all baselines under equivalent budgets.
- Review false positives and surviving mutations.
- Document limitations and threats to validity.
- Publish the benchmark methodology.

**Exit criteria:** Results can be reproduced and independently interpreted without relying on promotional claims.

## Phase 6 — Portfolio and public release (Weeks 19–21)

**Objective:** Make the project easy for technical reviewers to evaluate.

**Tasks:**

- Write a concise architecture overview.
- Document the threat model and trust boundaries.
- Publish the benchmark definitions.
- Include example policies and scenarios.
- Add a one-command local demonstration.
- Publish reproducible sample reports.
- Create architecture and sequence diagrams.
- Record a short demonstration video.
- Document known limitations and next steps.
- Add contribution and responsible-disclosure guidance.

**Exit criteria:** Another engineer can clone the repository, run the tests, reproduce the example results, and understand the security guarantees.

## Optional Phase 7 — Advanced research (Weeks 22–24+)

Choose one extension based on the measured weaknesses of the initial system.

Possible extensions:

- Concurrent policy updates and stale-version detection.
- Agent memory poisoning across sessions.
- Multi-agent trust boundaries.
- Model-to-model generalization of attack scenarios.
- Statistical evaluation across repeated model runs.
- A larger public benchmark of policy enforcement failures.
- Integration with an existing agent framework.

Do not pursue all of them at once.
