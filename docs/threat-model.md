# Threat Model

Status: **initial**, covering the implemented deterministic core.

## Assets

| Asset | Protected by |
| --- | --- |
| Synthetic confidential records (`confidential-record`, `admin-panel`) | Enforcement decisions + state-integrity invariant |
| Administrative operations | Least-privilege rules, deny-by-default |
| Policy integrity and authenticity | Canonical digest + Ed25519 signature |
| Policy lifecycle state | Explicit transition table, terminal states, audit log |
| Trust configuration (trusted key map) | Caller-supplied; not yet persisted |
| Scenario definitions and expected results | Scenario validator; scenarios are data |
| Evidence records | Independent observation from the resource store |

## Actors and failure sources

- A malicious user supplying hostile input.
- A prompt injection embedded in retrieved content.
- A compromised or misconfigured agent.
- An agent that hallucinates permissions.
- An invalid or maliciously modified policy.
- A bug in validation, lifecycle, or enforcement.
- A faulty evaluator.
- Incomplete or contradictory evidence.
- Concurrent operations (not yet addressed).

## Attack categories and current coverage

| Category | Example scenario | Status |
| --- | --- | --- |
| Prompt injection | Agent claims authorization; enforcement still denies | covered (`agent-claims-authorized`) |
| Tool misuse | Unsupported action with no matching rule | covered (`default-deny-unknown-action`) |
| Identity abuse | Reader attempts admin-only write | covered (`privilege-escalation`) |
| Policy tampering | Modify signed content | covered by signing tests |
| Unknown field injection | Add a field the validator would ignore | covered by validator tests |
| Lifecycle bypass | Jump `DRAFT → ACTIVE` | covered by lifecycle tests |
| Runtime bypass | Write despite a deny decision | covered by the golden verdict test |
| Sensitive data access | Reader reads confidential record | covered (`auth-read-denied`) |
| Action chaining | Allowed read followed by denied write | covered (`action-chaining`) |
| Evaluator failure | Missing evidence | covered (returns `INCONCLUSIVE`) |
| Fail-open on error | Enforcement exception allows operation | covered (fail-closed tests) |
| Memory poisoning | Persisted instruction changes later behaviour | out of scope (Phase 7) |
| Concurrency / stale version | Racing policy activation | out of scope (Phase 7) |

## Trust boundaries

```
 untrusted input ─┐
 agent output ────┼─→ enforcement point ─→ protected state ─→ evidence ─→ verdict
 policy document ─┘         │                                        ▲
                            └── decision log ────────────────────────┘
```

- The agent and its output are **untrusted**. Claims are recorded but never used for authorization.
- The policy document is untrusted until validated and signature-verified.
- The enforcement service is **trusted for decisions but not for state**. State is read directly from the store.
- The executor's report is **not trusted**. `executed: false` while a store write exists is treated as a contradiction.
- The evaluator is trusted; it is tested with deliberately incorrect and incomplete evidence.

## Assumptions

1. The process running the evaluator is not compromised.
2. The in-memory resource store is the ground truth for synthetic state.
3. The trusted key map is provisioned by the operator, not by the agent.
4. Scenarios are authored or reviewed by a human before being added to the baseline.
5. Timing is not part of any invariant; the evaluator makes no timing-based claims.

## Out of scope for the initial release

Production secret management, network-level isolation, multi-tenant isolation, model-level jailbreak robustness, and real external systems.

## Open gaps

- Only the first matching rule is applied; conflict precedence is undefined.
- Evidence is recorded in memory only. An adversary who can rewrite state and logs consistently is out of scope until evidence is persisted and tamper-evident.
- Key rotation and revocation are not implemented.
- No persistence, so audit records do not survive process exit.
