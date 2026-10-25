# Policy Contract

Status: **implemented** in `packages/policy-validator` and `packages/policy-signing`.

This document is the authoritative description of the policy format. If the code and this document disagree, the code is wrong.

## Policy document

```json
{
  "policyId": "demo-policy",
  "version": 1,
  "rules": [
    { "subject": "reader", "resource": "public-document", "action": "read", "effect": "allow" },
    { "subject": "reader", "resource": "confidential-record", "action": "read", "effect": "deny" }
  ],
  "metadata": { "createdBy": "demo", "createdAt": "2026-10-25" }
}
```

### Required fields

| Field | Type | Constraint |
| --- | --- | --- |
| `policyId` | string | non-empty identity of the policy |
| `version` | integer | `>= 1` |
| `rules` | array | may be empty (which denies everything) |

### Rule fields

| Field | Type | Constraint |
| --- | --- | --- |
| `subject` | string | role name, matched against `identity.role` |
| `resource` | string | resource identifier |
| `action` | string | operation name (`read`, `write`, …) |
| `effect` | string | exactly `allow` or `deny` |
| `condition` | object | optional; `{ operator: string, args: object }` |

### Metadata

`metadata` is informational and **must not affect enforcement**. Accepted keys: `createdBy`, `createdAt`, `notes`. Unknown metadata keys produce a warning, not a rejection.

## Unknown fields are rejected

`additionalProperties: false` applies to the policy document, every rule, and `condition`. An unknown field anywhere in the security-critical portion of the document is a validation error.

Rationale: a silently ignored field is a silent policy mutation. If a producer believes it added a restriction and the consumer drops it, the policy is weaker than intended.

## Deny-by-default

Structural validation says nothing about authorization. Enforcement is separate:

1. Find a rule matching `subject`, `resource`, and `action`.
2. If no rule matches, **deny**.
3. If a matching rule says `deny`, **deny**.
4. If a matching rule says `allow`, **allow**.

Multiple matching rules are not yet specified; the current implementation uses the first match in array order. A future version must define explicit precedence before multi-match policies are permitted.

## Canonical form and digest

Canonicalization sorts object keys recursively and preserves array order. The digest is `SHA-256(canonicalForm)` encoded as lowercase hex.

Two documents that differ only in key order produce the same digest. Changing any signed value changes the digest.

## Signing envelope

```json
{
  "policy": { "...": "..." },
  "digest": { "algorithm": "SHA-256", "digest": "<hex>", "canonicalForm": "<string>" },
  "signature": "<base64>",
  "keyId": "<first 16 hex chars of digest>-ed25519",
  "algorithm": "ed25519"
}
```

Verification is sign-then-seal and fails closed at every step:

1. The `keyId` must be present in the trusted key map.
2. The signature must verify over the recorded digest.
3. The digest recomputed from `policy` must equal the recorded digest.

A signature proves **integrity and signer authenticity under the configured trust model.** It does not prove that the policy is logically correct, and it does not prove that enforcement works.

## Lifecycle

```
DRAFT → VALIDATED → SIGNED → ACCEPTED → ACTIVE → VERIFIED
```

Terminal states: `REJECTED`, `INVALID`, `REVOKED`. Any state may transition to a terminal state; terminal states permit no further transitions.

| From | Allowed next |
| --- | --- |
| `DRAFT` | `VALIDATED` |
| `VALIDATED` | `SIGNED` |
| `SIGNED` | `ACCEPTED` |
| `ACCEPTED` | `ACTIVE` |
| `ACTIVE` | `VERIFIED` |
| `REJECTED` / `INVALID` / `REVOKED` | none |

`ACTIVE` means the controller activated the policy. `VERIFIED` means verification was recorded from evidence. Activation never implies verification.
