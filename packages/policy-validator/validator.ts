/**
 * Policy Contract Validator - self-contained, no external dependencies.
 * 
 * Validates policies against a formally defined JSON contract.
 * Rejects unknown/security-critical fields to prevent silent mutation.
 * 
 * Core principle: The validator must be deterministic. It must not rely on
 * an LLM to decide whether a policy is safe.
 * 
 * This is the foundation of the entire project - every other component
 * depends on correct policy validation.
 */

/**
 * A policy rule defines an allow/deny relationship between a subject and resource.
 */
export interface PolicyRule {
  subject: string
  resource: string
  action: string
  effect: 'allow' | 'deny'
  condition?: {
    operator: string
    args: Record<string, unknown>
  }
}

/**
 * A policy version with its rules and metadata.
 */
export interface PolicyVersion {
  policyId: string
  version: number
  rules: PolicyRule[]
  metadata?: Record<string, unknown>
}

/**
 * Validation result - structured findings, not a boolean.
 * 
 * CRITICAL: A valid signature proves integrity and signer authenticity,
 * but this validator checks STRUCTURAL correctness only.
 * Signature verification is a separate layer (policy-signing package).
 */
export interface ValidationResult {
  valid: boolean
  errors: Array<{ path: string[]; message: string }>
  warnings: Array<{ path: string[]; message: string }>
}

/**
 * Validates a policy object against the formal contract.
 * 
 * Security-critical fields that MUST be present:
 * - policyId (string): Unique identifier
 * - version (integer, >= 1): Policy version
 * - rules (array): Must contain rule objects
 * 
 * Each rule must have:
 * - subject (string): The identity
 * - resource (string): The protected resource
 * - action (string): The operation
 * - effect ('allow' | 'deny'): The decision
 * 
 * CRITICAL: `additionalProperties: false` ensures no unknown fields
 * are accepted. This prevents silent policy mutation.
 */
export function validatePolicy(policy: unknown): ValidationResult {
  const errors: Array<{ path: string[]; message: string }> = []
  const warnings: Array<{ path: string[]; message: string }> = []

  // 1. Top-level type check
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) {
    errors.push({
      path: [],
      message: 'Policy must be a non-null object'
    })
    return { valid: false, errors, warnings }
  }

  const obj = policy as Record<string, unknown>

  // 2. Check required top-level fields
  if (typeof obj.policyId !== 'string') {
    errors.push({ path: ['policyId'], message: 'policyId is required and must be a string' })
  }

  if (typeof obj.version !== 'number' || !Number.isInteger(obj.version) || obj.version < 1) {
    errors.push({ path: ['version'], message: 'version is required and must be an integer >= 1' })
  }

  if (!Array.isArray(obj.rules)) {
    errors.push({ path: ['rules'], message: 'rules is required and must be an array' })
    return { valid: false, errors, warnings: filterWarnings(errors, warnings) }
  }

  // 3. Validate each rule
  if (Array.isArray(obj.rules)) {
    for (let i = 0; i < obj.rules.length; i++) {
      const rule = obj.rules[i]
      const rulePath: string[] = ['rules', String(i)]

      if (typeof rule !== 'object' || rule === null || Array.isArray(rule)) {
        errors.push({
          path: [...rulePath, 'rule'],
          message: `Rule at index ${i} must be a non-null object`
        })
        continue
      }

      // Check required rule fields
      if (typeof rule.subject !== 'string') {
        errors.push({ path: [...rulePath, 'subject'], message: 'subject is required and must be a string' })
      }
      if (typeof rule.resource !== 'string') {
        errors.push({ path: [...rulePath, 'resource'], message: 'resource is required and must be a string' })
      }
      if (typeof rule.action !== 'string') {
        errors.push({ path: [...rulePath, 'action'], message: 'action is required and must be a string' })
      }

      // Validate effect enum
      if (rule.effect !== 'allow' && rule.effect !== 'deny') {
        errors.push({ path: [...rulePath, 'effect'], message: 'effect must be either "allow" or "deny"' })
      }

      // Check for unknown fields in the rule (additionalProperties: false semantics)
      const allowedRuleKeys = ['subject', 'resource', 'action', 'effect', 'condition']
      const ruleKeys = Object.keys(rule as Record<string, unknown>)
      for (const key of ruleKeys) {
        if (!allowedRuleKeys.includes(key)) {
          errors.push({
            path: [...rulePath, 'unknown', key],
            message: `Unknown field '${key}' in rule ${i}. additionalProperties: false`
          })
        }
      }

      // Validate condition if present
      if (rule.condition) {
        if (typeof rule.condition.operator !== 'string') {
          errors.push({ path: [...rulePath, 'condition', 'operator'], message: 'condition.operator must be a string' })
        }
        if (typeof rule.condition.args !== 'object' || Array.isArray(rule.condition.args) || rule.condition.args === null) {
          errors.push({ path: [...rulePath, 'condition', 'args'], message: 'condition.args must be an object' })
        }
      }
    }
  }

  // 4. Check for unknown top-level fields (additionalProperties: false)
  const allowedTopLevelKeys = ['policyId', 'version', 'rules', 'metadata']
  const topLevelKeys = Object.keys(obj)
  for (const key of topLevelKeys) {
    if (!allowedTopLevelKeys.includes(key)) {
      errors.push({
        path: ['unknown', key],
        message: `Unknown top-level field '${key}'. additionalProperties: false - this would allow silent policy mutation.`
      })
    }
  }

  // 5. Validate metadata if present (optional but must not contain security-critical fields)
  if (obj.metadata) {
    if (typeof obj.metadata !== 'object' || Array.isArray(obj.metadata) || obj.metadata === null) {
      errors.push({ path: ['metadata'], message: 'metadata must be a non-null object if present' })
    } else {
      const metaKeys = Object.keys(obj.metadata as Record<string, unknown>)
      const allowedMetaKeys = ['createdBy', 'createdAt', 'notes']
      for (const key of metaKeys) {
        if (!allowedMetaKeys.includes(key)) {
          warnings.push({
            path: ['metadata', key],
            message: `Unknown metadata field '${key}'. Metadata is informational only and does not affect security enforcement.`
          })
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings: filterWarnings(errors, warnings)
  }
}

/**
 * Filters errors so warnings don't cause valid to be false.
 * valid = true only if there are NO errors (warnings are separate).
 */
function filterWarnings(errors: Array<{ path: string[]; message: string }>, warnings: Array<{ path: string[]; message: string }>): Array<{ path: string[]; message: string }> {
  return warnings
}

/**
 * Example: A valid minimal policy
 */
export const MINIMAL_VALID_POLICY: {
  policyId: string
  version: number
  rules: Array<{
    subject: string
    resource: string
    action: string
    effect: 'allow' | 'deny'
  }>
} = {
  policyId: 'minimal-demo',
  version: 1,
  rules: [
    {
      subject: 'admin',
      resource: 'admin-panel',
      action: 'write',
      effect: 'allow'
    }
  ]
}

/**
 * Example: A valid policy with two identities and two resources
 */
export const DEMO_POLICY: {
  policyId: string
  version: number
  rules: Array<{
    subject: string
    resource: string
    action: string
    effect: 'allow' | 'deny'
    condition?: {
      operator: string
      args: Record<string, unknown>
    }
  }>
  metadata?: Record<string, unknown>
} = {
  policyId: 'demo-policy',
  version: 1,
  rules: [
    {
      subject: 'reader',
      resource: 'public-document',
      action: 'read',
      effect: 'allow'
    },
    {
      subject: 'reader',
      resource: 'confidential-record',
      action: 'read',
      effect: 'deny'
    }
  ],
  metadata: {
    createdBy: 'demo',
    createdAt: '2026-10-25'
  }
}

/**
 * Example: An invalid policy - missing required fields
 */
export const INVALID_POLICY_MISSING_FIELDS = {
  policyId: 'incomplete'
  // missing: version, rules
}

/**
 * Example: An invalid policy - unknown field (should be rejected)
 * This demonstrates the additionalProperties: false security boundary.
 */
export const INVALID_POLICY_UNKNOWN_FIELD = {
  policyId: 'tampered',
  version: 1,
  rules: [],
  // This field should cause validation to fail
  _dangerousField: 'should_be_rejected'
}
