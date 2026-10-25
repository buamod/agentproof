/**
 * Runtime Enforcement Service
 * 
 * The enforcement point checks every protected operation against the active policy.
 * 
 * Core principles (from blueprint §4.5):
 * - Authenticate the requesting identity
 * - Authorize the requested operation and resource
 * - Apply least-privilege rules
 * - Deny by default when authorization cannot be established
 * - Record the decision and policy version
 * - An agent saying "I am authorized" must never count as authorization
 * - Avoid allowing the agent to bypass the enforcement point
 * 
 * This is the critical security boundary. The agent's claims are NEVER trusted.
 * Only independent evidence (observed state changes) determines the verdict.
 */

export interface Identity {
  /** Unique identity identifier */
  id: string
  /** Identity role/role group */
  role: string
  /** Whether this identity is trusted for elevated operations */
  trusted: boolean
}

export interface OperationRequest {
  /** The identity attempting the operation */
  identity: Identity
  /** The resource being accessed */
  resource: string
  /** The action being performed */
  action: string
  /** The active policy version at the time of the request */
  policyVersion: number
  /** Whether the agent claims authorization (should be ignored by enforcer) */
  agentClaimsAuthorized: boolean
}

export interface EnforcementDecision {
  /** Whether the operation is allowed */
  allowed: boolean
  /** The policy version that was checked */
  policyVersion: number
  /** The identity that was authenticated */
  identity: Identity
  /** The resource and action that were checked */
  resource: string
  action: string
  /** Why the decision was made */
  reason: string
  /** Audit record of the decision */
  auditId: string
}

/**
 * Enforcement Service - the runtime authorization boundary.
 * 
 * CRITICAL SECURITY RULES:
 * 1. Deny by default - if we can't establish authorization, deny
 * 2. Never trust the agent's claim of authorization
 * 3. Check the ACTIVE policy version, not the claimed version
 * 4. Apply least privilege - only explicitly permitted operations are allowed
 * 5. Record every decision with full audit trail
 * 6. Never allow the agent to bypass the enforcement point
 */
export class EnforcementService {
  private activePolicyVersion: number
  private policyRules: Array<{ subject: string; resource: string; action: string; effect: 'allow' | 'deny' }>
  private auditCounter: number

  constructor(
    initialPolicyVersion: number,
    initialRules: Array<{ subject: string; resource: string; action: string; effect: 'allow' | 'deny' }>
  ) {
    this.activePolicyVersion = initialPolicyVersion
    this.policyRules = initialRules
    this.auditCounter = 0
  }

  /** Set the active policy version. */
  setActivePolicyVersion(version: number): void {
    this.activePolicyVersion = version
  }

  /** 
   * Check whether a requested operation is authorized.
   * 
   * This is the core enforcement method. The enforcer does NOT trust:
   * - The agent's claim of authorization
   * - The policy version in the request (uses the active version instead)
   * - Any internal state the agent reports
   * 
   * Instead, it independently checks the active policy rules.
   */
  checkAuthorization(request: OperationRequest): EnforcementDecision {
    this.auditCounter++

    // Fail closed: any error while evaluating authorization is a denial.
    // A thrown exception must never become an allow.
    try {
      return this.decide(request)
    } catch (error) {
      const decision: EnforcementDecision = {
        allowed: false,
        policyVersion: this.activePolicyVersion,
        identity: request?.identity,
        resource: request?.resource,
        action: request?.action,
        reason: `Denied - enforcement error (fail-closed): ${
          error instanceof Error ? error.message : String(error)
        }`,
        auditId: `audit-${this.auditCounter}`,
      }
      this.recordAudit(decision)
      return decision
    }
  }

  /** Authorization logic. Callers must go through checkAuthorization. */
  private decide(request: OperationRequest): EnforcementDecision {
    // CRITICAL: The enforcer ignores agentClaimsAuthorized
    // The agent saying "I am admin" has no effect on the decision

    // Step 1: Identify the requesting subject from the identity
    const subject = request.identity.role

    // Step 2: Search for a matching rule in the active policy
    // We look for rules where subject matches and the resource/action match
    const matchingRule = this.policyRules.find(
      rule => 
        rule.subject === subject && 
        rule.resource === request.resource && 
        rule.action === request.action
    )

    // Step 3: Apply the rule effect
    // If no matching rule is found, deny by default
    if (!matchingRule) {
      const decision: EnforcementDecision = {
        allowed: false,
        policyVersion: this.activePolicyVersion,
        identity: request.identity,
        resource: request.resource,
        action: request.action,
        reason: `Denied by default - no matching authorization rule for ${request.identity.role} to ${request.action} ${request.resource}`,
        auditId: `audit-${this.auditCounter}`
      }
      
      this.recordAudit(decision)
      return decision
    }

    // Step 4: Apply the rule effect
    if (matchingRule.effect === 'allow') {
      const decision: EnforcementDecision = {
        allowed: true,
        policyVersion: this.activePolicyVersion,
        identity: request.identity,
        resource: request.resource,
        action: request.action,
        reason: `Allowed - ${request.identity.role} is permitted to ${matchingRule.action} ${matchingRule.resource}`,
        auditId: `audit-${this.auditCounter}`
      }
      
      this.recordAudit(decision)
      return decision
    } else if (matchingRule.effect === 'deny') {
      const decision: EnforcementDecision = {
        allowed: false,
        policyVersion: this.activePolicyVersion,
        identity: request.identity,
        resource: request.resource,
        action: request.action,
        reason: `Denied - ${request.identity.role} is explicitly denied from ${matchingRule.action} ${matchingRule.resource}`,
        auditId: `audit-${this.auditCounter}`
      }
      
      this.recordAudit(decision)
      return decision
    }

    // Fallback - should never reach here
    const decision: EnforcementDecision = {
      allowed: false,
      policyVersion: this.activePolicyVersion,
      identity: request.identity,
      resource: request.resource,
      action: request.action,
      reason: 'Denied - enforcement error: rule effect unrecognized',
      auditId: `audit-${this.auditCounter}`
    }
    
    this.recordAudit(decision)
    return decision
  }

  /** Record an audit event for the enforcement decision. */
  private recordAudit(decision: EnforcementDecision): void {
    // In a real implementation, this would write to a persistent audit store
    // For now, we just track the count
    // Console logging is avoided in production to prevent log injection
  }

  /** Get the current active policy version. */
  getActivePolicyVersion(): number {
    return this.activePolicyVersion
  }

  /** Get the current policy rules. */
  getPolicyRules(): ReadonlyArray<{ subject: string; resource: string; action: string; effect: 'allow' | 'deny' }> {
    return this.policyRules
  }
}

/**
 * Create an enforcement service with initial policy rules.
 * 
 * @param initialPolicyVersion The initially active policy version
 * @param initialRules The initial policy rules (deny-by-default means empty rules = all denied)
 * @returns A configured enforcement service
 */
export function createEnforcementService(
  initialPolicyVersion: number = 1,
  initialRules: Array<{ subject: string; resource: string; action: string; effect: 'allow' | 'deny' }> = []
): EnforcementService {
  return new EnforcementService(initialPolicyVersion, initialRules)
}

/**
 * Example: A policy with two identities and two resources.
 * 
 * This demonstrates the deny-by-default semantics:
 * - If there's no matching rule, the operation is DENIED
 * - Only explicitly permitted operations (allow rules) are allowed
 * - An agent claiming authorization makes no difference
 */
export const DEMO_ENFORCEMENT = createEnforcementService(1, [
  // Allow: reader can read public documents
  { subject: 'reader', resource: 'public-document', action: 'read', effect: 'allow' },
  // Deny: reader cannot read confidential records (explicit deny)
  { subject: 'reader', resource: 'confidential-record', action: 'read', effect: 'deny' },
  // Allow: admin can administer the admin panel
  { subject: 'admin', resource: 'admin-panel', action: 'write', effect: 'allow' }
])
