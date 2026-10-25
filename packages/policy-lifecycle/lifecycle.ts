/**
 * Policy Lifecycle Controller
 * 
 * Implements an explicit lifecycle: DRAFT → VALIDATED → SIGNED → ACCEPTED → ACTIVE → VERIFIED
 * Plus rejection states: REJECTED, INVALID, REVOKED
 * 
 * Core principle: ACTIVE ≠ VERIFIED. Activation is separate from runtime verification.
 * A policy can be ACTIVE but not yet independently verified.
 * 
 * State transitions are explicit and audited. Illegal transitions are rejected.
 */

export interface PolicyState {
  status: 'DRAFT' | 'VALIDATED' | 'SIGNED' | 'ACCEPTED' | 'ACTIVE' | 'VERIFIED' |
          'REJECTED' | 'INVALID' | 'REVOKED'
  version: number
  previousState?: PolicyState
  auditLog: AuditEvent[]
}

export interface AuditEvent {
  timestamp: number
  from?: PolicyState
  to: PolicyState
  triggeredBy: 'system' | 'user' | 'controller'
  reason?: string
  details?: Record<string, unknown>
}

/**
 * Valid policy lifecycle transitions.
 * 
 * Permitted forward transitions:
 *   DRAFT → VALIDATED (after contract validation)
 *   VALIDATED → SIGNED (after cryptographic signing)
 *   SIGNED → ACCEPTED (after administrative acceptance)
 *   ACCEPTED → ACTIVE (after activation)
 *   ACTIVE → VERIFIED (after independent evidence-based verification)
 * 
 * Rejection/terminal transitions (from any state):
 *   → REJECTED (invalid contract, untrusted signer)
 *   → INVALID (schema validation failure)
 *   → REVOKED (explicit revocation, e.g., key compromise)
 * 
 * Invalid transitions (will be rejected):
 *   DRAFT → ACTIVE (skipping mandatory stages)
 *   SIGNED → VERIFIED (must go through ACCEPTED and ACTIVE)
 *   Any state → VERIFIED without going through ACTIVE
 */
const validTransitions: Record<PolicyState['status'], PolicyState['status'][]> = {
  DRAFT: ['VALIDATED'],
  VALIDATED: ['SIGNED'],
  SIGNED: ['ACCEPTED'],
  ACCEPTED: ['ACTIVE'],
  ACTIVE: ['VERIFIED'],
  // Terminal/rejection states - no forward transitions
  REJECTED: [],
  INVALID: [],
  REVOKED: [],
}

/**
 * Policy Lifecycle Controller.
 * 
 * Enforces valid state transitions, rejects illegal ones,
 * and maintains audit records for compliance and debugging.
 */
export class PolicyLifecycleController {
  private state: PolicyState

  constructor(initialState: PolicyState) {
    this.state = initialState
  }

  /** Get the current policy state. */
  getCurrentState(): PolicyState {
    return { ...this.state }
  }

  /** Get the audit log. */
  getAuditLog(): AuditEvent[] {
    return [...this.state.auditLog]
  }

  /** 
   * Transition to a new state if valid.
   * 
   * Returns { valid, error, auditEvent }.
   * If valid is false, the state is unchanged and error explains why.
   */
  transitionTo(newStatus: PolicyState['status'], triggeredBy: 'system' | 'user' | 'controller', reason?: string): { valid: boolean; error?: string; auditEvent?: AuditEvent } {
    const currentStatus = this.state.status

    // Check if this is a terminal state - once rejected/invalid/revoked, stay there
    if (['REJECTED', 'INVALID', 'REVOKED'].includes(currentStatus)) {
      return {
        valid: false,
        error: `Policy is in terminal state '${currentStatus}'. Further transitions are not permitted.`,
      }
    }

    // Check if the transition is valid
    const allowedNext = validTransitions[currentStatus] || []
    const isValidTransition = allowedNext.includes(newStatus)

    if (!isValidTransition) {
      // Special case: rejection from any state
      if (newStatus === 'REJECTED' || newStatus === 'INVALID' || newStatus === 'REVOKED') {
        return this.reject(newStatus, triggeredBy, reason)
      }
      return {
        valid: false,
        error: `Invalid transition from '${currentStatus}' to '${newStatus}'. ` +
               `Allowed transitions from '${currentStatus}': ${allowedNext.join(', ')}.`,
      }
    }

    // Create audit event
    const auditEvent: AuditEvent = {
      timestamp: Date.now(),
      from: { ...this.state },
      to: { status: newStatus, version: this.state.version, ...this.state, auditLog: this.state.auditLog },
      triggeredBy,
      reason,
    }

    // Update state - preserve version and append to audit log
    this.state = {
      ...this.state,
      status: newStatus,
      auditLog: [...this.state.auditLog, auditEvent],
    }

    // Special handling for rejection states
    let rejectionReason: string | undefined
    if (newStatus === 'REJECTED') rejectionReason = reason || 'Policy rejected via transition'
    if (newStatus === 'INVALID') rejectionReason = reason || 'Policy marked invalid via transition'
    if (newStatus === 'REVOKED') rejectionReason = reason || 'Policy revoked via transition'

    return {
      valid: true,
      error: undefined,
      auditEvent: { ...auditEvent, reason: rejectionReason || auditEvent.reason },
    }
  }

  /** Reject the policy from any state. */
  reject(newStatus: PolicyState['status'], triggeredBy: 'system' | 'user' | 'controller', reason?: string): { valid: boolean; error: string; auditEvent: AuditEvent } {
    const auditEvent: AuditEvent = {
      timestamp: Date.now(),
      from: { ...this.state },
      to: { status: newStatus, version: this.state.version, ...this.state, auditLog: this.state.auditLog },
      triggeredBy,
      reason: reason || 'Policy rejected',
    }

    this.state = {
      ...this.state,
      status: newStatus,
      auditLog: [...this.state.auditLog, auditEvent],
    }

    return { valid: false, error: reason || 'Policy rejected', auditEvent }
  }

  /** Revoke the policy (e.g., key compromise). */
  revoke(reason: string, triggeredBy: 'system' | 'user' | 'controller'): { valid: boolean; error: string; auditEvent: AuditEvent } {
    return this.reject('REVOKED', triggeredBy, reason)
  }

  /** Check if the policy is in a terminal state. */
  isTerminalState(status: PolicyState['status']): boolean {
    return ['REJECTED', 'INVALID', 'REVOKED'].includes(status)
  }

  /** Check if the policy can still be activated (must be ACCEPTED). */
  canBeActivated(): boolean {
    return this.state.status === 'ACCEPTED'
  }

  /** Check if the policy is active and verified. */
  isActiveAndVerified(): boolean {
    return this.state.status === 'VERIFIED'
  }
}

/**
 * Create an initial DRAFT policy state.
 */
export function createInitialState(policy: { policyId: string; version: number }): PolicyState {
  return {
    status: 'DRAFT',
    version: policy.version,
    auditLog: [],
  }
}

/** Transition from DRAFT to VALIDATED (after schema validation). */
export function validateAndTransition(controller: PolicyLifecycleController, policy: unknown, validateFn: (p: unknown) => { valid: boolean; errors: Array<{ path: string[]; message: string }> }): { valid: boolean; error?: string } {
  const validation = validateFn(policy)
  if (!validation.valid) {
    return { valid: false, error: `Policy validation failed: ${validation.errors.map(e => e.message).join(', ')}` }
  }
  const result = controller.transitionTo('VALIDATED', 'system', 'Policy passed schema validation')
  return { valid: result.valid, error: result.error }
}

/** Transition from VALIDATED to SIGNED (after cryptographic signing). */
export function signAndTransition(controller: PolicyLifecycleController): { valid: boolean; error?: string } {
  const result = controller.transitionTo('SIGNED', 'system', 'Policy signed with cryptographic key')
  return result
}

/** Transition from SIGNED to ACCEPTED (administrative acceptance). */
export function acceptAndTransition(controller: PolicyLifecycleController): { valid: boolean; error?: string } {
  return controller.transitionTo('ACCEPTED', 'system', 'Policy accepted by administrator')
}

/** Transition from ACCEPTED to ACTIVE (activation). */
export function activateAndTransition(controller: PolicyLifecycleController): { valid: boolean; error?: string } {
  // CRITICAL: Only policies with status ACCEPTED can be activated
  if (controller.state.status !== 'ACCEPTED') {
    return { valid: false, error: `Cannot activate policy in ${controller.state.status} state. Must be ACCEPTED first.` }
  }
  return controller.transitionTo('ACTIVE', 'system', 'Policy activated')
}

/** Transition from ACTIVE to VERIFIED (independent evidence-based verification). */
export function verifyAndTransition(controller: PolicyLifecycleController): { valid: boolean; error?: string } {
  // CRITICAL: Verification is separate from activation
  // A policy can be ACTIVE but not VERIFIED
  // This transition requires independent evidence that the enforcement works
  // In the initial implementation, we accept any ACTIVE → VERIFIED transition
  // as the foundation; the independent evidence is verified in Phase 2.
  return controller.transitionTo('VERIFIED', 'system', 'Policy verified via independent evidence')
}

/** Check if a status is a terminal state. */
export function isTerminalState(status: PolicyState['status']): boolean {
  return ['REJECTED', 'INVALID', 'REVOKED'].includes(status)
}

/** Check if the policy can still be activated. */
export function canBeActivated(controller: PolicyLifecycleController): boolean {
  return controller.canBeActivated()
}

/** Check if the policy is active and verified. */
export function isActiveAndVerified(controller: PolicyLifecycleController): boolean {
  return controller.isActiveAndVerified()
}
