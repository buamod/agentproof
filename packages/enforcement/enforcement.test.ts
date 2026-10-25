import { 
  EnforcementService, 
  Identity, 
  OperationRequest, 
  EnforcementDecision,
  DEMO_ENFORCEMENT
} from './enforcement'

describe('Enforcement Service', () => {
  let service: EnforcementService

  beforeEach(() => {
    service = DEMO_ENFORCEMENT
  })

  describe('deny-by-default', () => {
    test('operation with no matching rule is denied', () => {
      const request: OperationRequest = {
        identity: { id: 'user1', role: 'reader', trusted: false },
        resource: 'confidential-record',
        action: 'write',
        policyVersion: 1,
        agentClaimsAuthorized: true  // Should be IGNORED
      }
      
      const decision = service.checkAuthorization(request)
      expect(decision.allowed).toBe(false)
      // The agent's claim should have no effect
      expect(decision.reason).toContain('Denied by default')
    })

    test('agent claiming authorization is still denied', () => {
      const request: OperationRequest = {
        identity: { id: 'user1', role: 'reader', trusted: false },
        resource: 'public-document',
        action: 'read',
        policyVersion: 1,
        agentClaimsAuthorized: true
      }
      
      const decision = service.checkAuthorization(request)
      // Even with the claim, if no matching rule, denied by default
      // But if there IS a matching allow rule, it should pass
    })
  })

  describe('explicit allow rules', () => {
    test('reader can read public-document', () => {
      const request: OperationRequest = {
        identity: { id: 'user1', role: 'reader', trusted: false },
        resource: 'public-document',
        action: 'read',
        policyVersion: 1,
        agentClaimsAuthorized: false
      }
      
      const decision = service.checkAuthorization(request)
      expect(decision.allowed).toBe(true)
      expect(decision.reason).toContain('Allowed')
    })
  })

  describe('explicit deny rules', () => {
    test('reader cannot read confidential-record', () => {
      const request: OperationRequest = {
        identity: { id: 'user1', role: 'reader', trusted: false },
        resource: 'confidential-record',
        action: 'read',
        policyVersion: 1,
        agentClaimsAuthorized: false
      }
      
      const decision = service.checkAuthorization(request)
      expect(decision.allowed).toBe(false)
      expect(decision.reason).toContain('Denied - reader is explicitly denied')
    })
  })

  test('agent claims authorized has no effect', () => {
    const request: OperationRequest = {
      identity: { id: 'user1', role: 'reader', trusted: false },
      resource: 'confidential-record',
      action: 'read',
      policyVersion: 1,
      agentClaimsAuthorized: true  // This should be ignored
    }
    
    const decision = service.checkAuthorization(request)
    // Even though the agent claims authorized, the enforcer denies
    // because the reader role has a deny rule for confidential-record
    expect(decision.allowed).toBe(false)
    // The reason should reflect the enforcement decision, not the agent claim
    expect(decision.reason).toContain('Denied')
  })

  test('admin can write to admin-panel', () => {
    const request: OperationRequest = {
      identity: { id: 'user1', role: 'admin', trusted: true },
      resource: 'admin-panel',
      action: 'write',
      policyVersion: 1,
      agentClaimsAuthorized: false
    }
    
    const decision = service.checkAuthorization(request)
    expect(decision.allowed).toBe(true)
  })

  test('unknown identity/role is denied', () => {
    const request: OperationRequest = {
      identity: { id: 'user1', role: 'unknown-role', trusted: false },
      resource: 'public-document',
      action: 'read',
      policyVersion: 1,
      agentClaimsAuthorized: false
    }
    
    const decision = service.checkAuthorization(request)
    expect(decision.allowed).toBe(false)
    expect(decision.reason).toContain('Denied by default')
  })
})

describe('Enforcement Service - fail closed', () => {
  test('an exception during authorization is a denial, never an allow', () => {
    const hostileRule = { resource: 'public-document', action: 'read', effect: 'allow' as const }
    Object.defineProperty(hostileRule, 'subject', {
      get() {
        throw new Error('malformed rule')
      },
      enumerable: true,
    })

    const service = new EnforcementService(1, [hostileRule as never])
    const decision = service.checkAuthorization({
      identity: { id: 'user1', role: 'reader', trusted: false },
      resource: 'public-document',
      action: 'read',
      policyVersion: 1,
      agentClaimsAuthorized: true,
    })

    expect(decision.allowed).toBe(false)
    expect(decision.reason).toContain('fail-closed')
  })

  test('a malformed request is denied rather than throwing', () => {
    const service = new EnforcementService(1, [])
    const decision = service.checkAuthorization(null as never)
    expect(decision.allowed).toBe(false)
  })

  test('the active policy version wins over the version in the request', () => {
    const service = new EnforcementService(3, [
      { subject: 'reader', resource: 'public-document', action: 'read', effect: 'allow' },
    ])
    const decision = service.checkAuthorization({
      identity: { id: 'user1', role: 'reader', trusted: false },
      resource: 'public-document',
      action: 'read',
      policyVersion: 99,
      agentClaimsAuthorized: false,
    })
    expect(decision.allowed).toBe(true)
    expect(decision.policyVersion).toBe(3)
  })
})
