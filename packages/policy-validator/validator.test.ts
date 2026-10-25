import { 
  validatePolicy, 
  MINIMAL_VALID_POLICY, 
  DEMO_POLICY, 
  INVALID_POLICY_UNKNOWN_FIELD 
} from './validator'

describe('Policy Contract Validator (Self-Contained)', () => {
  describe('valid policies accept', () => {
    test('accepts a minimal valid policy', () => {
      const result = validatePolicy(MINIMAL_VALID_POLICY)
      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    test('accepts the demo policy with two identities and two resources', () => {
      const result = validatePolicy(DEMO_POLICY)
      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })
  })

  describe('invalid policies are rejected (security critical)', () => {
    test('rejects policy missing required `version` field', () => {
      const badPolicy = {
        policyId: 'incomplete'
        // missing: version, rules
      }
      
      const result = validatePolicy(badPolicy)
      expect(result.valid).toBe(false)
      expect(result.errors.some(e => String(e.path).includes('version'))).toBe(true)
    })

    test('rejects policy missing required `rules` field', () => {
      const badPolicy = {
        policyId: 'incomplete',
        version: 1
        // missing: rules
      }
      
      const result = validatePolicy(badPolicy)
      expect(result.valid).toBe(false)
      expect(result.errors.some(e => String(e.path).includes('rules'))).toBe(true)
    })

    test('rejects policy with unknown security-critical fields (additionalProperties: false)', () => {
      const result = validatePolicy(INVALID_POLICY_UNKNOWN_FIELD)
      
      // CRITICAL: This is the security boundary.
      // unknown field must cause rejection, not be silently accepted
      expect(result.valid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
      // The error should mention the unknown field
      expect(result.errors.some(e => 
        String(e.path).includes('_dangerousField') || 
        String(e.message).includes('unknown')
      )).toBe(true)
    })

    test('rejects policy with missing required `rules` field', () => {
      const badPolicy = {
        policyId: 'bad-policy',
        version: 1
      }
      
      const result = validatePolicy(badPolicy)
      expect(result.valid).toBe(false)
      expect(result.errors.some(e => String(e.path).includes('rules'))).toBe(true)
    })

    test('rejects policy with missing required `policyId` field', () => {
      const badPolicy = {
        version: 1,
        rules: []
      }
      
      const result = validatePolicy(badPolicy)
      expect(result.valid).toBe(false)
      expect(result.errors.some(e => String(e.path).includes('policyId'))).toBe(true)
    })

    test('rejects policy with invalid effect (not allow/deny)', () => {
      const badPolicy = {
        policyId: 'bad-policy',
        version: 1,
        rules: [
          {
            subject: 'admin',
            resource: 'admin-panel',
            action: 'write',
            effect: 'permissions'  // invalid effect
          }
        ]
      }
      
      const result = validatePolicy(badPolicy)
      expect(result.valid).toBe(false)
      expect(result.errors.some(e => String(e.path).includes('effect'))).toBe(true)
    })

    test('rejects rule with unknown fields (additionalProperties: false)', () => {
      const badPolicy = {
        policyId: 'bad-policy',
        version: 1,
        rules: [
          {
            subject: 'admin',
            resource: 'admin-panel',
            action: 'write',
            effect: 'allow',
            // Unknown field in rule - should be rejected
            _dangerousField: 'should_be_rejected'
          }
        ]
      }
      
      const result = validatePolicy(badPolicy)
      expect(result.valid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })
  })

  describe('deny-by-default semantics', () => {
    test('validator structurally validates; deny-by-default enforced at enforcement layer', () => {
      // Policy with only allow rules passes structural validation
      const policy = {
        policyId: 'deny-demo',
        version: 1,
        rules: [
          {
            subject: 'reader',
            resource: 'confidential-record',
            action: 'read',
            effect: 'allow'
          }
        ]
      }
      
      const result = validatePolicy(policy)
      // Structural validation passes
      expect(result.valid).toBe(true)
      // But enforcement layer (separate component) denies by default
      // This is key separation of concerns
    })
  })
})
