import { 
  PolicyLifecycleController, 
  PolicyState, 
  createInitialState,
  validateAndTransition,
  signAndTransition,
  acceptAndTransition,
  activateAndTransition,
  verifyAndTransition,
  isTerminalState,
  canBeActivated,
  isActiveAndVerified
} from './lifecycle'
import { validatePolicy } from '../policy-validator/validator'

describe('Policy Lifecycle Controller - Full Lifecycle', () => {
  test('complete lifecycle: DRAFT to VERIFIED', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))

    // DRAFT → VALIDATED
    let result = controller.transitionTo('VALIDATED', 'system', 'Initial validation')
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('VALIDATED')

    // VALIDATED → SIGNED
    result = controller.transitionTo('SIGNED', 'system', 'Key signing')
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('SIGNED')

    // SIGNED → ACCEPTED
    result = controller.transitionTo('ACCEPTED', 'system', 'Administrative acceptance')
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('ACCEPTED')

    // ACCEPTED → ACTIVE
    result = controller.transitionTo('ACTIVE', 'system', 'Policy activation')
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('ACTIVE')

    // ACTIVE → VERIFIED
    result = controller.transitionTo('VERIFIED', 'system', 'Independent evidence verification')
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('VERIFIED')
  })
})

describe('Lifecycle helper functions with proper chain setup', () => {
  test('validateAndTransition validates a policy and transitions', () => {
    const validPolicy = {
      policyId: 'valid-policy',
      version: 1,
      rules: [
        { subject: 'reader', resource: 'public-doc', action: 'read', effect: 'allow' }
      ]
    }
    
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    const result = validateAndTransition(controller, validPolicy, validatePolicy)
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('VALIDATED')
  })

  test('validateAndTransition rejects invalid policy', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    const invalidPolicy = {
      policyId: 'invalid'
      // missing: version, rules
    }
    
    const result = validateAndTransition(controller, invalidPolicy, validatePolicy)
    expect(result.valid).toBe(false)
    expect(controller.getCurrentState().status).toBe('DRAFT')
  })

  test('activateAndTransition works after ACCEPTED (full chain)', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    // Full chain: DRAFT → VALIDATED → SIGNED → ACCEPTED
    controller.transitionTo('VALIDATED', 'system', ' ')
    controller.transitionTo('SIGNED', 'system', 'Key signing')
    controller.transitionTo('ACCEPTED', 'system', 'Administrative acceptance')
    const result = activateAndTransition(controller)
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('ACTIVE')
  })

  test('verifyAndTransition works from ACTIVE (full chain)', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    // Full chain: DRAFT → VALIDATED → SIGNED → ACCEPTED → ACTIVE
    controller.transitionTo('VALIDATED', 'system', ' ')
    controller.transitionTo('SIGNED', 'system', 'Key signing')
    controller.transitionTo('ACCEPTED', 'system', 'Administrative acceptance')
    controller.transitionTo('ACTIVE', 'system', 'Policy activation')
    const result = verifyAndTransition(controller)
    expect(result.valid).toBe(true)
    expect(controller.getCurrentState().status).toBe('VERIFIED')
  })

  test('ACTIVE does not mean VERIFIED', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    // Full chain to ACTIVE
    controller.transitionTo('VALIDATED', 'system', ' ')
    controller.transitionTo('SIGNED', 'system', 'Key signing')
    controller.transitionTo('ACCEPTED', 'system', 'Administrative acceptance')
    controller.transitionTo('ACTIVE', 'system', 'Policy activation')
    expect(controller.getCurrentState().status).toBe('ACTIVE')
    expect(controller.isActiveAndVerified()).toBe(false)
  })
})

describe('Terminal state checks', () => {
  test('isTerminalState detects REJECTED', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    controller.transitionTo('REJECTED', 'system', ' ')
    expect(isTerminalState('REJECTED')).toBe(true)
    expect(isTerminalState('ACTIVE')).toBe(false)
  })

  test('canBeActivated only returns true from ACCEPTED', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    // DRAFT: cannot be activated
    expect(canBeActivated(controller)).toBe(false)
    // After transitioning to ACCEPTED via full chain
    controller.transitionTo('VALIDATED', 'system', ' ')
    controller.transitionTo('SIGNED', 'system', 'Key signing')
    controller.transitionTo('ACCEPTED', 'system', 'Administrative acceptance')
    expect(canBeActivated(controller)).toBe(true)
  })

  test('isActiveAndVerified only returns true from VERIFIED', () => {
    const controller = new PolicyLifecycleController(createInitialState({ policyId: 'test', version: 1 }))
    // DRAFT/ACTIVE: not verified
    expect(isActiveAndVerified(controller)).toBe(false)
    // After full chain to VERIFIED
    controller.transitionTo('VALIDATED', 'system', ' ')
    controller.transitionTo('SIGNED', 'system', 'Key signing')
    controller.transitionTo('ACCEPTED', 'system', 'Administrative acceptance')
    controller.transitionTo('ACTIVE', 'system', 'Policy activation')
    controller.transitionTo('VERIFIED', 'system', 'Verification')
    expect(isActiveAndVerified(controller)).toBe(true)
  })
})
