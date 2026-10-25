/**
 * Deterministic Scenario Format
 *
 * A scenario is pure data: preconditions, actions, expected enforcement
 * decisions, expected final state, and required evidence. Changing a scenario
 * never requires code changes.
 *
 * Scenarios are validated before execution. AI-generated scenarios must pass
 * exactly the same validator as hand-authored ones.
 */

export type ScenarioActionType = 'read' | 'write'
export type ExpectedDecision = 'allow' | 'deny'
export type ExpectedChange = 'unchanged' | 'changed'

export interface ScenarioResource {
  id: string
  classification: 'public' | 'confidential'
  content: string
}

export interface ScenarioPolicyRule {
  subject: string
  resource: string
  action: string
  effect: 'allow' | 'deny'
}

export interface ScenarioAction {
  identityId: string
  identityRole: string
  identityTrusted: boolean
  resource: string
  action: ScenarioActionType
  payload?: string
  expectedDecision: ExpectedDecision
  /** Whether the agent claims it is authorized. Must never influence enforcement. */
  agentClaimsAuthorized?: boolean
}

export interface ScenarioExpectedState {
  resource: string
  change: ExpectedChange
}

export interface Scenario {
  scenarioId: string
  version: number
  threatCategory: string
  description: string
  policyVersion: number
  policyRules: ScenarioPolicyRule[]
  resources: ScenarioResource[]
  actions: ScenarioAction[]
  expectedState: ScenarioExpectedState[]
  requiredEvidence: string[]
}

export interface ScenarioValidationError {
  path: string[]
  message: string
}

export interface ScenarioValidationResult {
  valid: boolean
  errors: ScenarioValidationError[]
}

const KNOWN_ACTIONS: ScenarioActionType[] = ['read', 'write']
const KNOWN_EFFECTS = ['allow', 'deny']
const KNOWN_EVIDENCE = [
  'pre-state',
  'post-state',
  'decision-log',
  'access-log',
  'mutation-log',
  'policy-version',
]

/**
 * Deterministically validate a scenario before it is allowed to execute.
 * Rejects unknown actions, unknown resources, unknown evidence kinds,
 * and references that cannot be resolved.
 */
export function validateScenario(scenario: unknown): ScenarioValidationResult {
  const errors: ScenarioValidationError[] = []

  if (typeof scenario !== 'object' || scenario === null || Array.isArray(scenario)) {
    return { valid: false, errors: [{ path: [], message: 'Scenario must be a non-null object' }] }
  }

  const s = scenario as Record<string, unknown>

  if (typeof s.scenarioId !== 'string' || s.scenarioId.length === 0) {
    errors.push({ path: ['scenarioId'], message: 'scenarioId is required and must be a non-empty string' })
  }
  if (typeof s.version !== 'number' || !Number.isInteger(s.version) || s.version < 1) {
    errors.push({ path: ['version'], message: 'version is required and must be an integer >= 1' })
  }
  if (typeof s.threatCategory !== 'string' || s.threatCategory.length === 0) {
    errors.push({ path: ['threatCategory'], message: 'threatCategory is required' })
  }
  if (typeof s.policyVersion !== 'number' || !Number.isInteger(s.policyVersion) || s.policyVersion < 1) {
    errors.push({ path: ['policyVersion'], message: 'policyVersion is required and must be an integer >= 1' })
  }

  const resources = Array.isArray(s.resources) ? (s.resources as Array<Record<string, unknown>>) : []
  if (!Array.isArray(s.resources) || resources.length === 0) {
    errors.push({ path: ['resources'], message: 'resources must be a non-empty array' })
  }

  const resourceIds = new Set<string>()
  for (let i = 0; i < resources.length; i++) {
    const r = resources[i]
    if (typeof r.id !== 'string' || r.id.length === 0) {
      errors.push({ path: ['resources', String(i), 'id'], message: 'resource id is required' })
      continue
    }
    resourceIds.add(r.id)
    if (r.classification !== 'public' && r.classification !== 'confidential') {
      errors.push({ path: ['resources', String(i), 'classification'], message: 'classification must be public or confidential' })
    }
    if (typeof r.content !== 'string') {
      errors.push({ path: ['resources', String(i), 'content'], message: 'content must be a string' })
    }
  }

  const rules = Array.isArray(s.policyRules) ? (s.policyRules as Array<Record<string, unknown>>) : []
  if (!Array.isArray(s.policyRules)) {
    errors.push({ path: ['policyRules'], message: 'policyRules must be an array' })
  }
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i]
    if (typeof rule.subject !== 'string') {
      errors.push({ path: ['policyRules', String(i), 'subject'], message: 'rule subject is required' })
    }
    if (typeof rule.resource !== 'string') {
      errors.push({ path: ['policyRules', String(i), 'resource'], message: 'rule resource is required' })
    }
    if (typeof rule.action !== 'string') {
      errors.push({ path: ['policyRules', String(i), 'action'], message: 'rule action is required' })
    }
    if (typeof rule.effect !== 'string' || !KNOWN_EFFECTS.includes(rule.effect)) {
      errors.push({ path: ['policyRules', String(i), 'effect'], message: 'effect must be allow or deny' })
    }
  }

  const actions = Array.isArray(s.actions) ? (s.actions as Array<Record<string, unknown>>) : []
  if (!Array.isArray(s.actions) || actions.length === 0) {
    errors.push({ path: ['actions'], message: 'actions must be a non-empty array' })
  }
  for (let i = 0; i < actions.length; i++) {
    const a = actions[i]
    if (typeof a.identityId !== 'string' || a.identityId.length === 0) {
      errors.push({ path: ['actions', String(i), 'identityId'], message: 'identityId is required' })
    }
    if (typeof a.identityRole !== 'string' || a.identityRole.length === 0) {
      errors.push({ path: ['actions', String(i), 'identityRole'], message: 'identityRole is required' })
    }
    if (typeof a.identityTrusted !== 'boolean') {
      errors.push({ path: ['actions', String(i), 'identityTrusted'], message: 'identityTrusted must be a boolean' })
    }
    if (typeof a.resource !== 'string' || !resourceIds.has(a.resource)) {
      errors.push({ path: ['actions', String(i), 'resource'], message: `resource must reference a declared resource (got ${String(a.resource)})` })
    }
    if (typeof a.action !== 'string' || !KNOWN_ACTIONS.includes(a.action as ScenarioActionType)) {
      errors.push({ path: ['actions', String(i), 'action'], message: 'action must be read or write' })
    }
    if (a.expectedDecision !== 'allow' && a.expectedDecision !== 'deny') {
      errors.push({ path: ['actions', String(i), 'expectedDecision'], message: 'expectedDecision must be allow or deny' })
    }
    if (a.action === 'write' && a.payload !== undefined && typeof a.payload !== 'string') {
      errors.push({ path: ['actions', String(i), 'payload'], message: 'payload must be a string when present' })
    }
  }

  const expectedState = Array.isArray(s.expectedState) ? (s.expectedState as Array<Record<string, unknown>>) : []
  if (!Array.isArray(s.expectedState) || expectedState.length === 0) {
    errors.push({ path: ['expectedState'], message: 'expectedState must be a non-empty array' })
  }
  for (let i = 0; i < expectedState.length; i++) {
    const e = expectedState[i]
    if (typeof e.resource !== 'string' || !resourceIds.has(e.resource)) {
      errors.push({ path: ['expectedState', String(i), 'resource'], message: 'expectedState must reference a declared resource' })
    }
    if (e.change !== 'unchanged' && e.change !== 'changed') {
      errors.push({ path: ['expectedState', String(i), 'change'], message: 'change must be unchanged or changed' })
    }
  }

  const requiredEvidence = Array.isArray(s.requiredEvidence) ? (s.requiredEvidence as string[]) : []
  if (!Array.isArray(s.requiredEvidence) || requiredEvidence.length === 0) {
    errors.push({ path: ['requiredEvidence'], message: 'requiredEvidence must be a non-empty array' })
  }
  for (let i = 0; i < requiredEvidence.length; i++) {
    if (!KNOWN_EVIDENCE.includes(requiredEvidence[i])) {
      errors.push({ path: ['requiredEvidence', String(i)], message: `unknown evidence kind: ${requiredEvidence[i]}` })
    }
  }

  return { valid: errors.length === 0, errors }
}
