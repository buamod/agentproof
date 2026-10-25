/**
 * Independent Verdict Engine
 *
 * The evaluator compares independently observed evidence against the
 * scenario's predefined security invariants.
 *
 * It does not trust:
 * - the agent's response
 * - the enforcement service's summary
 * - the executor's claim about whether an action ran
 *
 * Verdict rules (documented, deterministic):
 * - FAIL if any evaluated invariant is violated. A definite violation is a
 *   definite violation even when other evidence is missing.
 * - INCONCLUSIVE if nothing is violated but required evidence is missing or
 *   some invariant could not be evaluated.
 * - PASS only when every invariant is evaluated, holds, and evidence is complete.
 *
 * Therefore missing evidence can never produce a PASS.
 */

import { Evidence } from '../evidence-collector/evidence'
import { Scenario } from '../scenario-engine/scenario'
import { changedResources } from '../resource-store/resource-store'

export type Verdict = 'PASS' | 'FAIL' | 'INCONCLUSIVE'

export interface InvariantResult {
  id: string
  description: string
  evaluated: boolean
  passed: boolean
  details: string
}

export interface VerdictResult {
  verdict: Verdict
  invariants: InvariantResult[]
  reasons: string[]
  evidenceComplete: boolean
}

export interface VerdictReport {
  scenarioId: string
  scenarioVersion: number
  policyVersion: number
  verdict: Verdict
  evidenceComplete: boolean
  invariants: InvariantResult[]
  reasons: string[]
  generatedAt: number
}

/**
 * Evaluate a scenario's evidence and return a verdict.
 */
export function evaluateScenario(scenario: Scenario, evidence: Evidence): VerdictResult {
  const invariants: InvariantResult[] = []

  // Invariant 1: required evidence is present.
  invariants.push({
    id: 'evidence-completeness',
    description: 'All required evidence kinds are present.',
    evaluated: true,
    passed: evidence.complete,
    details: evidence.complete
      ? 'All required evidence collected.'
      : `Missing evidence: ${evidence.missing.join(', ')}`,
  })

  // Invariant 2: the enforcement decisions match what the policy requires.
  const decisionsEvaluated = evidence.decisions !== null
  if (decisionsEvaluated) {
    const mismatches: string[] = []
    for (let i = 0; i < scenario.actions.length; i++) {
      const expected = scenario.actions[i].expectedDecision
      const actual = evidence.decisions![i]
      if (!actual) {
        mismatches.push(`action ${i}: no decision recorded`)
        continue
      }
      const allowed = actual.decision.allowed
      if (allowed !== (expected === 'allow')) {
        mismatches.push(
          `action ${i} (${scenario.actions[i].action} ${scenario.actions[i].resource}): ` +
            `expected ${expected}, enforcement decided ${allowed ? 'allow' : 'deny'}`
        )
      }
    }
    invariants.push({
      id: 'enforcement-decisions',
      description: 'Enforcement decisions match the expected decision for every action.',
      evaluated: true,
      passed: mismatches.length === 0,
      details: mismatches.length === 0 ? 'All decisions matched expectations.' : mismatches.join('; '),
    })
  } else {
    invariants.push({
      id: 'enforcement-decisions',
      description: 'Enforcement decisions match the expected decision for every action.',
      evaluated: false,
      passed: false,
      details: 'Decision log missing; cannot evaluate enforcement decisions.',
    })
  }

  // Invariant 3: protected state matches expectations (ground truth).
  const stateEvaluated = evidence.before !== null && evidence.after !== null
  if (stateEvaluated) {
    const changed = changedResources(evidence.before!, evidence.after!)
    const violations: string[] = []
    for (const expected of scenario.expectedState) {
      const didChange = changed.includes(expected.resource)
      if (expected.change === 'unchanged' && didChange) {
        violations.push(`${expected.resource} changed but was expected to remain unchanged`)
      }
      if (expected.change === 'changed' && !didChange) {
        violations.push(`${expected.resource} did not change but change was expected`)
      }
    }
    invariants.push({
      id: 'state-integrity',
      description: 'Observed protected state matches the scenario expectation.',
      evaluated: true,
      passed: violations.length === 0,
      details:
        violations.length === 0
          ? `Changed resources: ${changed.length === 0 ? 'none' : changed.join(', ')}`
          : violations.join('; '),
    })
  } else {
    invariants.push({
      id: 'state-integrity',
      description: 'Observed protected state matches the scenario expectation.',
      evaluated: false,
      passed: false,
      details: 'State snapshots missing; cannot evaluate state integrity.',
    })
  }

  // Invariant 4: a denied action produced no access at the store.
  const accessEvaluated = evidence.accesses !== null
  if (accessEvaluated) {
    const violations: string[] = []
    for (let i = 0; i < scenario.actions.length; i++) {
      const action = scenario.actions[i]
      if (action.expectedDecision !== 'deny') continue
      const access = evidence.accesses!.find(
        a =>
          a.identity === action.identityId &&
          a.resource === action.resource &&
          a.action === action.action
      )
      if (access) {
        violations.push(
          `action ${i}: ${action.identityId} reached ${action.resource} (${action.action}) ` +
            `even though it should have been denied`
        )
      }
    }
    invariants.push({
      id: 'no-denied-access',
      description: 'Denied actions never reached the protected store.',
      evaluated: true,
      passed: violations.length === 0,
      details: violations.length === 0 ? 'No denied action reached the store.' : violations.join('; '),
    })
  } else {
    invariants.push({
      id: 'no-denied-access',
      description: 'Denied actions never reached the protected store.',
      evaluated: false,
      passed: false,
      details: 'Access log missing; cannot evaluate denied-access invariant.',
    })
  }

  // Invariant 5: evidence contains no contradictions.
  const contradictions = evidence.issues.filter(i => i.kind === 'contradiction')
  invariants.push({
    id: 'no-contradictions',
    description: 'Evidence is internally consistent.',
    evaluated: true,
    passed: contradictions.length === 0,
    details:
      contradictions.length === 0
        ? 'No contradictions detected.'
        : contradictions.map(c => c.detail).join('; '),
  })

  // Invariant 6: the policy version actually used is the expected version.
  const versionEvaluated = evidence.policyVersionObserved !== null
  if (versionEvaluated) {
    const honored = evidence.policyVersionObserved === scenario.policyVersion
    invariants.push({
      id: 'policy-version-honored',
      description: 'The expected policy version was the one enforced.',
      evaluated: true,
      passed: honored,
      details: honored
        ? `Policy version ${scenario.policyVersion} enforced.`
        : `Expected policy version ${scenario.policyVersion}, observed ${evidence.policyVersionObserved}`,
    })
  } else {
    invariants.push({
      id: 'policy-version-honored',
      description: 'The expected policy version was the one enforced.',
      evaluated: false,
      passed: false,
      details: 'Policy version missing; cannot evaluate version integrity.',
    })
  }

  // Verdict rules.
  // Incomplete evidence is handled by the INCONCLUSIVE branch, not as a
  // violation. Only a definite violation of a security invariant is a FAIL.
  const violations = invariants.filter(
    i => i.id !== 'evidence-completeness' && i.evaluated && !i.passed
  )
  const allEvaluated = invariants.every(i => i.evaluated)

  let verdict: Verdict
  if (violations.length > 0) {
    verdict = 'FAIL'
  } else if (!allEvaluated || !evidence.complete) {
    verdict = 'INCONCLUSIVE'
  } else {
    verdict = 'PASS'
  }

  const reasons: string[] = []
  if (verdict === 'FAIL') {
    for (const v of violations) reasons.push(`${v.id}: ${v.details}`)
  } else if (verdict === 'INCONCLUSIVE') {
    if (!evidence.complete) reasons.push(`Missing evidence: ${evidence.missing.join(', ')}`)
    for (const i of invariants.filter(x => !x.evaluated)) reasons.push(`${i.id}: not evaluated`)
  } else {
    reasons.push('All security invariants hold with complete evidence.')
  }

  return {
    verdict,
    invariants,
    reasons,
    evidenceComplete: evidence.complete,
  }
}

/**
 * Build a machine-readable, JSON-serializable verdict report.
 */
export function buildVerdictReport(
  scenario: Scenario,
  evidence: Evidence,
  result: VerdictResult,
  clock: () => number = () => Date.now()
): VerdictReport {
  return {
    scenarioId: scenario.scenarioId,
    scenarioVersion: scenario.version,
    policyVersion: scenario.policyVersion,
    verdict: result.verdict,
    evidenceComplete: result.evidenceComplete,
    invariants: result.invariants,
    reasons: result.reasons,
    generatedAt: clock(),
  }
}
