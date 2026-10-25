import { executeScenario, Executor, DEFAULT_EXECUTOR } from '../scenario-engine/engine'
import { findScenario } from '../scenario-engine/scenarios'
import { collectEvidence } from '../evidence-collector/evidence'
import { evaluateScenario, buildVerdictReport } from './verdict'

const fixedClock = () => 1700000000000

function runAndEvaluate(scenarioId: string, executor: Executor = DEFAULT_EXECUTOR, drop: string[] = []) {
  const scenario = findScenario(scenarioId)!
  const run = executeScenario(scenario, { clock: fixedClock, executor })
  const evidence = collectEvidence(run.record, scenario.requiredEvidence, { clock: fixedClock, drop })
  return { scenario, run, evidence, verdict: evaluateScenario(scenario, evidence) }
}

describe('Verdict engine - correct behaviour passes', () => {
  test('authorized read passes', () => {
    const { verdict } = runAndEvaluate('auth-read-allowed')
    expect(verdict.verdict).toBe('PASS')
    expect(verdict.evidenceComplete).toBe(true)
  })

  test('denied read passes when state is untouched', () => {
    const { verdict } = runAndEvaluate('auth-read-denied')
    expect(verdict.verdict).toBe('PASS')
  })

  test('authorized write passes when state changes as expected', () => {
    const { verdict } = runAndEvaluate('auth-write-allowed')
    expect(verdict.verdict).toBe('PASS')
  })

  test('agent claim does not change the verdict', () => {
    const { verdict } = runAndEvaluate('agent-claims-authorized')
    expect(verdict.verdict).toBe('PASS')
  })
})

describe('Verdict engine - GOLDEN CASE: do not trust the enforcer', () => {
  test('enforcer reports denied but the record was written -> FAIL', () => {
    // This executor asks the enforcer (which says denied), then writes anyway
    // while reporting that it did not execute.
    const lyingExecutor: Executor = ({ request, store, enforcement }) => {
      const decision = enforcement.checkAuthorization(request)
      // Bypass: write even though the decision was deny.
      store.write(request.identity.id, request.resource, 'BYPASSED-WRITE')
      return { decision, executed: false }
    }

    const { verdict, evidence } = runAndEvaluate('auth-write-denied', lyingExecutor)

    // The enforcer's own response said "denied". A naive test would pass.
    // The independent evaluator must fail because observed state changed.
    expect(verdict.verdict).toBe('FAIL')
    const stateInvariant = verdict.invariants.find(i => i.id === 'state-integrity')!
    expect(stateInvariant.passed).toBe(false)
    expect(evidence.issues.some(i => i.kind === 'contradiction')).toBe(true)
  })

  test('enforcer reports allowed but nothing was written -> FAIL', () => {
    // Fabricated allow with no execution. Expected decision was deny.
    const misreportExecutor: Executor = ({ request }) => {
      return {
        decision: {
          allowed: true,
          policyVersion: request.policyVersion,
          identity: request.identity,
          resource: request.resource,
          action: request.action,
          reason: 'fabricated allow',
          auditId: 'fake',
        },
        executed: false,
      }
    }

    const { verdict } = runAndEvaluate('auth-write-denied', misreportExecutor)
    expect(verdict.verdict).toBe('FAIL')
    const enforcementInvariant = verdict.invariants.find(i => i.id === 'enforcement-decisions')!
    expect(enforcementInvariant.passed).toBe(false)
  })

  test('executor bypasses enforcement entirely and writes -> FAIL', () => {
    const bypassExecutor: Executor = ({ request, store }) => {
      store.write(request.identity.id, request.resource, 'DIRECT-BYPASS')
      return {
        decision: {
          allowed: true,
          policyVersion: request.policyVersion,
          identity: request.identity,
          resource: request.resource,
          action: request.action,
          reason: 'bypass',
          auditId: 'bypass',
        },
        executed: true,
      }
    }

    const { verdict } = runAndEvaluate('privilege-escalation', bypassExecutor)
    expect(verdict.verdict).toBe('FAIL')
    expect(verdict.invariants.find(i => i.id === 'enforcement-decisions')!.passed).toBe(false)
    expect(verdict.invariants.find(i => i.id === 'state-integrity')!.passed).toBe(false)
  })
})

describe('Verdict engine - missing evidence is never a pass', () => {
  test('missing decision log -> INCONCLUSIVE', () => {
    const { verdict } = runAndEvaluate('auth-read-allowed', DEFAULT_EXECUTOR, ['decision-log'])
    expect(verdict.verdict).toBe('INCONCLUSIVE')
    expect(verdict.evidenceComplete).toBe(false)
  })

  test('missing both snapshots -> INCONCLUSIVE', () => {
    const { verdict } = runAndEvaluate('auth-read-allowed', DEFAULT_EXECUTOR, ['pre-state', 'post-state'])
    expect(verdict.verdict).toBe('INCONCLUSIVE')
  })

  test('all evidence missing -> INCONCLUSIVE, never PASS', () => {
    const { verdict } = runAndEvaluate('auth-read-allowed', DEFAULT_EXECUTOR, [
      'pre-state', 'post-state', 'decision-log', 'access-log', 'mutation-log', 'policy-version',
    ])
    expect(verdict.verdict).toBe('INCONCLUSIVE')
  })

  test('scenario that never executed -> INCONCLUSIVE', () => {
    const scenario = { ...findScenario('auth-read-allowed')!, actions: [] }
    const run = executeScenario(scenario, { clock: fixedClock })
    const evidence = collectEvidence(run.record, scenario.requiredEvidence, { clock: fixedClock })
    const verdict = evaluateScenario(scenario, evidence)
    expect(verdict.verdict).toBe('INCONCLUSIVE')
  })
})

describe('Verdict engine - version and tampering', () => {
  test('wrong policy version observed -> FAIL', () => {
    const scenario = findScenario('auth-read-allowed')!
    const run = executeScenario(scenario, { clock: fixedClock })
    const evidence = collectEvidence(run.record, scenario.requiredEvidence, { clock: fixedClock })
    evidence.policyVersionObserved = 99
    const verdict = evaluateScenario(scenario, evidence)
    expect(verdict.verdict).toBe('FAIL')
    expect(verdict.invariants.find(i => i.id === 'policy-version-honored')!.passed).toBe(false)
  })
})

describe('Verdict report', () => {
  test('report is JSON-serializable and carries verdict metadata', () => {
    const { scenario, evidence, verdict } = runAndEvaluate('auth-read-allowed')
    const report = buildVerdictReport(scenario, evidence, verdict, fixedClock)
    const json = JSON.parse(JSON.stringify(report))
    expect(json.scenarioId).toBe('auth-read-allowed')
    expect(json.verdict).toBe('PASS')
    expect(json.policyVersion).toBe(1)
    expect(Array.isArray(json.invariants)).toBe(true)
  })
})
