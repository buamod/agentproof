/**
 * Security regression suite - Phase 2 exit criteria.
 *
 * Proves that:
 * 1. Every baseline scenario passes with a correct executor.
 * 2. Runs are reproducible.
 * 3. A deliberately broken executor is detected as FAIL by independent evidence.
 * 4. Missing evidence never produces PASS.
 * 5. Invalid scenarios never execute.
 */

import { executeScenario, Executor, DEFAULT_EXECUTOR } from '../../packages/scenario-engine/engine'
import { BASELINE_SCENARIOS } from '../../packages/scenario-engine/scenarios'
import { collectEvidence } from '../../packages/evidence-collector/evidence'
import { evaluateScenario, buildVerdictReport, VerdictReport } from '../../packages/verdict-engine/verdict'
import { validateScenario } from '../../packages/scenario-engine/scenario'

const fixedClock = () => 1700000000000

function runScenario(scenarioId: string, executor: Executor = DEFAULT_EXECUTOR) {
  const scenario = BASELINE_SCENARIOS.find(s => s.scenarioId === scenarioId)!
  const run = executeScenario(scenario, { clock: fixedClock, executor })
  const evidence = collectEvidence(run.record, scenario.requiredEvidence, { clock: fixedClock })
  const verdict = evaluateScenario(scenario, evidence)
  const report = buildVerdictReport(scenario, evidence, verdict, fixedClock)
  return { scenario, run, evidence, verdict, report }
}

/** Executor that performs the operation even when enforcement denies it. */
const failOpenExecutor: Executor = ({ request, store, enforcement }) => {
  const decision = enforcement.checkAuthorization(request)
  if (request.action === 'read') {
    store.read(request.identity.id, request.resource)
  } else {
    store.write(request.identity.id, request.resource, 'FAIL-OPEN-WRITE')
  }
  return { decision, executed: true }
}

describe('Baseline scenarios pass with a correct executor', () => {
  for (const scenario of BASELINE_SCENARIOS) {
    test(`${scenario.scenarioId} -> PASS`, () => {
      const { verdict } = runScenario(scenario.scenarioId)
      expect(verdict.verdict).toBe('PASS')
      expect(verdict.evidenceComplete).toBe(true)
    })
  }
})

describe('Reproducibility', () => {
  test('the same scenario produces byte-identical reports across runs', () => {
    const a = runScenario('multi-action-mixed').report
    const b = runScenario('multi-action-mixed').report
    expect(JSON.stringify(a)).toBe(JSON.stringify(b))
  })

  test('every baseline report is JSON-serializable and versioned', () => {
    for (const scenario of BASELINE_SCENARIOS) {
      const { report } = runScenario(scenario.scenarioId)
      const parsed: VerdictReport = JSON.parse(JSON.stringify(report))
      expect(parsed.scenarioId).toBe(scenario.scenarioId)
      expect(parsed.policyVersion).toBe(scenario.policyVersion)
      expect(parsed.scenarioVersion).toBe(scenario.version)
      expect(['PASS', 'FAIL', 'INCONCLUSIVE']).toContain(parsed.verdict)
    }
  })
})

describe('Known defects are detected by independent evidence', () => {
  const scenariosWithDeniedActions = BASELINE_SCENARIOS.filter(s =>
    s.actions.some(a => a.expectedDecision === 'deny')
  )

  test('the defect list is non-empty', () => {
    expect(scenariosWithDeniedActions.length).toBeGreaterThan(0)
  })

  for (const scenario of scenariosWithDeniedActions) {
    test(`fail-open enforcement is detected for ${scenario.scenarioId}`, () => {
      const { verdict } = runScenario(scenario.scenarioId, failOpenExecutor)
      expect(verdict.verdict).toBe('FAIL')
      // The failure must be attributable to observed state or denied access,
      // not merely to the enforcer's own report.
      const evidenceBasedFailure =
        verdict.invariants.some(i => i.id === 'state-integrity' && !i.passed) ||
        verdict.invariants.some(i => i.id === 'no-denied-access' && !i.passed) ||
        verdict.invariants.some(i => i.id === 'no-contradictions' && !i.passed)
      expect(evidenceBasedFailure).toBe(true)
    })
  }
})

describe('Missing evidence cannot produce a pass', () => {
  for (const scenario of BASELINE_SCENARIOS) {
    test(`missing decision log for ${scenario.scenarioId} -> INCONCLUSIVE`, () => {
      const run = executeScenario(scenario, { clock: fixedClock })
      const evidence = collectEvidence(run.record, scenario.requiredEvidence, {
        clock: fixedClock,
        drop: ['decision-log'],
      })
      const verdict = evaluateScenario(scenario, evidence)
      expect(verdict.verdict).not.toBe('PASS')
    })
  }
})

describe('Invalid scenarios never execute', () => {
  test('a scenario with an unknown action is rejected before running', () => {
    const bad = {
      ...BASELINE_SCENARIOS[0],
      scenarioId: 'invalid-scenario',
      actions: [
        {
          identityId: 'x',
          identityRole: 'reader',
          identityTrusted: false,
          resource: 'public-document',
          action: 'delete',
          expectedDecision: 'allow',
        },
      ],
    }
    const validation = validateScenario(bad)
    expect(validation.valid).toBe(false)

    const run = executeScenario(bad as never, { clock: fixedClock })
    expect(run.recorded).toBe(false)
    expect(run.record).toBeUndefined()
  })
})

describe('Suite summary', () => {
  test('reports an aggregate verdict table for all baseline scenarios', () => {
    const rows = BASELINE_SCENARIOS.map(s => ({
      scenarioId: s.scenarioId,
      threatCategory: s.threatCategory,
      verdict: runScenario(s.scenarioId).verdict.verdict,
    }))
    const passed = rows.filter(r => r.verdict === 'PASS').length
    // Every baseline scenario must pass with the correct executor.
    expect(passed).toBe(rows.length)
    expect(rows.every(r => r.verdict === 'PASS')).toBe(true)
  })
})
