import { runMutationBenchmark } from './benchmark'
import { MUTATIONS, findMutation } from './catalog'
import { executeScenario } from '../scenario-engine/engine'
import { findScenario } from '../scenario-engine/scenarios'
import { collectEvidence } from '../evidence-collector/evidence'
import { evaluateScenario } from '../verdict-engine/verdict'
import { Executor } from '../scenario-engine/engine'

const clock = () => 1700000000000
const report = runMutationBenchmark({ clock })

function resultOf(id: string) {
  const r = report.results.find(x => x.mutantId === id)
  if (!r) throw new Error(`missing mutant: ${id}`)
  return r
}

describe('Mutation benchmark - detection', () => {
  test('every defect mutant is killed by at least one scenario', () => {
    const survivors = report.results.filter(r => r.kind === 'defect' && !r.killed)
    expect(survivors.map(r => r.mutantId)).toEqual([])
    expect(report.survived).toBe(0)
    expect(report.mutationScore).toBe(1)
  })

  test('no mutant is killed for an evidence-completeness reason alone', () => {
    for (const result of report.results.filter(r => r.kind === 'defect')) {
      expect(result.failedInvariants.length).toBeGreaterThan(0)
      expect(result.failedInvariants).not.toContain('evidence-completeness')
    }
  })

  test('kill attribution is specific, not accidental', () => {
    expect(resultOf('read-leak').failedInvariants).toContain('no-denied-access')
    expect(resultOf('read-leak').failedInvariants).not.toContain('state-integrity')

    expect(resultOf('write-bypass').failedInvariants).toContain('state-integrity')

    expect(resultOf('silent-no-op').failedInvariants).toContain('state-integrity')

    expect(resultOf('stale-policy-version').failedInvariants).toEqual(['policy-version-honored'])

    expect(resultOf('deny-all').failedInvariants).toContain('enforcement-decisions')
  })

  test('the fail-open mutant is caught by state evidence, not by the enforcer report', () => {
    const r = resultOf('fail-open')
    expect(r.killed).toBe(true)
    expect(r.failedInvariants).toContain('state-integrity')
    expect(r.failedInvariants).toContain('no-denied-access')
  })

  test('the silent fail-open mutant is also caught as a contradiction', () => {
    const r = resultOf('fail-open-silent')
    expect(r.killed).toBe(true)
    expect(r.failedInvariants).toContain('no-contradictions')
  })
})

describe('Mutation benchmark - controls', () => {
  test('correct executors are never reported as failures', () => {
    const controls = report.results.filter(r => r.kind === 'control')
    expect(controls.length).toBeGreaterThan(0)
    for (const control of controls) {
      expect(control.killed).toBe(false)
      expect(control.killedBy).toEqual([])
      expect(control.survivedIn.length).toBe(report.scenarioCount)
    }
    expect(report.falsePositiveCount).toBe(0)
  })
})

describe('Mutation benchmark - report integrity', () => {
  test('the report is reproducible', () => {
    const again = runMutationBenchmark({ clock })
    expect(JSON.stringify(again)).toBe(JSON.stringify(report))
  })

  test('the report is JSON-serializable and internally consistent', () => {
    const parsed = JSON.parse(JSON.stringify(report))
    expect(parsed.mutantCount).toBe(MUTATIONS.length)
    expect(parsed.defectCount).toBe(MUTATIONS.filter(m => m.kind === 'defect').length)
    expect(parsed.controlCount).toBe(MUTATIONS.filter(m => m.kind === 'control').length)
    expect(parsed.killed + parsed.survived).toBe(parsed.defectCount)
    expect(parsed.results).toHaveLength(parsed.mutantCount)
    expect(parsed.scenarioCount).toBe(parsed.scenarioIds.length)
  })

  test('every scenario is exercised for every mutant', () => {
    for (const result of report.results) {
      expect(result.outcomes).toHaveLength(report.scenarioCount)
      expect(result.outcomes.map(o => o.scenarioId).sort()).toEqual([...report.scenarioIds].sort())
    }
  })

  test('an unknown mutant id is not silently invented', () => {
    expect(findMutation('does-not-exist')).toBeUndefined()
  })
})

/**
 * This test pins a known boundary of the method.
 *
 * If an adversary can rewrite the recorded post-state and the store logs
 * consistently, the falsified evidence looks like a correct run. Detecting that
 * requires tamper-evident, persisted evidence (not yet implemented). The test
 * documents the limit rather than pretending the benchmark covers it.
 */
describe('Known limitation - consistent evidence fabrication', () => {
  test('rewriting state and logs together is not detected', () => {
    const scenario = findScenario('auth-write-denied')!
    const clockFn = clock

    const byzantineExecutor: Executor = ({ request, enforcement }) => {
      // Simulate an attacker who acts after the fact and can rewrite the record.
      return { decision: enforcement.checkAuthorization(request), executed: false }
    }

    const run = executeScenario(scenario, { clock: clockFn, executor: byzantineExecutor })
    const record = {
      ...run.record!,
      after: run.record!.before,
      accesses: [],
      mutations: [],
    }

    const evidence = collectEvidence(record, scenario.requiredEvidence, { clock: clockFn })
    const verdict = evaluateScenario(scenario, evidence)

    expect(verdict.verdict).toBe('PASS')
  })
})
