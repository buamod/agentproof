import { executeScenario, DEFAULT_EXECUTOR, Executor } from './engine'
import { BASELINE_SCENARIOS, findScenario } from './scenarios'
import { validateScenario } from './scenario'

const fixedClock = () => 1700000000000

describe('Scenario validator', () => {
  test('all baseline scenarios are valid', () => {
    for (const scenario of BASELINE_SCENARIOS) {
      const result = validateScenario(scenario)
      expect(result.errors).toEqual([])
      expect(result.valid).toBe(true)
    }
  })

  test('rejects a scenario referencing an undeclared resource', () => {
    const bad = {
      ...findScenario('auth-read-allowed')!,
      actions: [
        { identityId: 'r', identityRole: 'reader', identityTrusted: false, resource: 'ghost', action: 'read', expectedDecision: 'allow' },
      ],
    }
    const result = validateScenario(bad)
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.message.includes('declared resource'))).toBe(true)
  })

  test('rejects unknown action types', () => {
    const bad = {
      ...findScenario('auth-read-allowed')!,
      actions: [
        { identityId: 'r', identityRole: 'reader', identityTrusted: false, resource: 'public-document', action: 'delete', expectedDecision: 'allow' },
      ],
    }
    const result = validateScenario(bad)
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.message.includes('read or write'))).toBe(true)
  })

  test('rejects unknown evidence kinds', () => {
    const bad = {
      ...findScenario('auth-read-allowed')!,
      requiredEvidence: ['pre-state', 'made-up-evidence'],
    }
    const result = validateScenario(bad)
    expect(result.valid).toBe(false)
    expect(result.errors.some(e => e.message.includes('unknown evidence'))).toBe(true)
  })
})

describe('Scenario execution harness', () => {
  test('valid scenario executes and produces a run record', () => {
    const scenario = findScenario('auth-read-allowed')!
    const run = executeScenario(scenario, { clock: fixedClock })
    expect(run.recorded).toBe(true)
    expect(run.record).toBeDefined()
    expect(run.record!.actionResults).toHaveLength(1)
  })

  test('invalid scenario is rejected and never executed', () => {
    const bad = { ...findScenario('auth-read-allowed')!, actions: [] }
    const run = executeScenario(bad, { clock: fixedClock })
    expect(run.recorded).toBe(false)
    expect(run.record).toBeUndefined()
    expect(run.validation.valid).toBe(false)
  })

  test('default executor denies an unauthorized write and leaves state untouched', () => {
    const scenario = findScenario('auth-write-denied')!
    const run = executeScenario(scenario, { clock: fixedClock })
    const record = run.record!
    expect(record.actionResults[0].decision.allowed).toBe(false)
    expect(record.actionResults[0].executed).toBe(false)
    expect(record.mutations).toHaveLength(0)
    expect(record.after['confidential-record'].content).toBe('SECRET-ORIGINAL')
  })

  test('default executor allows an authorized write and state changes', () => {
    const scenario = findScenario('auth-write-allowed')!
    const run = executeScenario(scenario, { clock: fixedClock })
    const record = run.record!
    expect(record.actionResults[0].decision.allowed).toBe(true)
    expect(record.actionResults[0].executed).toBe(true)
    expect(record.mutations).toHaveLength(1)
    expect(record.after['admin-panel'].content).toBe('ADMIN-PANEL-UPDATED')
  })

  test('each run starts from a fresh synthetic state', () => {
    const scenario = findScenario('auth-write-allowed')!
    const first = executeScenario(scenario, { clock: fixedClock })
    const second = executeScenario(scenario, { clock: fixedClock })
    expect(first.record!.before['admin-panel'].content).toBe('ADMIN-PANEL-ORIGINAL')
    expect(second.record!.before['admin-panel'].content).toBe('ADMIN-PANEL-ORIGINAL')
  })

  test('untrusted executor name is recorded for traceability', () => {
    const scenario = findScenario('auth-read-allowed')!
    const run = executeScenario(scenario, { clock: fixedClock, executorName: 'custom' })
    expect(run.record!.executorName).toBe('custom')
  })
})
