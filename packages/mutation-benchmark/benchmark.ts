/**
 * Mutation benchmark.
 *
 * A mutant is "killed" when at least one scenario in the suite returns FAIL for
 * it. A suite-level kill is the right unit: the benchmark measures whether the
 * suite as a whole notices that the control is broken.
 *
 * INCONCLUSIVE is not a kill. If a mutant makes evidence unavailable, the suite
 * has not proven the control is broken; that is a survival, reported as such.
 */

import { executeScenario } from '../scenario-engine/engine'
import { BASELINE_SCENARIOS } from '../scenario-engine/scenarios'
import { collectEvidence } from '../evidence-collector/evidence'
import { evaluateScenario, Verdict } from '../verdict-engine/verdict'
import { MUTATIONS, Mutation } from './catalog'

export interface ScenarioOutcome {
  scenarioId: string
  verdict: Verdict
  failedInvariants: string[]
}

export interface MutantResult {
  mutantId: string
  description: string
  kind: Mutation['kind']
  killed: boolean
  /** Scenarios that returned FAIL for this mutant. */
  killedBy: string[]
  /** Scenario outcomes that were not FAIL. */
  survivedIn: string[]
  /** Invariants observed failing anywhere for this mutant. */
  failedInvariants: string[]
  outcomes: ScenarioOutcome[]
}

export interface BenchmarkReport {
  generatedAt: number
  scenarioCount: number
  scenarioIds: string[]
  mutantCount: number
  defectCount: number
  controlCount: number
  killed: number
  survived: number
  /** killed / defectCount */
  mutationScore: number
  falsePositiveCount: number
  results: MutantResult[]
}

export interface BenchmarkOptions {
  mutations?: Mutation[]
  clock?: () => number
}

/**
 * Run every mutation against every scenario.
 * The default clock is fixed so reports are byte-identical across runs.
 */
export function runMutationBenchmark(options: BenchmarkOptions = {}): BenchmarkReport {
  const clock = options.clock ?? (() => 1700000000000)
  const mutations = options.mutations ?? MUTATIONS

  const results: MutantResult[] = mutations.map(mutation => {
    const outcomes: ScenarioOutcome[] = []

    for (const scenario of BASELINE_SCENARIOS) {
      const run = executeScenario(scenario, {
        clock,
        executor: mutation.executor,
        executorName: `mutant:${mutation.id}`,
      })

      if (!run.recorded || !run.record) {
        outcomes.push({
          scenarioId: scenario.scenarioId,
          verdict: 'INCONCLUSIVE',
          failedInvariants: ['scenario-not-executed'],
        })
        continue
      }

      const record = mutation.transformRecord ? mutation.transformRecord(run.record) : run.record
      const evidence = collectEvidence(record, scenario.requiredEvidence, { clock })
      const verdict = evaluateScenario(scenario, evidence)

      outcomes.push({
        scenarioId: scenario.scenarioId,
        verdict: verdict.verdict,
        failedInvariants: verdict.invariants
          .filter(i => i.evaluated && !i.passed && i.id !== 'evidence-completeness')
          .map(i => i.id),
      })
    }

    const killedBy = outcomes.filter(o => o.verdict === 'FAIL').map(o => o.scenarioId)
    const survivedIn = outcomes.filter(o => o.verdict !== 'FAIL').map(o => o.scenarioId)
    const failedInvariants = [...new Set(outcomes.flatMap(o => o.failedInvariants))].sort()

    return {
      mutantId: mutation.id,
      description: mutation.description,
      kind: mutation.kind,
      killed: killedBy.length > 0,
      killedBy,
      survivedIn,
      failedInvariants,
      outcomes,
    }
  })

  const defects = results.filter(r => r.kind === 'defect')
  const controls = results.filter(r => r.kind === 'control')
  const killed = defects.filter(r => r.killed).length
  const falsePositives = controls.filter(r => r.killed).length

  return {
    generatedAt: clock(),
    scenarioCount: BASELINE_SCENARIOS.length,
    scenarioIds: BASELINE_SCENARIOS.map(s => s.scenarioId),
    mutantCount: results.length,
    defectCount: defects.length,
    controlCount: controls.length,
    killed,
    survived: defects.length - killed,
    mutationScore: defects.length === 0 ? 0 : killed / defects.length,
    falsePositiveCount: falsePositives,
    results,
  }
}
