/**
 * AgentProof - deterministic demo
 *
 * Demonstrates the core claim: a security control is judged by independent
 * evidence about protected state, not by what the enforcement service or the
 * agent says happened.
 *
 * Run: pnpm demo
 */

import { executeScenario, Executor, DEFAULT_EXECUTOR } from '../packages/scenario-engine/engine'
import { BASELINE_SCENARIOS, findScenario } from '../packages/scenario-engine/scenarios'
import { collectEvidence } from '../packages/evidence-collector/evidence'
import { evaluateScenario } from '../packages/verdict-engine/verdict'

const clock = () => 1700000000000

function banner(title: string): void {
  console.log('')
  console.log('='.repeat(72))
  console.log(title)
  console.log('='.repeat(72))
}

function run(scenarioId: string, executor: Executor = DEFAULT_EXECUTOR, drop: string[] = []) {
  const scenario = findScenario(scenarioId)!
  const result = executeScenario(scenario, { clock, executor })
  const evidence = collectEvidence(result.record, scenario.requiredEvidence, { clock, drop })
  const verdict = evaluateScenario(scenario, evidence)
  return { scenario, evidence, verdict }
}

function printVerdict(label: string, verdict: ReturnType<typeof evaluateScenario>): void {
  console.log('')
  console.log(`  ${label}`)
  console.log(`  verdict: ${verdict.verdict}`)
  for (const reason of verdict.reasons) {
    console.log(`    - ${reason}`)
  }
}

banner('1. A legitimate operation succeeds under a valid policy')
{
  const { verdict } = run('auth-read-allowed')
  printVerdict('reader reads public-document', verdict)
}

banner('2. A prohibited operation is denied and protected state is unchanged')
{
  const { verdict, evidence } = run('auth-write-denied')
  printVerdict('reader attempts to write confidential-record', verdict)
  console.log(`  confidential-record before: ${evidence.before!['confidential-record'].content}`)
  console.log(`  confidential-record after:  ${evidence.after!['confidential-record'].content}`)
}

banner('3. A broken control is caught by independent evidence')
{
  // The enforcer still says "denied", but the executor writes anyway.
  const failOpen: Executor = ({ request, store, enforcement }) => {
    const decision = enforcement.checkAuthorization(request)
    store.write(request.identity.id, request.resource, 'WRITTEN-DESPITE-DENIAL')
    return { decision, executed: false }
  }

  const { verdict, evidence } = run('auth-write-denied', failOpen)
  printVerdict('enforcer reports "denied" but the record was modified', verdict)
  console.log(`  enforcement said: ${evidence.decisions![0].decision.allowed ? 'allow' : 'deny'}`)
  console.log(`  confidential-record after: ${evidence.after!['confidential-record'].content}`)
  console.log(`  observed mutations: ${evidence.mutations!.length}`)
}

banner('4. Missing evidence produces INCONCLUSIVE, never PASS')
{
  const { verdict } = run('auth-read-allowed', DEFAULT_EXECUTOR, ['decision-log', 'post-state'])
  printVerdict('required evidence was dropped', verdict)
}

banner('5. Baseline suite summary')
{
  const rows = BASELINE_SCENARIOS.map(s => {
    const { verdict } = run(s.scenarioId)
    return { id: s.scenarioId, category: s.threatCategory, verdict: verdict.verdict }
  })

  const idWidth = Math.max(...rows.map(r => r.id.length))
  const catWidth = Math.max(...rows.map(r => r.category.length))
  for (const row of rows) {
    console.log(
      `  ${row.id.padEnd(idWidth)}  ${row.category.padEnd(catWidth)}  ${row.verdict}`
    )
  }

  const passed = rows.filter(r => r.verdict === 'PASS').length
  console.log('')
  console.log(`  ${passed}/${rows.length} scenarios passed with the correct executor.`)
}

banner('Done')
console.log('')
console.log('  PASS         all invariants hold with complete evidence')
console.log('  FAIL         a security invariant was violated')
console.log('  INCONCLUSIVE evidence was insufficient to decide')
console.log('')
