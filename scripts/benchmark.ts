/**
 * AgentProof mutation benchmark.
 *
 * Usage:
 *   pnpm benchmark          human-readable table
 *   pnpm benchmark --json   machine-readable report on stdout
 */

import { runMutationBenchmark } from '../packages/mutation-benchmark/benchmark'
import { MUTATIONS } from '../packages/mutation-benchmark/catalog'

const clock = () => 1700000000000
const report = runMutationBenchmark({ clock })

if (process.argv.includes('--json')) {
  console.log(JSON.stringify(report, null, 2))
  process.exit(0)
}

const width = Math.max(...MUTATIONS.map(m => m.id.length), 'mutant'.length)

console.log('')
console.log('AgentProof mutation benchmark')
console.log('='.repeat(78))
console.log(
  `scenarios ${report.scenarioCount}   mutants ${report.mutantCount} ` +
    `(${report.defectCount} defects, ${report.controlCount} controls)`
)
console.log('')

console.log(`${'mutant'.padEnd(width)}  ${'kind'.padEnd(8)}  ${'result'.padEnd(8)}  caught by`)
console.log('-'.repeat(78))
for (const r of report.results) {
  const status = r.kind === 'control' ? (r.killed ? 'FALSE +' : 'ok') : r.killed ? 'killed' : 'SURVIVED'
  const detail = r.killed
    ? `${r.killedBy.length}/${report.scenarioCount} scenarios: ${r.killedBy.slice(0, 2).join(', ')}`
    : r.kind === 'control'
      ? 'all scenarios PASS'
      : 'no scenario FAILED'
  console.log(`${r.mutantId.padEnd(width)}  ${r.kind.padEnd(8)}  ${status.padEnd(8)}  ${detail}`)
}

console.log('')
console.log('-'.repeat(78))
console.log(`mutation score     ${report.killed}/${report.defectCount} defects killed ` +
  `(${(report.mutationScore * 100).toFixed(0)}%)`)
console.log(`false positives    ${report.falsePositiveCount}/${report.controlCount} correct executors flagged`)
console.log(`survivors          ${report.survived}`)
console.log('')

if (report.survived > 0 || report.falsePositiveCount > 0) {
  process.exitCode = 1
}
