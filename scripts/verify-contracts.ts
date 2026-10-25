/**
 * Contract gate.
 *
 * Every policy and scenario shipped in the repository is re-validated here.
 * The gate exists so a malformed contract cannot reach the benchmark unnoticed:
 * a bad expectation or an unknown action would otherwise produce confident,
 * meaningless verdicts.
 */

import {
  validatePolicy,
  DEMO_POLICY,
  MINIMAL_VALID_POLICY,
  INVALID_POLICY_MISSING_FIELDS,
  INVALID_POLICY_UNKNOWN_FIELD,
} from '../packages/policy-validator/validator'
import { BASELINE_SCENARIOS } from '../packages/scenario-engine/scenarios'
import { validateScenario } from '../packages/scenario-engine/scenario'

const KNOWN_EVIDENCE = [
  'pre-state',
  'post-state',
  'decision-log',
  'access-log',
  'mutation-log',
  'policy-version',
]

const failures: string[] = []
let checks = 0

function expect(condition: boolean, message: string): void {
  checks++
  if (!condition) failures.push(message)
}

// ---------------------------------------------------------------- policies
for (const [name, policy] of Object.entries({
  'DEMO_POLICY': DEMO_POLICY,
  'MINIMAL_VALID_POLICY': MINIMAL_VALID_POLICY,
})) {
  const result = validatePolicy(policy)
  expect(result.valid, `${name} should be valid: ${result.errors.map(e => e.message).join('; ')}`)
}

for (const [name, policy] of Object.entries({
  'INVALID_POLICY_MISSING_FIELDS': INVALID_POLICY_MISSING_FIELDS,
  'INVALID_POLICY_UNKNOWN_FIELD': INVALID_POLICY_UNKNOWN_FIELD,
})) {
  const result = validatePolicy(policy)
  expect(!result.valid, `${name} must be rejected, but the validator accepted it`)
}

// --------------------------------------------------------------- scenarios
const ids = new Set<string>()

for (const scenario of BASELINE_SCENARIOS) {
  const result = validateScenario(scenario)
  expect(result.valid, `${scenario.scenarioId} is invalid: ${result.errors.map(e => e.message).join('; ')}`)
  expect(!ids.has(scenario.scenarioId), `duplicate scenarioId: ${scenario.scenarioId}`)
  ids.add(scenario.scenarioId)

  const resourceIds = new Set(scenario.resources.map(r => r.id))
  for (const action of scenario.actions) {
    expect(
      resourceIds.has(action.resource),
      `${scenario.scenarioId}: action references undeclared resource ${action.resource}`
    )
  }

  for (const kind of scenario.requiredEvidence) {
    expect(
      KNOWN_EVIDENCE.includes(kind),
      `${scenario.scenarioId}: unknown evidence kind ${kind}`
    )
  }
}

expect(BASELINE_SCENARIOS.length > 0, 'no baseline scenarios found')
expect(
  BASELINE_SCENARIOS.some(s => s.actions.some(a => a.expectedDecision === 'deny')),
  'the suite contains no denied action, so it cannot exercise a control boundary'
)

// ------------------------------------------------------------------ report
console.log('')
console.log('Contract gate')
console.log('='.repeat(60))
console.log(`policies validated:  ${Object.keys({ DEMO_POLICY, MINIMAL_VALID_POLICY }).length}`)
console.log(`invalid policies rejected: ${Object.keys({ INVALID_POLICY_MISSING_FIELDS, INVALID_POLICY_UNKNOWN_FIELD }).length}`)
console.log(`scenarios validated: ${BASELINE_SCENARIOS.length}`)
console.log(`assertions:          ${checks}`)
console.log('')

if (failures.length > 0) {
  console.error('Contract gate failed:\n')
  for (const failure of failures) console.error(`  - ${failure}`)
  process.exit(1)
}

console.log('All contracts valid.')
