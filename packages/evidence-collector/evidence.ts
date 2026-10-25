/**
 * Evidence Collector
 *
 * Assembles the observations a verdict can be based on.
 *
 * Independence rule: state comes from resource snapshots and the store's own
 * access/mutation logs - not from the agent's report and not only from the
 * enforcement service's response.
 *
 * Missing evidence is represented as null so that "absent" and "empty" are
 * distinguishable. A scenario with no accesses is not missing an access log.
 */

import { RunRecord, ActionRecord } from '../scenario-engine/engine'
import {
  ResourceSnapshot,
  AccessEvent,
  MutationEvent,
} from '../resource-store/resource-store'

export interface EvidenceIssue {
  kind: 'missing' | 'contradiction'
  detail: string
}

export interface Evidence {
  scenarioId: string
  scenarioVersion: number
  policyVersionObserved: number | null
  before: ResourceSnapshot | null
  after: ResourceSnapshot | null
  decisions: ActionRecord[] | null
  accesses: AccessEvent[] | null
  mutations: MutationEvent[] | null
  requiredEvidence: string[]
  complete: boolean
  missing: string[]
  issues: EvidenceIssue[]
  collectedAt: number
}

export interface CollectOptions {
  /**
   * Simulate missing evidence for failure-path testing.
   * Any evidence kind listed here is set to null before completeness is checked.
   */
  drop?: string[]
  clock?: () => number
}

const ALL_KINDS = [
  'pre-state',
  'post-state',
  'decision-log',
  'access-log',
  'mutation-log',
  'policy-version',
]

/**
 * Collect evidence from a run record.
 *
 * If the run never happened (invalid scenario rejected before execution),
 * pass undefined and every piece of evidence is reported missing.
 */
export function collectEvidence(
  record: RunRecord | undefined,
  requiredEvidence: string[] = ALL_KINDS,
  options: CollectOptions = {}
): Evidence {
  const clock = options.clock ?? (() => Date.now())
  const drop = new Set(options.drop ?? [])

  let before: ResourceSnapshot | null = record ? record.before : null
  let after: ResourceSnapshot | null = record ? record.after : null
  let decisions: ActionRecord[] | null = record ? record.actionResults : null
  let accesses: AccessEvent[] | null = record ? record.accesses : null
  let mutations: MutationEvent[] | null = record ? record.mutations : null
  let policyVersionObserved: number | null = record ? record.policyVersion : null

  if (drop.has('pre-state')) before = null
  if (drop.has('post-state')) after = null
  if (drop.has('decision-log')) decisions = null
  if (drop.has('access-log')) accesses = null
  if (drop.has('mutation-log')) mutations = null
  if (drop.has('policy-version')) policyVersionObserved = null

  const missing: string[] = []
  for (const kind of requiredEvidence) {
    if (kind === 'pre-state' && before === null) missing.push(kind)
    if (kind === 'post-state' && after === null) missing.push(kind)
    if (kind === 'decision-log' && decisions === null) missing.push(kind)
    if (kind === 'access-log' && accesses === null) missing.push(kind)
    if (kind === 'mutation-log' && mutations === null) missing.push(kind)
    if (kind === 'policy-version' && policyVersionObserved === null) missing.push(kind)
  }

  const issues: EvidenceIssue[] = missing.map(kind => ({
    kind: 'missing' as const,
    detail: `Required evidence missing: ${kind}`,
  }))

  // Contradiction detection: an operation the executor reports as not executed
  // shows up in the store's independent logs anyway. That is exactly the
  // fail-open / misreport pattern we must catch.
  if (decisions && accesses) {
    for (const action of decisions) {
      if (action.executed) continue
      const matchingAccess = accesses.find(
        a =>
          a.identity === action.request.identity.id &&
          a.resource === action.request.resource &&
          a.action === action.request.action
      )
      if (matchingAccess) {
        issues.push({
          kind: 'contradiction',
          detail:
            `Contradiction: action ${action.index} reported not executed, ` +
            `but the store recorded a ${matchingAccess.action} of ${matchingAccess.resource}.`,
        })
      }
    }
  }

  return {
    scenarioId: record ? record.scenarioId : 'unknown',
    scenarioVersion: record ? record.scenarioVersion : 0,
    policyVersionObserved,
    before,
    after,
    decisions,
    accesses,
    mutations,
    requiredEvidence: [...requiredEvidence],
    complete: missing.length === 0,
    missing,
    issues,
    collectedAt: clock(),
  }
}
