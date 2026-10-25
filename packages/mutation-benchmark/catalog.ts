/**
 * Mutation catalog.
 *
 * Mutation testing here asks a different question from ordinary unit coverage:
 * if a security control is defective, does the suite return FAIL for a reason
 * that comes from evidence?
 *
 * Two kinds of entries:
 * - `defect`  a broken control or tampered record that MUST be caught
 * - `control` a correct but differently written executor that must NOT be caught
 *
 * Controls guard against a suite that "detects" everything by failing randomly.
 */

import {
  Executor,
  RunRecord,
  DEFAULT_EXECUTOR,
} from '../scenario-engine/engine'
import {
  EnforcementDecision,
  OperationRequest,
} from '../enforcement/enforcement'
import { ResourceStore } from '../resource-store/resource-store'

export type MutantKind = 'defect' | 'control'

export interface Mutation {
  id: string
  description: string
  kind: MutantKind
  /** Executor to use. Defaults to the correct executor when omitted. */
  executor?: Executor
  /** Optional tampering applied to the recorded run before evidence collection. */
  transformRecord?: (record: RunRecord) => RunRecord
}

function decide(
  request: OperationRequest,
  allowed: boolean,
  reason: string
): EnforcementDecision {
  return {
    allowed,
    policyVersion: request.policyVersion,
    identity: request.identity,
    resource: request.resource,
    action: request.action,
    reason,
    auditId: `mutant-${request.identity.id}`,
  }
}

function perform(
  request: OperationRequest,
  store: ResourceStore,
  payload?: string
): boolean {
  if (request.action === 'read') {
    return store.read(request.identity.id, request.resource) !== undefined
  }
  return store.write(request.identity.id, request.resource, payload ?? 'mutant-write')
}

export const MUTATIONS: Mutation[] = [
  // ---------------------------------------------------------------- defects
  {
    id: 'fail-open',
    kind: 'defect',
    description: 'Performs the operation even when enforcement denies it, and reports it honestly.',
    executor: ({ request, store, enforcement, payload }) => {
      const decision = enforcement.checkAuthorization(request)
      const executed = perform(request, store, payload)
      return { decision, executed }
    },
  },
  {
    id: 'fail-open-silent',
    kind: 'defect',
    description: 'Performs a denied operation but reports that it did not execute.',
    executor: ({ request, store, enforcement, payload }) => {
      const decision = enforcement.checkAuthorization(request)
      perform(request, store, payload)
      return { decision, executed: false }
    },
  },
  {
    id: 'allow-all',
    kind: 'defect',
    description: 'Never consults policy; allows and performs every action.',
    executor: ({ request, store, payload }) => {
      perform(request, store, payload)
      return { decision: decide(request, true, 'mutant: allow-all'), executed: true }
    },
  },
  {
    id: 'deny-all',
    kind: 'defect',
    description: 'Denies every action, including operations the policy permits.',
    executor: ({ request }) => ({
      decision: decide(request, false, 'mutant: deny-all'),
      executed: false,
    }),
  },
  {
    id: 'fabricated-allow',
    kind: 'defect',
    description: 'Reports an allow decision without evaluating policy or performing the action.',
    executor: ({ request }) => ({
      decision: decide(request, true, 'mutant: fabricated allow'),
      executed: false,
    }),
  },
  {
    id: 'read-leak',
    kind: 'defect',
    description: 'Reads denied resources but respects write denials.',
    executor: ({ request, store, enforcement }) => {
      const decision = enforcement.checkAuthorization(request)
      if (request.action === 'read') {
        const executed = perform(request, store)
        return { decision, executed }
      }
      if (!decision.allowed) return { decision, executed: false }
      return { decision, executed: perform(request, store) }
    },
  },
  {
    id: 'write-bypass',
    kind: 'defect',
    description: 'Writes denied resources but respects read denials.',
    executor: ({ request, store, enforcement, payload }) => {
      const decision = enforcement.checkAuthorization(request)
      if (request.action === 'write') {
        const executed = perform(request, store, payload)
        return { decision, executed }
      }
      if (!decision.allowed) return { decision, executed: false }
      return { decision, executed: perform(request, store) }
    },
  },
  {
    id: 'silent-no-op',
    kind: 'defect',
    description: 'Reports an allowed write as executed but never touches the store.',
    executor: ({ request, store, enforcement }) => {
      const decision = enforcement.checkAuthorization(request)
      if (!decision.allowed) return { decision, executed: false }
      if (request.action === 'write') {
        // Claims success without writing. Only state evidence can catch this.
        return { decision, executed: true }
      }
      return { decision, executed: perform(request, store) }
    },
  },
  {
    id: 'inverted-decisions',
    kind: 'defect',
    description: 'Inverts every authorization decision and acts on the inverted result.',
    executor: ({ request, store, enforcement, payload }) => {
      const actual = enforcement.checkAuthorization(request)
      const decision = decide(request, !actual.allowed, 'mutant: inverted decision')
      return {
        decision,
        executed: decision.allowed ? perform(request, store, payload) : false,
      }
    },
  },
  {
    id: 'identity-blind',
    kind: 'defect',
    description: 'Matches rules by resource and action only, ignoring the requesting role.',
    executor: ({ request, store, enforcement, payload }) => {
      const rule = enforcement
        .getPolicyRules()
        .find(r => r.resource === request.resource && r.action === request.action)
      const allowed = rule?.effect === 'allow'
      const decision = decide(request, allowed, 'mutant: identity-blind')
      return { decision, executed: allowed ? perform(request, store, payload) : false }
    },
  },
  {
    id: 'stale-policy-version',
    kind: 'defect',
    description: 'Runs the right policy but records the wrong policy version.',
    transformRecord: record => ({ ...record, policyVersion: 0 }),
  },

  // --------------------------------------------------------------- controls
  {
    id: 'control-default',
    kind: 'control',
    description: 'The reference executor.',
    executor: DEFAULT_EXECUTOR,
  },
  {
    id: 'control-explicit',
    kind: 'control',
    description: 'Correct executor written independently, with explicit guards.',
    executor: ({ request, store, enforcement, payload }) => {
      const decision = enforcement.checkAuthorization(request)
      if (decision.allowed !== true) return { decision, executed: false }
      if (request.action === 'read') {
        return { decision, executed: store.read(request.identity.id, request.resource) !== undefined }
      }
      return {
        decision,
        executed: store.write(request.identity.id, request.resource, payload ?? 'explicit-write'),
      }
    },
  },
  {
    id: 'control-cautious',
    kind: 'control',
    description: 'Correct executor that re-checks the resource exists before acting.',
    executor: ({ request, store, enforcement, payload }) => {
      const decision = enforcement.checkAuthorization(request)
      if (!decision.allowed) return { decision, executed: false }
      if (!store.listResourceIds().includes(request.resource)) {
        return { decision, executed: false }
      }
      if (request.action === 'read') {
        return { decision, executed: store.read(request.identity.id, request.resource) !== undefined }
      }
      return {
        decision,
        executed: store.write(request.identity.id, request.resource, payload ?? 'cautious-write'),
      }
    },
  },
]

export function findMutation(id: string): Mutation | undefined {
  return MUTATIONS.find(m => m.id === id)
}
