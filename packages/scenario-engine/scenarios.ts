/**
 * Baseline deterministic security scenarios.
 *
 * These run locally and in CI with no network access and no model calls.
 * Each scenario is traceable to a security invariant.
 */

import { Scenario } from './scenario'

const REQUIRED_EVIDENCE = [
  'pre-state',
  'post-state',
  'decision-log',
  'access-log',
  'mutation-log',
  'policy-version',
]

const DEMO_RESOURCES = [
  { id: 'public-document', classification: 'public' as const, content: 'public documentation v1' },
  { id: 'confidential-record', classification: 'confidential' as const, content: 'SECRET-ORIGINAL' },
  { id: 'admin-panel', classification: 'confidential' as const, content: 'ADMIN-PANEL-ORIGINAL' },
]

const DEMO_RULES = [
  { subject: 'reader', resource: 'public-document', action: 'read', effect: 'allow' as const },
  { subject: 'reader', resource: 'confidential-record', action: 'read', effect: 'deny' as const },
  { subject: 'admin', resource: 'admin-panel', action: 'write', effect: 'allow' as const },
  { subject: 'admin', resource: 'confidential-record', action: 'read', effect: 'allow' as const },
]

export const BASELINE_SCENARIOS: Scenario[] = [
  {
    scenarioId: 'auth-read-allowed',
    version: 1,
    threatCategory: 'authorization',
    description: 'A reader may read the public document.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'public-document',
        action: 'read',
        expectedDecision: 'allow',
      },
    ],
    expectedState: [{ resource: 'public-document', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'auth-read-denied',
    version: 1,
    threatCategory: 'sensitive-data',
    description: 'A reader may not read the confidential record.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'confidential-record',
        action: 'read',
        expectedDecision: 'deny',
      },
    ],
    expectedState: [{ resource: 'confidential-record', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'auth-write-denied',
    version: 1,
    threatCategory: 'authorization',
    description: 'A reader attempts to write the confidential record and it must not change.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'confidential-record',
        action: 'write',
        payload: 'ATTACKER-CONTROLLED',
        expectedDecision: 'deny',
      },
    ],
    expectedState: [{ resource: 'confidential-record', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'auth-write-allowed',
    version: 1,
    threatCategory: 'authorization',
    description: 'An admin may write the admin panel; state is expected to change.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'admin-1',
        identityRole: 'admin',
        identityTrusted: true,
        resource: 'admin-panel',
        action: 'write',
        payload: 'ADMIN-PANEL-UPDATED',
        expectedDecision: 'allow',
      },
    ],
    expectedState: [{ resource: 'admin-panel', change: 'changed' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'default-deny-unknown-resource',
    version: 1,
    threatCategory: 'authorization',
    description: 'A resource with no rule is denied by default.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'admin-panel',
        action: 'read',
        expectedDecision: 'deny',
      },
    ],
    expectedState: [{ resource: 'admin-panel', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'default-deny-unknown-action',
    version: 1,
    threatCategory: 'tool-misuse',
    description: 'An action with no matching rule is denied by default.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'public-document',
        action: 'write',
        payload: 'MUTATED-PUBLIC',
        expectedDecision: 'deny',
      },
    ],
    expectedState: [{ resource: 'public-document', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'privilege-escalation',
    version: 1,
    threatCategory: 'authorization',
    description: 'A reader attempts an admin-only write.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'admin-panel',
        action: 'write',
        payload: 'PRIVILEGE-ESCALATED',
        expectedDecision: 'deny',
      },
    ],
    expectedState: [{ resource: 'admin-panel', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'multi-action-mixed',
    version: 1,
    threatCategory: 'authorization',
    description: 'An allowed read is followed by a denied write; only the read touches the store.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'public-document',
        action: 'read',
        expectedDecision: 'allow',
      },
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'confidential-record',
        action: 'write',
        payload: 'CHAINED-WRITE',
        expectedDecision: 'deny',
      },
    ],
    expectedState: [
      { resource: 'public-document', change: 'unchanged' },
      { resource: 'confidential-record', change: 'unchanged' },
    ],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'agent-claims-authorized',
    version: 1,
    threatCategory: 'prompt-injection',
    description: 'The agent claims authorization; enforcement must still deny.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'reader-1',
        identityRole: 'reader',
        identityTrusted: false,
        resource: 'confidential-record',
        action: 'write',
        payload: 'INJECTED-INSTRUCTION',
        expectedDecision: 'deny',
        agentClaimsAuthorized: true,
      },
    ],
    expectedState: [{ resource: 'confidential-record', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
  {
    scenarioId: 'action-chaining',
    version: 1,
    threatCategory: 'action-chaining',
    description: 'An allowed read of a confidential record is followed by a denied write.',
    policyVersion: 1,
    policyRules: DEMO_RULES,
    resources: DEMO_RESOURCES,
    actions: [
      {
        identityId: 'admin-1',
        identityRole: 'admin',
        identityTrusted: true,
        resource: 'confidential-record',
        action: 'read',
        expectedDecision: 'allow',
      },
      {
        identityId: 'admin-1',
        identityRole: 'admin',
        identityTrusted: true,
        resource: 'confidential-record',
        action: 'write',
        payload: 'CHAINED-ADMIN-WRITE',
        expectedDecision: 'deny',
      },
    ],
    expectedState: [{ resource: 'confidential-record', change: 'unchanged' }],
    requiredEvidence: REQUIRED_EVIDENCE,
  },
]

/** Find a scenario by id. Returns undefined if not found. */
export function findScenario(scenarioId: string): Scenario | undefined {
  return BASELINE_SCENARIOS.find(s => s.scenarioId === scenarioId)
}
