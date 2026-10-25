/**
 * Deterministic Scenario Execution Harness
 *
 * Responsibilities:
 * - Validate the scenario before execution
 * - Reset fixtures to a known state
 * - Snapshot state before execution
 * - Execute actions through the enforcement boundary
 * - Snapshot state after execution
 * - Emit observations (NO verdict logic lives here)
 *
 * The harness never decides pass or fail. That is the verdict engine's job,
 * and the verdict engine only sees evidence.
 */

import { ResourceStore, ResourceSnapshot } from '../resource-store/resource-store'
import {
  EnforcementService,
  OperationRequest,
  EnforcementDecision,
} from '../enforcement/enforcement'
import {
  Scenario,
  validateScenario,
  ScenarioValidationResult,
} from './scenario'

export interface ActionRecord {
  index: number
  request: OperationRequest
  decision: EnforcementDecision
  executed: boolean
  expectedDecision: 'allow' | 'deny'
}

export interface RunRecord {
  scenarioId: string
  scenarioVersion: number
  policyVersion: number
  executorName: string
  startedAt: number
  completedAt: number
  before: ResourceSnapshot
  after: ResourceSnapshot
  actionResults: ActionRecord[]
  accesses: ReturnType<ResourceStore['getAccesses']>
  mutations: ReturnType<ResourceStore['getMutations']>
  requiredEvidence: string[]
}

export interface ExecutorContext {
  request: OperationRequest
  store: ResourceStore
  enforcement: EnforcementService
  /** Write payload declared by the scenario, if any. */
  payload?: string
}

export interface ExecutorResult {
  decision: EnforcementDecision
  executed: boolean
}

/**
 * An executor decides how an action is carried out.
 *
 * The default executor asks the enforcement service, and only touches the
 * store when the decision is "allowed". Defect-injection executors can violate
 * that (for example, write while reporting "denied") to prove the evaluator
 * detects the violation.
 */
export type Executor = (ctx: ExecutorContext) => ExecutorResult

/** The correct executor: only perform the operation when authorization allows it. */
export const DEFAULT_EXECUTOR: Executor = ({ request, store, enforcement, payload }) => {
  const decision = enforcement.checkAuthorization(request)
  if (!decision.allowed) {
    return { decision, executed: false }
  }

  let executed = false
  if (request.action === 'read') {
    executed = store.read(request.identity.id, request.resource) !== undefined
  } else if (request.action === 'write') {
    executed = store.write(request.identity.id, request.resource, payload ?? 'empty-write')
  }
  return { decision, executed }
}

export interface ExecuteOptions {
  executor?: Executor
  executorName?: string
  clock?: () => number
}

export interface ScenarioRunResult {
  scenarioId: string
  scenarioVersion: number
  validation: ScenarioValidationResult
  /** True only when validation passed and the scenario actually executed. */
  recorded: boolean
  record?: RunRecord
}

/**
 * Execute a scenario. Invalid scenarios are rejected and never run.
 */
export function executeScenario(scenario: Scenario, options: ExecuteOptions = {}): ScenarioRunResult {
  const validation = validateScenario(scenario)
  if (!validation.valid) {
    return {
      scenarioId: scenario.scenarioId,
      scenarioVersion: scenario.version,
      validation,
      recorded: false,
    }
  }

  const clock = options.clock ?? (() => Date.now())
  const executor = options.executor ?? DEFAULT_EXECUTOR
  const executorName = options.executorName ?? 'default'

  // Fresh synthetic state per run - reproducibility.
  const store = new ResourceStore(scenario.resources, clock)
  const enforcement = new EnforcementService(scenario.policyVersion, scenario.policyRules)

  const startedAt = clock()
  const before = store.snapshot()

  const actionResults: ActionRecord[] = []
  for (let i = 0; i < scenario.actions.length; i++) {
    const action = scenario.actions[i]
    const request: OperationRequest = {
      identity: {
        id: action.identityId,
        role: action.identityRole,
        trusted: action.identityTrusted,
      },
      resource: action.resource,
      action: action.action,
      policyVersion: scenario.policyVersion,
      // Recorded for evidence, but the enforcer must ignore it.
      agentClaimsAuthorized: action.agentClaimsAuthorized ?? false,
    }

    const result = executor({ request, store, enforcement, payload: action.payload })
    actionResults.push({
      index: i,
      request,
      decision: result.decision,
      executed: result.executed,
      expectedDecision: action.expectedDecision,
    })
  }

  const after = store.snapshot()
  const completedAt = clock()

  return {
    scenarioId: scenario.scenarioId,
    scenarioVersion: scenario.version,
    validation,
    recorded: true,
    record: {
      scenarioId: scenario.scenarioId,
      scenarioVersion: scenario.version,
      policyVersion: scenario.policyVersion,
      executorName,
      startedAt,
      completedAt,
      before,
      after,
      actionResults,
      accesses: store.getAccesses(),
      mutations: store.getMutations(),
      requiredEvidence: [...scenario.requiredEvidence],
    },
  }
}
