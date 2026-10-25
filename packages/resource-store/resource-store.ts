/**
 * Synthetic Resource Store
 *
 * This is the "ground truth" that the independent evaluator inspects.
 *
 * CRITICAL: The store records its own access and mutation history, independent
 * of whatever the enforcement service or the agent claims happened. This is
 * what breaks the common-mode failure where a buggy enforcer reports "denied"
 * while the underlying data was actually modified.
 *
 * The evaluator reads from this store directly. It never trusts the executor.
 */

export type Classification = 'public' | 'confidential'

export interface ResourceRecord {
  id: string
  classification: Classification
  content: string
  version: number
}

export interface SnapshotEntry {
  id: string
  classification: Classification
  contentHash: string
  content: string
  version: number
}

export type ResourceSnapshot = Record<string, SnapshotEntry>

export interface AccessEvent {
  timestamp: number
  identity: string
  resource: string
  action: 'read' | 'write'
  outcome: 'executed'
}

export interface MutationEvent {
  timestamp: number
  identity: string
  resource: string
  beforeVersion: number
  afterVersion: number
  beforeContent: string
  afterContent: string
}

/**
 * Deterministic hash of content, used for snapshot comparison.
 * Not cryptographic - just a stable comparison primitive for the evaluator.
 */
function contentHash(content: string): string {
  let hash = 0
  for (let i = 0; i < content.length; i++) {
    hash = ((hash << 5) - hash + content.charCodeAt(i)) | 0
  }
  return `${content.length}:${hash}`
}

/**
 * In-memory synthetic protected state.
 *
 * All operations that actually reach the store are logged. If an enforcement
 * bypass occurs, it shows up here as an access or mutation that should not
 * have happened.
 */
export class ResourceStore {
  private records = new Map<string, ResourceRecord>()
  private accesses: AccessEvent[] = []
  private mutations: MutationEvent[] = []
  private clock: () => number

  constructor(
    seed: Array<{ id: string; classification: Classification; content: string }> = [],
    clock: () => number = () => Date.now()
  ) {
    this.clock = clock
    for (const r of seed) {
      this.records.set(r.id, {
        id: r.id,
        classification: r.classification,
        content: r.content,
        version: 1,
      })
    }
  }

  /** List resource ids in deterministic order. */
  listResourceIds(): string[] {
    return [...this.records.keys()].sort()
  }

  /** Read a record. Records an access event if the record exists. */
  read(identity: string, resource: string): ResourceRecord | undefined {
    const record = this.records.get(resource)
    if (!record) return undefined
    this.accesses.push({
      timestamp: this.clock(),
      identity,
      resource,
      action: 'read',
      outcome: 'executed',
    })
    return { ...record }
  }

  /**
   * Write a record. Records an access event and a mutation event.
   * Returns false when the resource does not exist.
   */
  write(identity: string, resource: string, content: string): boolean {
    const record = this.records.get(resource)
    if (!record) return false

    const beforeVersion = record.version
    const beforeContent = record.content
    record.content = content
    record.version = beforeVersion + 1

    this.accesses.push({
      timestamp: this.clock(),
      identity,
      resource,
      action: 'write',
      outcome: 'executed',
    })
    this.mutations.push({
      timestamp: this.clock(),
      identity,
      resource,
      beforeVersion,
      afterVersion: record.version,
      beforeContent,
      afterContent: content,
    })
    return true
  }

  /** Capture a complete snapshot of current state. */
  snapshot(): ResourceSnapshot {
    const snap: ResourceSnapshot = {}
    for (const id of this.listResourceIds()) {
      const r = this.records.get(id)!
      snap[id] = {
        id: r.id,
        classification: r.classification,
        contentHash: contentHash(r.content),
        content: r.content,
        version: r.version,
      }
    }
    return snap
  }

  /** All access events observed so far. */
  getAccesses(): AccessEvent[] {
    return [...this.accesses]
  }

  /** All mutation events observed so far. */
  getMutations(): MutationEvent[] {
    return [...this.mutations]
  }

  /** Reset the observation logs (used between scenario runs). */
  resetLogs(): void {
    this.accesses = []
    this.mutations = []
  }
}

/**
 * Compare two snapshots and return the ids whose content changed.
 */
export function changedResources(before: ResourceSnapshot, after: ResourceSnapshot): string[] {
  const ids = new Set([...Object.keys(before), ...Object.keys(after)])
  const changed: string[] = []
  for (const id of [...ids].sort()) {
    const b = before[id]
    const a = after[id]
    if (!b || !a) {
      changed.push(id)
      continue
    }
    if (b.contentHash !== a.contentHash) changed.push(id)
  }
  return changed
}
