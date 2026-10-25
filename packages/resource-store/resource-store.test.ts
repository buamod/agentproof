import { ResourceStore, changedResources } from './resource-store'

const seed = [
  { id: 'public-document', classification: 'public' as const, content: 'hello' },
  { id: 'confidential-record', classification: 'confidential' as const, content: 'secret' },
]

describe('ResourceStore', () => {
  test('snapshot captures all resources deterministically', () => {
    const store = new ResourceStore(seed)
    const snap = store.snapshot()
    expect(Object.keys(snap)).toEqual(['confidential-record', 'public-document'])
    expect(snap['confidential-record'].content).toBe('secret')
  })

  test('write changes content, version, and is observable in mutation log', () => {
    const store = new ResourceStore(seed)
    const ok = store.write('admin', 'confidential-record', 'new-secret')
    expect(ok).toBe(true)
    expect(store.snapshot()['confidential-record'].content).toBe('new-secret')
    expect(store.snapshot()['confidential-record'].version).toBe(2)
    expect(store.getMutations()).toHaveLength(1)
    expect(store.getMutations()[0].identity).toBe('admin')
  })

  test('read records an access event', () => {
    const store = new ResourceStore(seed)
    const record = store.read('reader', 'public-document')
    expect(record?.content).toBe('hello')
    expect(store.getAccesses()).toHaveLength(1)
    expect(store.getAccesses()[0].action).toBe('read')
  })

  test('reading a missing resource does not log an access', () => {
    const store = new ResourceStore(seed)
    const record = store.read('reader', 'does-not-exist')
    expect(record).toBeUndefined()
    expect(store.getAccesses()).toHaveLength(0)
  })

  test('changedResources detects content change', () => {
    const store = new ResourceStore(seed)
    const before = store.snapshot()
    store.write('admin', 'confidential-record', 'tampered')
    const after = store.snapshot()
    expect(changedResources(before, after)).toEqual(['confidential-record'])
  })

  test('changedResources returns empty when nothing changed', () => {
    const store = new ResourceStore(seed)
    const before = store.snapshot()
    const after = store.snapshot()
    expect(changedResources(before, after)).toEqual([])
  })
})
