/**
 * The queue's start path refuses an old-model graph (§4.11.6) for the writers
 * that attach to Domain nodes, with a status the queue treats as permanent: a
 * 409 reads as "busy" there and would requeue the job until a full recon ran.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  legacy: vi.fn(),
  orchestratorFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => h.findUnique(...a) } } }))
vi.mock('@/lib/engagement', () => ({ loadEngagement: async () => ({ blockers: [] }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: vi.fn() }))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: (...a: unknown[]) => h.legacy(...a),
}))

import { dispatchStart } from './startScan'
import { classifyStartFailure } from './scanStartOutcome'

beforeEach(() => {
  vi.clearAllMocks()
  h.findUnique.mockResolvedValue({
    id: 'p1', userId: 'u1', supplyChainInputMode: null, targetDomain: '',
    domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk'],
  })
  h.legacy.mockResolvedValue(['co.uk'])
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r1' }) })
})

describe('dispatchStart on an old-model graph', () => {
  test.each(['partial_recon', 'gvm', 'ai_attack'])('%s is refused, permanently', async kind => {
    const r = await dispatchStart(kind, 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(false)
    expect(r.status).toBe(422)
    expect(r.error).toMatch(/built before the current scope model; run a full recon first/)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(classifyStartFailure(r.status, { error: r.error }).temporary).toBe(false)
  })

  test('a scanner that never attaches to Domain nodes is not asked', async () => {
    await dispatchStart('github_hunt', 'p1')
    expect(h.legacy).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })

  test('a current graph starts', async () => {
    h.legacy.mockResolvedValue([])
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(true)
  })
})
