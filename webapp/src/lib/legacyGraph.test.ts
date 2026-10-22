/**
 * Old-model detection (§4.11.6). The vectors are the ones the graph_db helper
 * `legacy_domain_nodes` is tested against: the Cypher is the same in both
 * languages, and `legacyDomainNames` is its predicate in TypeScript.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { resolveScopeGroups } from '@/lib/scopeGroups'
import {
  LEGACY_DOMAINS_QUERY, LEGACY_GRAPH_MESSAGE, type DomainRow,
  findLegacyDomains, legacyDomainNames, legacyGraphParams, legacyGraphRefusal,
} from './legacyGraph'

const batch = (...hosts: string[]) => resolveScopeGroups({ domainBatchMode: true, domainBatchHosts: hosts }).groups
const single = (targetDomain: string, subdomainList: string[] = []) =>
  resolveScopeGroups({ targetDomain, subdomainList }).groups

const VECTORS: { name: string; rows: DomainRow[]; groups: ReturnType<typeof batch>; legacy: string[] }[] = [
  {
    name: 'a suffix-root Domain left by the old grouping is legacy',
    rows: [{ name: 'co.uk', hasData: true }, { name: 'acme.co.uk', hasData: true }],
    groups: batch('www.acme.co.uk'),
    legacy: ['co.uk'],
  },
  {
    name: 'a mixed-case single-domain target is not legacy',
    rows: [{ name: 'Alpha.test', hasData: true }],
    groups: single('alpha.test'),
    legacy: [],
  },
  {
    name: 'a Domain with no data (a seed) is not legacy',
    rows: [{ name: 'co.uk', hasData: false }],
    groups: batch('www.acme.co.uk'),
    legacy: [],
  },
  {
    name: 'the IP-mode root is never legacy',
    rows: [{ name: 'old.acme.co.uk', ipMode: true, hasData: true }],
    groups: batch('www.acme.co.uk'),
    legacy: [],
  },
  {
    name: 'a Domain unrelated to the scope is a removed root, not legacy',
    rows: [{ name: 'gone.test', hasData: true }],
    groups: batch('www.acme.co.uk'),
    legacy: [],
  },
  {
    name: 'a deeper Domain under a current scan root is legacy',
    rows: [{ name: 'api.example.com', hasData: true }, { name: 'example.com', hasData: true }],
    groups: batch('*.example.com'),
    legacy: ['api.example.com'],
  },
]

describe('legacyDomainNames (the query predicate)', () => {
  test.each(VECTORS)('$name', ({ rows, groups, legacy }) => {
    expect(legacyDomainNames(rows, groups)).toEqual(legacy)
  })
})

describe('legacyGraphParams', () => {
  test('expected are the scan roots; related are orgs and scan roots, lower-cased', () => {
    expect(legacyGraphParams(batch('WWW.Acme.CO.UK', '*.beta.test'))).toEqual({
      expected: ['acme.co.uk', 'beta.test'],
      related: ['acme.co.uk', 'beta.test'],
    })
  })
})

describe('findLegacyDomains', () => {
  test('runs the §4.11.6 query, tenant-scoped, and returns the names', async () => {
    const calls: { q: string; p: Record<string, unknown> }[] = []
    const runner = {
      run: async (q: string, p: Record<string, unknown>) => {
        calls.push({ q, p })
        return { records: [{ get: (k: string) => (k === 'legacy' ? ['co.uk'] : undefined) }] }
      },
    }
    expect(await findLegacyDomains(runner, 'u1', 'p1', batch('www.acme.co.uk'))).toEqual(['co.uk'])
    expect(calls[0].q).toBe(LEGACY_DOMAINS_QUERY)
    expect(calls[0].q).toContain('MATCH (d:Domain {user_id: $uid, project_id: $pid})')
    expect(calls[0].q).toContain('toLower(d.name)')
    expect(calls[0].p).toEqual({ uid: 'u1', pid: 'p1', expected: ['acme.co.uk'], related: ['acme.co.uk'] })
  })

  test('no scope (IP mode) asks nothing', async () => {
    const runner = { run: async () => { throw new Error('must not run') } }
    expect(await findLegacyDomains(runner, 'u1', 'p1', [])).toEqual([])
  })
})

describe('legacyGraphRefusal', () => {
  test('carries the message and the names', () => {
    const r = legacyGraphRefusal(['co.uk'])
    expect(r.error.startsWith(LEGACY_GRAPH_MESSAGE)).toBe(true)
    expect(r.error).toContain('co.uk')
    expect(r).toMatchObject({ code: 'legacy_graph', legacyGraph: ['co.uk'] })
  })
})
