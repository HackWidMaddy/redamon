import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { resolveScopeGroups } from './scopeGroups'

// The fixture recon, the orchestrator and the agent also read: this side proves
// its scopeGroups is what the webapp really derives from the project's fields.
const FIXTURE = join(process.cwd(), '..', 'tests', 'fixtures', 'scope_groups_contract.json')

describe.skipIf(!existsSync(FIXTURE))('scope groups: cross-service contract', () => {
  const cases = existsSync(FIXTURE) ? JSON.parse(readFileSync(FIXTURE, 'utf8')).cases : []
  test.each(cases.map((c: { name: string }) => [c.name, c]))('%s', (_name, c) => {
    const { groups, invalid } = resolveScopeGroups(c.project)
    expect(invalid).toEqual([])
    expect(groups.map(g => ({
      scanRoot: g.scanRoot, orgDomain: g.orgDomain, mode: g.mode, includeRoot: g.includeRoot,
      exactHosts: g.exactHosts, entries: g.entries,
    }))).toEqual(c.scopeGroups)
  })
})
