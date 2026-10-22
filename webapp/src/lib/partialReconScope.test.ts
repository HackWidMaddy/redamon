import { describe, test, expect } from 'vitest'
import { admitsPartialHost, discoveryDomains, partialScopeFields, resolveProjectRoots } from './partialReconScope'

const PID = 'p1'

describe('resolveProjectRoots', () => {
  test('a batch offers its scope-group scan roots, derived from the host list', () => {
    const scope = resolveProjectRoots({
      domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk', '*.example.com', 'v1.example.com'],
      // A stale legacy record grouped under the bare suffix must not be offered.
      domainBatchGroups: [{ rootDomain: 'co.uk', prefixes: ['www.acme.'] }],
    }, PID)
    expect(scope.roots).toEqual(['acme.co.uk', 'example.com'])
    expect(scope.wildcardRoots).toEqual(['example.com'])
  })

  test('a single domain keeps the stored spelling of its target', () => {
    expect(resolveProjectRoots({ targetDomain: 'Alpha.test', subdomainList: [] }, PID).roots).toEqual(['Alpha.test'])
  })

  test('without the host list it falls back to the legacy record', () => {
    const scope = resolveProjectRoots({
      domainBatchMode: true, domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['*'] }],
    }, PID)
    expect(scope.roots).toEqual(['example.com'])
    expect(scope.groups).toEqual([])
  })

  test('IP mode offers the synthetic root', () => {
    expect(resolveProjectRoots({ ipMode: true }, PID).roots).toEqual(['ip-targets.p1'])
  })
})

describe('discoveryDomains', () => {
  test('only an ENUMERATE group is offered to SubdomainDiscovery', () => {
    const scope = resolveProjectRoots({ domainBatchMode: true, domainBatchHosts: ['*.a.com', 'www.b.com'] }, PID)
    expect(discoveryDomains(scope, ['a.com', 'b.com'])).toEqual(['a.com'])
  })

  test('an EXACT single-domain project no longer enumerates', () => {
    const exact = resolveProjectRoots({ targetDomain: 'example.com', subdomainList: ['www.'] }, PID)
    expect(discoveryDomains(exact, ['example.com'])).toEqual([])
    const enumerate = resolveProjectRoots({ targetDomain: 'example.com', subdomainList: ['.'] }, PID)
    expect(discoveryDomains(enumerate, ['example.com'])).toEqual(['example.com'])
  })
})

describe('admitsPartialHost (§4.6 partial user-typed rule)', () => {
  const scope = resolveProjectRoots({
    domainBatchMode: true, domainBatchHosts: ['www.example.com', 'example.com'],
  }, PID)

  test('ENUMERATE admits strict subdomains, the root only with Root on', () => {
    const enumOnly = resolveProjectRoots({ domainBatchMode: true, domainBatchHosts: ['*.example.org'] }, PID)
    expect(admitsPartialHost(enumOnly, 'x.example.org')).toBe(true)
    expect(admitsPartialHost(enumOnly, 'example.org')).toBe(false)
  })

  test('EXACT admits its listed hosts and its root with Root on, nothing else', () => {
    expect(admitsPartialHost(scope, 'WWW.example.com')).toBe(true)
    expect(admitsPartialHost(scope, 'example.com')).toBe(true)
    expect(admitsPartialHost(scope, 'mail.example.com')).toBe(false)
  })
})

describe('partialScopeFields', () => {
  test('a graph Domain that is no scan root is stale', () => {
    const scope = resolveProjectRoots({ domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk'] }, PID)
    const fields = partialScopeFields(scope, [
      { name: 'co.uk', hasData: true }, { name: 'acme.co.uk', hasData: false },
    ])
    expect(fields.domains).toEqual(['acme.co.uk'])
    expect(fields.stale_domains).toEqual(['co.uk'])
    expect(fields.empty_domains).toEqual(['acme.co.uk'])
  })
})
