import { describe, test, expect } from 'vitest'
import { scopeGuardrailNames } from './domainBatch'

describe('scopeGuardrailNames', () => {
  test('a batch yields every host (wildcard stripped) before every group root', () => {
    expect(scopeGuardrailNames({
      domainBatchMode: true,
      domainBatchHosts: ['www.agency.gov.uk', '*.example.com', 'api.example.com'],
    })).toEqual(['www.agency.gov.uk', 'example.com', 'api.example.com', 'gov.uk'])
  })

  test('a single-domain project yields the target, then each prefix host', () => {
    expect(scopeGuardrailNames({
      targetDomain: '*.Example.com', subdomainList: ['www.', '.', 'eu.api.', '*'],
    })).toEqual(['example.com', 'www.example.com', 'eu.api.example.com'])
  })

  test('IP mode has no names, whatever else the row still holds', () => {
    expect(scopeGuardrailNames({ ipMode: true, targetDomain: 'example.com', domainBatchHosts: ['a.example.com'] }))
      .toEqual([])
  })

  test('an empty single-domain target has no names', () => {
    expect(scopeGuardrailNames({ targetDomain: '  ' })).toEqual([])
  })
})
