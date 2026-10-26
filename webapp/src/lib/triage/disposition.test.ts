/**
 * Disposition: one answer per finding to "can this go in a report?" (plan 10.1).
 *
 * The vectors are shared with disposition.integration.test.ts, which runs the
 * Cypher half over the same rows on a real Neo4j: the report and Insights group
 * in Cypher while the board and MCP decide in TypeScript, and a drift would
 * print one count and list another.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import vectors from './disposition.vectors.json'
import {
  BLOCKER_AI_FALSE_POSITIVE,
  BLOCKER_NOT_TRIAGED,
  DISPOSITIONS,
  DISPOSITION_LABELS,
  INFO_SEVERITIES,
  TIER_RULE_NO_IMPACT,
  TIER_RULE_PROVEN,
  blockerCypher,
  disposition,
  dispositionCypher,
  dispositionText,
  readDisposition,
} from './disposition'
import { PUBLIC_CLIENT_KEY_TYPES } from '@/lib/secrets/publicClientKeys'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

interface Vector {
  why: string
  props: Record<string, unknown>
  disposition: string
  blocker: string | null
}

describe('disposition, over the shared vectors', () => {
  test.each((vectors as Vector[]).map((v) => [v.why, v] as const))('%s', (_why, v) => {
    expect(disposition(v.props)).toEqual({ disposition: v.disposition, blocker: v.blocker })
  })

  test('the vectors reach every disposition and both fixed blockers', () => {
    const seen = new Set((vectors as Vector[]).map((v) => v.disposition))
    expect([...seen].sort()).toEqual([...DISPOSITIONS].sort())
    const blockers = new Set((vectors as Vector[]).map((v) => v.blocker))
    expect(blockers.has(BLOCKER_NOT_TRIAGED)).toBe(true)
    expect(blockers.has(BLOCKER_AI_FALSE_POSITIVE)).toBe(true)
  })
})

describe('disposition rules that matter for safety', () => {
  test('SECURITY: an AI false positive is never excluded and never reportable', () => {
    for (const p of [
      { triage_state: 'false_positive', triage_decided_by: 'review' },
      { triage_status: 'likely_noise', triage_source: 'ai' },
    ]) {
      expect(disposition(p).disposition).toBe('candidate')
      expect(disposition(p).blocker).toBe(BLOCKER_AI_FALSE_POSITIVE)
    }
  })

  test('nothing is reportable by default: missing or unknown values are candidates', () => {
    for (const p of [{}, { triage_status: 'weird' }, { triage_tier_rule: 'made up' }, { triage_source: 'human' }]) {
      expect(disposition(p).disposition).not.toBe('reportable')
    }
  })

  test('only a person\'s confirmed, never an unattributed one, makes a finding reportable', () => {
    expect(disposition({ triage_status: 'confirmed', triage_source: 'human' }).disposition).toBe('reportable')
    expect(disposition({ triage_status: 'confirmed', triage_source: 'ai' }).disposition).toBe('candidate')
    expect(disposition({ triage_status: 'confirmed' }).disposition).toBe('candidate')
  })

  test('a blocker is named for candidates only', () => {
    for (const v of vectors as Vector[]) {
      expect(v.blocker === null).toBe(v.disposition !== 'candidate')
    }
  })
})

describe('readDisposition: props a reader could not read', () => {
  test('no props means no answer, never a default', () => {
    for (const bad of [null, undefined, 'x', 3, ['triage_state']]) {
      expect(readDisposition(bad)).toBeNull()
    }
  })

  test('a props object is read as disposition reads it', () => {
    expect(readDisposition({ triage_tier_rule: 'proven' })).toEqual({ disposition: 'reportable', blocker: null })
  })
})

describe('the words every surface shares', () => {
  test('one label per disposition', () => {
    expect(DISPOSITION_LABELS).toEqual({
      reportable: 'Reportable', candidate: 'Candidate', info: 'Info', excluded: 'Excluded',
    })
  })

  test('a candidate names its blocker, and an untriaged one says so plainly', () => {
    expect(dispositionText({ disposition: 'candidate', blocker: 'credible, with impact worth planning for' }))
      .toBe('Candidate, blocked by credible, with impact worth planning for')
    expect(dispositionText({ disposition: 'candidate', blocker: BLOCKER_NOT_TRIAGED }))
      .toBe('Candidate, not triaged yet')
    expect(dispositionText({ disposition: 'reportable', blocker: null })).toBe('Reportable')
    expect(dispositionText({ disposition: 'info', blocker: null })).toBe('Info')
  })
})

describe('the Cypher half', () => {
  const SCORE_MODEL = join(__dirname, '../../../../agentic/cypherfix_triage/score_model.py')

  test('the tier rules it reads are the strings score_model.tier_rule returns', () => {
    const src = readFileSync(SCORE_MODEL, 'utf8')
    expect(src).toContain(`return "T1", "${TIER_RULE_PROVEN}"`)
    expect(src).toContain(`return "T4", "${TIER_RULE_NO_IMPACT}"`)
  })

  test('the info severities are the board\'s own (triage_mixin severity rank)', () => {
    const mixin = readFileSync(join(__dirname, '../../../../graph_db/mixins/recon/triage_mixin.py'), 'utf8')
    expect(mixin).toContain(`IN [${INFO_SEVERITIES.map((s) => `'${s}'`).join(', ')}]`)
  })

  test('it checks excluded, then reportable, then info, and leaves candidate last', () => {
    const q = dispositionCypher('n')
    const order = ['excluded', 'reportable', 'info', 'candidate'].map((d) => q.indexOf(`'${d}'`))
    expect(order.every((i) => i >= 0)).toBe(true)
    expect([...order].sort((a, b) => a - b)).toEqual(order)
  })

  test('it carries every constant the TypeScript half reads', () => {
    const q = dispositionCypher('n') + blockerCypher('n')
    for (const s of [TIER_RULE_PROVEN, TIER_RULE_NO_IMPACT, BLOCKER_NOT_TRIAGED, BLOCKER_AI_FALSE_POSITIVE,
      ...INFO_SEVERITIES, PUBLIC_CLIENT_KEY_TYPES[0]]) {
      expect(q).toContain(`'${s}'`)
    }
    expect(q).toContain("coalesce(n.triage_source, '') = 'human'")
  })

  test('it binds only the variable it is given, no parameter, and never names Muted', () => {
    for (const q of [dispositionCypher('jf'), blockerCypher('jf')]) {
      expect(q).not.toMatch(/\bn\./)
      expect(q).toMatch(/jf\.triage_tier_rule/)
      expect(q).not.toMatch(/\$/)
      expect(q).not.toMatch(/Muted/)
    }
  })

  test('a variable that is not a Cypher identifier is refused', () => {
    expect(() => dispositionCypher('n) DETACH DELETE (m')).toThrow(/identifier/)
    expect(() => blockerCypher('1n')).toThrow(/identifier/)
  })

  test('the blocker is null outside candidates', () => {
    expect(blockerCypher('n')).toMatch(/^CASE WHEN .* = 'candidate' THEN .* END$/s)
  })
})
