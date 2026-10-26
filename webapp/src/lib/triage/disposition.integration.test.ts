/** @vitest-environment node */
/**
 * L4, real Neo4j: the Cypher and TypeScript halves of disposition agree.
 *
 * The report and Insights group by `dispositionCypher` / `blockerCypher`; the
 * board and MCP `list_findings` decide with `disposition`. Every shared vector
 * is written as a node and evaluated by both.
 *
 * Skipped unless a Neo4j answers. To run it:
 *   docker run --rm --network host -v "$PWD/webapp:/app" -w /app \
 *     -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER -e NEO4J_PASSWORD \
 *     --entrypoint sh redamon-webapp -c \
 *     'node_modules/.bin/vitest run src/lib/triage/disposition.integration.test.ts'
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest'
import neo4j, { type Driver, type Session } from 'neo4j-driver'
import vectors from './disposition.vectors.json'
import { blockerCypher, disposition, dispositionCypher, queryDispositionSummary } from './disposition'

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687'
const USER = process.env.NEO4J_USER || 'neo4j'
const PASSWORD = process.env.NEO4J_PASSWORD || ''

let driver: Driver | undefined
let session: Session | undefined
let alive = false
const PID = `DISPOSITION_${Math.random().toString(36).slice(2, 10)}`

const ROWS = (vectors as { props: Record<string, unknown> }[]).map((v) => v.props)

beforeAll(async () => {
  if (!PASSWORD) return
  try {
    driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
    session = driver.session()
    await session.run('RETURN 1')
    alive = true
  } catch { alive = false }
})

afterAll(async () => {
  if (alive && session) await session.run('MATCH (n {project_id: $pid}) DETACH DELETE n', { pid: PID })
  if (session) await session.close()
  if (driver) await driver.close()
})

describe('TS/Cypher parity of disposition', () => {
  test('every vector gets the same disposition and blocker in both halves', async (ctx) => {
    if (!alive || !session) ctx.skip()
    await session!.run(
      `UNWIND range(0, size($rows) - 1) AS i
       CREATE (n:Vulnerability {id: 'row-' + toString(i), project_id: $pid, user_id: 'u'})
       SET n += $rows[i]`,
      { pid: PID, rows: ROWS },
    )
    const res = await session!.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       RETURN toInteger(substring(v.id, 4)) AS i,
              ${dispositionCypher('v')} AS disposition,
              ${blockerCypher('v')} AS blocker
       ORDER BY i`,
      { pid: PID },
    )
    const got = res.records.map((r) => ({
      disposition: r.get('disposition') as string,
      blocker: r.get('blocker') as string | null,
    }))
    expect(got).toEqual(ROWS.map((p) => disposition(p)))
  })

  test('the project summary tallies exactly what the TypeScript half decides', async (ctx) => {
    if (!alive || !session) ctx.skip()
    const summary = await queryDispositionSummary(session!, PID)
    const want = { reportable: 0, candidate: 0, info: 0, excluded: 0 }
    const blockers = new Map<string, number>()
    for (const r of ROWS.map((p) => disposition(p))) {
      want[r.disposition] += 1
      if (r.blocker) blockers.set(r.blocker, (blockers.get(r.blocker) ?? 0) + 1)
    }
    expect(summary).toMatchObject(want)
    expect(new Map(summary!.blockers.map((b) => [b.blocker, b.count]))).toEqual(blockers)
  })
})
