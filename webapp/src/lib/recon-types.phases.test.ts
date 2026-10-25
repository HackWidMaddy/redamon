/**
 * The log drawers' phase lists equal the orchestrator's phase patterns.
 *
 * Each drawer shows "Phase N/M": N is the number the orchestrator's
 * *_PHASE_PATTERNS entry carries (recon_orchestrator/container_manager.py), M
 * is the length of the TS list. The GVM drawer hard-coded M = 4 against five
 * patterns and showed "Phase 5/4" (drift-map #22). The Python source is parsed,
 * so a pattern added there fails here.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { GITHUB_HUNT_PHASES, GVM_PHASES, TRUFFLEHOG_PHASES } from './recon-types'

const CONTAINER_MANAGER = join(__dirname, '../../../recon_orchestrator/container_manager.py')
const available = existsSync(CONTAINER_MANAGER)

/** [name, number] per entry of the Python list literal `name = [...]`. */
function pythonPhases(name: string): Array<[string, number]> {
  const src = readFileSync(CONTAINER_MANAGER, 'utf8')
  const body = new RegExp(`^${name} = \\[\\n([\\s\\S]*?)\\n\\]`, 'm').exec(src)
  expect(body, `${name} not found in container_manager.py`).toBeTruthy()
  return body![1].split('\n')
    .map(line => /,\s*"([^"]+)",\s*([\d.]+)\),?\s*$/.exec(line))
    .filter((m): m is RegExpExecArray => m !== null)
    .map(m => [m[1], Number(m[2])])
}

describe.skipIf(!available)('drawer phase lists equal the orchestrator patterns', () => {
  test.each([
    ['GVM_PHASE_PATTERNS', GVM_PHASES],
    ['GITHUB_HUNT_PHASE_PATTERNS', GITHUB_HUNT_PHASES],
    ['TRUFFLEHOG_PHASE_PATTERNS', TRUFFLEHOG_PHASES],
  ] as const)('%s', (name, ts) => {
    const py = pythonPhases(name)
    expect(py.length).toBeGreaterThan(0)
    // Same names in the same order, numbered 1..n, so N never exceeds M.
    expect([...ts]).toEqual(py.map(([phase]) => phase))
    expect(py.map(([, n]) => n)).toEqual(py.map((_, i) => i + 1))
  })
})
