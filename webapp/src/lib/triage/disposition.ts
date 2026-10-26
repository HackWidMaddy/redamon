/**
 * One answer per finding to "can this go in a report?" (plan 10, read-side).
 *
 *   reportable  proven (an exploit or a validator showed it), or a person confirmed it
 *   candidate   might be real; its `blocker` says what is missing
 *   info        no impact, even if real
 *   excluded    a person judged it a false positive, or a rule resolved it
 *
 * Computed from what the Priority Board already stores, in this order, so the
 * first rule that matches wins. An AI review alone decides none of them: its
 * false positive stays a candidate with a blocker that says so, because the
 * reviewer reads target-controlled text (see reportable.ts). Unknown or missing
 * values make a candidate "not triaged yet", never a reportable finding.
 *
 * "Excluded" and "AI review" are reportable.ts's buckets, and the public-key
 * test is publicClientKeys.ts's, so a finding's disposition can never disagree
 * with the report's "not counted" lines or its public-key list.
 *
 * Both halves are built from the same constants: the board and MCP decide in
 * TypeScript, the report and Insights group in Cypher. The live parity check
 * over the shared vectors is disposition.integration.test.ts. Neither Cypher
 * half names the `Muted` label or binds a parameter, so any query can carry it.
 */
import { reportBucket, reportBucketCypher, reportCountable, type ReportTriageProps } from './reportable'
import { isPublicClientKey, publicClientKeyCypher } from '@/lib/secrets/publicClientKeys'

export const DISPOSITIONS = ['reportable', 'candidate', 'info', 'excluded'] as const
export type Disposition = (typeof DISPOSITIONS)[number]

export const DISPOSITION_LABELS: Record<Disposition, string> = {
  reportable: 'Reportable',
  candidate: 'Candidate',
  info: 'Info',
  excluded: 'Excluded',
}

/** What each disposition means, for a tooltip or a legend. */
export const DISPOSITION_MEANINGS: Record<Disposition, string> = {
  reportable: 'Proven (an exploit or a validator showed it), or a person confirmed it.',
  candidate: 'Might be real. Verify it before reporting it.',
  info: 'No impact, even if real.',
  excluded: 'A person judged it a false positive, or it was resolved (fixed, gone, inactive).',
}

/** The heading the severity breakdowns carry: a scanner's severity is a claim. */
export const SCANNER_SEVERITY_LABEL = 'Scanner severity (not yet verified)'

/** The tier rules read here, exactly as `score_model.tier_rule` returns them. */
export const TIER_RULE_PROVEN = 'proven'
export const TIER_RULE_NO_IMPACT = 'nothing here has any impact'

export const BLOCKER_NOT_TRIAGED = 'not triaged yet'
export const BLOCKER_AI_FALSE_POSITIVE = 'AI review: likely false positive'

/** The board's own info-level severities (the triage mixin's severity rank). */
export const INFO_SEVERITIES = ['info', 'informational', 'none'] as const

export interface DispositionResult {
  disposition: Disposition
  /** Set for a candidate only. */
  blocker: string | null
}

/** A finding's property bag, or a Priority Board row. */
export interface DispositionProps extends ReportTriageProps {
  triage_tier_rule?: unknown
  severity?: unknown
  public_client_key?: unknown
  secret_type?: unknown
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/

function quoted(values: readonly string[]): string {
  return `[${values.map((v) => `'${v}'`).join(', ')}]`
}

function tierRuleOf(p: DispositionProps): string {
  return typeof p.triage_tier_rule === 'string' ? p.triage_tier_rule : ''
}

/** As `evidence.person_decided` reads a Real: a legacy or unattributed one is not a person's. */
function personConfirmed(p: DispositionProps): boolean {
  return p.triage_status === 'confirmed' && p.triage_source === 'human'
}

function infoSeverity(p: DispositionProps): boolean {
  return typeof p.severity === 'string' &&
    (INFO_SEVERITIES as readonly string[]).includes(p.severity.trim().toLowerCase())
}

export function disposition(p: DispositionProps): DispositionResult {
  const bucket = reportBucket(p)
  if (bucket === 'resolved' || bucket === 'person_false_positive') {
    return { disposition: 'excluded', blocker: null }
  }
  const rule = tierRuleOf(p)
  if (rule === TIER_RULE_PROVEN || personConfirmed(p)) {
    return { disposition: 'reportable', blocker: null }
  }
  if (rule === TIER_RULE_NO_IMPACT || isPublicClientKey(p.public_client_key, p.secret_type) ||
      (rule === '' && infoSeverity(p))) {
    return { disposition: 'info', blocker: null }
  }
  if (bucket === 'ai_flagged') return { disposition: 'candidate', blocker: BLOCKER_AI_FALSE_POSITIVE }
  return { disposition: 'candidate', blocker: rule || BLOCKER_NOT_TRIAGED }
}

/** Null when there are no props to read: a reader then shows nothing, never a default. */
export function readDisposition(props: unknown): DispositionResult | null {
  if (!props || typeof props !== 'object' || Array.isArray(props)) return null
  return disposition(props as DispositionProps)
}

/** "Candidate, blocked by <blocker>", in the words every surface uses. */
export function dispositionText(r: DispositionResult): string {
  const label = DISPOSITION_LABELS[r.disposition]
  if (r.disposition !== 'candidate' || !r.blocker) return label
  if (r.blocker === BLOCKER_NOT_TRIAGED) return `${label}, ${BLOCKER_NOT_TRIAGED}`
  return `${label}, blocked by ${r.blocker}`
}

function checked(v: string): string {
  if (!IDENTIFIER.test(v)) throw new Error(`not a Cypher identifier: ${v}`)
  return v
}

function tierRuleCypher(v: string): string {
  return `coalesce(${v}.triage_tier_rule, '')`
}

/** A Cypher expression yielding the `Disposition` of the finding bound to `v`. */
export function dispositionCypher(v: string): string {
  checked(v)
  const rule = tierRuleCypher(v)
  return (
    `CASE WHEN NOT (${reportCountable(v)}) THEN 'excluded' ` +
    `WHEN ${rule} = '${TIER_RULE_PROVEN}' ` +
    `OR (coalesce(${v}.triage_status, '') = 'confirmed' AND coalesce(${v}.triage_source, '') = 'human') ` +
    `THEN 'reportable' ` +
    `WHEN ${rule} = '${TIER_RULE_NO_IMPACT}' OR ${publicClientKeyCypher(v)} ` +
    `OR (${rule} = '' AND toLower(trim(toString(coalesce(${v}.severity, '')))) IN ${quoted(INFO_SEVERITIES)}) ` +
    `THEN 'info' ELSE 'candidate' END`
  )
}

/** A Cypher expression yielding the blocker of the finding bound to `v`: null unless a candidate. */
export function blockerCypher(v: string): string {
  checked(v)
  const rule = tierRuleCypher(v)
  return (
    `CASE WHEN ${dispositionCypher(v)} = 'candidate' THEN ` +
    `CASE WHEN ${reportBucketCypher(v)} = 'ai_flagged' THEN '${BLOCKER_AI_FALSE_POSITIVE}' ` +
    `WHEN ${rule} <> '' THEN ${v}.triage_tier_rule ELSE '${BLOCKER_NOT_TRIAGED}' END END`
  )
}
