import { Prisma } from '@prisma/client'
import { scopeGuardrailNames, splitWildcard, validateDomainBatch } from '@/lib/domainBatch'
import { firstHardBlocked } from '@/lib/hard-guardrail'

export interface ImportScopeResult {
  /** Set when the import must be refused, with the HTTP status to refuse it with. */
  error?: string
  status?: number
  warnings: string[]
}

/**
 * Normalise an imported bundle's scope columns IN PLACE, the way the create
 * routes do, and refuse a scope they would refuse.
 *
 * Import is a second creation path. Copying the bundle's columns verbatim let a
 * bundle carry a hand-written `domainBatchGroups` the host list never produced,
 * a project in IP mode and batch mode at once, or a government target, none of
 * which any create route accepts. So the groups are re-derived from the hosts,
 * the modes are exclusive, a non-batch row keeps no batch scope, and the hard
 * guardrail runs in every mode.
 *
 * A batch host the current rules refuse is dropped with a warning rather than
 * refusing the bundle, so an older export still imports; nothing surviving is a
 * refusal.
 */
export function normalizeImportedScope(fields: Record<string, unknown>): ImportScopeResult {
  const warnings: string[] = []
  const ipMode = fields.ipMode === true
  const batchMode = fields.domainBatchMode === true
  if (ipMode && batchMode) {
    return {
      error: 'This bundle sets both IP mode and Domain batch mode. A project has one targeting mode; it was not imported.',
      status: 400,
      warnings,
    }
  }

  if (batchMode) {
    const raw = Array.isArray(fields.domainBatchHosts)
      ? fields.domainBatchHosts.filter((h): h is string => typeof h === 'string')
      : []
    let batch = validateDomainBatch(raw)
    if (batch.invalid.length > 0) {
      warnings.push(`Dropped hostnames the current rules refuse: ${batch.invalid.slice(0, 5).join(', ')}`
        + (batch.invalid.length > 5 ? ` (+${batch.invalid.length - 5} more)` : ''))
      batch = validateDomainBatch(raw.filter(h => !batch.invalid.includes(h.trim())))
    }
    if (!batch.ok) {
      return { error: `The bundle's hostname list cannot be imported: ${batch.errors.join(' ')}`, status: 400, warnings }
    }
    fields.domainBatchHosts = batch.groups.flatMap(g => g.hosts)
    fields.domainBatchGroups = batch.groups as unknown as Prisma.InputJsonValue
    fields.targetDomain = ''
  } else {
    fields.domainBatchGroups = Prisma.DbNull
    fields.domainBatchHosts = []
    if (!ipMode && typeof fields.targetDomain === 'string') {
      fields.targetDomain = splitWildcard(fields.targetDomain.trim()).rest
    }
  }

  const blocked = firstHardBlocked(scopeGuardrailNames({
    ipMode,
    domainBatchMode: batchMode,
    domainBatchHosts: fields.domainBatchHosts as string[],
    targetDomain: typeof fields.targetDomain === 'string' ? fields.targetDomain : '',
    subdomainList: Array.isArray(fields.subdomainList)
      ? fields.subdomainList.filter((s): s is string => typeof s === 'string')
      : [],
  }))
  if (blocked) {
    return { error: `Target permanently blocked: ${blocked.name}: ${blocked.reason}`, status: 403, warnings }
  }
  return { warnings }
}
