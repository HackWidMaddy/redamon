"""
Domain batch: which domains a project would actually scan.

Kept OUT of api.py deliberately. This feeds the hard guardrail, the one control an
operator cannot switch off, and api.py cannot be imported without FastAPI and the
Docker client - so the security decision would have been untestable in the unit
tier. Mirrors auth.py, which is standalone for the same reason.

The contract, and why each half matters:

  - a Domain-batch project has an EMPTY targetDomain and keeps its scope in
    domainBatchGroups, so a guardrail that reads targetDomain alone waves every
    batch target through;
  - a root that fails the charset check is DROPPED, never repaired: a repaired
    hostname would be a target the operator never approved;
  - an empty result in batch mode means "cannot determine scope", which the caller
    must treat as a refusal, not as "nothing to check". Fail closed.
"""
from __future__ import annotations

import re

_BATCH_ROOT_CHARSET = re.compile(r'^[a-z0-9.-]+$')


def batch_guardrail_targets(project: dict) -> list[str]:
    """Every root domain a Domain-batch project would scan, deduplicated, in order."""
    groups = project.get('domainBatchGroups')
    if not isinstance(groups, list):
        return []

    roots: list[str] = []
    for entry in groups:
        if not isinstance(entry, dict):
            continue
        root = str(entry.get('rootDomain') or '').strip().lower()
        if not root or not _BATCH_ROOT_CHARSET.match(root) or '..' in root:
            continue
        if root not in roots:
            roots.append(root)
    return roots


# ---------------------------------------------------------------------------
# Partial recon. The orchestrator is the only authority on which roots a run
# may touch: the client names at most a subset, never a root of its own.
# ---------------------------------------------------------------------------

# The only settings a partial run may override: the Nuclei checkboxes, the one
# thing the modal sends. The recon modules apply every override they receive,
# so an open dict would let a crafted request switch off ROE_ENABLED or empty
# ROE_EXCLUDED_HOSTS. Mirrors ALLOWED_SETTINGS_OVERRIDES in recon/partial_recon.py,
# which drops anything else again inside the container.
PARTIAL_OVERRIDE_KEYS = frozenset({
    'CVE_LOOKUP_ENABLED',
    'MITRE_ENABLED',
    'SECURITY_CHECK_ENABLED',
})

# Same ceiling as a Domain batch (MAX_BATCH_GROUPS in webapp/src/lib/domainBatch.ts).
MAX_REQUESTED_ROOTS = 50


class PartialScopeError(ValueError):
    """A partial-recon start to refuse, with the HTTP status to refuse it with."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _usable_root(root: str) -> bool:
    # The charset is checked on the lowercased name but the stored spelling is
    # kept: a single-domain target is saved trimmed, not lowercased, and the
    # graph's Domain node carries exactly that name.
    low = root.strip().lower()
    return bool(low) and bool(_BATCH_ROOT_CHARSET.match(low)) and '..' not in low


def partial_project_roots(project: dict, project_id: str) -> list[str]:
    """Every root this project scans, re-validated. Raises PartialScopeError(400)."""
    if project.get('ipMode', False):
        # The name recon/main.py mints for IP mode's synthetic Domain node.
        roots = [f"ip-targets.{project_id}"]
    elif project.get('domainBatchMode', False):
        roots = batch_guardrail_targets(project)
        if not roots:
            raise PartialScopeError(
                400,
                "Domain batch project has no valid domain groups. "
                "Re-save the project's hostname list before scanning.",
            )
    else:
        target = str(project.get('targetDomain') or '').strip()
        roots = [target] if target else []

    roots = [r for r in roots if _usable_root(r)]
    if not roots:
        raise PartialScopeError(400, "This project has no usable scan target.")
    return roots


def narrow_partial_roots(roots: list[str], graph_inputs: dict) -> list[str]:
    """The project roots this run covers, narrowed by the request. Sorted.

    `graph_inputs.domains` is intersected with the roots. A legacy request (a
    job queued before multi-root partial recon) carries only `domain`, which
    must be a current root. Neither means every root.
    """
    graph_inputs = graph_inputs if isinstance(graph_inputs, dict) else {}
    by_key = {r.lower(): r for r in roots}

    requested = graph_inputs.get('domains')
    if requested is not None:
        if (not isinstance(requested, list) or len(requested) > MAX_REQUESTED_ROOTS
                or not all(isinstance(x, str) for x in requested)):
            raise PartialScopeError(
                400, f"graph_inputs.domains must be a list of at most "
                     f"{MAX_REQUESTED_ROOTS} domain names.")
        chosen = {by_key[x.strip().lower()] for x in requested if x.strip().lower() in by_key}
        if not chosen:
            raise PartialScopeError(400, "None of the requested domains is a target of this project.")
        return sorted(chosen)

    legacy = graph_inputs.get('domain')
    if legacy:
        if not isinstance(legacy, str) or legacy.strip().lower() not in by_key:
            raise PartialScopeError(400, f"{legacy!r} is not a target of this project.")
        return [by_key[legacy.strip().lower()]]

    return sorted(roots)


def validate_partial_overrides(overrides) -> dict:
    """The settings overrides, or PartialScopeError(400) for anything not allowed."""
    if overrides is None:
        return {}
    if not isinstance(overrides, dict):
        raise PartialScopeError(400, "settings_overrides must be an object.")
    unknown = sorted(k for k in overrides if k not in PARTIAL_OVERRIDE_KEYS)
    if unknown:
        raise PartialScopeError(
            400, f"settings_overrides may only set {sorted(PARTIAL_OVERRIDE_KEYS)}; "
                 f"refused: {unknown}")
    not_bool = sorted(k for k, v in overrides.items() if not isinstance(v, bool))
    if not_bool:
        raise PartialScopeError(400, f"settings_overrides must be true/false: {not_bool}")
    return dict(overrides)


def _batch_hosts(project: dict) -> list[str]:
    """The listed hosts of a Domain-batch project, from its derived groups.

    A wildcard entry is stored as `*.<root>`: its marker is stripped. Anything
    with a `*` elsewhere, or outside the charset, is dropped rather than repaired.
    """
    groups = project.get('domainBatchGroups')
    hosts: list[str] = []
    for entry in groups if isinstance(groups, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get('hosts'), list):
            continue
        for raw in entry['hosts']:
            host = str(raw or '').strip().lower()
            if host.startswith('*.'):
                host = host[2:]
            if host and _BATCH_ROOT_CHARSET.match(host) and '..' not in host and host not in hosts:
                hosts.append(host)
    return hosts


def guardrail_targets(project: dict) -> list[str]:
    """Every name to hard-guardrail before starting a recon, whatever the mode.

    IP mode returns [] (IPs are not hard-blocked; see hard_guardrail.is_hard_blocked).
    Batch mode returns every listed host, then every group root: a host under a
    multi-label government name (`www.isa.org.jm`) groups under a root no rule
    names (`org.jm`), so checking the roots alone lets it through. Anything else
    returns the single target, then its prefix hosts.
    """
    if project.get('ipMode', False):
        return []
    if project.get('domainBatchMode', False):
        hosts = _batch_hosts(project)
        return hosts + [r for r in batch_guardrail_targets(project) if r not in hosts]
    target = str(project.get('targetDomain') or '').strip()
    if not target:
        return []
    names = [target]
    subs = project.get('subdomainList')
    for raw in subs if isinstance(subs, list) else []:
        prefix = str(raw or '').strip().lower().rstrip('.')
        if prefix and '*' not in prefix and f'{prefix}.{target}' not in names:
            names.append(f'{prefix}.{target}')
    return names
