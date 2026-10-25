"""Per-host, per-module coverage stamps on BaseURL nodes (plan 09.1).

A recon module that works per web host stamps every BaseURL it considered, as
flat properties (a property cannot hold a map):

  <module>_at       when the module's run started
  <module>_status   complete | partial | no_input | failed
  <module>_inputs   what it had for that host: JS files read, URLs scanned
  <module>_outputs  findings it reported for that host
  <module>_reason   why the status is not complete; absent when it is

A BaseURL the module never considered carries no stamp, and that absence is
what "not scanned" means - but only in a project where the module stamped some
other host. A project scanned before stamps existed has none at all, and a
reader says "coverage not recorded" there, never "not scanned".

The rows come from recon (recon/helpers/coverage_stamps.py builds them).
"""
from datetime import datetime, timezone
from urllib.parse import urlsplit

#: The modules that stamp, in display order. The webapp keeps its own copy
#: (webapp/src/lib/coverageStamps.ts); tests/test_coverage_stamps_parity.py
#: holds the two together.
COVERAGE_MODULES = ("js_recon", "nuclei")
COVERAGE_STATUSES = ("complete", "partial", "no_input", "failed")
COVERAGE_FIELDS = ("at", "status", "inputs", "outputs", "reason")
COVERAGE_PROPERTIES = tuple(f"{m}_{f}" for m in COVERAGE_MODULES for f in COVERAGE_FIELDS)

_DEFAULT_PORTS = {"http": 80, "https": 443}


def base_url_variants(url: str) -> list:
    """The spellings one web service's ``BaseURL.url`` can have: as given, and
    with its scheme's default port added or dropped. ``[]`` when not http(s)."""
    try:
        parts = urlsplit(str(url or "").strip())
        port = parts.port
    except ValueError:
        return []
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return []
    if ":" in host:
        host = f"[{host}]"
    default = _DEFAULT_PORTS[scheme]
    bare, explicit = f"{scheme}://{host}", f"{scheme}://{host}:{default}"
    if port is None:
        return [bare, explicit]
    if port == default:
        return [explicit, bare]
    return [f"{scheme}://{host}:{port}"]


def stamp_base_url_coverage(session, module: str, coverage: dict, user_id: str, project_id: str,
                            in_scope=None) -> int:
    """Stamp ``coverage = {"at", "hosts": {base_url: row}}`` on this tenant's
    existing BaseURLs; returns how many were stamped.

    MATCH, never MERGE: a stamp describes a host some writer already put in
    the graph, it never creates one. ``in_scope(hostname)`` drops a row the
    caller's scope does not cover. The module name is interpolated into the
    property names, so it must be one of COVERAGE_MODULES.
    """
    if module not in COVERAGE_MODULES:
        raise ValueError(f"unknown coverage module {module!r}")
    rows = []
    for url, row in ((coverage or {}).get("hosts") or {}).items():
        if not isinstance(row, dict) or row.get("status") not in COVERAGE_STATUSES:
            continue
        urls = base_url_variants(url)
        if not urls or (in_scope is not None and not in_scope(urlsplit(urls[0]).hostname or "")):
            continue
        rows.append({
            "urls": urls,
            "status": row["status"],
            "inputs": int(row.get("inputs") or 0),
            "outputs": int(row.get("outputs") or 0),
            "reason": str(row["reason"])[:200] if row.get("reason") else None,
        })
    if not rows:
        return 0
    at = (coverage or {}).get("at") or datetime.now(timezone.utc).isoformat()
    record = session.run(
        f"""
        UNWIND $rows AS row
        UNWIND row.urls AS url
        MATCH (bu:BaseURL {{url: url, user_id: $uid, project_id: $pid}})
        SET bu.{module}_at = datetime($at),
            bu.{module}_status = row.status,
            bu.{module}_inputs = row.inputs,
            bu.{module}_outputs = row.outputs,
            bu.{module}_reason = row.reason
        RETURN count(bu) AS stamped
        """,
        rows=rows, at=at, uid=user_id, pid=project_id,
    ).single()
    return int((record or {}).get("stamped", 0) or 0)
