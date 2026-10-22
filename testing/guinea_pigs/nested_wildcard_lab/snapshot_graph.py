#!/usr/bin/env python3
"""Snapshot one project's recon graph and recon JSON for the regression replay.

    snapshot_graph.py --project-id <pid> --user-id <uid> --out <dir>

Writes <dir>/graph.json (the sets compare_snapshots.py diffs) and copies the
project's recon JSON files from recon/output/ into <dir>/recon/.

Read-only. Every Cypher statement is scoped by user_id AND project_id on each
entity node it matches (graph-db-writes: no unscoped entity MATCH). It talks to
Neo4j's HTTP endpoint on 127.0.0.1:7474 with NEO4J_PASSWORD from the
environment, or from the repository's .env when unset; the password is never
printed. Stdlib only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

# Keys whose value differs on every run of the same scan; their presence is kept.
_TIMEISH = re.compile(r"(time|timestamp|duration|_at$|^at$|started|finished|date|elapsed|run_id)", re.I)

QUERIES = {
    "domain": """
        MATCH (d:Domain {user_id: $uid, project_id: $pid})
        RETURN d.name AS k""",
    "subdomain": """
        MATCH (s:Subdomain {user_id: $uid, project_id: $pid})
        RETURN s.name + '|scan_root=' + toString(coalesce(s.is_scan_root, false)) AS k""",
    "subdomain_parent": """
        MATCH (s:Subdomain {user_id: $uid, project_id: $pid})-[:BELONGS_TO]->(d:Domain {user_id: $uid, project_id: $pid})
        RETURN s.name + ' -> ' + d.name AS k""",
    "external_domain": """
        MATCH (e:ExternalDomain {user_id: $uid, project_id: $pid})
        RETURN e.domain AS k""",
    "ip_port": """
        MATCH (i:IP {user_id: $uid, project_id: $pid})-[:HAS_PORT]->(p:Port {user_id: $uid, project_id: $pid})
        RETURN i.address + ':' + toString(p.number) + '/' + coalesce(p.protocol, '') AS k""",
    "base_url": """
        MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
        RETURN b.url AS k""",
    "endpoint": """
        MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint {user_id: $uid, project_id: $pid})
        RETURN b.url + ' ' + coalesce(e.method, '') + ' ' + coalesce(e.path, '') AS k""",
    # The parent list is sorted client-side: Cypher has no list sort without APOC.
    "vulnerability": """
        MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
        OPTIONAL MATCH (p {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v)
        RETURN coalesce(v.source, '') AS source,
               coalesce(v.template_id, v.type, v.name, '') AS what,
               coalesce(v.host, v.hostname, v.domain, '') AS host,
               collect(DISTINCT labels(p)[0] + ':' +
                       coalesce(p.name, p.url, p.address, p.domain, toString(p.number), '?')) AS parents""",
    "dns_email_finding": """
        MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability {user_id: $uid, project_id: $pid})
        RETURN d.name + '|' + coalesce(v.type, v.name, '') + '|' + coalesce(v.id, '') AS k""",
}

DOMAIN_PROPS = """
    MATCH (d:Domain {user_id: $uid, project_id: $pid})
    RETURN d.name AS name, properties(d) AS props"""


def _neo4j_password() -> str:
    pw = os.environ.get("NEO4J_PASSWORD")
    if pw:
        return pw
    env = REPO / ".env"
    for line in env.read_text().splitlines():
        if line.startswith("NEO4J_PASSWORD="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    sys.exit("NEO4J_PASSWORD is not set and not in .env")


def _cypher(statement: str, params: dict) -> list[dict]:
    url = os.environ.get("NEO4J_HTTP_URL", "http://127.0.0.1:7474") + "/db/neo4j/tx/commit"
    body = json.dumps({"statements": [{"statement": statement, "parameters": params}]}).encode()
    token = base64.b64encode(f"neo4j:{_neo4j_password()}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "Authorization": f"Basic {token}",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        out = json.load(resp)
    if out.get("errors"):
        raise RuntimeError(out["errors"][0].get("message", "cypher error"))
    res = out["results"][0]
    cols = res["columns"]
    return [dict(zip(cols, row["row"])) for row in res["data"]]


def _metadata_view(meta):
    """The metadata with every time-like value masked, at any depth."""
    if isinstance(meta, dict):
        return {k: ("<volatile>" if _TIMEISH.search(str(k)) else _metadata_view(v)) for k, v in sorted(meta.items())}
    if isinstance(meta, list):
        return [_metadata_view(v) for v in meta]
    return meta


def snapshot(pid: str, uid: str, out: Path) -> dict:
    params = {"uid": uid, "pid": pid}
    sets: dict[str, list[str]] = {}
    for name, q in QUERIES.items():
        rows = _cypher(q, params)
        if name == "vulnerability":
            keys = []
            for r in rows:
                parents = ";".join(sorted(p for p in (r["parents"] or []) if p))
                keys.append(f"{r['source']}|{r['what']}|{r['host']}|{parents}")
            sets[name] = sorted(set(keys))
        else:
            sets[name] = sorted({r["k"] for r in rows if r["k"] is not None})

    domain_props: dict[str, dict] = {}
    coverage_gaps: list[str] = []
    skipped: list[str] = []
    for r in _cypher(DOMAIN_PROPS, params):
        props = r["props"] or {}
        domain_props[r["name"]] = {k: ("<volatile>" if _TIMEISH.search(k) else v) for k, v in sorted(props.items())}
        try:
            for gap in json.loads(props.get("recon_coverage_gaps") or "[]"):
                coverage_gaps.append(f"{r['name']}|{json.dumps(gap, sort_keys=True)}")
        except (TypeError, ValueError):
            coverage_gaps.append(f"{r['name']}|<unparsable>")
        for h in props.get("recon_skipped_hosts") or []:
            skipped.append(f"{r['name']}|{h}")
    sets["coverage_gap"] = sorted(set(coverage_gaps))
    sets["skipped_host"] = sorted(set(skipped))

    recon_dir = out / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)
    recon_json: dict[str, dict] = {}
    for f in sorted((REPO / "recon" / "output").glob(f"recon_{pid}*.json")):
        shutil.copy2(f, recon_dir / f.name)
        try:
            data = json.loads(f.read_text())
        except ValueError:
            recon_json[f.name] = {"error": "unparsable"}
            continue
        recon_json[f.name] = {
            "top_level_keys": sorted(data.keys()),
            "metadata": _metadata_view(data.get("metadata") or {}),
        }

    snap = {
        "project_id": pid,
        "user_id": uid,
        "taken_at": datetime.now(timezone.utc).isoformat(),
        "sets": sets,
        "domain_props": domain_props,
        "recon_json": recon_json,
    }
    (out / "graph.json").write_text(json.dumps(snap, indent=2, sort_keys=True, default=str))
    return snap


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--user-id", required=True)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    snap = snapshot(a.project_id, a.user_id, a.out)
    for name, values in snap["sets"].items():
        print(f"{name:20s} {len(values)}")
    print(f"recon files          {len(snap['recon_json'])}")
    print(f"written              {a.out / 'graph.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
