"""Tenant isolation for the queries multi-root partial recon added or rewrote.

A node's natural key (a Domain name, a Subdomain name, a BaseURL) is NOT unique
across projects: uniqueness is (key, user_id, project_id). A query that anchors
on a labelled node without the tenant pair reads or writes another project's
graph - and a multi-root run, which matches many Domain names at once, would do
it for every root. So every MATCH / OPTIONAL MATCH / MERGE whose first node
carries an entity label must also carry user_id and project_id. A node reached
through a relationship from a scoped anchor, or a bare variable bound earlier,
is already inside the tenant.

Source-level on purpose: the partial builders and writers run against Neo4j,
which the unit gate does not have. The last test proves the scan catches a
violation, so a green run is not vacuous.
"""
import ast
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Entity labels only; CVE/CWE/CAPEC reference nodes are global by design.
ENTITY_LABELS = {
    "Domain", "Subdomain", "IP", "Port", "Service", "BaseURL", "Endpoint", "Parameter",
    "Certificate", "Technology", "UserInput", "ExternalDomain", "Vulnerability", "DNSRecord",
}
_CLAUSE = re.compile(
    r"\b(?:OPTIONAL\s+MATCH|MATCH|MERGE)\s*\(\s*\w*\s*(?::\s*(\w+))?\s*(\{[^}]*\})?", re.I)

# (file, functions) this feature added or rewrote. None = the whole file.
TARGETS = [
    ("recon/partial_recon_modules/graph_builders.py", None),
    ("recon/partial_recon_modules/origin_enrichment.py", {"_inject_graph_fronted_hosts"}),
    ("recon/partial_recon_modules/user_inputs.py", {"_create_user_subdomains_in_graph"}),
    ("recon/partial_recon_modules/vulnerability_scanning.py", None),
    ("recon/partial_recon_modules/subdomain_discovery.py", None),
    ("graph_db/mixins/recon/domain_mixin.py", {"ensure_root_domains", "update_graph_coverage"}),
    ("graph_db/mixins/osint_mixin.py", {
        "update_graph_from_external_domains", "update_graph_from_urlscan_discovery",
        "update_graph_from_uncover"}),
]


def _cypher_in(path: Path, functions):
    """(function, cypher) for every string literal in scope that holds a clause."""
    tree = ast.parse(path.read_text(), filename=str(path))
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if functions is not None and fn.name not in functions:
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and re.search(r"\b(MATCH|MERGE)\b", node.value):
                yield fn.name, node.value


def unscoped_anchors(cypher: str) -> list:
    """The labelled first-node patterns that lack user_id or project_id."""
    bad = []
    for match in _CLAUSE.finditer(cypher):
        label, props = match.group(1), match.group(2) or ""
        if label in ENTITY_LABELS and not ("user_id" in props and "project_id" in props):
            bad.append(match.group(0).strip())
    return bad


class TestMultiRootQueriesAreTenantScoped(unittest.TestCase):
    def test_every_anchored_clause_carries_the_tenant_pair(self):
        offenders, scanned = [], 0
        for rel, functions in TARGETS:
            path = REPO / rel
            self.assertTrue(path.exists(), f"{rel} moved; update TARGETS")
            for fn, cypher in _cypher_in(path, functions):
                scanned += 1
                offenders += [f"{rel}:{fn}: {clause}" for clause in unscoped_anchors(cypher)]
        self.assertGreater(scanned, 20, "the scan found almost no queries; the extractor is broken")
        self.assertEqual(offenders, [], "anchored without the tenant key:\n  " + "\n  ".join(offenders))

    def test_the_scan_catches_a_violation(self):
        self.assertEqual(
            unscoped_anchors("MATCH (d:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(s) RETURN s"),
            ["MATCH (d:Domain {name: $domain}"])
        self.assertEqual(unscoped_anchors("MERGE (s:Subdomain {name: $n, user_id: $u})"),
                         ["MERGE (s:Subdomain {name: $n, user_id: $u}"])
        # A bare bound variable and a scoped anchor pass.
        self.assertEqual(unscoped_anchors(
            "MATCH (d:Domain {user_id: $uid, project_id: $pid}) MERGE (d)-[:HAS_SUBDOMAIN]->(s)"), [])


if __name__ == "__main__":
    unittest.main()
