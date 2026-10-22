"""LIVE-Neo4j proof of the Origin-IP Discovery graph write + fronted-host count.

The unit tests prove `stable_vuln_id` is deterministic and tenant-salted, but
only a real database proves the Cypher is VALID on Neo4j 5.x and that:

  * update_graph_from_origin_discovery creates IP + HAS_ORIGIN + Vulnerability,
    is idempotent on re-run, keeps tenants separate, and leaves no orphan edge
    after the project is wiped (strategy row 2);
  * an origin exposure CONVERGES onto the same Vulnerability node the
    security-check producer writes for the same (type, url, ip) in one tenant -
    one node, not two (strategy row 3 + regression for the port-less-url fix);
  * the fronted-host count for the partial-recon modal lives in the webapp's
    graph-inputs route now; the orchestrator query this file used to prove was
    deleted with its endpoint (ORC-04).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_origin_discovery_graph_live.py -v

Everything is scoped to throwaway project ids and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()


def _origin_payload(host, ip, port=443, method="favicon_hash", source="shodan"):
    return {"origin_discovery": {"confirmed": [{
        "type": "waf_bypass", "severity": "high",
        "name": "Origin Server Exposed (CDN Bypass)",
        "subdomain": host, "matched_ip": ip,
        "url": f"https://{ip}:{port}",           # port-full probe url
        "origin_discovery_method": method, "origin_source": source,
        "confidence_score": 91.0, "cdn_fronting": "cloudflare",
        "port": port, "match_method": "host-header",
        "evidence": f"{host} -> {ip}:{port}", "source": "origin_discovery",
    }], "candidates_meta": {}}}


def _security_check_waf_payload(host, ip):
    return {"vuln_scan": {"security_checks": {"findings": [{
        "type": "waf_bypass", "severity": "high",
        "name": "WAF Bypass via Direct IP Access",
        "url": f"https://{ip}",                  # port-less url the check emits
        "matched_ip": ip, "hostname": host,
        "evidence": "WAF on subdomain but not IP",
    }]}}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestOriginDiscoveryGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "od-itest-user"
        cls.pid_a = "od-itest-a-%s" % uuid.uuid4().hex[:10]
        cls.pid_b = "od-itest-b-%s" % uuid.uuid4().hex[:10]

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.client.driver.session() as s:
                for pid in (cls.pid_a, cls.pid_b):
                    s.run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n", pid=pid)
        finally:
            cls.client.close()

    def _count(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, **params).single()[0]

    # -- row 2: write, idempotency, tenant isolation, no orphan on wipe ------
    def test_write_creates_nodes_idempotent_isolated_and_wipes_clean(self):
        host, ip = "www.acme-itest.test", "45.33.32.10"
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_a)

        self.assertEqual(self._count(
            "MATCH (i:IP {address:$ip, project_id:$pid}) WHERE i.origin_confirmed = true RETURN count(i)",
            ip=ip, pid=self.pid_a), 1, "origin IP node not created / not flagged")
        self.assertEqual(self._count(
            "MATCH (:Subdomain {name:$h, project_id:$pid})-[r:HAS_ORIGIN]->(:IP {address:$ip, project_id:$pid}) RETURN count(r)",
            h=host, ip=ip, pid=self.pid_a), 1, "HAS_ORIGIN edge not created")
        self.assertEqual(self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', project_id:$pid}) RETURN count(v)",
            pid=self.pid_a), 1, "Vulnerability not created")

        # idempotent re-run -> still exactly one of each
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_a)
        self.assertEqual(self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', project_id:$pid}) RETURN count(v)",
            pid=self.pid_a), 1, "re-run duplicated the Vulnerability")
        self.assertEqual(self._count(
            "MATCH (:Subdomain {name:$h, project_id:$pid})-[r:HAS_ORIGIN]->(:IP) RETURN count(r)",
            h=host, pid=self.pid_a), 1, "re-run duplicated HAS_ORIGIN")

        # tenant B, SAME host+ip -> a separate Vulnerability node (tenant-salted id).
        # Scope to THIS ip so a sibling test's data in pid_b can't skew the count.
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_b)
        ids = self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', matched_ip:$ip}) WHERE v.project_id IN [$a,$b] "
            "RETURN count(DISTINCT v.id)", ip=ip, a=self.pid_a, b=self.pid_b)
        self.assertEqual(ids, 2, "cross-tenant Vulnerability id collision (F1)")

        # wipe A -> no A nodes, no orphan HAS_ORIGIN survives
        self.client.clear_project_data(self.user, self.pid_a)
        self.assertEqual(self._count(
            "MATCH (n) WHERE n.project_id = $pid RETURN count(n)", pid=self.pid_a), 0,
            "project wipe left nodes behind")
        self.assertEqual(self._count(
            "MATCH (:Subdomain {project_id:$pid})-[r:HAS_ORIGIN]->() RETURN count(r)", pid=self.pid_a), 0,
            "orphan HAS_ORIGIN survived the wipe")

    # -- row 3: convergence with the security-check producer (one node) ------
    def test_converges_with_security_check_producer(self):
        host, ip = "shop.acme-itest.test", "45.33.32.20"
        self.client.update_graph_from_vuln_scan(_security_check_waf_payload(host, ip), self.user, self.pid_b)
        self.client.update_graph_from_origin_discovery(_origin_payload(host, ip), self.user, self.pid_b)
        n = self._count(
            "MATCH (v:Vulnerability {type:'waf_bypass', matched_ip:$ip, project_id:$pid}) RETURN count(v)",
            ip=ip, pid=self.pid_b)
        self.assertEqual(n, 1, "security_check + origin_discovery did NOT converge -> report double-count (F4)")

    # -- row 4: fronted count reads Endpoint/IP, not BaseURL -----------------


if __name__ == "__main__":
    unittest.main()
