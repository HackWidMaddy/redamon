"""
P6 (§4.11): the graph's Domain node is the ORGANISATION; a scan root is where
a group of the project points.

scan_root_for_host decides scope (Subdomain or ExternalDomain), and
org_for_scan_root picks the Domain a host attaches to. Every writer that used
to MATCH Domain{<scan root>} now finds the org, so a scan root below its org
neither gets a Domain of its own nor loses its data (S-1, S-3, S-4, S-35).

Recording fakes, no Neo4j: tests/test_org_domain_lock_integration.py runs the
locked writes against a real one.
"""
import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.scope import (  # noqa: E402
    IN_SCOPE, OUT_OF_SCOPE, SKIPPED, _NO_HOST, attach_for_host, build_host_scope,
    classify_host, host_in_scope, org_for_scan_root, scan_root_for_host,
)


def _group(root, org, mode="enumerate", include_root=False, exact=()):
    return {"scan_root": root, "org_domain": org, "mode": mode,
            "include_root": include_root, "exact_hosts": list(exact)}


# api.example.com enumerated with Root off, example.com listing www only.
RECON = {
    "domain": "api.example.com",
    "all_project_roots": ["api.example.com", "example.com"],
    "scope_groups": [_group("api.example.com", "example.com"),
                     _group("example.com", "example.com", "exact", False, ["www.example.com"])],
}


class TestScopeVersusAttach(unittest.TestCase):
    def test_a_host_under_a_deeper_root_attaches_to_the_org(self):
        self.assertEqual(scan_root_for_host("v1.api.example.com", RECON), "api.example.com")
        self.assertEqual(attach_for_host("v1.api.example.com", RECON), (IN_SCOPE, "example.com"))

    def test_a_root_that_is_no_target_is_skipped_never_readmitted_by_a_shorter_root(self):
        # The match STOPS at the longest root (§4.11.2).
        self.assertEqual(classify_host("api.example.com", RECON), (SKIPPED, "api.example.com"))
        self.assertIsNone(scan_root_for_host("api.example.com", RECON))
        self.assertEqual(attach_for_host("api.example.com", RECON), (SKIPPED, None))

    def test_a_host_under_no_root_is_an_external_domain_even_sharing_the_org(self):
        self.assertEqual(classify_host("cdn.other.test", RECON), (OUT_OF_SCOPE, None))
        # under example.com (an EXACT group): in the graph scope, attached to the org
        self.assertEqual(attach_for_host("mail.example.com", RECON), (IN_SCOPE, "example.com"))

    def test_a_root_with_include_root_is_a_target(self):
        recon = dict(RECON, scope_groups=[_group("api.example.com", "example.com", include_root=True)])
        self.assertEqual(scan_root_for_host("api.example.com", recon), "api.example.com")

    def test_a_legacy_file_attaches_as_before(self):
        legacy = {"domain": "alpha.test", "all_project_roots": ["alpha.test"]}
        self.assertEqual(attach_for_host("alpha.test", legacy), (IN_SCOPE, "alpha.test"))
        self.assertEqual(org_for_scan_root("alpha.test", legacy), "alpha.test")

    def test_the_host_scope_of_a_root_that_is_no_target_admits_nothing(self):
        # An empty set reads as "no filter"; the root itself is no target.
        scope = build_host_scope({"domain": "api.example.com", "subdomains": [],
                                  "scope_groups": [_group("api.example.com", "example.com")]})
        self.assertEqual(scope, {_NO_HOST})
        self.assertFalse(host_in_scope("api.example.com", scope))
        self.assertFalse(host_in_scope("evil.test", scope))


class TestRunDefaultScopeGroups(unittest.TestCase):
    """A partial run sets the project's groups once; a recon dict that carries
    its own still wins."""

    def tearDown(self):
        from graph_db.mixins.recon.scope import set_run_scope_groups
        set_run_scope_groups([])

    def test_the_default_is_used_when_the_dict_has_none(self):
        from graph_db.mixins.recon.scope import set_run_scope_groups
        set_run_scope_groups([_group("api.example.com", "example.com")])
        self.assertEqual(org_for_scan_root("api.example.com", {"domain": "api.example.com"}), "example.com")

    def test_an_explicit_dict_wins_over_the_default(self):
        from graph_db.mixins.recon.scope import set_run_scope_groups
        set_run_scope_groups([_group("api.example.com", "example.com")])
        own = {"scope_groups": [_group("api.example.com", "api.example.com")]}
        self.assertEqual(org_for_scan_root("api.example.com", own), "api.example.com")

    def test_without_either_the_scan_root_is_its_own_domain(self):
        self.assertEqual(org_for_scan_root("api.example.com", {}), "api.example.com")


# --- recording fakes ----------------------------------------------------------

class _Result:
    def __init__(self, row=None):
        self._row = row if row is not None else {"n": 1, "matched": 1, "linked": 0, "exists": False,
                                                 "seeded": 1}

    def single(self):
        return self._row

    def __iter__(self):
        return iter([])

    def data(self):
        return []

    def consume(self):
        return None


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return _Result()

    def execute_write(self, work):
        return work(self)


class _Driver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _Session(self.calls)


def _client(*mixins):
    cls = type("Client", tuple(mixins), {})
    c = cls.__new__(cls)
    c.driver = _Driver()
    return c


def _domain_params(calls, needle="MATCH (d:Domain {name: $root_domain"):
    return [p for q, p in calls if needle in q]


class TestDomainDiscoveryWriter(unittest.TestCase):
    def _write(self, recon):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        c = _client(DomainMixin)
        c.update_graph_from_domain_discovery(recon, "u1", "p1")
        return c.driver.calls

    def _recon(self, include_root):
        subs = (["api.example.com"] if include_root else []) + ["v1.api.example.com"]
        return {
            "domain": "api.example.com",
            "metadata": {"root_domain": "api.example.com", "org_domain": "example.com",
                         "scan_timestamp": "t", "filtered_mode": False, "wildcard_mode": True,
                         "target": "api.example.com", "subdomain_filter": [], "modules_executed": ["x"]},
            "whois": {"registrar": "R", "name_servers": [], "emails": []},
            "subdomains": subs,
            "dns": {"domain": {"has_records": True}, "subdomains": {}},
            "scope_groups": [_group("api.example.com", "example.com", include_root=include_root)],
        }

    def test_the_domain_is_the_org_and_carries_no_run_fields(self):
        calls = self._write(self._recon(False))
        (q, p), = [(q, p) for q, p in calls if "MERGE (d:Domain" in q]
        self.assertEqual(p["name"], "example.com")
        for gone in ("target", "filtered_mode", "wildcard_mode", "subdomain_filter",
                     "modules_executed", "anonymous_mode", "bruteforce_mode", "scan_type"):
            self.assertNotIn(gone, p["props"])
        self.assertEqual(p["props"]["scan_timestamp"], "t")
        # an empty WHOIS list never blanks what another group of the org wrote
        self.assertNotIn("name_servers", p["props"])
        self.assertEqual(p["props"]["registrar"], "R")

    def test_hosts_link_to_the_org(self):
        calls = self._write(self._recon(False))
        links = [p for q, p in calls if "MERGE (s)-[:BELONGS_TO]->(d)" in q]
        self.assertEqual({p["domain"] for p in links}, {"example.com"})

    def test_a_deeper_scan_root_that_is_a_target_is_a_marked_subdomain(self):
        calls = self._write(self._recon(True))
        marks = {p["name"]: p["is_scan_root"] for q, p in calls if "s.is_scan_root" in q}
        self.assertEqual(marks, {"api.example.com": True, "v1.api.example.com": False})

    def test_the_org_apex_keeps_its_shape(self):
        recon = self._recon(True)
        recon["metadata"] = dict(recon["metadata"], root_domain="example.com")
        recon["domain"] = "example.com"
        recon["subdomains"] = ["example.com"]
        recon["scope_groups"] = [_group("example.com", "example.com", include_root=True)]
        calls = self._write(recon)
        marks = {p["name"]: p["is_scan_root"] for q, p in calls if "s.is_scan_root" in q}
        self.assertEqual(marks, {"example.com": False})


class TestFlatStampsLandOnTheOrg(unittest.TestCase):
    """GDB-07: the four per-tool stamp writers matched metadata.root_domain,
    which is 0 nodes for a scan root below its org."""

    RECON = {"domain": "api.example.com",
             "metadata": {"root_domain": "api.example.com", "org_domain": "example.com"},
             "scope_groups": [_group("api.example.com", "example.com")]}

    def _stamp(self, mixin, method, key):
        c = _client(mixin)
        getattr(c, method)(dict(self.RECON, **{key: {"scan_metadata": {}, "summary": {}}}), "u1", "p1")
        stamped = _domain_params(c.driver.calls)
        self.assertTrue(stamped, method)
        self.assertEqual({p["root_domain"] for p in stamped}, {"example.com"}, method)

    def test_port_scan(self):
        from graph_db.mixins.recon.port_mixin import PortMixin
        self._stamp(PortMixin, "update_graph_from_port_scan", "port_scan")

    def test_http_probe(self):
        from graph_db.mixins.recon.http_mixin import HttpMixin
        self._stamp(HttpMixin, "update_graph_from_http_probe", "http_probe")

    def test_resource_enum(self):
        from graph_db.mixins.recon.resource_mixin import ResourceMixin
        self._stamp(ResourceMixin, "update_graph_from_resource_enum", "resource_enum")

    def test_vuln_scan(self):
        from graph_db.mixins.recon.vuln_mixin import VulnMixin
        self._stamp(VulnMixin, "update_graph_from_vuln_scan", "vuln_scan")


class TestDnsFindingsOnTheOrg(unittest.TestCase):
    def _write(self, domain_batch, finding_domain):
        from graph_db.mixins.recon.vuln_mixin import VulnMixin
        c = _client(VulnMixin)
        c.update_graph_from_vuln_scan({
            "domain": "api.example.com",
            "metadata": {"root_domain": "api.example.com", "org_domain": "example.com",
                         "domain_batch": domain_batch},
            "scope_groups": [_group("api.example.com", "example.com")],
            "vuln_scan": {"scan_metadata": {}, "summary": {}, "security_checks": {"findings": [
                {"type": "spf_missing", "severity": "low", "name": "SPF", "domain": finding_domain}]}},
        }, "u1", "p1")
        return c.driver.calls

    def test_a_domain_level_finding_links_to_the_org(self):
        calls = self._write(True, "api.example.com")
        links = [p for q, p in calls if "MATCH (d:Domain {name: $domain" in q and "HAS_VULNERABILITY" in q]
        self.assertTrue(links)
        self.assertEqual({p["domain"] for p in links}, {"example.com"})


class TestShodanDnsBase(unittest.TestCase):
    """S-35: Shodan answers for the org it was asked about; its labels never
    become <label>.<deeper scan root>."""

    def test_records_are_built_on_the_queried_domain(self):
        from graph_db.mixins.osint_mixin import OsintMixin
        c = _client(OsintMixin)
        recon = dict(RECON, scope_groups=[_group("api.example.com", "example.com"),
                                          _group("example.com", "example.com", "enumerate")],
                     shodan={"hosts": [], "reverse_dns": {}, "cves": [],
                             "domain_dns": {"domain": "example.com", "subdomains": ["mail", "v1.api"],
                                            "records": []}})
        c.update_graph_from_shodan(recon, "u1", "p1")
        names = {p["name"] for q, p in c.driver.calls if "MERGE (s:Subdomain" in q}
        self.assertEqual(names, {"mail.example.com", "v1.api.example.com"})
        self.assertFalse(any(n.endswith(".api.example.com.api.example.com") or n == "mail.api.example.com"
                             for n in names))
        links = {p["domain"] for q, p in c.driver.calls if "MERGE (s)-[:BELONGS_TO]->(d)" in q}
        self.assertEqual(links, {"example.com"})


class TestPartialWriters(unittest.TestCase):
    def test_partial_discovery_attaches_to_the_org(self):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        from graph_db.mixins.recon.user_input_mixin import UserInputMixin
        c = _client(DomainMixin, UserInputMixin)
        c.update_graph_from_partial_discovery(
            {"domain": "api.example.com", "subdomains": ["api.example.com", "a.api.example.com"],
             "dns": {}, "scope_groups": [_group("api.example.com", "example.com", include_root=True)]},
            "u1", "p1")
        ensured = [p["names"] for q, p in c.driver.calls if "UNWIND $names" in q]
        self.assertEqual(ensured, [["example.com"]])
        links = {p["domain"] for q, p in c.driver.calls if "MERGE (s)-[:BELONGS_TO]->(d)" in q}
        self.assertEqual(links, {"example.com"})
        marks = {p["name"]: p["is_scan_root"] for q, p in c.driver.calls if "s.is_scan_root" in q}
        self.assertEqual(marks, {"api.example.com": True, "a.api.example.com": False})

    def test_partial_discovery_takes_an_explicit_org(self):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        from graph_db.mixins.recon.user_input_mixin import UserInputMixin
        c = _client(DomainMixin, UserInputMixin)
        c.update_graph_from_partial_discovery({"domain": "api.example.com", "subdomains": [], "dns": {}},
                                              "u1", "p1", org_domain="example.com")
        self.assertEqual([p["names"] for q, p in c.driver.calls if "UNWIND $names" in q], [["example.com"]])

    def test_a_user_input_hangs_off_the_org_of_its_root(self):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        from graph_db.mixins.recon.user_input_mixin import UserInputMixin
        c = _client(DomainMixin, UserInputMixin)
        c.create_user_input_node(["api.example.com", "other.test"],
                                 {"id": "ui1", "values": ["v1.api.example.com"]}, "u1", "p1",
                                 root_orgs={"api.example.com": "example.com"})
        (p,), = [[p for q, p in c.driver.calls if "HAS_USER_INPUT" in q]]
        self.assertEqual(p["domain"], "example.com")


class TestOpenApiSourceStatus(unittest.TestCase):
    """§4.11.5: per scan root, on the org Domain, in one locked statement."""

    def test_entries_are_filed_under_their_scan_root(self):
        from graph_db.mixins.recon.resource_mixin import openapi_status_entry
        self.assertEqual(openapi_status_entry("api.example.com", "doc1|h|ok|t"),
                         "api.example.com|doc1|h|ok|t")
        self.assertEqual(openapi_status_entry("api.example.com", "api.example.com|doc1|h|ok|t"),
                         "api.example.com|doc1|h|ok|t")

    def test_the_lock_is_the_first_clause_and_only_this_root_is_replaced(self):
        from graph_db.mixins.recon.resource_mixin import write_openapi_source_status
        calls = []
        write_openapi_source_status(_Session(calls), "u1", "p1", "Example.com", "api.example.com",
                                    ["doc1|h|ok|t"])
        (q, p), = calls
        self.assertLess(q.index("SET d._scope_lock = true REMOVE d._scope_lock"), q.index("WITH d"))
        self.assertIn("NOT s STARTS WITH $root + '|'", q)
        self.assertEqual((p["org"], p["root"], p["new"]),
                         ("example.com", "api.example.com", ["api.example.com|doc1|h|ok|t"]))

    def test_the_writer_runs_it_in_a_managed_write(self):
        import inspect
        from graph_db.mixins.recon import resource_mixin
        src = inspect.getsource(resource_mixin.ResourceMixin.update_graph_from_resource_enum)
        self.assertIn("session.execute_write(lambda tx: write_openapi_source_status(", src)


class TestUncoverIsScopeChecked(unittest.TestCase):
    def test_hosts_outside_every_scan_root_get_no_node_and_ips_hang_off_the_org(self):
        from graph_db.mixins.osint_mixin import OsintMixin
        c = _client(OsintMixin)
        stats = c.update_graph_from_uncover(dict(RECON, uncover={
            "hosts": ["v1.api.example.com", "unrelated.test"], "ips": ["192.0.2.1"],
            "ip_ports": {}, "urls": [], "sources": [], "source_counts": {}}), "u1", "p1")
        names = {p["name"] for q, p in c.driver.calls if "MERGE (s:Subdomain" in q}
        self.assertEqual(names, {"v1.api.example.com"})
        self.assertEqual(stats["hosts_out_of_scope"], 1)
        has_ip = [p for q, p in c.driver.calls if "HAS_IP" in q]
        self.assertTrue(has_ip)
        self.assertEqual({p["domain"] for p in has_ip}, {"example.com"})


if __name__ == "__main__":
    unittest.main()
