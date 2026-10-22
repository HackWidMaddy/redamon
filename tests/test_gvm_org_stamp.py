"""SCN-01: GVM stamps the org Domain(s), and scans a scan root only when it is
a target.

A Domain node is the org, so a stamp matched on the scan root found nothing for
a root below its org, and a batch's merged recon file names every org in
metadata.org_domains.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from gvm_scan import gvm_scanner as gvm_mod  # noqa: E402


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))

        class _R:
            def single(self):
                return {"n": 0, "count": 0, "matched": 0}

            def __iter__(self):
                return iter([])
        return _R()


class _Driver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _Session(self.calls)


class TestGvmStamp(unittest.TestCase):
    def _stamped(self, metadata):
        from graph_db.mixins.gvm_mixin import GvmMixin
        cls = type("C", (GvmMixin,), {})
        c = cls.__new__(cls)
        c.driver = _Driver()
        c.update_graph_from_gvm_scan({"metadata": metadata, "scans": [{"vulnerabilities": []}],
                                      "summary": {}}, "u1", "p1")
        return [p["root_domain"] for q, p in c.driver.calls if "d.gvm_scan_timestamp" in q]

    def test_a_single_domain_stamps_its_org(self):
        self.assertEqual(self._stamped({"target_domain": "api.example.com",
                                        "org_domain": "example.com",
                                        "org_domains": ["example.com"]}), ["example.com"])

    def test_a_batch_stamps_every_org(self):
        self.assertEqual(self._stamped({"target_domain": "", "org_domain": "",
                                        "org_domains": ["a.test", "b.test"]}), ["a.test", "b.test"])

    def test_an_older_result_stamps_its_target_domain(self):
        self.assertEqual(self._stamped({"target_domain": "example.com"}), ["example.com"])


class TestGvmTargets(unittest.TestCase):
    def _recon(self, metadata):
        return {"domain": "api.example.com", "metadata": dict(root_domain="api.example.com", **metadata),
                "dns": {"domain": {"has_records": True, "ips": {"ipv4": ["192.0.2.1"]}},
                        "subdomains": {"v1.api.example.com": {"has_records": True,
                                                              "ips": {"ipv4": ["192.0.2.2"]}}}}}

    def test_a_scan_root_that_is_no_target_is_not_scanned(self):
        ips, hosts = gvm_mod.extract_targets_from_recon(
            self._recon({"scope_mode": "enumerate", "include_root_domain": False}))
        self.assertEqual(hosts, {"v1.api.example.com"})
        self.assertEqual(ips, {"192.0.2.2"})

    def test_with_root_on_it_is(self):
        ips, hosts = gvm_mod.extract_targets_from_recon(
            self._recon({"scope_mode": "enumerate", "include_root_domain": True}))
        self.assertEqual(hosts, {"api.example.com", "v1.api.example.com"})

    def test_an_older_recon_file_keeps_the_root(self):
        _, hosts = gvm_mod.extract_targets_from_recon(self._recon({}))
        self.assertIn("api.example.com", hosts)


if __name__ == "__main__":
    unittest.main()
