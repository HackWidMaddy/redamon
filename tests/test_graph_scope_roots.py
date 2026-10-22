"""
graph_db: attaching a write to the right project root.

A Domain-batch project has one Domain node per root, and a partial run can now
cover all of them in one write. graph_db/mixins/recon/scope.py resolves a host to
its root (mirroring recon's helpers, since graph_db must not import recon), and
create_user_input_node attaches the UserInput to the root its input names -
refusing outright when there is no root, because MERGE on an empty name would
create a Domain {name: ""} node.

Fixture roots are alpha.test / beta.test / gamma.test only.

Run with:
    python3 -m pytest tests/test_graph_scope_roots.py -v
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon.scope import attach_roots, root_for_host, scope_roots  # noqa: E402
from graph_db.mixins.recon.user_input_mixin import UserInputMixin, _user_input_root  # noqa: E402
from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402

ROOTS = ["alpha.test", "beta.test", "gamma.test"]


class TestScopeRoots(unittest.TestCase):
    def test_domains_list(self):
        self.assertEqual(scope_roots({"domains": ["alpha.test", "beta.test"], "domain": "alpha.test"}),
                         ["alpha.test", "beta.test"])

    def test_single_domain(self):
        self.assertEqual(scope_roots({"domain": "alpha.test"}), ["alpha.test"])

    def test_empty(self):
        self.assertEqual(scope_roots({"domain": ""}), [])
        self.assertEqual(scope_roots({}), [])


class TestAttachRoots(unittest.TestCase):
    """The writer attachment set: every project root, so the full pipeline (which
    scans one group at a time) still attaches a cross-root host to its own root."""

    def test_all_project_roots_wins_over_the_group_scan_scope(self):
        # The full pipeline: domain is the group root, domains is unset, and the
        # whole batch travels in all_project_roots for the writers only.
        recon = {"domain": "alpha.test", "all_project_roots": ROOTS}
        self.assertEqual(attach_roots(recon), ROOTS)
        self.assertEqual(scope_roots(recon), ["alpha.test"])   # scan stays in the group

    def test_falls_back_to_the_scan_scope_when_absent(self):
        # A partial run, or a single-domain project: no separate attachment set.
        self.assertEqual(attach_roots({"domains": ROOTS}), ROOTS)
        self.assertEqual(attach_roots({"domain": "alpha.test"}), ["alpha.test"])

    def test_blank_entries_are_ignored(self):
        self.assertEqual(attach_roots({"domain": "alpha.test", "all_project_roots": ["", " "]}),
                         ["alpha.test"])


class TestRootForHost(unittest.TestCase):
    def test_label_boundaries(self):
        self.assertEqual(root_for_host("www.beta.test", ROOTS), "beta.test")
        self.assertEqual(root_for_host("beta.test", ROOTS), "beta.test")
        self.assertIsNone(root_for_host("xbeta.test", ROOTS))
        self.assertIsNone(root_for_host("beta.test.example", ROOTS))

    def test_scanner_output_shapes(self):
        # host:port, full URLs and upper case all occur in scanner output.
        self.assertEqual(root_for_host("https://API.Gamma.test:8443/x", ROOTS), "gamma.test")
        self.assertEqual(root_for_host("mail.alpha.test:993", ROOTS), "alpha.test")

    def test_longest_root_wins(self):
        self.assertEqual(root_for_host("a.api.alpha.test", ["alpha.test", "api.alpha.test"]),
                         "api.alpha.test")

    def test_ip_mode(self):
        self.assertEqual(root_for_host("192-0-2-10", ["ip-targets.p1"], ip_mode=True), "ip-targets.p1")
        self.assertIsNone(root_for_host("192-0-2-10", ["ip-targets.p1"]))


class _Client(DomainMixin, UserInputMixin):
    def __init__(self):
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        self.driver = MagicMock()
        self.driver.session.return_value = session
        self.session = session

    def merged_domain(self):
        """The Domain the UserInput was linked to; it must also be the one ensured."""
        ensured = linked = None
        for call in self.session.run.call_args_list:
            if "MERGE (d:Domain" in call[0][0]:
                ensured = call[1]["names"]
            if "HAS_USER_INPUT" in call[0][0]:
                linked = call[1]["domain"]
        assert ensured == [linked], (ensured, linked)
        return linked


def _ui(values, input_type="subdomains"):
    return {"id": "ui-1", "input_type": input_type, "values": values, "tool_id": "Httpx"}


class TestCreateUserInputNode(unittest.TestCase):
    def test_an_empty_domain_raises_and_writes_nothing(self):
        c = _Client()
        with self.assertRaises(ValueError):
            c.create_user_input_node("", _ui(["api.alpha.test"]), "u1", "p1")
        c.session.run.assert_not_called()

    def test_an_empty_root_list_raises(self):
        with self.assertRaises(ValueError):
            _Client().create_user_input_node([], _ui(["1.2.3.4"], "ips"), "u1", "p1")

    def test_a_single_root_string_is_used_as_is(self):
        c = _Client()
        c.create_user_input_node("alpha.test", _ui(["whatever"]), "u1", "p1")
        self.assertEqual(c.merged_domain(), "alpha.test")

    def test_the_first_hostname_picks_the_root(self):
        c = _Client()
        c.create_user_input_node(ROOTS, _ui(["api.gamma.test", "www.alpha.test"]), "u1", "p1")
        self.assertEqual(c.merged_domain(), "gamma.test")

    def test_urls_resolve_through_their_host(self):
        self.assertEqual(_user_input_root(ROOTS, ["https://shop.beta.test/cart"]), "beta.test")

    def test_ip_only_input_falls_back_to_the_first_root(self):
        self.assertEqual(_user_input_root(ROOTS, ["192.0.2.10", "198.51.100.0/24"]), "alpha.test")

    def test_a_host_under_no_root_falls_back_to_the_first_root(self):
        self.assertEqual(_user_input_root(ROOTS, ["unrelated.example"]), "alpha.test")


class TestEnsureRootDomains(unittest.TestCase):
    """The full batch clears the graph once, then runs groups in order; the later
    groups' Domain nodes are restored up front so cross-root writes can link."""

    def _mixin(self):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        m = DomainMixin()
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        session.run.return_value.single.return_value = {"seeded": 3}
        m.driver = MagicMock()
        m.driver.session.return_value = session
        return m, session

    def test_every_root_is_merged_on_the_tenant_key(self):
        m, session = self._mixin()
        self.assertEqual(m.ensure_root_domains(ROOTS + ["", "  "], "u1", "p1"), 3)
        query, params = session.run.call_args.args[0], session.run.call_args.kwargs
        self.assertIn("MERGE (d:Domain {name: name, user_id: $user_id, project_id: $project_id})", query)
        self.assertEqual(params["names"], ROOTS)
        self.assertEqual((params["user_id"], params["project_id"]), ("u1", "p1"))

    def test_no_roots_writes_nothing(self):
        m, session = self._mixin()
        self.assertEqual(m.ensure_root_domains([], "u1", "p1"), 0)
        session.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
