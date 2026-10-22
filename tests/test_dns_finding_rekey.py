"""tooling/scripts/dns_finding_rekey.py (plan 10.4, TOOL-01).

A Domain batch's SPF/DMARC/DNSSEC/AXFR findings are keyed on the batch root, so
a regroup (`co.uk` -> `acme.co.uk`) gives them new ids. The script carries the
mute, the Priority Board layers, the un-mute exemptions, the fix items and the
captured transactions over to the new id. Fake Neo4j and Postgres sessions; the
PSL is a stub, so no network and no real target names.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from graph_db.mixins.recon.vuln_mixin import stable_vuln_id  # noqa: E402
from tooling.scripts import dns_finding_rekey as rk  # noqa: E402

UID, PID = "u-rekey", "p-rekey"


def org(host):
    """A tiny PSL: co.uk is a suffix, everything else registers at two labels."""
    labels = host.split(".")
    if host.endswith(".co.uk"):
        return ".".join(labels[-3:]) if len(labels) >= 3 else None
    if host == "co.uk" or len(labels) < 2:
        return None
    return ".".join(labels[-2:])


def vid(kind, root):
    return stable_vuln_id(kind, "", root, UID, PID)


class FakeSession:
    def __init__(self, findings=(), nodes=None):
        self.findings = list(findings)
        self.nodes = nodes or {}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if query is rk.DNS_FINDINGS:
            return list(self.findings)
        if query is rk.READ_PAIR:
            return [{"id": i, **self.nodes[i]} for i in (params["old"], params["new"])
                    if i in self.nodes]
        return []

    def writes(self):
        return [(q, p) for q, p in self.calls if q not in (rk.DNS_FINDINGS, rk.READ_PAIR)]


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = [("id",), ("user_id",), ("domain_batch_hosts",)]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.log.append(("sql", " ".join(sql.split()), params))

    def fetchall(self):
        return self.conn.rows


class FakeConn:
    def __init__(self, rows):
        self.rows = rows
        self.log = []

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.log.append(("commit",))


def _finding(kind, root, fid=None):
    return {"domain": root, "type": kind, "id": fid or vid(kind, root)}


def _project(hosts):
    return {"id": PID, "user_id": UID, "domain_batch_hosts": hosts}


class TestPlan(unittest.TestCase):
    def test_a_suffix_root_moves_to_the_one_org_under_it(self):
        s = FakeSession([_finding("spf_missing", "co.uk"), _finding("dnssec_missing", "co.uk")])
        plan = rk.plan_project(s, _project(["www.acme.co.uk", "*.acme.co.uk"]), org)
        self.assertEqual([(r["type"], r["old_root"], r["new_root"], r["old_id"], r["new_id"])
                          for r in plan["rekeys"]], [
            ("spf_missing", "co.uk", "acme.co.uk", vid("spf_missing", "co.uk"),
             vid("spf_missing", "acme.co.uk")),
            ("dnssec_missing", "co.uk", "acme.co.uk", vid("dnssec_missing", "co.uk"),
             vid("dnssec_missing", "acme.co.uk")),
        ])
        self.assertEqual(plan["ambiguous"], [])

    def test_a_root_holding_several_orgs_is_listed_not_rekeyed(self):
        # The old finding was about co.uk itself: its mute says nothing about
        # either org's mail records.
        s = FakeSession([_finding("dmarc_missing", "co.uk")])
        plan = rk.plan_project(s, _project(["www.acme.co.uk", "mail.other.co.uk"]), org)
        self.assertEqual(plan["rekeys"], [])
        self.assertEqual(plan["ambiguous"][0]["orgs"], ["acme.co.uk", "other.co.uk"])

    def test_a_deeper_root_moves_to_its_org(self):
        s = FakeSession([_finding("zone_transfer", "api.example.test")])
        plan = rk.plan_project(s, _project(["x.api.example.test"]), org)
        self.assertEqual(plan["rekeys"][0]["new_root"], "example.test")

    def test_an_unchanged_root_is_left_alone(self):
        s = FakeSession([_finding("spf_missing", "example.test")])
        self.assertEqual(rk.plan_project(s, _project(["www.example.test"]), org)["rekeys"], [])

    def test_a_finding_not_keyed_on_its_root_is_not_touched(self):
        # A single-domain finding keys on "", whatever Domain it hangs off.
        s = FakeSession([_finding("spf_missing", "co.uk", fid=vid("spf_missing", ""))])
        self.assertEqual(rk.plan_project(s, _project(["www.acme.co.uk"]), org)["rekeys"], [])

    def test_a_removed_root_is_left_for_the_prune(self):
        s = FakeSession([_finding("spf_missing", "co.uk")])
        plan = rk.plan_project(s, _project(["www.example.test"]), org)
        self.assertEqual((plan["rekeys"], plan["ambiguous"]), ([], []))

    def test_the_query_is_tenant_scoped_and_dns_only(self):
        s = FakeSession([])
        rk.plan_project(s, _project([]), org)
        query, params = s.calls[0]
        self.assertIn("(d:Domain {user_id: $uid, project_id: $pid})", query)
        self.assertIn("(v:Vulnerability {user_id: $uid, project_id: $pid})", query)
        self.assertEqual((params["uid"], params["pid"]), (UID, PID))
        self.assertEqual(set(params["types"]),
                         {"spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer"})


REKEY = {"old_id": "old1", "new_id": "new1", "type": "spf_missing",
         "old_root": "co.uk", "new_root": "acme.co.uk"}

HUMAN = {"triage_source": "human", "triage_status": "likely_noise", "triage_reason": "ours",
         "triage_priority_score": 12.5, "triage_tier": "T4", "triage_decided_by": "person",
         "stale_since": "2026-10-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"}
BASE = {"triage_math_score": 40.0, "triage_priority_score": 40.0, "triage_tier": "T3",
        "triage_decided_by": "rules", "updated_at": "2026-10-20T00:00:00Z"}
MUTED_BY_PERSON = {"muted_at": "t1", "muted_by": "user-1", "muted_reason": "accepted"}


class TestGraphRekey(unittest.TestCase):
    def test_with_no_new_node_the_id_is_renamed_in_place(self):
        s = FakeSession(nodes={"old1": {"muted": True, "props": {**HUMAN, **MUTED_BY_PERSON}}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, REKEY), "renamed")
        [(query, params)] = s.writes()
        self.assertIs(query, rk.RENAME)
        self.assertEqual((params["old"], params["new"], params["uid"], params["pid"]),
                         ("old1", "new1", UID, PID))

    def test_a_persons_decision_and_mute_move_onto_a_scanned_new_node(self):
        s = FakeSession(nodes={
            "old1": {"muted": True, "props": {**HUMAN, **MUTED_BY_PERSON}},
            "new1": {"muted": False, "props": dict(BASE)},
        })
        self.assertEqual(rk.rekey_graph(s, UID, PID, REKEY), "merged")
        [(query, params)] = s.writes()
        carried = params["carried"]
        # the decision block moves whole, its final carried unchanged, never recomputed
        self.assertEqual(carried["triage_source"], "human")
        self.assertEqual(carried["triage_priority_score"], 12.5)
        self.assertEqual(carried["triage_decided_by"], "person")
        # the new node's own block is removed first, so the two never mix
        self.assertIn("REMOVE keep.triage_math_score", query)
        self.assertIn("keep.triage_priority_score", query)
        # the mute comes with it; the stale stamp belongs to the old node only
        self.assertTrue(params["mute"])
        self.assertEqual(carried["muted_by"], "user-1")
        self.assertNotIn("stale_since", carried)
        self.assertIn("DETACH DELETE dead", query)

    def test_the_new_nodes_own_decision_wins(self):
        s = FakeSession(nodes={
            "old1": {"muted": False, "props": dict(BASE)},
            "new1": {"muted": False, "props": dict(HUMAN)},
        })
        rk.rekey_graph(s, UID, PID, REKEY)
        [(query, params)] = s.writes()
        self.assertEqual(params["carried"], {})
        self.assertNotIn("REMOVE", query)

    def test_mcp_mute_provenance_never_lands_on_a_persons_mute(self):
        old = {"muted": True, "props": {"muted_by": "user-1", "muted_channel": "mcp",
                                        "muted_token": "rdm_abc"}}
        s = FakeSession(nodes={"old1": old, "new1": {"muted": True, "props": MUTED_BY_PERSON}})
        rk.rekey_graph(s, UID, PID, REKEY)
        [(_, params)] = s.writes()
        self.assertFalse(params["mute"])
        self.assertNotIn("muted_channel", params["carried"])
        self.assertNotIn("muted_token", params["carried"])

    def test_an_old_node_already_gone_is_a_no_op(self):
        s = FakeSession(nodes={"new1": {"muted": False, "props": {}}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, REKEY), "gone")
        self.assertEqual(s.writes(), [])

    def test_no_write_touches_updated_at(self):
        for nodes in ({"old1": {"muted": False, "props": HUMAN}},
                      {"old1": {"muted": True, "props": {**HUMAN, **MUTED_BY_PERSON}},
                       "new1": {"muted": False, "props": BASE}}):
            s = FakeSession(nodes=nodes)
            rk.rekey_graph(s, UID, PID, REKEY)
            for query, params in s.writes():
                self.assertNotIn("updated_at", query)
                self.assertNotIn("updated_at", params.get("carried", {}))


class TestPostgresRekey(unittest.TestCase):
    def test_every_row_that_names_the_old_id_follows_it(self):
        conn = FakeConn([])
        with conn.cursor() as cur:
            rk.rekey_postgres(cur, PID, REKEY)
        statements = [(sql, params) for kind, *rest in conn.log if kind == "sql"
                      for sql, params in [rest]]
        text = "\n".join(sql for sql, _ in statements)
        self.assertIn("UPDATE node_filter_exemptions e SET node_key = %(new)s", text)
        self.assertIn("DELETE FROM node_filter_exemptions", text)
        self.assertIn("array_replace(finding_ids, %(old)s, %(new)s)", text)
        self.assertIn("UPDATE captured_http_transactions SET finding_id = %(new)s", text)
        self.assertNotIn("updated_at", text)
        for _, params in statements:
            self.assertEqual(params, {"pid": PID, "old": "old1", "new": "new1",
                                      "label": "Vulnerability"})


class TestRun(unittest.TestCase):
    def _setup(self):
        session = FakeSession([_finding("spf_missing", "co.uk")],
                              nodes={vid("spf_missing", "co.uk"): {"muted": False, "props": {}}})
        conn = FakeConn([(PID, UID, ["www.acme.co.uk"])])
        return session, conn

    def test_a_dry_run_writes_nothing(self):
        session, conn = self._setup()
        out = []
        summary = rk.run(conn, FakeDriver(session), None, False, org, out=out.append)
        self.assertEqual(len(summary[PID]["rekeys"]), 1)
        self.assertEqual(session.writes(), [])
        self.assertEqual([e for e in conn.log if e[0] != "sql" or "UPDATE" in e[1]
                          or "DELETE" in e[1]], [])
        self.assertTrue(any("(dry run)" in line for line in out))

    def test_apply_updates_postgres_before_the_graph(self):
        session, conn = self._setup()
        order = []
        with patch.object(rk, "rekey_postgres", side_effect=lambda *a: order.append("pg")), \
             patch.object(rk, "rekey_graph", side_effect=lambda *a: order.append("graph") or "renamed"):
            rk.run(conn, FakeDriver(session), PID, True, org, out=lambda *_: None)
        self.assertEqual(order, ["pg", "graph"])
        self.assertIn(("commit",), conn.log)

    def test_a_blank_project_id_is_refused(self):
        with self.assertRaises(ValueError):
            rk.run(FakeConn([]), FakeDriver(FakeSession()), "  ", False, org)

    def test_apply_refuses_while_services_run(self):
        with patch.object(rk, "services_are_up", return_value=["webapp"]):
            self.assertEqual(rk.main(["--all", "--apply"]), 2)


if __name__ == "__main__":
    unittest.main()
