"""Priority Board scoring of recon findings a field report proved noisy.

JS Recon DOM sinks, developer comments and unreachable source-map references
had no class of their own, so they fell through to `generic_secret`: a lexical
`Function()` match in a vendor bundle was scored like a leaked API key.

Run: ./agentic/run_tests.sh tests/test_score_model_recon_fp.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402


def js_finding(finding_type, severity, **kw):
    row = {"id": "j1", "label": "JsReconFinding", "source": "js_recon",
           "finding_type": finding_type, "severity": severity, "host": "h1"}
    row.update(kw)
    return row


class TestJsReconClasses(unittest.TestCase):
    def test_dom_sink_has_its_own_class(self):
        self.assertEqual(sm._class_for(js_finding("dom_sink", "low")).name, "dom_sink")

    def test_legacy_critical_sink_is_capped(self):
        # Scans before the detector fix stamped every Function() match critical.
        result = sm.score(js_finding("dom_sink", "critical"), sm.ProjectFacts())
        self.assertAlmostEqual(result.impact.value, sm.JS_RECON_CLASSES["dom_sink"].impact)
        self.assertIn("caps", result.impact.evidence)

    def test_source_fed_sink_outranks_a_sourceless_one(self):
        fed = sm.score(js_finding("dom_sink", "high"), sm.ProjectFacts())
        lead = sm.score(js_finding("dom_sink", "low"), sm.ProjectFacts())
        self.assertGreater(fed.impact.value, lead.impact.value)
        self.assertGreater(fed.risk, lead.risk)

    def test_a_sink_scores_below_a_generic_secret(self):
        sink = sm.score(js_finding("dom_sink", "critical"), sm.ProjectFacts())
        secret = sm.score(js_finding("secret", "critical"), sm.ProjectFacts())
        self.assertLess(sink.risk, secret.risk)

    def test_dev_comment_map_reference_and_dev_reference_are_info_disclosure(self):
        for kind in ("dev_comment", "source_map_reference", "dev_reference"):
            with self.subTest(kind=kind):
                self.assertEqual(sm._class_for(js_finding(kind, "medium")).name, "info_disclosure")

    def test_unreachable_map_reference_ranks_below_a_real_map(self):
        ref = sm.score(js_finding("source_map_reference", "medium"), sm.ProjectFacts())
        real = sm.score(js_finding("source_map_exposure", "medium"), sm.ProjectFacts())
        self.assertLess(ref.risk, real.risk)

    def test_no_dom_sink_reaches_the_top_two_tiers_unproven(self):
        for severity in ("critical", "high", "medium", "low", "info"):
            with self.subTest(severity=severity):
                result = sm.score(js_finding("dom_sink", severity), sm.ProjectFacts())
                self.assertIn(result.tier, ("T3", "T4"))

    def test_the_model_version_moved_with_the_tables(self):
        self.assertNotIn(sm.SCORE_MODEL_VERSION, ("v3.2.0", "v3.3.0", "v3.4.0"))


def shodan_cve(**kw):
    row = {"id": "shodan-CVE-2021-23017-203.0.113.9", "label": "Vulnerability", "source": "shodan_api",
           "name": "CVE-2021-23017", "cve_ids": ["CVE-2021-23017"], "host": "h1"}
    row.update(kw)
    return row


class TestShodanPassiveCves(unittest.TestCase):
    """Shodan's IP-keyed CVE list is a catalog correlation: no service, no
    version, no test. 160 such rows with blank severity sat in the plan tier."""

    def c_of(self, row):
        return sm.confidence(row, sm.ProjectFacts()).value

    def test_catalog_match_is_a_low_confidence_lead(self):
        self.assertEqual(self.c_of(shodan_cve(detection_method="passive_catalog")), 0.25)

    def test_rows_written_before_the_grading_are_catalog_matches(self):
        for source in ("shodan_api", "internetdb", "shodan"):
            with self.subTest(source=source):
                self.assertEqual(self.c_of(shodan_cve(source=source)), 0.25)

    def test_banner_version_match_is_a_passive_guess(self):
        self.assertEqual(self.c_of(shodan_cve(detection_method="passive_version_match")), 0.4)

    def test_shodan_verified_is_credible_but_never_act_now_unproven(self):
        self.assertEqual(self.c_of(shodan_cve(detection_method="passive_verified")), 0.6)
        row = shodan_cve(detection_method="passive_verified", severity="critical", cvss_score=9.8, cisa_kev=True)
        result = sm.score(row, sm.ProjectFacts(live_hosts={"h1"}))
        self.assertEqual(result.tier, "T3")

    def test_a_sensitive_dev_comment_keeps_its_severity(self):
        medium = sm.score(js_finding("dev_comment", "medium"), sm.ProjectFacts())
        low = sm.score(js_finding("dev_comment", "low"), sm.ProjectFacts())
        self.assertGreater(medium.impact.value, low.impact.value)

    def test_catalog_match_leaves_the_plan_tier(self):
        facts = sm.ProjectFacts(live_hosts={"h1"})
        legacy = sm.score(shodan_cve(), facts)
        graded = sm.score(shodan_cve(detection_method="passive_version_match", severity="high",
                                     cvss_score=7.7), facts)
        self.assertEqual(legacy.tier, "T4")
        self.assertEqual(graded.tier, "T3")

    def test_proof_still_wins(self):
        facts = sm.ProjectFacts(proven_cve_ids={"CVE-2021-23017"})
        self.assertEqual(sm.confidence(shodan_cve(), facts).value, 1.0)

    def test_other_passive_sources_are_unchanged(self):
        for source in ("criminalip", "netlas", "censys"):
            with self.subTest(source=source):
                self.assertEqual(self.c_of(shodan_cve(source=source)), 0.4)


def firebase_secret(status, info):
    """A Secret as js_recon stores a Firebase URL's validation result."""
    validation = {"status": status, "valid": status == "validated", "info": info, "error": "",
                  "checked_at": "2026-10-23T10:00:00Z"}
    return {"id": "s1", "label": "Secret", "source": "js_recon", "secret_type": "Firebase URL",
            "severity": "high", "host": "h1", "validation_status": status,
            "validation_info": json.dumps(validation)}


class TestLockedFirebase(unittest.TestCase):
    """js_recon stored a database answering 401 (rules refuse the read) as
    'validated', which is_proven reads as proof: a locked database ranked T1."""

    LOCKED_401 = firebase_secret("invalid", "Database locked, anonymous read refused: status=401")

    def test_a_locked_database_is_inactive_and_not_proven(self):
        facts = sm.ProjectFacts(live_hosts={"h1"})
        state, why = sm.finding_state(self.LOCKED_401, facts)
        self.assertEqual(state, sm.STATE_INACTIVE)
        self.assertIn("rejected", why)
        self.assertFalse(sm.is_proven(self.LOCKED_401, facts))

    def test_a_locked_database_never_reaches_act_now(self):
        locked_403 = firebase_secret("invalid", "Database locked, anonymous read refused: status=403")
        facts = sm.ProjectFacts(live_hosts={"h1"})
        self.assertFalse(sm.is_proven(locked_403, facts))
        self.assertNotEqual(sm.score(locked_403, facts).tier, "T1")

    def test_the_old_validated_shape_was_read_as_proof(self):
        # Why the recon fix matters: the stored word, not the info text, is proof.
        legacy = firebase_secret("validated", "Database exists but requires auth")
        self.assertTrue(sm.is_proven(legacy, sm.ProjectFacts(live_hosts={"h1"})))


def waf_bypass(source, severity="high"):
    return {"id": "waf-1", "label": "Vulnerability", "source": source, "type": "waf_bypass",
            "name": "Origin Server Exposed (CDN Bypass)", "severity": severity,
            "host": "h1", "url": "https://203.0.113.10"}


class TestWafBypassWhicheverWriterCreatedIt(unittest.TestCase):
    """security_check and origin_discovery MERGE one waf_bypass node (shared
    stable_vuln_id) and `source` is set on create only, so the class used to
    depend on which writer got there first: uncapped "unclassified" via origin
    discovery, a "high" then scoring impact 0.75."""

    def test_both_sources_get_the_cdn_bypass_class(self):
        for source in ("security_check", "origin_discovery"):
            with self.subTest(source=source):
                klass = sm._class_for(waf_bypass(source))
                self.assertEqual(klass.name, "cdn_bypass")
                self.assertTrue(klass.caps_impact)

    def test_same_impact_cap_and_tier_from_either_writer(self):
        facts = sm.ProjectFacts(live_hosts={"h1"})
        check = sm.score(waf_bypass("security_check"), facts)
        origin = sm.score(waf_bypass("origin_discovery"), facts)
        self.assertAlmostEqual(origin.impact.value, check.impact.value)
        self.assertLessEqual(origin.impact.value, sm.SECURITY_CHECK_CLASSES["waf_bypass"].impact)
        self.assertEqual(origin.tier, check.tier)

    def test_a_type_outside_the_catalog_keeps_its_source_routing(self):
        row = {"label": "Vulnerability", "source": "nuclei", "type": "http",
               "category": "sqli", "severity": "high"}
        self.assertEqual(sm._class_for(row).name, "sqli")



if __name__ == "__main__":
    unittest.main()
