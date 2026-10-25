"""End-to-end assertions for the false-positive lab, run entirely over MCP.

Run after e2e_fp.py:   python3 validate_e2e.py <projectId>
The HTTP-layer project (e2e_fp.py --http-layer): python3 validate_e2e.py <projectId> --http-layer
The passive-CVE project (e2e_fp.py --passive-cves), after each of its runs:
    python3 validate_e2e.py <projectId> --passive-cves baseline|partial|unscanned|off

N-01, a run with no JS input keeps the earlier js_recon findings, takes a second
run: `--js-count` prints the count, then switch resource_enum off, rerun, and
`--js-count-equals <n>` asserts it is unchanged (README.md, "Running the proof").

The JS-coverage project (e2e_fp.py --js-coverage): `--js-coverage first` after
its first run (prints JS_BULK_COUNT=<n>), then rerun it with a low
jsReconMaxFiles and .20's /js/app.min.js hidden, and `--js-coverage capped <n>`.

The vhost-naming / tlsx CDN-tag project (e2e_fp.py --vhost-origin):
`--vhost-origin`.

The plan-09 per-host coverage projects: `--coverage stamps` on the
e2e_fp.py --coverage project (writes the linked CVEs to
coverage_cve_snapshot.json), `--coverage import <thatProjectId>` on its
exported-then-imported copy, `--coverage clean` on the --coverage-clean
project, and `--coverage lost` on it once its graph nodes are deleted.

Every check is read-only Cypher through query_graph (tenant-scoped by the
server) and prints PASS / FAIL with what the graph actually holds. Exit 0 only
when every assertion holds. Case ids match README.md.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mcp_client as mcp  # noqa: E402

USAGE = ("usage: validate_e2e.py <projectId> [--js-count | --js-count-equals <n> | --http-layer"
         " | --passive-cves baseline|partial|unscanned|off | --js-coverage first | --js-coverage capped <n>"
         " | --vhost-origin | --coverage stamps|clean|lost | --coverage import <originalProjectId>]")
if len(sys.argv) not in (2, 3, 4, 5):
    sys.exit(USAGE)
P = sys.argv[1]
NET = "192.88.94"
APEX = "fplab.test"
results = []


def q(cypher):
    out, err = mcp.call("query_graph", {"projectId": P, "cypher": cypher})
    if err or not isinstance(out, dict):
        raise RuntimeError(f"query failed: {json.dumps(out)[:500]}")
    return out.get("records", [])


def check(case, ok, detail):
    results.append((case, bool(ok), detail))


def report():
    width = max(len(c) for c, _, _ in results)
    for case, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {case:<{width}}  {detail}")
    failed = [c for c, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; FAILED: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


def http_layer_checks():
    """Plan 03 cases, on the project e2e_fp.py --http-layer creates."""
    api = q("""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND v.type = 'ip_api_exposed'
               RETURN v.matched_ip AS ip, v.severity AS sev, v.evidence AS ev, v.control_check AS cc""")
    by_ip = {r["ip"]: r for r in api}
    silent = sorted(ip for ip in (f"{NET}.15", f"{NET}.20", f"{NET}.25") if ip in by_ip)
    check("A-01", not silent, f"API Endpoint Exposed on IP on catch-alls: {silent} (expect none on the cache "
                              f"and SPA hosts, nor on the JSON catch-all .25)")
    r = by_ip.get(f"{NET}.22")
    check("A-02", r and r["sev"] == "high" and r["cc"] == "passed" and "control_check: passed" in (r["ev"] or ""),
          f"the real API on .22: {r}")

    ep = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = 'http://{NET}.23' AND e.path = '/'
               OPTIONAL MATCH (e)-[:USES_TECHNOLOGY]->(t:Technology)
               RETURN e.title AS title, e.server AS server, e.first_status_code AS first,
                      e.status_code AS last, e.redirect_chain_codes AS chain,
                      e.redirected_off_host AS off, e.final_url AS final, collect(t.name) AS techs""")
    r = ep[0] if ep else None
    check("R-01", r and not r["title"] and not r["server"] and not [t for t in r["techs"] if "SAP" in (t or "")],
          f".23's root Endpoint keeps nothing from the third-party IdP page: {r}")
    check("R-02", r and r["first"] == 302 and r["off"] is True and (r["chain"] or [None])[0] == 302
          and (r["final"] or "").endswith("/saml/login"), f".23's redirect chain: {r}")
    ext = q(f"""MATCH (d:ExternalDomain) WHERE d.domain = '{NET}.21'
                RETURN d.sources AS src, d.redirect_from_urls AS frm, d.titles_seen AS titles""")
    r = ext[0] if ext else None
    check("R-03", r and "http_probe_redirect" in (r["src"] or [])
          and any(f"{NET}.23" in u for u in (r["frm"] or [])), f"the IdP host is an external domain: {r}")

    js = q(f"""MATCH (e:Endpoint) WHERE (e.source = 'js_recon' OR e.js_recon_source = true)
               AND e.baseurl IN ['http://{NET}.20', 'http://{NET}.22']
               RETURN e.baseurl AS b, e.path AS p, e.validation_status AS vs ORDER BY b, p""")
    shell = [x for x in js if x["b"] == f"http://{NET}.20" and x["p"] in ("/api/read", "/api/list")]
    check("E-02", not shell, f"js_recon Endpoints for paths the SPA shell answers like any path: {shell}")
    real = [x for x in js if x["b"] == f"http://{NET}.22" and x["p"] == "/api/v1"]
    check("E-03", real and real[0]["vs"] == "hittable", f"the real API path from the bundle: {real}")

    deny_hosts = [f"http://{NET}.{n}" for n in (26, 27, 28)]
    roots = q(f"""MATCH (e:Endpoint) WHERE e.path = '/' AND e.baseurl STARTS WITH 'http://{NET}.'
                  RETURN e.baseurl AS b, e.shared_body_cluster AS n""")
    marks = {r["b"]: r["n"] for r in roots}
    check("D-01", all((marks.get(b) or 0) >= 3 for b in deny_hosts),
          f"the shared deny page: { {b: marks.get(b) for b in deny_hosts} } (expect shared_body_cluster >= 3)")
    others = {b: n for b, n in marks.items() if n is not None and b not in deny_hosts}
    check("D-02", not others, f"pages no other host serves are not marked: {others}")


PASSIVE = "['shodan_api', 'internetdb', 'shodan', 'shodan_host_lookup']"


def passive_cves(stage):
    """Plan 04 cases, on the project e2e_fp.py --passive-cves creates, after each run."""
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source IN {PASSIVE}
                 RETURN v.id AS id, v.target_ip AS ip, v.target_port AS port, v.name AS cve,
                        v.port_confirmed AS pc, v.triage_state AS state,
                        v.triage_base_tier_rule AS rule, v.triage_tier AS tier,
                        toString(v.updated_at) AS seen""")
    by = {(r["ip"], r["cve"]): r for r in rows}
    ssh, nginx, catalog = (by.get((f"{NET}.14", "CVE-2018-15473")), by.get((f"{NET}.10", "CVE-2021-23017")),
                           by.get((f"{NET}.10", "CVE-2019-11043")))
    heartbleed = by.get((f"{NET}.13", "CVE-2014-0160"))
    if stage == "baseline":
        check("P-01", ssh and ssh["port"] == 22 and ssh["pc"] is False,
              f".14's OpenSSH CVE on 22, closed on the lab and in the port list: {ssh}")
        check("P-02", nginx and nginx["port"] == 80 and nginx["pc"] is True,
              f".10's nginx CVE on 80, which naabu found open: {nginx}")
        check("P-03", heartbleed and heartbleed["port"] == 443 and heartbleed["pc"] is False,
              f".13's verified CVE on 443, closed on the lab: {heartbleed}")
        check("P-04", ssh and ssh["state"] == "inactive" and ssh["rule"] == "the port scan found the port closed",
              f"the board: .14's CVE is resolved as inactive with the closed-port reason: {ssh}")
        check("P-05", nginx and nginx["state"] == "open" and nginx["tier"] not in ("T1", "T2"),
              f"the board: .10's confirmed CVE stays open, below Act soon: {nginx}")
        ports = q(f"""MATCH (i:IP)-[:HAS_PORT]->(p:Port) WHERE i.address IN ['{NET}.14', '{NET}.10']
                      RETURN i.address AS ip, p.number AS port, p.source AS src, p.passive_only AS passive""")
        pb = {(r["ip"], r["port"]): r for r in ports}
        p22, p80 = pb.get((f"{NET}.14", 22)), pb.get((f"{NET}.10", 80))
        check("P-06", p22 and p22["passive"] is True and p80 and p80["passive"] is False,
              f"Port 22 only Shodan saw is passive_only, port 80 naabu found is not: {p22} / {p80}")
        check("H-04", not [r for r in rows if r["ip"] in (f"{NET}.11", f"{NET}.12")],
              "no CVE on the Vercel / cdn-tagged hosts")
    elif stage == "partial":
        check("P-07", heartbleed is not None and nginx is not None and heartbleed["seen"] < nginx["seen"],
              f".13 could not be looked up: its CVE is kept as it was ({heartbleed}), .10's was refreshed "
              f"({nginx and nginx['seen']})")
        check("P-08", catalog is None, f".10's CVE the provider dropped is pruned: {catalog}")
        gaps = q("""MATCH (d:Domain) WHERE d.recon_coverage_gaps IS NOT NULL
                     RETURN d.recon_coverage_gaps AS g""")
        listed = [g for r in gaps for g in json.loads(r["g"] or "[]") if g.get("source") == "shodan"]
        check("P-09", len(listed) == 1 and listed[0].get("hosts") == 1,
              f"the coverage record names Shodan once, for one IP: {listed}")
    elif stage == "unscanned":
        check("P-10", ssh and ssh["pc"] is None,
              f"with naabu on 80,443 the scan did not look at 22: no port_confirmed: {ssh}")
        check("P-11", nginx and nginx["pc"] is True, f".10's port 80 is still confirmed open: {nginx}")
    elif stage == "off":
        # query_graph never sees a muted finding; the muted-findings tool does.
        out, err = mcp.call("search_muted_findings", {"projectId": P, "search": "CVE-2021-23017"})
        muted = [] if err else (out.get("findings") or out.get("items") or out.get("results") or [])
        check("P-12", not rows and len(muted) == 1 and "stale" in json.dumps(muted[0]).lower(),
              f"Shodan switched off: no unmuted Shodan CVE is left ({rows}); the muted one is kept "
              f"and stale: {json.dumps(muted)[:400]}")
    else:
        sys.exit(USAGE)


SPA = f"http://{NET}.20"
BULK = f"http://{NET}.29"
COVERAGE_FILES = {"/static/js/main.4f3a.js": "static", "/_next/static/chunks/pages/app-91c.js": "next",
                  "/js/app.min.js": "min", "/js/bundle.js__v_ab12": "hash"}


def bulk_count():
    """js_recon findings on the bulk host: what a capped rerun must keep."""
    total = 0
    for label in ("JsReconFinding", "Secret"):
        rows = q(f"""MATCH (f:{label}) WHERE f.source = 'js_recon'
                     AND f.source_url STARTS WITH '{BULK}/' RETURN count(f) AS n""")
        total += rows[0]["n"]
    return total


def js_coverage_checks(stage, expected_bulk=None):
    """Plan 06 cases, on the project e2e_fp.py --js-coverage creates."""
    files = q(f"""MATCH (jf:JsReconFinding {{finding_type: 'js_file'}}) WHERE jf.source_url STARTS WITH '{SPA}/'
                  OPTIONAL MATCH (jf)-[:HAS_ENDPOINT]->(e:Endpoint)
                  RETURN jf.source_url AS url, collect(e.path) AS paths""")
    by_url = {r["url"][len(SPA):]: r["paths"] for r in files}
    if stage == "first":
        # Each file calls fetch("/api/cov/<marker>"): its Endpoint under the
        # file's own node proves the file was downloaded and analyzed.
        analyzed = {p: f"/api/cov/{m}" in by_url.get(p, []) for p, m in COVERAGE_FILES.items()}
        check("J-11", all(analyzed.values()), f"bundles the default exclude list matches, analyzed: {analyzed}")
        excluded = [p for p in COVERAGE_FILES if p != "/js/bundle.js__v_ab12"]
        eps = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{SPA}' AND e.path IN {excluded}
                    RETURN e.path AS p""")
        check("J-12", not eps, f"the excluded JS files handed to js_recon are no Endpoints: {[r['p'] for r in eps]}")

        mapped = f"{SPA}/static/js/main.4f3a.js.map#src/config.ts"
        sec = q(f"""MATCH (s:Secret {{source: 'js_recon'}}) WHERE s.source_url = '{mapped}'
                    OPTIONAL MATCH (jf:JsReconFinding {{finding_type: 'js_file', source_url: '{mapped}'}})-[:HAS_SECRET]->(s)
                    RETURN s.secret_type AS t, s.base_url AS b, s.validation_status AS vs, count(jf) AS files""")
        r = sec[0] if sec else None
        check("S-04", r and r["t"] == "Stripe Secret Key" and r["b"] == SPA and r["files"] == 1,
              f"the key in the map's src/config.ts is a Secret under its own file node: {r}")
        ep = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{SPA}' AND e.path = '/api/v2/orders'
                   RETURN e.method AS m, e.source AS src, e.js_recon_source AS js""")
        check("S-04b", ep and ep[0]["m"] == "GET", f"the map source's fetch is an Endpoint: {ep}")
        sm = q(f"""MATCH (f:JsReconFinding) WHERE f.finding_type = 'source_map_exposure'
                   AND f.source_url IN ['{SPA}/static/js/main.4f3a.js', '{SPA}/static/js/main.4f2a9c.js']
                   RETURN f.source_url AS js, f.severity AS sev, f.secrets_in_source AS n""")
        maps_ = {r["js"].rsplit("/", 1)[-1]: r for r in sm}
        r = maps_.get("main.4f3a.js")
        check("S-04c", r and r["sev"] == "low" and r["n"] == 1, f"the map itself is low and counts its secret: {r}")
        lib = [r for label in ("Secret", "JsReconFinding") for r in q(
            f"""MATCH (s:{label}) WHERE s.source = 'js_recon'
                AND (s.source_url CONTAINS 'lib.8e1f.js.map#' OR coalesce(s.matched_text, '') CONTAINS 'LIBRARYEXAMPLE')
                RETURN '{label}' AS l, s.source_url AS u""")]
        check("S-05", not lib, f"library sources feed no detector: {lib}")

        refs = q(f"""MATCH (f:JsReconFinding) WHERE f.finding_type = 'source_map_reference'
                     AND f.source_url STARTS WITH '{SPA}/' RETURN f.source_url AS js, f.control_check AS cc""")
        ref = {r["js"].rsplit("/", 1)[-1]: r["cc"] for r in refs}
        check("M-07", "s3miss.0c1d.js" not in ref, f"an S3 AccessDenied 403 for a missing map: {ref.get('s3miss.0c1d.js')}")
        check("M-08", "cfmiss.2e3f.js" not in ref, f"a 403 the made-up sibling also gets: {ref.get('cfmiss.2e3f.js')}")
        check("M-04", ref.get("private.9c3d.js") == "passed", f"a 403 the sibling does not get: {ref.get('private.9c3d.js')}")

        want = {("GET", "/v1/lab-orders"), ("GET", "/lab-users"), ("GET", "/api/lab-users/"),
                ("GET", "/v2/lab-items"), ("GET", "/v1/lab-accounts"), ("GET", "/api/lab-export")}
        got = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{SPA}' AND (e.path CONTAINS 'lab-' OR e.path = '/q')
                    RETURN e.method AS m, e.path AS p, e.path_template AS t""")
        have = {(r["m"], r["p"]) for r in got}
        tmpl = {r["p"]: r["t"] for r in got}
        check("E-04", want <= have and tmpl.get("/api/lab-users/") == "/api/lab-users/${id}",
              f"the call shapes in calls.6e7f.js: missing {sorted(want - have)}; template {tmpl.get('/api/lab-users/')}")
        noise = sorted(p for _, p in have if "lab-key" in p or "lab-q" in p)
        check("E-05", not noise, f"Map / URLSearchParams / headers .get() yield no Endpoint: {noise}")

        detail = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = '{BULK}' AND e.path ENDS WITH '/detail' RETURN count(e) AS n""")
        check("F-00", detail[0]["n"] >= 500, f"bulk map sources analyzed at volume: {detail[0]['n']} detail endpoints")
        print(f"JS_BULK_COUNT={bulk_count()}")
        return

    gaps = q("""MATCH (d:Domain) WHERE d.recon_coverage_gaps IS NOT NULL
                RETURN d.name AS d, d.recon_coverage_gaps AS g""")
    text = " ".join(str(r["g"]) for r in gaps)
    check("F-01", "js_recon_file_cap" in text, f"the file cap is a coverage gap: {text[:400]}")
    check("F-02", "/js/app.min.js" not in by_url,
          f"a fully analyzed host still prunes: the hidden file's findings are gone: {by_url.get('/js/app.min.js')}")
    got = bulk_count()
    check("F-03", got == expected_bulk, f"the capped host keeps its findings: {got} (expect {expected_bulk})")


def vhost_origin_checks():
    """Plan 07 cases, on the project e2e_fp.py --vhost-origin creates."""
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip = '{NET}.31'
                 RETURN v.hostname AS h, v.name AS name, v.type AS type, v.layer AS layer,
                        v.severity AS sev ORDER BY h""")
    by_host = {r["h"]: r for r in rows}
    portal = by_host.get(f"portal.{APEX}") or {}
    check("V-11", (portal.get("name"), portal.get("type"), portal.get("layer"))
          == (f"Hidden Virtual Host: portal.{APEX}", "hidden_vhost", "both"),
          f"same app on L7 and L4: {portal} (expect the hidden-vhost name and type, layer both)")
    split = by_host.get(f"split.{APEX}") or {}
    check("V-12", (split.get("name"), split.get("type"), split.get("layer"), split.get("sev"))
          == (f"Routing Inconsistency (L7 vs L4): split.{APEX}", "host_header_bypass", "both", "high"),
          f"Host and SNI reach different apps: {split} (expect the routing name, high)")
    check("V-13", sorted(by_host) == [f"portal.{APEX}", f"split.{APEX}"],
          f"names reported on .31: {sorted(by_host)} (expect portal and split only; the rest hit the default page)")
    ips = {r["ip"]: r for r in q(f"""MATCH (i:IP) WHERE i.address IN ['{NET}.31', '{NET}.32']
                                     RETURN i.address AS ip, i.is_cdn AS cdn, i.cdn_name AS name,
                                            i.cdn_source AS src""")}
    edge = ips.get(f"{NET}.32") or {}
    check("T-01", (edge.get("cdn"), edge.get("name"), edge.get("src")) == (True, "cloudflare", "tlsx"),
          f".32 behind a Cloudflare-issued certificate: {edge} (expect is_cdn, cloudflare, cdn_source tlsx)")
    plain = ips.get(f"{NET}.31") or {}
    check("T-02", plain and not plain.get("cdn") and plain.get("src") is None,
          f".31 with the lab's own certificate: {plain} (expect no CDN tag)")


CVE_SNAPSHOT = os.environ.get("COVERAGE_CVE_SNAPSHOT", "coverage_cve_snapshot.json")


def _summary(project_id=None):
    out, err = mcp.call("graph_summary", {"projectId": project_id or P})
    if err or not isinstance(out, dict):
        raise RuntimeError(f"graph_summary failed: {json.dumps(out)[:500]}")
    return out


def _stamps():
    """Each BaseURL's stamps, by the lab host it serves."""
    rows = q("""MATCH (b:BaseURL) RETURN b.url AS url, b.js_recon_status AS js, b.js_recon_inputs AS ji,
                       b.js_recon_outputs AS jo, b.js_recon_reason AS jr, b.nuclei_status AS nu,
                       b.nuclei_inputs AS ni, b.nuclei_reason AS nr""")
    return {r["url"].split("://", 1)[1].split(":")[0]: r for r in rows if "://" in (r["url"] or "")}


def _cve_links(project_id=None):
    global P
    saved, P = P, project_id or P
    try:
        return q("""MATCH (v:Vulnerability)-[r:INCLUDES_CVE]->(c:CVE)
                    RETURN c.id AS id, properties(c) AS props, count(r) AS links ORDER BY id""")
    finally:
        P = saved


def coverage_checks(stage, other=None):
    """Plan 09 cases, on the projects e2e_fp.py --coverage / --coverage-clean create."""
    if stage == "stamps":
        hosts = _stamps()
        spa, api, down = hosts.get(f"{NET}.20") or {}, hosts.get(f"{NET}.22") or {}, hosts.get(f"{NET}.33")
        check("CV-01", spa.get("js") in ("complete", "partial") and (spa.get("ji") or 0) > 0 and (spa.get("jo") or 0) > 0,
              f".20 (serves JavaScript): {spa} (expect js_recon complete or partial, files read, findings)")
        check("CV-02", (api.get("js"), api.get("ji")) == ("no_input", 0),
              f".22 (a JSON API, no JavaScript): {api} (expect js_recon no_input)")
        check("CV-03", down is not None and down.get("js") is None and down.get("nu") is None,
              f".33 (answers 503): {down} (expect a BaseURL with no stamp from either module)")
        scanned = {h: r for h, r in hosts.items() if r.get("nu")}
        check("CV-04", {f"{NET}.20", f"{NET}.22"} <= set(scanned)
              and all(r["nu"] in ("complete", "partial") and (r["ni"] or 0) > 0 for r in scanned.values()),
              f"nuclei stamps: { {h: (r['nu'], r['ni'], r['nr']) for h, r in scanned.items()} }")
        cov = _summary().get("coverage") or {}
        js, nu = cov.get("js_recon") or {}, cov.get("nuclei") or {}
        check("CV-05", js.get("recorded") and nu.get("recorded") and js.get("not_scanned", 0) >= 1
              and nu.get("not_scanned", 0) >= 1 and js.get("no_input", 0) >= 1,
              f"graph_summary coverage: {cov} (expect both recorded, .33 not_scanned, .22 no_input)")
        links = _cve_links()
        check("CV-06", links, f"INCLUDES_CVE links: {[(r['id'], r['links']) for r in links]} (expect some)")
        with open(CVE_SNAPSHOT, "w") as fh:
            json.dump(links, fh, sort_keys=True, default=str)
        print(f"CVE_LINKS={sum(r['links'] for r in links)} (snapshot in {CVE_SNAPSHOT})")
    elif stage == "clean":
        plain = _stamps().get(f"{NET}.34") or {}
        check("CC-01", (plain.get("js"), plain.get("ji"), plain.get("jo")) == ("complete", 1, 0),
              f".34 (one script, nothing in it): {plain} (expect js_recon complete, 1 file, 0 findings)")
        check("CC-02", js_recon_count() == 0, "js_recon findings: expect none")
        js = (_summary().get("coverage") or {}).get("js_recon") or {}
        check("CC-03", js.get("recorded") and js.get("complete") == 1,
              f"graph_summary coverage.js_recon: {js} (expect one complete host)")
    elif stage == "lost":
        out = _summary()
        check("GL-01", out.get("warning") == "graph_data_missing" and out.get("liveGraphState") == "stable",
              f"graph_summary after the project's nodes were deleted: warning={out.get('warning')!r}, "
              f"graphDataMissing={out.get('graphDataMissing')}")
    elif stage == "import":
        with open(CVE_SNAPSHOT) as fh:
            before = json.load(fh)
        original, imported = _cve_links(other), _cve_links()
        count = lambda rows: sorted((r["id"], r["links"]) for r in rows)  # noqa: E731
        check("EX-01", original and count(imported) == count(original),
              f"INCLUDES_CVE links, imported {count(imported)} vs original {count(original)}")
        same = json.loads(json.dumps(imported, sort_keys=True, default=str))
        check("EX-02", [r["props"] for r in same] == [r["props"] for r in before],
              "linked CVE nodes' properties after the import equal the snapshot taken before the export")
    else:
        sys.exit(USAGE)


def js_recon_count():
    """JsReconFinding + Secret written by js_recon: what a run with no JS input must keep."""
    findings = q("MATCH (f:JsReconFinding) WHERE f.source = 'js_recon' RETURN count(f) AS n")
    secrets = q("MATCH (s:Secret) WHERE s.source = 'js_recon' RETURN count(s) AS n")
    return findings[0]["n"] + secrets[0]["n"]


if len(sys.argv) > 2:
    if sys.argv[2] == "--js-count" and len(sys.argv) == 3:
        print(f"JS_RECON_COUNT={js_recon_count()}")
        sys.exit(0)
    if sys.argv[2] == "--js-count-equals" and len(sys.argv) == 4:
        expected, got = int(sys.argv[3]), js_recon_count()
        print(f"{'PASS' if got == expected else 'FAIL'}  N-01  js_recon findings after a run with "
              f"no JS input: {got} (expect the {expected} from before)")
        sys.exit(0 if got == expected else 1)
    if sys.argv[2] == "--http-layer" and len(sys.argv) == 3:
        http_layer_checks()
        sys.exit(report())
    if sys.argv[2] == "--js-coverage" and sys.argv[3:4] == ["first"] and len(sys.argv) == 4:
        js_coverage_checks("first")
        sys.exit(report())
    if sys.argv[2] == "--js-coverage" and sys.argv[3:4] == ["capped"] and len(sys.argv) == 5:
        js_coverage_checks("capped", int(sys.argv[4]))
        sys.exit(report())
    if sys.argv[2] == "--vhost-origin" and len(sys.argv) == 3:
        vhost_origin_checks()
        sys.exit(report())
    if sys.argv[2] == "--passive-cves" and len(sys.argv) == 4:
        passive_cves(sys.argv[3])
        sys.exit(report())
    if sys.argv[2] == "--coverage" and len(sys.argv) in (4, 5):
        coverage_checks(sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else None)
        sys.exit(report())
    sys.exit(USAGE)


# --------------------------------------------------------------------------- VHost
def vhosts(ip):
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip = '{ip}'
                 RETURN v.hostname AS h, v.layer AS layer, v.severity AS sev ORDER BY h, layer""")
    return sorted((r["h"], r["layer"]) for r in rows), rows


got, _ = vhosts(f"{NET}.10")
check("V-01/V-02/V-03", got == [(f"admin.{APEX}", "L7"), (f"wiki.{APEX}", "L7")],
      f"Fastly-like edge: {got} (expect admin + wiki, L7, nothing from the 19 catch-all names)")
got, _ = vhosts(f"{NET}.11")
check("V-04/V-05", got == [(f"admin.{APEX}", "L4")], f"Cloudflare-like edge: {got} (expect the SNI-routed admin only)")
got, _ = vhosts(f"{NET}.12")
check("V-07", got == [], f"provider redirect: {got}")
got, _ = vhosts(f"{NET}.13")
check("V-08", got == [], f"Akamai-style deny page: {got}")
got, _ = vhosts(f"{NET}.14")
check("V-09/V-10", got == [(f"admin.{APEX}", "L7")],
      f"rate-limited edge: {got} (expect admin kept despite its 429 on the second probe, no 429 names)")
got = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip IN ['{NET}.15', '{NET}.20']
            RETURN v.ip AS ip, v.hostname AS h""")
check("V-catch-all", got == [], f"catch-all app hosts (cache, SPA): {got}")
got = q("""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.severity = 'high'
           RETURN v.ip AS ip, v.hostname AS h""")
check("V-06", got == [], f"vhost findings rated high: {got}")
got = q(f"""MATCH (i:IP) WHERE i.address IN ['{NET}.10', '{NET}.13']
            RETURN i.address AS ip, i.vhost_sni_suppressed_by_control AS supp""")
check("V-controls", all((r.get("supp") or 0) >= 15 for r in got) and len(got) == 2,
      f"control-suppressed names per edge: {got}")


# --------------------------------------------------------------------------- JS: DOM sinks
def sinks(file_name):
    rows = q(f"""MATCH (f:JsReconFinding) WHERE f.finding_type = 'dom_sink' AND f.source_url ENDS WITH '/{file_name}'
                 RETURN f.title AS t, f.severity AS sev, f.confidence AS conf, f.user_source AS src,
                        f.vendor AS vendor, f.third_party AS tp, f.evidence AS ev, f.id AS id
                 ORDER BY t, sev""")
    return sorted((r["t"], r["sev"]) for r in rows), rows


got, rows = sinks("main.4f2a9c.js")
check("J-01/J-02/J-03/J-05/J-06",
      got == [("innerHTML", "high"), ("innerHTML", "low"), ("location.href", "low")],
      f"main bundle sinks: {got} (expect the hash->innerHTML bug high, the sourceless sink and the "
      f"navigation write low, no Function/eval/__proto__ from the shim or the guards)")
high = [r for r in rows if r["sev"] == "high"]
check("X-04", high and "location.hash" in (high[0].get("ev") or "") and "!function" not in (high[0].get("ev") or ""),
      f"evidence of the real bug: {(high[0].get('ev') if high else None)!r:.160}")
got, _ = sinks("msg.7c8d.js")
check("J-04", got == [("eval", "critical")], f"minified message handler: {got}")
got, _ = sinks("proto.6a7b.js")
check("J-07", got == [("__proto__", "low")], f"prototype writes: {got} (expect the write through __proto__, not the shim)")
got, rows = sinks("vendor.3c1d.js")
check("J-08", got == [("innerHTML", "info")] and all(r.get("vendor") for r in rows), f"vendor bundle: {got}")
got, _ = sinks("jquery.prettyPhoto.js")
check("J-10", got == [("innerHTML", "high")], f"hash-reading plugin: {got}")
got, rows = sinks("loader.js")
if rows:
    check("J-09", all(r["sev"] == "info" and r.get("tp") for r in rows), f"third-party loader: {got}")
else:
    check("J-09 (not crawled)", True, "the third-party loader was not collected by the crawl; nothing to judge")


# --------------------------------------------------------------------------- JS: source maps
def maps():
    rows = q("""MATCH (f:JsReconFinding) WHERE f.finding_type IN ['source_map_exposure', 'source_map_reference']
                RETURN f.source_url AS js, f.finding_type AS t, f.severity AS sev, f.map_url AS map,
                       f.fetch_result AS fr, f.first_party_files AS fp, f.has_sources_content AS sc,
                       f.control_check AS cc""")
    return {r["js"].rsplit("/", 1)[-1]: r for r in rows}


m = maps()
r = m.get("main.4f2a9c.js")
check("M-01", r and r["t"] == "source_map_exposure" and r["sev"] == "low" and r["fp"] == 2
      and (r["map"] or "").endswith("main.4f2a9c.js.map"),
      f"served map with own source (low: its impact is the findings its sources produce): {r}")
r = m.get("lib.8e1f.js")
check("M-02", r and r["t"] == "source_map_exposure" and r["sev"] == "low" and r["fp"] == 0, f"library-only map: {r}")
check("M-03", "shell.2b7a.js" not in m, f"map answered by the SPA shell: {m.get('shell.2b7a.js')}")
r = m.get("private.9c3d.js")
check("M-04", r and r["t"] == "source_map_reference" and r["sev"] == "info" and r["fr"] == "http_403"
      and r["cc"] == "passed", f"map behind a 403 a made-up sibling does not get: {r}")
check("M-07", "s3miss.0c1d.js" not in m, f"an S3 AccessDenied 403 for a missing map: {m.get('s3miss.0c1d.js')}")
check("M-08", "cfmiss.2e3f.js" not in m, f"a 403 the made-up sibling also gets: {m.get('cfmiss.2e3f.js')}")
r = m.get("buildref.7a8b.js")
check("M-05", r and r["t"] == "source_map_reference" and r["fr"] in ("unreachable", "unsafe")
      and f"{NET}.99" in (r["map"] or ""), f"map on another unreachable host: {r}")
r = m.get("inline.5e6f.js")
check("M-06", r and r["t"] == "source_map_exposure" and (r["map"] or "").startswith("data:application/json;base64,…")
      and len(r["map"] or "") < 300, f"inline map stored as a label: {r}")


# --------------------------------------------------------------------------- JS: secrets
secrets = q("""MATCH (s:Secret) WHERE s.source = 'js_recon'
               RETURN s.secret_type AS t, s.matched_text AS mt, s.sample AS sample""")
types_ = sorted(r["t"] for r in secrets)
blob = json.dumps(secrets)
noise = [w for w in ("Forgot your", "auth.form", "#password-input", "/account/reset-password",
                     "Keep this secret", "localhost", "devapi", "debug") if w in blob]
check("K-01", not noise, f"UI text / dev literals stored as secrets: {noise}")
check("K-04/K-05", "AWS Access Key ID" in types_ and "Generic API Key" in types_
      and sum(1 for t in types_ if t in ("Generic Secret", "Hardcoded Password")) >= 2,
      f"Secret types: {types_} (expect the AWS key, the API key, 'Summer 2024!' and '$ecureP4ss2024')")
refs = q("""MATCH (f:JsReconFinding) WHERE f.finding_type = 'dev_reference'
            RETURN f.title AS t, f.evidence AS ev, f.severity AS sev ORDER BY t""")
got = sorted((r["t"], r["sev"]) for r in refs)
check("K-02", got == [("Debug Flag", "info"), ("Internal/Staging URL", "info"), ("Localhost with Port", "info")]
      and any("devapi.fplab.test" in (r["ev"] or "") for r in refs), f"developer references: {refs}")
check("K-03", "developer.vendor.test" not in json.dumps(refs) + blob, "documentation host not reported")
ext = sorted(r["d"] for r in q("""MATCH (f:JsReconFinding) WHERE f.finding_type = 'external_domain'
                                   RETURN f.title AS d"""))
own = {f"{NET}.{n}" for n in (10, 11, 12, 13, 14, 15, 20)}
check("X-05", f"{NET}.99" in ext and not own.intersection(ext),
      f"external domains: {ext} (expect the unreachable map host, never a scanned target IP)")

long_secrets = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.source_url ENDS WITH '/auth.1d2e.js'
                    RETURN s.secret_type AS t, size(s.matched_text) AS n""")
got = sorted((r["t"], r["n"]) for r in long_secrets)
# The lab's JWT carries role service_role, so since plan 05.6 it is named by its role.
check("K-06", any(t in ("JWT Token", "Supabase service_role key") and n >= 220 for t, n in got)
      and any(t == "Bearer Token" and n >= 220 for t, n in got),
      f"secrets longer than 200 characters: {got} (expect the JWT and its Bearer header, not dropped "
      f"as a base64 blob)")
font = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.source_url ENDS WITH '/theme.5b6c.js'
            RETURN s.secret_type AS t, s.matched_text AS mt""")
check("K-07", [(r["t"], r["mt"]) for r in font] == [("AWS Access Key ID", "AKIAZ3FPLB7QW4XN6R2T")],
      f"key 8,000 characters after a font marker on a long minified line: {font}")
# Plan 05: keys.8c2d.js
keys = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.source_url ENDS WITH '/keys.8c2d.js'
            RETURN s.secret_type AS t, s.severity AS sev, s.confidence AS conf,
                   s.public_client_key AS pub, s.matched_text AS mt, s.context AS ctx""")
by_t = {}
for r in keys:
    by_t.setdefault(r["t"], []).append(r)
pub = sorted((t, r["sev"], r["pub"]) for t in ("GCP API Key", "Segment Write Key") for r in by_t.get(t, []))
check("K-08", pub == [("GCP API Key", "info", True), ("Segment Write Key", "info", True)],
      f"public-by-design keys: {pub} (expect both at info with public_client_key)")
check("K-09", "LoginForm_password__3xYz9" not in json.dumps(secrets) and "Secret_secret__a1B2c" not in json.dumps(secrets),
      f"CSS-module class names stored as secrets: {[r['t'] for r in secrets if '__' in (r['mt'] or '')]}")
sup = {t: sorted((r["sev"], r["pub"]) for r in by_t.get(t, [])) for t in ("Supabase service_role key", "Supabase anon key")}
check("K-10", sup == {"Supabase service_role key": [("critical", False)], "Supabase anon key": [("info", True)]}
      and not by_t.get("JWT Token") and not by_t.get("Supabase Key"),
      f"Supabase keys by role: {sup}; other names on them: {sorted(t for t in by_t if 'JWT' in t or t == 'Supabase Key')}")
signed = [r["sev"] for r in by_t.get("Signed URL in client code", [])]
zap = [r["sev"] for r in by_t.get("Zapier Webhook", [])]
check("K-11", signed == ["medium"] and zap == ["high"],
      f"presigned S3 URL: {signed} (expect medium); Zapier hook: {zap} (expect high)")
raws = [r["mt"] for r in keys if r["mt"]]
two = sorted(r["t"] for r in keys if r["t"] in ("GitHub Token Classic", "Stripe Secret Key"))
leaks = [(r["t"], raw[:8]) for r in keys for raw in raws if raw in (r["ctx"] or "")]
check("K-12", two == ["GitHub Token Classic", "Stripe Secret Key"] and all(r["ctx"] for r in keys) and not leaks,
      f"two keys 100 characters apart: {two}; contexts present: {all(r['ctx'] for r in keys)}; "
      f"raw values inside a context: {leaks}")
eps = q(f"""MATCH (e:Endpoint) WHERE e.baseurl = 'http://{NET}.20' AND e.path IN ['/api/read', '/api/list', '/api/save']
            RETURN e.path AS path, e.method AS method ORDER BY path, method""")
got = sorted((r["path"], r["method"]) for r in eps)
check("E-01", got == [("/api/list", "GET"), ("/api/read", "GET"), ("/api/save", "POST")],
      f"endpoint methods on a minified line with postMessage: {got} (expect read and list GET, the "
      f"axios.post control POST)")


# --------------------------------------------------------------------------- Shodan
shodan = q(f"""MATCH (i:IP)-[:HAS_VULNERABILITY]->(v:Vulnerability)
               WHERE v.source IN ['shodan_api', 'internetdb', 'shodan'] AND i.address STARTS WITH '{NET}.'
               RETURN i.address AS ip, v.name AS cve, v.source AS src, v.detection_method AS dm,
                      v.severity AS sev, v.target_port AS port, v.product AS product, v.verified AS verified""")
by = {(r["ip"], r["cve"]): r for r in shodan}
api = any(r["src"] == "shodan_api" for r in shodan)
check("H-04", not [r for r in shodan if r["ip"] in (f"{NET}.11", f"{NET}.12")],
      f"CVE rows on the Vercel / cdn-tagged hosts: {[r for r in shodan if r['ip'] in (f'{NET}.11', f'{NET}.12')]}")
r = by.get((f"{NET}.10", "CVE-2021-23017"))
if api:
    check("H-01", r and r["dm"] == "passive_version_match" and r["sev"] == "high" and r["port"] == 80
          and r["product"] == "nginx", f"banner CVE: {r}")
    r2 = by.get((f"{NET}.13", "CVE-2014-0160"))
    check("H-02", r2 and r2["dm"] == "passive_verified" and r2["verified"] is True and r2["port"] == 443,
          f"verified banner CVE: {r2}")
else:
    check("H-01/H-02 (InternetDB path)", r and r["dm"] == "passive_catalog",
          f"no Shodan key configured, so only InternetDB answered: {r}")
r = by.get((f"{NET}.10", "CVE-2019-11043"))
check("H-03", r and r["dm"] == "passive_catalog" and not r.get("sev"), f"catalog-only CVE: {r}")


# --------------------------------------------------------------------------- Cache
cache = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'cache_poisoning'
              RETURN coalesce(v.endpoint_url, v.url, v.matched_at) AS url, v.cache_impact AS impact,
                     v.confidence_tier AS tier""")
urls = json.dumps(cache)
check("C-02", "/promo" not in urls, f"A/B page reported as poisoned: {[c for c in cache if '/promo' in json.dumps(c)]}")
check("C-01", "/home" in urls, f"real unkeyed-header poisoning on /home: {cache}")


# --------------------------------------------------------------------------- Priority Board
# query_graph scopes every query to the tenant through a labelled node, so the
# two finding kinds are read separately rather than through one unlabelled MATCH.
tiers = q("""MATCH (n:JsReconFinding) WHERE n.finding_type IN ['dom_sink', 'dev_reference']
             RETURN 'JsReconFinding' AS label, n.finding_type AS kind, n.title AS name,
                    n.severity AS sev, n.triage_tier AS tier""")
tiers += q("""MATCH (n:Vulnerability) WHERE n.source IN ['shodan_api', 'internetdb']
              RETURN 'Vulnerability' AS label, n.source AS kind, n.name AS name,
                     n.severity AS sev, n.triage_tier AS tier""")
scored = [t for t in tiers if t.get("tier")]
bad = [t for t in scored if t["tier"] in ("T1", "T2")]
check("X-01a", scored and not bad, f"{len(scored)} scored; in T1/T2: {bad}")
cat = [t for t in scored if t["kind"] in ("shodan_api", "internetdb") and t["name"] == "CVE-2019-11043"]
check("X-01b", cat and all(t["tier"] == "T4" for t in cat), f"catalog-only CVE tier: {cat}")
refs_t = [t for t in scored if t["kind"] == "dev_reference"]
check("X-01c", refs_t and all(t["tier"] == "T4" for t in refs_t), f"developer reference tiers: {refs_t}")
public = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.public_client_key = true
              RETURN s.secret_type AS t, s.triage_tier AS tier""")
check("X-01d", public and all(r["tier"] == "T4" for r in public),
      f"public client keys on the board: {sorted((r['t'], r['tier']) for r in public)} (expect every one in T4)")


# --------------------------------------------------------------------------- Priority Board: secret groups
# Grouped by the leaked VALUE, and learned per pattern: before plan 02 every
# js_recon secret of one category on one host was a single board row.
aws = q(f"""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.secret_type = 'AWS Access Key ID'
              AND s.base_url = 'http://{NET}.20' AND s.triage_group_key IS NOT NULL
              RETURN s.matched_text AS mt, s.source_url AS url, s.triage_group_key AS g,
                     s.triage_detector AS d""")
by_value = {}
for r in aws:
    by_value.setdefault(r["mt"], set()).add(r["g"])
groups = [g for gs in by_value.values() for g in gs]
check("S-01", len(by_value) >= 2 and len(set(groups)) == len(by_value) == len(groups),
      f"distinct AWS keys on one host -> groups: { {k[:8]: sorted(v) for k, v in by_value.items()} } "
      f"(expect one group per key, never one per category)")
twice = [r for r in aws if r["mt"] == "AKIAZ3FPLB7QW4XN6R2T"]
check("S-02", len({r["url"] for r in twice}) == 2 and len({r["g"] for r in twice}) == 1,
      f"the same key in theme and config bundles: {[(r['url'].rsplit('/', 1)[-1], r['g']) for r in twice]} "
      f"(expect two findings, one group: one rotation)")
check("S-03", aws and {r["d"] for r in aws} == {"js_recon:aws-access-key-id"},
      f"detector of the AWS secrets: {sorted({r['d'] for r in aws})} (expect the pattern, not 'js_recon:cloud')")


# --------------------------------------------------------------------------- report
sys.exit(report())
