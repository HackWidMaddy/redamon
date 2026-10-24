"""End-to-end assertions for the false-positive lab, run entirely over MCP.

Run after e2e_fp.py:   python3 validate_e2e.py <projectId>
The HTTP-layer project (e2e_fp.py --http-layer): python3 validate_e2e.py <projectId> --http-layer
The passive-CVE project (e2e_fp.py --passive-cves), after each of its runs:
    python3 validate_e2e.py <projectId> --passive-cves baseline|partial|unscanned|off

N-01, a run with no JS input keeps the earlier js_recon findings, takes a second
run: `--js-count` prints the count, then switch resource_enum off, rerun, and
`--js-count-equals <n>` asserts it is unchanged (README.md, "Running the proof").

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
         " | --passive-cves baseline|partial|unscanned|off]")
if len(sys.argv) not in (2, 3, 4):
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
    if sys.argv[2] == "--passive-cves" and len(sys.argv) == 4:
        passive_cves(sys.argv[3])
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
                       f.fetch_result AS fr, f.first_party_files AS fp, f.has_sources_content AS sc""")
    return {r["js"].rsplit("/", 1)[-1]: r for r in rows}


m = maps()
r = m.get("main.4f2a9c.js")
check("M-01", r and r["t"] == "source_map_exposure" and r["sev"] == "high" and r["fp"] == 2
      and (r["map"] or "").endswith("main.4f2a9c.js.map"), f"served map with own source: {r}")
r = m.get("lib.8e1f.js")
check("M-02", r and r["t"] == "source_map_exposure" and r["sev"] == "low" and r["fp"] == 0, f"library-only map: {r}")
check("M-03", "shell.2b7a.js" not in m, f"map answered by the SPA shell: {m.get('shell.2b7a.js')}")
r = m.get("private.9c3d.js")
check("M-04", r and r["t"] == "source_map_reference" and r["sev"] == "info" and r["fr"] == "http_403",
      f"map behind a 403: {r}")
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
check("K-06", any(t == "JWT Token" and n >= 220 for t, n in got)
      and any(t == "Bearer Token" and n >= 220 for t, n in got),
      f"secrets longer than 200 characters: {got} (expect the JWT and its Bearer header, not dropped "
      f"as a base64 blob)")
font = q("""MATCH (s:Secret) WHERE s.source = 'js_recon' AND s.source_url ENDS WITH '/theme.5b6c.js'
            RETURN s.secret_type AS t, s.matched_text AS mt""")
check("K-07", [(r["t"], r["mt"]) for r in font] == [("AWS Access Key ID", "AKIAZ3FPLB7QW4XN6R2T")],
      f"key 8,000 characters after a font marker on a long minified line: {font}")
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
