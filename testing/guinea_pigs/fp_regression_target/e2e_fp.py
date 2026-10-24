"""Drive a real full recon against the false-positive lab, entirely over MCP.

Creates an IP-mode project on the lab's targets with exactly the modules under
test, checks its scope, starts the full pipeline, waits for it, then runs the
Priority Board and waits for that. Prints PROJECT_ID=<id> for validate_e2e.py.

    cd testing/guinea_pigs/fp_regression_target
    docker compose up -d --build
    # the orchestrator must forward the Shodan stub (see README.md)
    python3 e2e_fp.py                       # new project + full run
    python3 e2e_fp.py --rerun <projectId>   # a second run on the same project
    python3 e2e_fp.py --http-layer          # the plan-03 HTTP-layer project (own hosts)
    python3 e2e_fp.py --passive-cves        # the plan-04 passive-CVE project (port scan + Shodan)
    python3 e2e_fp.py --rerun <id> --set '{"naabuCustomPorts": "80,443"}' --no-triage
    python3 e2e_fp.py --rerun <id> --shodan-state 'unavailable=192.88.94.13&hide=CVE-2019-11043'
    python3 e2e_fp.py --js-coverage         # the plan-06 JS-coverage project (.20 + the bulk host .29)
    python3 e2e_fp.py --rerun <id> --no-triage --set '{"jsReconMaxFiles": 60}' --spa-state 'hide=/js/app.min.js'

Reads MCP_SERVER_TOKEN from the repo .env through the lab's mcp_client, which
never prints it.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mcp_client as mcp  # noqa: E402

NET = "192.88.94"
TARGETS = [f"{NET}.{n}" for n in (10, 11, 12, 13, 14, 15, 20)]
APEX = "fplab.test"
VHOST_NAMES = ["admin", "wiki", "dev", "staging", "jenkins", "portal-internal", "qa", "grafana", "vpn",
               "api-gateway", "kibana", "ci", "sso", "monitoring", "backoffice", "uat", "x1",
               "preprod-eu-west", "status", "mail", "intranet"]

AI_OFF = [
    "portScanAiPortCatalogEnabled", "masscanAiPortCatalogEnabled", "nmapAiVersionRegexEnabled",
    "httpProbeAiHeaderScanEnabled", "httpProbeAiFaviconHashEnabled", "httpProbeAiTitleDetectionEnabled",
    "httpProbeAiWappalyzerEnabled", "resourceEnumAiClassifierEnabled", "resourceEnumAiPathClassifierEnabled",
    "resourceEnumAiRagPathFlagEnabled", "resourceEnumAiParamInjectableFlagEnabled",
    "resourceEnumAiToolArgPathEnabled", "domainReconAiTxtHintEnabled", "domainReconAiNsHintEnabled",
    "ffufAiExtensions",
]

SETTINGS = {
    "scanModules": ["port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon"],
    "naabuEnabled": True, "naabuCustomPorts": "80,443", "naabuTopPorts": "",
    "masscanEnabled": False, "nmapEnabled": False, "bannerGrabEnabled": False, "tlsxEnabled": False,
    "katanaEnabled": True, "katanaDepth": 2, "katanaJsCrawl": True,
    "hakrawlerEnabled": False, "gauEnabled": False, "ffufEnabled": False, "arjunEnabled": False,
    "jsluiceEnabled": False, "captureProxyEnabled": False,
    "nucleiEnabled": False, "securityCheckEnabled": False, "cveLookupEnabled": False, "mitreEnabled": False,
    "whoisEnabled": False, "urlscanEnabled": False, "otxEnabled": False, "subdomainDiscoveryEnabled": False,
    "aiSurfaceReconEnabled": False, "graphqlSecurityEnabled": False, "graphqlCopEnabled": False,
    "serializedScanEnabled": False, "supplyChainReconEnabled": False, "originDiscoveryEnabled": False,
    "subjackEnabled": False, "nucleiTakeoversEnabled": False, "baddnsEnabled": False,
    "scaIntelCorrelationEnabled": False,
    # Under test
    "vhostSniEnabled": True, "vhostSniTestL7": True, "vhostSniTestL4": True,
    "vhostSniUseDefaultWordlist": False, "vhostSniUseGraphCandidates": False,
    "vhostSniInjectDiscovered": False, "vhostSniBaselineSizeTolerance": 50, "vhostSniConcurrency": 8,
    "vhostSniCustomWordlist": "\n".join(f"{w}.{APEX}" for w in VHOST_NAMES),
    "jsReconEnabled": True, "jsReconSourceMaps": True, "jsReconDomSinks": True, "jsReconRegexPatterns": True,
    "jsReconValidateKeys": False, "jsReconValidateEndpoints": False, "jsReconMinConfidence": "low",
    "jsReconIncludeChunks": True, "jsReconIncludeArchivedJs": False,
    "shodanEnabled": True, "shodanHostLookup": True, "shodanPassiveCves": True,
    "shodanReverseDns": False, "shodanDomainDns": False,
    "webCachePoisonEnabled": True, "webCachePoisonScanProfile": "safe-confirm",
    # Rules-only ranking: the tiers under test come from the score model, and a
    # budget above 0 makes the UI ask for a review model first.
    "triageReviewBudget": 0,
    **{k: False for k in AI_OFF},
}


# The HTTP-layer cases (plan 03) run as their own project: the security checks
# and endpoint validation they need are off in the main one. .21 (the vendor
# host serving the SAML page .23 redirects to) stays OUTSIDE the target list.
HTTP_LAYER_TARGETS = [f"{NET}.{n}" for n in (15, 20, 22, 23, 25, 26, 27, 28)]
HTTP_LAYER_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon"],
    "securityCheckEnabled": True,
    "jsReconValidateEndpoints": True,
    "vhostSniEnabled": False, "shodanEnabled": False, "webCachePoisonEnabled": False,
}


# The passive-CVE cases (plan 04) run as their own project with only the port
# scan and Shodan, so each of their reruns takes minutes. 22 is in the port list
# and closed on every lab host; .14's Shodan banner is on 22.
PASSIVE_TARGETS = [f"{NET}.{n}" for n in (10, 11, 12, 13, 14)]
PASSIVE_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan"],
    "naabuCustomPorts": "22,80,443",
    "katanaEnabled": False, "vhostSniEnabled": False, "jsReconEnabled": False,
    "webCachePoisonEnabled": False,
}
SHODAN_STUB = f"http://{NET}.30/_lab/shodan"


def _default_katana_excludes():
    """The shipped KATANA_EXCLUDE_PATTERNS (/static/, /_next/static, .min.js, ...),
    read from the recon defaults so the case runs against the real list."""
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))
    from recon.project_settings import DEFAULT_SETTINGS
    return list(DEFAULT_SETTINGS["KATANA_EXCLUDE_PATTERNS"])


# JS coverage (plan 06) runs as its own project: .20's bundles behind the
# default exclude list, and .29's 520 chunks for the file budget. JS recon is
# switched on by jsReconEnabled alone; scanModules holds no "js_recon".
JS_COVERAGE_TARGETS = [f"{NET}.{n}" for n in (20, 29)]
JS_COVERAGE_SETTINGS = {
    **SETTINGS,
    "scanModules": ["port_scan", "http_probe", "resource_enum"],
    "naabuCustomPorts": "80", "katanaJsCrawl": False,
    "vhostSniEnabled": False, "shodanEnabled": False, "webCachePoisonEnabled": False,
}
SPA_STATE = f"http://{NET}.20/_lab/js"


def spa_state(query=""):
    """Which .20 paths answer with the SPA shell for the next run ('' resets it)."""
    with urllib.request.urlopen(f"{SPA_STATE}?{query}", timeout=10) as resp:
        return json.loads(resp.read())


def shodan_state(query=""):
    """Set what the Shodan stub answers for the next lookups ('' resets it)."""
    with urllib.request.urlopen(f"{SHODAN_STUB}?{query}", timeout=10) as resp:
        return json.loads(resp.read())


def start_recon(project_id):
    """start_recon, waiting out the token's rate limit once: the passive-CVE
    project starts four runs in a row."""
    import re
    out, err = mcp.call("start_recon", {"projectId": project_id, "mode": "new"})
    wait_s = re.search(r"Try again in (\d+)s", json.dumps(out)) if err else None
    if wait_s:
        print(f"[*] start_recon rate-limited: waiting {wait_s.group(1)}s", flush=True)
        time.sleep(int(wait_s.group(1)) + 5)
        out, err = mcp.call("start_recon", {"projectId": project_id, "mode": "new"})
    if err:
        raise SystemExit(f"[!] start_recon failed: {json.dumps(out)[:800]}")
    return out


def call(tool, args):
    out, err = mcp.call(tool, args)
    if err:
        raise SystemExit(f"[!] {tool} failed: {json.dumps(out)[:800]}")
    return out


def reset_lab():
    """The rate-limit edge counts admin's requests and the cache holds pages:
    restart both so every run starts from the same state."""
    for name in ("redamon-fp-ratelimit", "redamon-fp-cache"):
        subprocess.run(["docker", "restart", name], check=False, capture_output=True)
    time.sleep(2)


def wait(tool, project_id, done, timeout, every=15):
    deadline, last = time.time() + timeout, None
    while time.time() < deadline:
        state = call(tool, {"projectId": project_id})
        view = json.dumps({k: state.get(k) for k in ("status", "phase", "currentPhase", "current_phase",
                                                     "state", "running") if k in state})
        if view != last:
            print(f"    {time.strftime('%H:%M:%S')} {tool}: {view}", flush=True)
            last = view
        if done(state):
            return state
        time.sleep(every)
    raise SystemExit(f"[!] {tool} timed out after {timeout}s")


def _recon_done(state):
    status = str(state.get("status") or state.get("state") or "").lower()
    return status in ("completed", "error", "failed", "stopped", "idle") and not state.get("running")


def _triage_done(state):
    status = str(state.get("status") or state.get("state") or "").lower()
    return status in ("completed", "error", "failed", "idle", "done") and not state.get("running")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rerun", metavar="PROJECT_ID")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--no-triage", action="store_true")
    ap.add_argument("--http-layer", action="store_true",
                    help="create the plan-03 HTTP-layer project instead of the main one")
    ap.add_argument("--passive-cves", action="store_true",
                    help="create the plan-04 passive-CVE project instead of the main one")
    ap.add_argument("--set", metavar="JSON", help="settings to change before the run (update_recon_settings)")
    ap.add_argument("--shodan-state", metavar="QUERY", default="",
                    help="Shodan stub state for this run, e.g. 'unavailable=<ip>&hide=<cve>'")
    ap.add_argument("--js-coverage", action="store_true",
                    help="create the plan-06 JS-coverage project instead of the main one")
    ap.add_argument("--spa-state", metavar="QUERY", default="",
                    help="SPA (.20) state for this run, e.g. 'hide=/js/app.min.js'")
    args = ap.parse_args()

    mcp.init()
    reset_lab()
    if args.rerun:
        project_id = args.rerun
    else:
        kind = (" (HTTP layer)" if args.http_layer else " (passive CVEs)" if args.passive_cves else
                " (JS coverage)" if args.js_coverage else "")
        targets, settings = ((HTTP_LAYER_TARGETS, HTTP_LAYER_SETTINGS) if args.http_layer else
                             (PASSIVE_TARGETS, PASSIVE_SETTINGS) if args.passive_cves else
                             (JS_COVERAGE_TARGETS, {**JS_COVERAGE_SETTINGS,
                                                    "katanaExcludePatterns": _default_katana_excludes()})
                             if args.js_coverage else (TARGETS, SETTINGS))
        name = f"FP regression lab{kind} {time.strftime('%Y-%m-%d %H:%M:%S')}"
        out = call("create_project", {"name": name, "engagementKind": "internal",
                                      "description": "Guinea pig: testing/guinea_pigs/fp_regression_target",
                                      "targetIps": targets, "settings": settings})
        project_id = (out.get("project") or {}).get("id") or out.get("id") or out.get("projectId")
        print(f"[+] project {project_id} ({name})", flush=True)
    if args.set:
        changed = call("update_recon_settings", {"projectId": project_id, "settings": json.loads(args.set)})
        print("[*] settings:", json.dumps(changed)[:300], flush=True)
    print("[*] Shodan stub:", json.dumps(shodan_state(args.shodan_state)), flush=True)
    print("[*] SPA state:", json.dumps(spa_state(args.spa_state)), flush=True)
    try:
        print("[*] preflight:", json.dumps(call("preflight_scope_check", {"projectId": project_id}))[:600],
              flush=True)
        started = start_recon(project_id)
        print("[+] start_recon:", json.dumps(started)[:400], flush=True)
        time.sleep(20)
        final = wait("get_recon_status", project_id, _recon_done, args.timeout)
        print("[+] recon finished:", json.dumps(final)[:600], flush=True)
    finally:
        if args.shodan_state:
            shodan_state("")
        if args.spa_state:
            spa_state("")
    if not args.no_triage:
        out, err = mcp.call("start_triage_run", {"projectId": project_id})
        if err and "triage:run" in json.dumps(out):
            # A token minted without this scope can still drive the recon; the
            # Priority Board is then started from the UI (or a token with the scope).
            print("[!] this MCP token lacks the triage:run scope: start the Priority Board "
                  "run from the UI, then run validate_e2e.py", flush=True)
        elif err:
            raise SystemExit(f"[!] start_triage_run failed: {json.dumps(out)[:800]}")
        else:
            print("[*] start_triage_run:", json.dumps(out)[:400], flush=True)
            time.sleep(10)
            tri = wait("get_triage_status", project_id, _triage_done, 1800)
            print("[+] triage finished:", json.dumps(tri)[:600], flush=True)
    print(f"PROJECT_ID={project_id}")


if __name__ == "__main__":
    main()
