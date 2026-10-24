# False-positive regression guinea pig

End-to-end proof, through a real IP-mode recon run driven entirely over MCP,
that the false-positive filters drop the noise **and** keep the real findings.
Every case that must stay silent sits next to one that must still fire, so a
green run proves both halves.

```bash
docker compose up -d --build        # sixteen hosts on 192.88.94.0/24, no host ports
docker compose down
```

`192.88.94.0/24` is in the deprecated 6to4 relay prefix, like the other recon
labs: JS recon fetches through an SSRF guard that rejects loopback, RFC1918 and
TEST-NET, and Python treats this prefix as global. Scan containers run with
`network_mode: host` and reach the lab over the local bridge; nothing leaves
the host.

## Running the proof

1. **Point Shodan at the stub.** `.30` answers the Shodan host API and
   InternetDB with fixed records, so the Shodan cases are reproducible and no
   real lookup is made. Restart the orchestrator with the two lab-only
   overrides, and without them when you are done:

   ```bash
   SHODAN_API_BASE=http://192.88.94.30 \
   SHODAN_INTERNETDB_BASE=http://192.88.94.30/internetdb \
     docker compose up -d --no-deps recon-orchestrator      # from the repo root
   # afterwards
   docker compose up -d --no-deps recon-orchestrator
   ```

   Whatever these name receives the project's Shodan API key; never set them
   in a real deployment. With no Shodan key configured the run takes the
   InternetDB path, and `validate_e2e.py` checks that path instead.

2. **Run the recon:** `python3 e2e_fp.py`. It creates an `internal` IP-mode
   project over `.10`-`.15` and `.20` with only the modules under test (naabu
   on 80/443, httpx, katana, Vhost/SNI with a fixed `*.fplab.test` list, JS
   recon, Shodan, web cache poisoning; every AI hook off), runs
   `preflight_scope_check`, starts the full pipeline, waits for it, then runs
   the Priority Board and waits for that. It restarts the rate-limit and cache
   hosts first, so every run starts from the same state, and prints
   `PROJECT_ID=<id>`. `--rerun <id>` scans the same project again.

3. **Assert the graph:** `python3 validate_e2e.py <projectId>`. Read-only
   Cypher through MCP `query_graph`; exit 0 only when every case holds. The MCP
   token is read from the repo `.env` and never printed.

4. **The HTTP layer (plan 03).** `python3 e2e_fp.py --http-layer` creates a
   second `internal` IP-mode project over `.15`, `.20`, `.22`, `.23`, `.25` and
   `.26`-`.28` with the security checks and JS Recon endpoint validation on
   (both off in the main project), then `python3 validate_e2e.py <id>
   --http-layer` asserts its cases. `.21` stays outside that project on
   purpose: it is the third-party IdP `.23` redirects to. The WAF case runs the
   check directly, because an IP-mode run has no hostname to put behind an
   edge: with the `waf-bypass` lab up (its edge at `<edge>`),

   ```bash
   docker run --rm --network host -v "$PWD/../../..:/repo" -w /repo/recon \
     -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon:latest -c \
     'from recon.helpers import security_checks as sc; print(sc.check_waf_bypass("<edge>", "192.88.94.24"))'
   ```

   must print `None` (W-01), while the same call with the `waf-bypass` origin
   still returns the `payload_differential` finding.

5. **A run with no JS input (N-01).** `python3 validate_e2e.py <id> --js-count`
   prints the project's js_recon findings. Switch Resource Enumeration off
   (`update_recon_settings` with `scanModules` minus `resource_enum`), run
   `python3 e2e_fp.py --rerun <id> --no-triage`, then
   `python3 validate_e2e.py <id> --js-count-equals <n>`: the count must not
   change. Switch Resource Enumeration back on afterwards.

## Hosts and the cases they carry

| Host | Behaves like | Case | Must hold |
|---|---|---|---|
| `.10` | a Fastly-style edge: bare IP 421, unknown names a 500 echoing the name plus a random cache node and epoch | V-01/02/03 | only `admin` (JSON app) and `wiki` (a page that changes per request) are reported; the 500 catch-all is not |
| `.11` | a Cloudflare-style TLS edge that routes on SNI and blocks everything else with a Ray-ID page | V-04/05 | only the SNI-routed `admin` is reported, on L4 |
| `.12` | a provider that 301s every name to `https://<name>/` | V-07 | no vhost finding |
| `.13` | an Akamai-style deny page with an entity-encoded reference per request | V-08 | no vhost finding |
| `.14` | an edge that rate-limits: `admin` answers once then 429s, some names 429 from the start | V-09/10 | `admin` is still reported; no 429 name is |
| `.15`, `.20` | catch-all apps (cache front end, SPA shell) | V-catch-all | no vhost finding |
| all | | V-06, V-controls | no vhost finding rated high; on `.10` and `.13` at least 15 names are dropped because a made-up control name answered the same way |
| `.20` | SPA bundle: sinks with no attacker-controlled source, a `location.hash` sink buried after 400 sourceless ones, guards that look like sinks | J-01/02/03/05/06, X-04 | sourceless sinks stay info; the hash sink is high and its evidence is the sink, not minified noise |
| `.20` | minified `message` handler that `eval`s | J-04 | critical |
| `.20` | an `Object.prototype` shim beside a real write through `__proto__` | J-07 | only the `__proto__` write, low |
| `.20` | a vendor bundle | J-08 | info, marked vendor |
| `.20` | a jQuery plugin that writes the hash into `innerHTML` | J-10 | high, despite the vendor-looking file name |
| `.21` | a third-party loader on another host | J-09 | info and marked third-party, when the crawl collects it |
| `.20` | source maps: first-party sources (served as octet-stream), library-only, a 403, the SPA shell answering a map URL, a map on an unreachable host, an inline `data:` map | M-01..M-06 | first-party map high, library map low, the shell is no map, the 403 and the unreachable host are an info reference, the inline map is stored truncated |
| `.20` | UI labels that read like secrets beside real ones | K-01, K-04/05 | the labels are not secrets; the AWS key, the generic API key and both passwords are |
| `.20` | debug flag, internal URL, localhost with port, a documentation host | K-02, K-03 | the three dev references are info; the documentation host is not reported |
| `.20` | a 228-character JWT in quotes and as a `Bearer` header | K-06 | both are Secrets, not dropped as a base64 blob |
| `.20` | a 5-line bundle whose last line is 20,000 characters: `fontFamily` near its start, an AWS-format key 8,000 characters later | K-07 | the key is a Secret; a font marker hides only what sits next to it |
| `.20` | `window.postMessage(1);fetch("/api/read");api.get("/api/list")` beside an `axios.post` control | E-01 | `/api/read` and `/api/list` are GET, `/api/save` is POST |
| `.20` | a second run with Resource Enumeration off, so js_recon gets no JS file | N-01 | every earlier js_recon finding is kept |
| `.20` | URLs back to the scanned host and to another, unreachable one | X-05 | the scanned IP is never an external domain of itself; the other host is |
| `.10`-`.13` | Shodan stub (`.30`): an unverified version-matched CVE, a verified one, a catalog-only CVE, a cloud-host org, a `cdn` tag | H-01..H-04 | the version match stays a high candidate on its own port; the verified CVE is marked verified; the catalog CVE carries no severity; the CDN and cloud hosts get no Shodan finding |
| `.15` | a shared cache keyed on the URL only: `/promo` alternates two variants, `/home` reflects `X-Forwarded-Host` | C-01, C-02 | `/home` is reported as poisoned; the A/B page is not |
| `.20` | two different AWS keys (main and theme bundles), and the theme key shipped again in a config bundle | S-01/02/03 | after the Priority Board: one board group per key value, never one per category; the same key in two files is one group; the detector is the pattern (`js_recon:aws-access-key-id`) |
| `.22` | a JSON API: `200` on `/api/v1`, `404 {"code":"NOT_FOUND"}` on every other path | A-02 | one High "API Endpoint Exposed on IP" whose evidence says `control_check: passed` |
| `.25`, `.15`, `.20` | `.25` answers `200 {"code":"NOT_FOUND"}` to every path (a made-up control path included); `.15` and `.20` are the catch-all apps | A-01 | no "API Endpoint Exposed on IP" |
| `.23` | `/` answers `302` to `.21`'s "SAP NetWeaver SAML Login" page, outside the project | R-01/02/03 | `.23`'s root Endpoint has no title, server or SAP technology; `first_status_code` 302, `redirected_off_host` true, `final_url` the IdP page; `.21` is an ExternalDomain from `http_probe_redirect` |
| `.20`, `.22` | the SPA shell answers `/api/read` and `/api/list` like any path; a bundle also calls `.22`'s `/api/v1` | E-02/03 | with endpoint validation on, no js_recon Endpoint for the shell's paths; `/api/v1` on `.22` is `hittable` |
| `.26`-`.28` | one gateway deny page, the same bytes, on three hosts | D-01/02 | their root Endpoints carry `shared_body_cluster` 3; no other root page is marked |
| `.24` | an HTTPS origin that `302`s every path, WAF probe payloads included, to `/login` | W-01 | behind the `waf-bypass` edge: no WAF-bypass finding (the old rule counted the 302 as "served") |
| all | the Priority Board after the run | X-01a/b/c | no DOM sink, developer reference or Shodan CVE reaches T1/T2; the catalog-only CVE and the developer references sit in T4 |

## Not covered here

Subdomain takeover and origin discovery need public DNS for the lab names
(dnspython ignores `/etc/hosts`), and routing a lab domain on the host needs
root. Their fixes are covered by unit and regression tests in `recon/tests/`.
