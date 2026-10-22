#!/usr/bin/env python3
"""Run a sequence of partial recons on a lab project, then snapshot it.

    run_partials.py --project-id <pid> --user-id <uid> --root nwlab.test --out <dir> \
        [--tools SubdomainDiscovery,Naabu,Httpx,Nuclei,Katana]

Partial recon is not on the MCP surface, so this signs in to the webapp with the
UI credentials from the repository's .env (never printed) and uses the same
routes as the partial-recon modal: POST /api/recon/<pid>/partial with graph
targets, then GET .../partial/<run>/status until the run ends. The routing gate
runs before every start. Stdlib only.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_scan  # noqa: E402  (routing_gate)
import snapshot_graph  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
BASE = "http://localhost:3000"
_DONE = {"completed", "error", "idle"}


def _env() -> dict:
    out = {}
    for line in (REPO / ".env").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


class Webapp:
    def __init__(self) -> None:
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        env = _env()
        status, _ = self.call("POST", "/api/auth/login",
                              {"email": env["UI_LOGIN_USERNAME"], "password": env["UI_LOGIN_PASSWORD"]})
        if status != 200:
            sys.exit(f"webapp login failed ({status})")

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(BASE + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.op.open(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


def run_one(app: Webapp, pid: str, tool: str, root: str, poll: int) -> dict:
    run_scan.routing_gate()
    status, started = app.call("POST", f"/api/recon/{pid}/partial", {
        "tool_id": tool, "graph_inputs": {"domains": [root]},
        "user_inputs": [], "user_targets": None, "include_graph_targets": True,
    })
    if status != 200:
        return {"tool": tool, "status": "refused", "http": status, "error": started.get("error")}
    run_id = started.get("run_id")
    print(f"[{tool}] started run {run_id}", flush=True)
    state: dict = {}
    while True:
        time.sleep(poll)
        _, state = app.call("GET", f"/api/recon/{pid}/partial/{run_id}/status")
        if str(state.get("status")) in _DONE:
            break
    print(f"[{tool}] {state.get('status')} {state.get('error') or ''}", flush=True)
    return {"tool": tool, "run_id": run_id, "status": state.get("status"), "error": state.get("error")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--user-id", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--tools", default="SubdomainDiscovery,Naabu,Httpx,Nuclei,Katana")
    ap.add_argument("--poll", type=int, default=20)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    app = Webapp()
    results = [run_one(app, a.project_id, t.strip(), a.root, a.poll) for t in a.tools.split(",") if t.strip()]
    (a.out / "partials.json").write_text(json.dumps(results, indent=2))
    snapshot_graph.snapshot(a.project_id, a.user_id, a.out)
    print(json.dumps(results, indent=2))
    return 0 if all(r["status"] == "completed" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
