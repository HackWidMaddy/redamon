#!/usr/bin/env python3
"""Minimal client for RedAmon's inbound MCP server (JSON-RPC over HTTP).

    nwlab_mcp.py <tool> '<json arguments>'      # prints the tool's JSON result

The token is read from the environment variable named by NWLAB_MCP_TOKEN_VAR
(default MCP_SERVER_TOKEN_LAB), or from that key in the repository's .env. It is
never printed. Stdlib only.
"""
from __future__ import annotations

import itertools
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
_ids = itertools.count(1)


def _token() -> str:
    var = os.environ.get("NWLAB_MCP_TOKEN_VAR", "MCP_SERVER_TOKEN_LAB")
    if os.environ.get(var):
        return os.environ[var]
    for line in (REPO / ".env").read_text().splitlines():
        if line.startswith(var + "="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f"{var} is not set and not in .env")


def _endpoint() -> str:
    port = os.environ.get("WEBAPP_PORT", "3000")
    return os.environ.get("NWLAB_MCP_URL", f"http://localhost:{port}/api/mcp-server")


def _parse(body: str) -> dict:
    """The server answers either plain JSON or a one-event SSE stream."""
    body = body.strip()
    if body.startswith("{"):
        return json.loads(body)
    for line in body.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    raise ValueError("unrecognised MCP response")


def rpc(method: str, params: dict | None = None) -> dict:
    payload = {"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params or {}}
    req = urllib.request.Request(_endpoint(), data=json.dumps(payload).encode(), method="POST", headers={
        "Authorization": f"Bearer {_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    })
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return _parse(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": {"code": e.code, "message": e.read().decode()[:500]}}


class ToolError(RuntimeError):
    pass


def call(tool: str, arguments: dict | None = None) -> dict:
    """Call one tool; return its structured result, or raise ToolError."""
    out = rpc("tools/call", {"name": tool, "arguments": arguments or {}})
    if "error" in out:
        raise ToolError(json.dumps(out["error"]))
    result = out.get("result", {})
    text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
    if result.get("isError"):
        raise ToolError(text or "tool error")
    if result.get("structuredContent") is not None:
        return result["structuredContent"]
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


def cypher_rows(project_id: str, cypher: str) -> list[dict]:
    """Rows of a read-only Cypher through query_graph (needs graph:cypher)."""
    res = call("query_graph", {"projectId": project_id, "cypher": cypher})
    return res.get("records", [])


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    if sys.argv[1] == "tools/list":
        out = rpc("tools/list")
        for t in out.get("result", {}).get("tools", []):
            print(t["name"])
        return 0
    try:
        print(json.dumps(call(sys.argv[1], args), indent=2, default=str))
    except ToolError as e:
        print(f"TOOL ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
