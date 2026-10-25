"""Every executor path asks the one RoE gate, and the gate names real tools.

Drift-map #1: the Rules of Engagement ban (ROE_FORBIDDEN_TOOLS,
ROE_FORBIDDEN_CATEGORIES, the account-lockout Hydra block) used to be checked in
plan waves only, so a single `use_tool` call to a forbidden tool ran. #8: the
category map named two retired tools and missed proxy_brain, so forbidding a
category refused nothing new.

These tests drive each executor path for real (the single-tool node, the plan
wave, and a fireteam member's own graph, for both of its executors) and check
two things on each: the path consults `roe_gate.check_tool_call` with the tool
name, and a forbidden tool never reaches the executor. A structural test then
fails when a new module starts dispatching tools without asking the gate.
"""
from __future__ import annotations

import contextlib
import re
import sys
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AGENTIC_DIR))

import project_settings  # noqa: E402
from orchestrator_helpers import roe_gate  # noqa: E402
from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node  # noqa: E402
from orchestrator_helpers.nodes.execute_tool_node import execute_tool_node  # noqa: E402
from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402

_CONFIG = {"configurable": {"user_id": "u1", "project_id": "p1", "session_id": "s1"}}


@contextlib.contextmanager
def _settings(**overrides):
    """Run with a settings snapshot (get_settings() falls back to _settings
    outside a session task)."""
    base = dict(project_settings.DEFAULT_AGENT_SETTINGS)
    base.update(overrides)
    with mock.patch.object(project_settings, "_settings", base):
        yield


def _roe(**overrides):
    values = dict(
        ROE_ENABLED=True, ROE_FORBIDDEN_TOOLS=[], ROE_FORBIDDEN_CATEGORIES=[],
        ROE_ALLOW_ACCOUNT_LOCKOUT=True, ROE_ALLOW_DOS=True,
        ROE_MAX_SEVERITY_PHASE="post_exploitation",
    )
    values.update(overrides)
    return _settings(**values)


def _executor():
    ok = {"success": True, "output": "ran", "error": None}
    ex = MagicMock()
    ex.execute = AsyncMock(return_value=ok)
    ex.execute_with_progress = AsyncMock(return_value=ok)
    return ex


def _dispatched(ex) -> bool:
    return ex.execute.await_count + ex.execute_with_progress.await_count > 0


def _single_state(tool_name, tool_args=None, phase="exploitation"):
    return {
        "messages": [], "current_iteration": 1, "current_phase": phase,
        "_current_step": {"tool_name": tool_name, "tool_args": tool_args or {}},
    }


def _plan_state(tool_names, phase="exploitation"):
    return {
        "messages": [], "current_iteration": 1, "current_phase": phase,
        "_current_plan": {"steps": [
            {"tool_name": n, "tool_args": {}} for n in tool_names
        ]},
    }


def _member_state(action, tool_name, phase="exploitation"):
    """A member pre-seeded the way an operator-approved redeploy seeds one:
    the graph dispatches straight to the executor. With no LLM, the member's
    next think ends it, so one invocation runs exactly one executor turn."""
    state = {
        "messages": [], "current_iteration": 1, "max_iterations": 5,
        "current_phase": phase, "user_id": "u1", "project_id": "p1",
        "session_id": "s1", "member_id": "m-1", "member_name": "Member",
        "fireteam_id": "ft-1", "tools": [tool_name], "task": "t",
        "_decision": {"action": action},
    }
    if action == "use_tool":
        state["_current_step"] = {"tool_name": tool_name, "tool_args": {}}
    else:
        state["_current_plan"] = {"steps": [{"tool_name": tool_name, "tool_args": {}}]}
    return state


async def _run_single(ex, tool_name, tool_args=None, phase="exploitation"):
    out = await execute_tool_node(
        _single_state(tool_name, tool_args, phase), _CONFIG, tool_executor=ex,
        streaming_callbacks={}, session_manager_base="http://x",
    )
    return out["_current_step"]


async def _run_plan(ex, tool_names, phase="exploitation"):
    out = await execute_plan_node(
        _plan_state(tool_names, phase), _CONFIG, tool_executor=ex,
        streaming_callbacks={}, session_manager_base="http://x",
    )
    return out["_current_plan"]["steps"]


async def _run_member(ex, action, tool_name, phase="exploitation"):
    from orchestrator_helpers.fireteam_member_graph import build_fireteam_member_graph

    graph = build_fireteam_member_graph(
        llm_getter=lambda: None, tool_executor=ex, streaming_callbacks={},
        session_manager_base="http://x", neo4j_creds=None,
    )
    final = await graph.ainvoke(_member_state(action, tool_name, phase), _CONFIG)
    if action == "use_tool":
        return [final["_current_step"]]
    return final["_current_plan"]["steps"]


class EveryPathConsultsTheGate(unittest.IsolatedAsyncioTestCase):
    """Patch the gate to refuse everything: each path must ask it about the tool
    it is about to run, and honour the refusal."""

    async def _assert_consults(self, run):
        ex = _executor()
        gate = MagicMock(return_value="RoE BLOCKED: test refusal")
        with mock.patch.object(roe_gate, "check_tool_call", gate), _settings():
            steps = await run(ex)
        self.assertTrue(gate.called, "this executor path never asked the RoE gate")
        self.assertEqual(gate.call_args.args[0], "execute_nmap")
        self.assertFalse(_dispatched(ex), "a refused tool reached the executor")
        for step in steps:
            self.assertFalse(step["success"])
            self.assertIn("RoE BLOCKED", step["tool_output"])

    async def test_single_tool_path(self):
        async def run(ex):
            return [await _run_single(ex, "execute_nmap")]
        await self._assert_consults(run)

    async def test_plan_wave_path(self):
        await self._assert_consults(lambda ex: _run_plan(ex, ["execute_nmap"]))

    async def test_fireteam_member_single_tool_path(self):
        await self._assert_consults(lambda ex: _run_member(ex, "use_tool", "execute_nmap"))

    async def test_fireteam_member_plan_wave_path(self):
        await self._assert_consults(lambda ex: _run_member(ex, "plan_tools", "execute_nmap"))


class AForbiddenToolIsRefusedOnEveryPath(unittest.IsolatedAsyncioTestCase):
    """The real gate, real settings: a tool the engagement forbids never runs."""

    async def _assert_refused(self, run, **roe):
        ex = _executor()
        with _roe(**roe):
            steps = await run(ex)
        self.assertFalse(_dispatched(ex), "a forbidden tool reached the executor")
        for step in steps:
            self.assertFalse(step["success"])
            self.assertIn("forbidden by the Rules of Engagement", step["tool_output"])

    async def test_single_tool_path(self):
        async def run(ex):
            return [await _run_single(ex, "execute_nmap")]
        await self._assert_refused(run, ROE_FORBIDDEN_TOOLS=["execute_nmap"])

    async def test_plan_wave_path(self):
        await self._assert_refused(
            lambda ex: _run_plan(ex, ["execute_nmap"]), ROE_FORBIDDEN_TOOLS=["execute_nmap"])

    async def test_fireteam_member_single_tool_path(self):
        await self._assert_refused(
            lambda ex: _run_member(ex, "use_tool", "execute_nmap"),
            ROE_FORBIDDEN_TOOLS=["execute_nmap"])

    async def test_fireteam_member_plan_wave_path(self):
        await self._assert_refused(
            lambda ex: _run_member(ex, "plan_tools", "execute_nmap"),
            ROE_FORBIDDEN_TOOLS=["execute_nmap"])

    async def test_single_tool_path_honours_a_forbidden_category(self):
        async def run(ex):
            return [await _run_single(ex, "proxy_brain")]
        await self._assert_refused(run, ROE_FORBIDDEN_CATEGORIES=["brute_force"])

    async def test_single_tool_path_honours_the_account_lockout_block(self):
        async def run(ex):
            return [await _run_single(ex, "execute_hydra")]
        await self._assert_refused(run, ROE_ALLOW_ACCOUNT_LOCKOUT=False)

    async def test_a_forbidden_tool_cannot_be_started_as_a_background_job(self):
        async def run(ex):
            return [await _run_single(ex, "job_spawn", {"tool_name": "execute_nmap", "args": {}})]
        await self._assert_refused(run, ROE_FORBIDDEN_TOOLS=["execute_nmap"])

    async def test_an_allowed_tool_still_runs(self):
        ex = _executor()
        with _roe(ROE_FORBIDDEN_TOOLS=["execute_hydra"]):
            step = await _run_single(ex, "execute_nmap")
        self.assertTrue(_dispatched(ex))
        self.assertTrue(step["success"])


class TheGateItself(unittest.TestCase):
    def test_disabled_roe_refuses_nothing(self):
        with _settings(ROE_ENABLED=False, ROE_FORBIDDEN_TOOLS=["execute_nmap"]):
            self.assertIsNone(roe_gate.check_tool_call("execute_nmap", {}, "exploitation"))

    def test_the_phase_cap_refuses_any_tool_past_it(self):
        with _roe(ROE_MAX_SEVERITY_PHASE="informational"):
            reason = roe_gate.check_tool_call("execute_curl", {}, "exploitation")
        self.assertIn("exceeds maximum allowed phase", reason)

    def test_proxy_brain_is_in_both_active_traffic_categories(self):
        for category in ("brute_force", "exploitation"):
            with self.subTest(category=category), _roe(ROE_FORBIDDEN_CATEGORIES=[category]):
                self.assertIsNotNone(roe_gate.check_tool_call("proxy_brain", {}, "exploitation"))

    def test_a_job_spawn_of_an_allowed_tool_passes(self):
        with _roe(ROE_FORBIDDEN_TOOLS=["execute_hydra"]):
            self.assertIsNone(roe_gate.check_tool_call(
                "job_spawn", {"tool_name": "execute_nmap"}, "exploitation"))


class TheCategoryMapNamesRealTools(unittest.TestCase):
    def test_every_category_tool_is_a_registry_key(self):
        unknown = {
            cat: sorted(set(tools) - set(TOOL_REGISTRY))
            for cat, tools in roe_gate.CATEGORY_TOOL_MAP.items()
            if set(tools) - set(TOOL_REGISTRY)
        }
        self.assertEqual(unknown, {}, "CATEGORY_TOOL_MAP names tools the agent does not have, "
                                      "so forbidding the category refuses nothing for them")


# Modules that call the tool executor directly and are, on purpose, not agent
# decisions the RoE judges. Each needs a reason; anything else must ask the gate.
_NOT_AGENT_EXECUTORS = {
    "api.py": "operator-initiated sandbox file reads and the inbound MCP Kali "
              "surface, which skips agent phase and RoE checks by design",
}
_DISPATCH = re.compile(r"\btool_executor\.execute(?:_with_progress)?\(")


class NoExecutorPathSkipsTheGate(unittest.TestCase):
    def test_every_module_that_dispatches_tools_asks_the_gate(self):
        callers = []
        for path in sorted(_AGENTIC_DIR.rglob("*.py")):
            rel = path.relative_to(_AGENTIC_DIR).as_posix()
            if rel.startswith("tests/") or rel in _NOT_AGENT_EXECUTORS:
                continue
            src = path.read_text(encoding="utf-8")
            if _DISPATCH.search(src):
                callers.append(rel)
                self.assertIn("roe_gate.check_tool_call(", src,
                              f"{rel} dispatches tools without asking the RoE gate")
        # The two nodes every path (root and fireteam member) runs through.
        self.assertIn("orchestrator_helpers/nodes/execute_tool_node.py", callers)
        self.assertIn("orchestrator_helpers/nodes/execute_plan_node.py", callers)

    def test_fireteam_members_run_the_gated_nodes(self):
        src = (_AGENTIC_DIR / "orchestrator_helpers" / "fireteam_member_graph.py").read_text(
            encoding="utf-8")
        self.assertIn("await execute_tool_node(", src)
        self.assertIn("await execute_plan_node(", src)


if __name__ == "__main__":
    unittest.main()
