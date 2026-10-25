"""The one Rules of Engagement gate every agent executor asks before running a tool.

Three executor paths run tools: the single-tool node (execute_tool_node), the
plan-wave node (execute_plan_node), and every fireteam member, whose graph
reuses those same two nodes (fireteam_member_graph.py). Each calls
`check_tool_call` and refuses the call when it returns a reason. A ban
enforced on one path only is no ban: the agent simply takes the other path.
agentic/tests/test_roe_gate.py drives every path and fails if one stops asking.

The gate also looks through `job_spawn` at the tool it would start, for the
same reason the executor checks a spawned tool's phase: otherwise a forbidden
tool runs as a background job.
"""

from __future__ import annotations

# What forbidding a category refuses. Every name must be a TOOL_REGISTRY key, or
# the category silently refuses nothing (test_roe_gate.py). proxy_brain replays
# and fuzzes captured requests, so both categories that cover active attack
# traffic name it.
CATEGORY_TOOL_MAP = {
    'brute_force': ['execute_hydra', 'execute_wpscan', 'execute_ffuf', 'proxy_brain'],
    'dos': [],
    'social_engineering': [],
    'exploitation': ['metasploit_console', 'execute_hydra', 'proxy_brain'],
}

PHASE_ORDER = {'informational': 0, 'exploitation': 1, 'post_exploitation': 2}


def _dispatched_tools(tool_name: str, tool_args) -> list[str]:
    names = [tool_name]
    if tool_name == 'job_spawn' and isinstance(tool_args, dict):
        target = tool_args.get('tool_name')
        if isinstance(target, str) and target:
            names.append(target)
    return names


def roe_block_reason(tool_name: str, phase: str) -> str | None:
    """The Rules of Engagement verdict for one tool: a refusal message, or None."""
    from project_settings import get_setting

    if not get_setting('ROE_ENABLED', False):
        return None

    forbidden = set(get_setting('ROE_FORBIDDEN_TOOLS', []))
    for cat in get_setting('ROE_FORBIDDEN_CATEGORIES', []):
        forbidden.update(CATEGORY_TOOL_MAP.get(cat, []))

    if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
        forbidden.add('execute_hydra')
    if not get_setting('ROE_ALLOW_DOS', False):
        forbidden.update(CATEGORY_TOOL_MAP.get('dos', []))

    if tool_name in forbidden:
        return f"RoE BLOCKED: Tool '{tool_name}' is forbidden by the Rules of Engagement."

    max_phase = get_setting('ROE_MAX_SEVERITY_PHASE', 'post_exploitation')
    if PHASE_ORDER.get(phase, 0) > PHASE_ORDER.get(max_phase, 2):
        return f"RoE BLOCKED: Current phase '{phase}' exceeds maximum allowed phase '{max_phase}'."

    return None


def check_tool_call(tool_name: str, tool_args, phase: str) -> str | None:
    """Every executor's pre-dispatch check: a refusal message, or None to run the tool."""
    for name in _dispatched_tools(tool_name, tool_args):
        reason = roe_block_reason(name, phase)
        if reason:
            return reason
    return None
