"""
The agent's session-start hard guardrail, driven through initialize_node itself.

project_settings.guardrail_names() is unit-tested on its own; this pins that the
node actually uses it. The node used to loop over the batch group roots only, so
a host under a multi-label government name that groups under an unblocked root
(www.isa.org.jm under org.jm) started a session.
"""
import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The package re-exports the function under the module's name; take the module.
node = importlib.import_module('orchestrator_helpers.nodes.initialize_node')

CONFIG = {'configurable': {'user_id': 'u1', 'project_id': 'p1', 'thread_id': 's1'}}


def _settings(**values):
    def _impl(key, default=None):
        return values.get(key, default)
    return _impl


def _run(**settings):
    fake = _settings(**settings)
    with patch('project_settings.get_setting', fake), patch.object(node, 'get_setting', fake):
        return asyncio.run(node.initialize_node({}, CONFIG, llm=MagicMock(), neo4j_creds=('bolt://x', 'u', 'p')))


def test_a_batch_host_under_an_unblocked_root_ends_the_session_and_names_the_host():
    result = _run(
        DOMAIN_BATCH_MODE=True,
        DOMAIN_BATCH_GROUPS=[
            {'rootDomain': 'example.com', 'prefixes': ['www.'], 'hosts': ['www.example.com']},
            {'rootDomain': 'org.jm', 'prefixes': ['www.isa.'], 'hosts': ['www.isa.org.jm']},
        ],
        AGENT_GUARDRAIL_ENABLED=False,
    )
    assert result['_guardrail_blocked'] is True
    assert result['task_complete'] is True
    assert '`www.isa.org.jm`' in result['messages'][0].content


def test_ip_mode_is_not_hard_blocked():
    result = _run(
        IP_MODE=True, TARGET_IPS=['192.0.2.10'],
        DOMAIN_BATCH_MODE=True,
        DOMAIN_BATCH_GROUPS=[{'rootDomain': 'gov.uk', 'hosts': ['www.agency.gov.uk']}],
        AGENT_GUARDRAIL_ENABLED=False,
    )
    assert not result.get('_guardrail_blocked')
