"""GDB-11 against a real Neo4j: parallel writers on one org Domain keep each
other's data (S-5, S-21).

Several scan roots share one org Domain, and up to twelve partial recons run at
once, so `openapi_source_status` and the coverage record are written by a
statement that locks the node before it reads. Without the lock, two writers
read the same old value and the second commit drops the first's entries.

Integration tier: needs NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD and skips
without them. It creates and deletes one fixture tenant, so run it only against
a disposable database:

    docker network create --internal lock-it
    docker run -d --rm --name lock-neo4j --network lock-it \\
      -e NEO4J_AUTH=neo4j/fixture-password neo4j:5.26-community
    docker run --rm --network lock-it -v "$PWD:/repo" -w /repo -e PYTHONPATH=/repo \\
      -e NEO4J_URI=bolt://lock-neo4j:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD=fixture-password \\
      --entrypoint python redamon-agent -m pytest -q -m integration \\
      tests/test_org_domain_lock_integration.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

pytestmark = pytest.mark.integration

UID, PID = 'fixture-lock-user', 'fixture-lock-project'
ROUNDS = 50


def _neo4j_configured() -> bool:
    return bool(os.getenv('NEO4J_URI') and os.getenv('NEO4J_PASSWORD'))


@unittest.skipUnless(_neo4j_configured(), 'NEO4J_URI / NEO4J_PASSWORD not set (integration tier)')
class TestOrgDomainLock(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from graph_db import Neo4jClient
        cls.client = Neo4jClient()
        cls.driver = cls.client.driver

    @classmethod
    def tearDownClass(cls):
        cls._wipe()
        cls.client.close()

    @classmethod
    def _wipe(cls):
        with cls.driver.session() as session:
            session.run('MATCH (n {user_id: $u}) DETACH DELETE n', u=UID).consume()

    def setUp(self):
        self._wipe()
        with self.driver.session() as session:
            session.run("MERGE (d:Domain {name: 'example.com', user_id: $u, project_id: $p})",
                        u=UID, p=PID).consume()

    def _prop(self, name):
        with self.driver.session() as session:
            return session.run(
                f"MATCH (d:Domain {{name: 'example.com', user_id: $u, project_id: $p}}) RETURN d.{name} AS v",
                u=UID, p=PID).single()['v']

    @staticmethod
    def _together(*fns):
        barrier = threading.Barrier(len(fns))
        errors = []

        def run(fn):
            try:
                barrier.wait()
                fn()
            except Exception as e:  # noqa: BLE001 - surfaced by the assertion below
                errors.append(e)

        threads = [threading.Thread(target=run, args=(fn,)) for fn in fns]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return errors

    def test_two_scan_roots_write_openapi_status_at_once_and_both_survive(self):
        from graph_db.mixins.recon.resource_mixin import write_openapi_source_status

        def writer(root, n):
            def fn():
                with self.driver.session() as session:
                    session.execute_write(lambda tx: write_openapi_source_status(
                        tx, UID, PID, 'example.com', root, [f'doc{n}|h|ok|t']))
            return fn

        for n in range(ROUNDS):
            errors = self._together(writer('api.example.com', n), writer('example.com', n))
            self.assertEqual(errors, [])
            status = sorted(self._prop('openapi_source_status') or [])
            self.assertEqual(status, [f'api.example.com|doc{n}|h|ok|t', f'example.com|doc{n}|h|ok|t'],
                             f'round {n}')

    def test_two_groups_of_one_run_merge_their_coverage(self):
        def stamp(root, n):
            def fn():
                self.client.update_graph_coverage(UID, PID, root, {
                    'at': '2026-01-01T00:00:00+00:00', 'org_domain': 'example.com',
                    'gaps_json': json.dumps([{'source': f'{root}-{n}', 'root': root}]),
                    'skipped_hosts': [f'{root}:443'], 'nuclei_truncated': False,
                }, run_started_at=f'RUN{n}')
            return fn

        for n in range(ROUNDS):
            errors = self._together(stamp('api.example.com', n), stamp('example.com', n))
            self.assertEqual(errors, [])
            self.assertEqual(sorted(self._prop('recon_coverage_roots')), ['api.example.com', 'example.com'],
                             f'round {n}')
            gaps = json.loads(self._prop('recon_coverage_gaps'))
            self.assertEqual(sorted(g['root'] for g in gaps), ['api.example.com', 'example.com'])
            self.assertEqual(self._prop('recon_coverage_run'), f'RUN{n}')


if __name__ == '__main__':
    unittest.main()
