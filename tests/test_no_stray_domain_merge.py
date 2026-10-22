"""No writer creates a Domain node outside the allowed sites (plan 4.11.6, GDB-12).

Partial recon refuses a project whose graph holds a Domain the current scope
does not expect (legacy_domain_nodes). A writer that MERGEs a Domain from a
name it derived itself (a guessed registrable part, the root of a stray host)
would re-create such a node on every run and block partial recon for good.

So a Domain is created in exactly three places, all in the Domain mixin:
  - update_graph_from_domain_discovery: the run's own Domain, named after the
    root the run scanned;
  - update_graph_from_ip_recon: the IP-mode root `ip-targets.<project>`;
  - ensure_root_domains: the project's roots, for a batch before its first
    group and for a partial run whose root Domain is missing.
Every other writer MATCHes the Domain or calls ensure_root_domains.

This is a source scan: a Cypher string that MERGEs or CREATEs `(x:Domain ...)`
anywhere else fails it.
"""
import ast
import re
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SCANNED = ('graph_db', 'recon', 'scanners', 'agentic', 'mcp')
_DOMAIN_MIXIN = 'graph_db/mixins/recon/domain_mixin.py'
ALLOWED = {
    (_DOMAIN_MIXIN, 'update_graph_from_domain_discovery'),
    (_DOMAIN_MIXIN, 'update_graph_from_ip_recon'),
    (_DOMAIN_MIXIN, 'ensure_root_domains'),
}

_DOMAIN_PATTERN = re.compile(r'\(\s*\w*\s*:\s*Domain\b')
# FOR is the index/constraint DDL (`CREATE INDEX ... FOR (d:Domain)`), not a write.
_CLAUSE = re.compile(r'\b(OPTIONAL\s+MATCH|MATCH|MERGE|CREATE|FOR)\b')


def domain_writes(source: str):
    """Line numbers where a Cypher clause MERGEs or CREATEs a Domain node: the
    nearest clause keyword before `(x:Domain` decides, so the end of a
    `MERGE (a)-[:R]->(d:Domain {...})` path counts and a MATCH does not."""
    lines = []
    for m in _DOMAIN_PATTERN.finditer(source):
        clauses = list(_CLAUSE.finditer(source, max(0, m.start() - 400), m.start()))
        if clauses and clauses[-1].group(1) in ('MERGE', 'CREATE'):
            lines.append(source.count('\n', 0, m.start()) + 1)
    return lines


def enclosing_function(tree: ast.AST, line: int) -> str:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= (node.end_lineno or node.lineno):
                if best is None or node.lineno > best.lineno:
                    best = node
    return best.name if best else '<module>'


def _sources():
    for top in _SCANNED:
        root = _REPO / top
        if not root.is_dir():
            continue
        for path in root.rglob('*.py'):
            rel = path.relative_to(_REPO).as_posix()
            if '/tests/' in f'/{rel}' or '__pycache__' in rel or 'node_modules' in rel:
                continue
            yield rel, path


def find_sites():
    sites = []
    for rel, path in _sources():
        try:
            source = path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        if ':Domain' not in source and ': Domain' not in source:
            continue
        lines = domain_writes(source)
        if not lines:
            continue
        tree = ast.parse(source)
        sites += [(rel, enclosing_function(tree, n), n) for n in lines]
    return sites


class TestNoStrayDomainMerge(unittest.TestCase):
    def test_only_the_allowed_writers_create_a_domain(self):
        stray = [f'{rel}:{line} ({fn})' for rel, fn, line in find_sites()
                 if (rel, fn) not in ALLOWED]
        self.assertEqual(stray, [], 'a Domain is created outside the allowed sites: '
                         'MATCH it, or create it through ensure_root_domains')

    def test_the_scan_still_sees_the_allowed_writers(self):
        # A broken pattern would find nothing and pass the test above.
        found = {(rel, fn) for rel, fn, _ in find_sites()}
        self.assertEqual(found & ALLOWED, ALLOWED)


class TestDetector(unittest.TestCase):
    def test_what_counts_as_a_write(self):
        self.assertEqual(domain_writes('MERGE (d:Domain {name: $n})'), [1])
        self.assertEqual(domain_writes('MERGE (:Domain {name: $n})'), [1])
        self.assertEqual(domain_writes('CREATE (d:Domain {name: $n})'), [1])
        self.assertEqual(domain_writes('MATCH (s) MERGE (s)-[:BELONGS_TO]->(d:Domain {name: $n})'), [1])
        self.assertEqual(domain_writes('MERGE (s:Subdomain {name: $s})\nWITH s\nMATCH (d:Domain {name: $n})'), [])
        self.assertEqual(domain_writes('OPTIONAL MATCH (d:Domain {name: $n})'), [])
        self.assertEqual(domain_writes('MERGE (ed:ExternalDomain {domain: $d})'), [])
        self.assertEqual(domain_writes('CREATE INDEX idx IF NOT EXISTS FOR (d:Domain) ON (d.name)'), [])
        self.assertEqual(domain_writes('FOREACH (_ IN [1] | MERGE (d:Domain {name: $n}))'), [1])

    def test_the_enclosing_function_is_the_innermost(self):
        tree = ast.parse('def outer():\n    def inner():\n        x = 1\n    y = 2\n')
        self.assertEqual(enclosing_function(tree, 3), 'inner')
        self.assertEqual(enclosing_function(tree, 4), 'outer')


if __name__ == '__main__':
    unittest.main()
