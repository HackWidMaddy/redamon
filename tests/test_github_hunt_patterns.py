"""The GitHub hunt's own copy of the secret patterns (plan 05).

05.4: the keyword-anchored patterns are bounded here as in js_recon, and the
Azure AD client secret must be assigned to the client-secret key.
05.9: `sample` holds the matched value, redacted, never the keyword a
capturing group happened to catch.

PyGithub is stubbed so the module imports without it, and the hunter is built
via __new__ so nothing touches the network. Every value is synthetic.
"""
import re
import sys
import time
import types
import unittest.mock as mock
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = str(REPO_ROOT / "scanners" / "github_secret_hunt")

AZURE_VALUE = "Qx7~Lm2.Rt9_Wn4-Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko"


@pytest.fixture(scope="module")
def ghh():
    stub = types.ModuleType("github")
    stub.Github = object
    stub.Auth = types.SimpleNamespace(Token=lambda *a, **k: None)
    exc = types.ModuleType("github.GithubException")
    exc.RateLimitExceededException = type("RateLimitExceededException", (Exception,), {})
    exc.GithubException = type("GithubException", (Exception,), {})
    stub.GithubException = exc
    with mock.patch.dict(sys.modules, {"github": stub, "github.GithubException": exc}), \
            mock.patch.object(sys, "path", [SCANNER_DIR] + sys.path):
        import github_secret_hunt
        yield github_secret_hunt


def _hits(ghh, name, text):
    return [m.group(0) for m in ghh.COMPILED_SECRET_PATTERNS[name].finditer(text)]


class TestBoundedPatterns:
    def test_no_pattern_has_a_bare_dot_star(self, ghh):
        unbounded = [n for n, rx in ghh.SECRET_PATTERNS.items() if re.search(r"(?<!\\)\.[*+]", rx)]
        assert unbounded == []

    def test_every_gap_is_lazy_and_at_most_120(self, ghh):
        assert [n for n, rx in ghh.SECRET_PATTERNS.items()
                if "[^\\n]{0," in rx and "[^\\n]{0,120}?" not in rx] == []

    def test_msal_empty_default_is_no_azure_hit(self, ghh):
        text = ('// azure msal\nconst cfg = {clientId: "x", clientSecret: "", '
                'build: "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"};')
        assert _hits(ghh, "Azure AD Client Secret", text) == []

    def test_an_assigned_azure_secret_is_a_hit(self, ghh):
        text = f'AZURE_AD = {{ "client_secret": "{AZURE_VALUE}" }}'
        assert len(_hits(ghh, "Azure AD Client Secret", text)) == 1

    def test_a_long_line_cannot_run_away(self, ghh):
        line = "etsy=1;" + "var q=function(a,b){return a+b};" * 1000 + 'x="k3x9q2m7a8b1c4d5e6f7g8h9";'
        start = time.monotonic()
        assert _hits(ghh, "Etsy Access Token", line) == []
        assert time.monotonic() - start < 5

    def test_a_mailgun_public_key_is_not_an_api_key(self, ghh):
        assert _hits(ghh, "Mailgun API Key", "pubkey-4e9a1c7f3b5d8e2a6c0f9b1d7e3a5c8f") == []
        assert _hits(ghh, "Mailgun API Key", 'k="key-8d2f6b0a4c9e1f7b3d5a8c2e6f0b4d9a"') != []
