"""P18-P21: the published and agent-facing docs do not name what no longer exists,
and (P21) their links, anchors, images and counts still hold.

Deliberately crude. These cannot tell whether a page is well written, only
whether it still names something that was deleted - which is the failure that
actually happens, and the one that is worst where it happens:

  a WIKI page          two of them are mirrored to redamon.org, so a stale claim
                       is public rather than internal
  an AGENT-FACING      the guides under docs/readmes/coding_agent_prompts/ are
  guide                the instructions a coding agent follows. A stale line
                       there does not mislead a reader, it produces wrong code
                       that passes review because the guide said to write it
  a runtime string     playbook.ts is read by the connected agent at run time,
                       so a line naming a deleted tool sends it after something
                       that answers "unknown tool"
"""
from __future__ import annotations

import re
from pathlib import Path

import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WIKI = REPO_ROOT / "redamon.wiki"
PROMPTS = REPO_ROOT / "docs" / "readmes" / "coding_agent_prompts"
SKILLS = REPO_ROOT / "skills"

sys.path.insert(0, str(REPO_ROOT / "tooling" / "scripts"))
from wiki_checkout import SKIP_REASON, wiki_checkout_present  # noqa: E402

# An empty checkout fails the whole file here, at collection, unless allowed.
pytestmark = pytest.mark.skipif(not wiki_checkout_present(WIKI), reason=SKIP_REASON)


def _wiki_pages() -> list[Path]:
    return sorted(WIKI.glob("*.md"))


# --- P18: no wiki page names a deleted tool or disposition -------------------------------

#: Things this programme removed. A page naming one is stale.
_GONE = {
    "tighten_engagement_roe": "the tool was deleted; the limits are ordinary settings now",
    "tighten_only": "the disposition was deleted; there are three, not four",
    "tighten-only": "the disposition was deleted; there are three, not four",
}

#: A deleted name that came back with another meaning. `roe_parse: tighten_only` is a
#: live registry class (the safety switches a RoE document may only turn on), so only a
#: line that does not name `roe_parse` can mean the deleted MCP disposition.
_REUSED_IN = {"tighten_only": "roe_parse"}


def _names_deleted(term: str, line: str) -> bool:
    return term in line and not (term in _REUSED_IN and _REUSED_IN[term] in line)


@pytest.mark.parametrize("term", sorted(_GONE))
def test_p18_no_wiki_page_names_something_that_was_deleted(term):
    offenders = []
    for page in _wiki_pages():
        for i, line in enumerate(page.read_text(encoding="utf-8").split("\n"), 1):
            if _names_deleted(term, line):
                offenders.append(f"{page.name}:{i}: {line.strip()[:120]}")
    assert offenders == [], f"{term}: {_GONE[term]}"


@pytest.mark.parametrize(
    ("line", "stale"),
    [
        ("Set the field's disposition to `tighten_only`.", True),
        ("The `tighten-only` direction rule (`roe_parse` aside).", True),
        ("Both lists come from the settings registry (`roe_parse: deny` and `tighten_only`).", False),
    ],
)
def test_p18_the_reused_name_exemption_is_only_for_the_live_class(line, stale):
    """The exemption must not hide the deleted disposition or its hyphenated spelling."""
    assert any(_names_deleted(term, line) for term in _GONE) is stale


def test_p18_no_wiki_page_calls_the_engagement_record_mcp_settable():
    """The record is UI-only, and a page saying otherwise sends somebody to a refusal."""
    claims = re.compile(
        r"roe(ClientName|ClientContact\w*|EmergencyContact|Notes|RawText|EngagementType)"
        r"[^\n]{0,80}(settable|update_recon_settings|writable)",
        re.I,
    )
    offenders = []
    for page in _wiki_pages():
        for i, line in enumerate(page.read_text(encoding="utf-8").split("\n"), 1):
            if claims.search(line):
                offenders.append(f"{page.name}:{i}: {line.strip()[:120]}")
    assert offenders == []


def test_p18_the_roe_page_states_the_split():
    """The page's whole subject changed; a page that still describes one concept is stale."""
    text = (WIKI / "Rules-of-Engagement.md").read_text(encoding="utf-8")
    assert "Engagement limits" in text
    assert "Engagement record" in text
    # The claim Part C removes.
    assert "become read-only afterward" not in text


def test_p18_no_page_claims_the_roe_settings_are_fixed_at_creation():
    """They are not. Only the RECORD is; the limits are editable for the project's life."""
    offenders = []
    stale = re.compile(r"RoE settings are (configured|fixed).{0,60}(creation|created)", re.I)
    for page in _wiki_pages():
        for i, line in enumerate(page.read_text(encoding="utf-8").split("\n"), 1):
            if stale.search(line):
                offenders.append(f"{page.name}:{i}: {line.strip()[:120]}")
    assert offenders == []


# --- P20: no agent-facing guide names a deny reason the registry dropped ------------------

def _agent_facing_files() -> list[Path]:
    out: list[Path] = []
    if PROMPTS.is_dir():
        out += sorted(PROMPTS.glob("*.md"))
    if SKILLS.is_dir():
        out += sorted(SKILLS.rglob("*.md"))
    return out


def _registry_deny_reasons() -> set[str]:
    import json

    schema = json.loads(
        (REPO_ROOT / "recon_settings" / "registry.schema.json").read_text(encoding="utf-8")
    )
    return set(schema["definitions"]["deny_reason"]["enum"])


#: Reasons an earlier model defined and this one does not. `unbounded` is the one
#: that mattered: a guide told an agent to deny a field for having no UI bound,
#: and the field then became unreachable with nothing failing.
_RETIRED_REASONS = ["unbounded", "othertarget", "intrusive", "wordlist", "headers", "egress"]


def test_p20_the_retired_reasons_really_are_retired():
    """If one of these came back, the test below would be asserting the wrong thing."""
    live = _registry_deny_reasons()
    assert [r for r in _RETIRED_REASONS if r in live] == []


#: A line that says a thing does NOT exist is the instruction we want, not the one
#: we are hunting. Without this the guards fail on their own replacement text,
#: which teaches people to delete the guard rather than the stale line.
_NEGATED = re.compile(r"\b(no|not|never|stopped|deleted|removed|replaced|retired)\b", re.I)


@pytest.mark.parametrize("reason", _RETIRED_REASONS)
def test_p20_no_agent_facing_guide_names_a_retired_deny_reason(reason):
    """Matched on the `deny_reason` KEY, not on the bare word.

    `egress` is also the name of a real guard in the capture proxy, and
    `wordlist` is a real thing a tool reads. Only a line that presents one of
    these AS a deny reason is stale.
    """
    pattern = re.compile(rf"deny[ _-]?reason[^\n]{{0,60}}[`\'\"]{reason}[`\'\"]", re.I)
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if pattern.search(line) and not _NEGATED.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:120]}")
    assert offenders == []


# --- P19: no guide tells an agent to hand-edit a generated artifact -----------------------

#: Files a generator owns. Editing one by hand is undone by the next build, and
#: the drift test fails afterwards rather than at the edit. Matched as a substring
#: of a line, so a basename two files share carries its folder.
_GENERATED = [
    "registry.json",
    "registryDigest.generated.ts",
    "roe_parse_prompt.py",
    "graph_db/schema_catalog.py",
    "node_filters/catalog.json",
    "nodeFilters/catalog.json",
    "manifest.schema.json",
    "screen.schema.json",
    "catalog.schema.json",
    "MCP-API-Reference.md",
    "Project-Settings-Registry.md",
]

#: Generated pages that live in the wiki checkout rather than in this repository.
_GENERATED_IN_WIKI = {"MCP-API-Reference.md", "Project-Settings-Registry.md"}


def test_p19_every_generated_artifact_still_exists():
    """A name for a file that no longer exists guards nothing (drift-map #35)."""
    import shutil
    import subprocess

    if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    tracked = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"], capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    missing = [
        name for name in _GENERATED
        if name not in _GENERATED_IN_WIKI and not any(f.endswith(name) for f in tracked)
    ]
    assert missing == [], f"_GENERATED names files nothing tracks: {missing}"

_EDIT_VERB = re.compile(
    r"\b(edit|add to|update|hand-edit|modify|append to|extend)\b[^\n]{0,80}", re.I
)


@pytest.mark.parametrize("artifact", _GENERATED)
def test_p19_no_guide_instructs_editing_a_generated_artifact(artifact):
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if artifact not in line:
                continue
            # A line that says it is generated, or says NOT to edit it, is the
            # instruction we want rather than the one we are hunting.
            if re.search(r"\b(generated|never edit|do not edit|build artifact|regenerat)", line, re.I):
                continue
            if _EDIT_VERB.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:140]}")
    assert offenders == []


def test_p19_no_guide_teaches_the_deleted_allow_deny_tables():
    """The positive allowlist was replaced by registry dispositions.

    A guide still teaching "add the column to the ALLOW table" produces code
    against a file that no longer exists.
    """
    # An INSTRUCTION to use one, not a mention of it. "There is no ALLOW/DENY
    # table" is the correction, and flagging it would teach people to delete the
    # guard rather than the stale line.
    pattern = re.compile(
        r"\b(add|put|place|classif\w*|goes|sits|appears)\b[^\n]{0,80}(ALLOW|DENY)[ /]*(or[ ]*DENY)?\s+table",
        re.I,
    )
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if pattern.search(line) and not _NEGATED.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:140]}")
    assert offenders == []


def test_p19_no_guide_names_the_deleted_tool():
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if "tighten_engagement_roe" in line:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:140]}")
    assert offenders == []


# --- Links, anchors, images and counts (drift-map guard 13) ----------------------
#
# A heading renamed under an incoming `Page#anchor`, a screenshot that was never
# committed and a count copied into a sentence all go stale with nothing failing.
# Checked: every wiki page link and anchor (from the top-level wiki pages and from
# the repository docs), every same-file and cross-file anchor, every image, every
# link into this repository from the wiki, and the counts below. Whether a relative
# FILE link exists is the path audit's job (drift-audit.sh); here only its anchor.
#
# Wave 3 of the drift-map fix pass corrects the docs, so what is broken today is
# named in _DOCS_DRIFT with its map item, and an entry that no longer fails must
# leave it: the allowlist can only shrink.

_GH = "https://github.com/samugit83/redamon"
_FENCE = re.compile(r"^\s*(```|~~~)")
_LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_IMAGE = re.compile(
    r"!\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)|<img\b[^>]*\bsrc=[\"']([^\"']+)[\"']", re.I)
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_EXPLICIT_ANCHOR = re.compile(r"<a\s+(?:name|id)=[\"']([^\"']+)[\"']", re.I)

#: Repository docs whose links and counts are checked, beside the top-level wiki
#: pages (the subfolders hold session transcripts and per-benchmark patches, and
#: redamon.org copies only the top level).
_REPO_DOC_FILES = ("README.md", "CONTRIBUTING.md", "THIRD-PARTY-LICENSES.md",
                   "testing/guinea_pigs/README.md")
#: Pages that quote stale numbers on purpose, or are generated from code.
_COUNTS_NOT_CHECKED = ("docs/readmes/README.DRIFT_MAP.md", "redamon.wiki/MCP-API-Reference.md",
                       "redamon.wiki/Project-Settings-Registry.md")


def _recon_preset_count() -> int:
    index = (REPO_ROOT / "webapp/src/lib/recon-presets/index.ts").read_text(encoding="utf-8")
    return len(re.findall(r"from '\./presets/", index))


def _mcp_preset_count() -> int:
    text = (REPO_ROOT / "webapp/src/lib/mcp/presets.ts").read_text(encoding="utf-8")
    body = text[text.index("export const MCP_PRESETS"):]
    return len(re.findall(r"^  \{", body[: body.index("\n]\n")], re.M))


def _node_type_count() -> int:
    import importlib.util

    spec = importlib.util.spec_from_file_location("schema_keys", REPO_ROOT / "graph_db" / "schema_keys.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return len(module.LABELS_WITH_KEYS)


def _settings_count() -> int:
    import json

    return len(json.loads((REPO_ROOT / "recon_settings/registry.json").read_text(encoding="utf-8"))["fields"])


#: (kind, pattern, only these files or None, the real number). A claim "N" must
#: equal it; "N+" must be a floor within 10% of it, since "169+ settings" for 741
#: is true and useless. Prefer "see the generated page" to a number.
_COUNT_CLAIMS = [
    ("recon presets", re.compile(r"\b(\d+)(\+?)\s+(?:built-in|recon)\s+presets\b", re.I), None, _recon_preset_count),
    ("recon presets", re.compile(r"\b(\d+)(\+?)\s+presets\b", re.I),
     {"Recon-Presets.md", "VHost-and-SNI-Enumeration.md"}, _recon_preset_count),
    ("MCP presets", re.compile(r"\b(\d+)(\+?)\s+(?:MCP\s+server\s+)?presets\b", re.I),
     {"MCP-Tool-Plugins.md", "README.md"}, _mcp_preset_count),
    ("node types", re.compile(r"\b(\d+)(\+?)\s+node\s+(?:types|labels)\b", re.I), None, _node_type_count),
    ("settings", re.compile(r"\b(\d{3,})(\+?)\s+(?:configurable\s+|tunable\s+|project\s+)?(?:settings|parameters)\b(?!\s+mappings)", re.I),
     None, _settings_count),
]

#: Claims the patterns match that count something else, by (file, phrase).
_NOT_A_COUNT_OF_THE_SET = {
    ("docs/readmes/README.AGENTIC_SYSTEM.md", "5 node types"): "EvoGraph's own node types",
    ("redamon.wiki/Home.md", "5 node types"): "EvoGraph's own node types",
    ("redamon.wiki/MCP-Tool-Plugins.md", "4 presets"): "the presets that need extra setup",
}

#: Broken today, fixed by wave 3. (kind, file, target) -> map item.
_DOCS_DRIFT = {
    ("anchor", "CONTRIBUTING.md", "README.md#contributors-wall-of-fame"): "drift-map #53",
    ("anchor", "CONTRIBUTING.md", "README.md#video-showcase"): "drift-map #53",
    ("anchor", "README.md", "docs/readmes/README.AGENTIC_SYSTEM.md#fireteam--parallel-specialist-sub-agents"): "drift-map #53",
    ("anchor", "README.md", "docs/readmes/README.AGENTIC_SYSTEM.md#evograph--evolutive-attack-chain-graph"): "drift-map #53",
    ("anchor", "docs/readmes/README.AGENTIC_SYSTEM.md", "#fireteam--parallel-specialist-sub-agents"): "drift-map #53",
    ("anchor", "docs/readmes/README.AGENTIC_SYSTEM.md", "#evograph--evolutive-attack-chain-graph"): "drift-map #53",
    ("anchor", "docs/readmes/README.SUPPLY_CHAIN.md", "#layer-l1--standalone-scan-other-scans"): "drift-map #53",
    ("anchor", "docs/readmes/README.SUPPLY_CHAIN.md", "#layer-l2--recon-pipeline-module"): "drift-map #53",
    ("anchor", "docs/readmes/README.SUPPLY_CHAIN.md", "#layer-l3--agent-tools"): "drift-map #53",
    ("anchor", "redamon.wiki/AI-Gauntlet.md", "#screenshots-to-capture"): "drift-map #53",
    ("anchor", "redamon.wiki/Agent-Skills.md", "#path-traversal-lfi-rfi"): "drift-map #53",
    ("anchor", "redamon.wiki/Deploying-to-a-Server.md", "#the-env-reference-every-variable"): "drift-map #53",
    ("anchor", "redamon.wiki/XBOW-Validation-Benchmark.md", "#35-score"): "drift-map #53",
    ("wiki-link", "README.md", f"{_GH}/wiki/The-Graph-Dashboard#redamon-terminal"): "drift-map #52",
    ("wiki-link", "README.md", f"{_GH}/wiki/Pentest-Agent#tool-confirmation-gate"): "drift-map #52",
    ("wiki-link", "redamon.wiki/AI-Agent-Guide.md", "Agent-Skills#phishing--social-engineering"): "drift-map #53",
    ("wiki-link", "redamon.wiki/Agent-Workspace.md", "Creating-a-Project#switching-between-projects"): "drift-map #53",
    ("wiki-link", "redamon.wiki/CVE-Intel.md", "Project-Settings-Reference#tool-matrix"): "drift-map #53",
    ("wiki-link", "redamon.wiki/GVM-Vulnerability-Scanning.md", "Deploying-to-a-Server#1-a-linux-server"): "drift-map #53",
    ("wiki-link", "redamon.wiki/GVM-Vulnerability-Scanning.md", "Creating-a-Project#tab-8-gvm-scan"): "drift-map #53",
    ("wiki-link", "redamon.wiki/Global-Settings.md", "Project-Settings-Reference#agent-settings"): "drift-map #53",
    ("wiki-link", "redamon.wiki/GraphQL-Security-Testing.md",
     "Running-Reconnaissance#group-6-phase-a-nuclei--graphql-security-parallel"): "drift-map #53",
    ("wiki-link", "redamon.wiki/Project-Settings-Reference.md", "AI-Agent-Guide#tunnel-providers"): "drift-map #53",
    ("wiki-link", "redamon.wiki/Project-Settings-Reference.md", "Agent-Skills#phishing--social-engineering"): "drift-map #53",
    ("wiki-link", "redamon.wiki/Subdomain-Takeover-Detection.md",
     "Running-Reconnaissance#group-6-phase-a-nuclei--graphql-security-parallel"): "drift-map #53",
    ("wiki-link", "redamon.wiki/Tradecraft-Lookup.md", "Project-Settings-Reference#agent-settings"): "drift-map #53",
    ("wiki-link", "redamon.wiki/Troubleshooting.md", "Getting-Started#minimum-system-requirements"): "drift-map #53",
    ("wiki-link", "redamon.wiki/VHost-and-SNI-Enumeration.md",
     "Running-Reconnaissance#group-6-phase-a-nuclei--graphql-security--subdomain-takeover--vhost--sni-parallel"): "drift-map #53",
    ("image", "redamon.wiki/EvoGraph-Attack-Chain-Evolution.md", "images/evograph-bridges.png"): "drift-map #55",
    ("image", "redamon.wiki/Global-Settings.md", "images/mcp-tool-plugins-tab.png"): "drift-map #55",
    ("image", "redamon.wiki/MCP-Tool-Plugins.md", "images/mcp-tool-plugins-overview.png"): "drift-map #55",
    ("count", "README.md", "node types:17"): "drift-map #48",
    ("count", "README.md", "node types:19"): "drift-map #48",
    ("count", "README.md", "MCP presets:39"): "drift-map #47",
    ("count", "README.md", "settings:500+"): "drift-map #49",
    ("count", "docs/readmes/README.DEV.md", "settings:190+"): "drift-map #49",
    ("count", "docs/readmes/README.POSTGRES.md", "settings:169+"): "drift-map #49",
    ("count", "docs/readmes/README.RECON.md", "settings:169+"): "drift-map #49",
    ("count", "docs/readmes/TECH_STACK.md", "node types:17"): "drift-map #48",
    ("count", "redamon.wiki/AI-Assisted-Development.md", "settings:190+"): "drift-map #49",
    ("count", "redamon.wiki/AI-Assisted-Development.md", "node types:17"): "drift-map #48",
    ("count", "redamon.wiki/Attack-Surface-Graph.md", "node types:25"): "drift-map #48",
    ("count", "redamon.wiki/Creating-a-Project.md", "settings:196+"): "drift-map #49",
    ("count", "redamon.wiki/Creating-a-Project.md", "recon presets:21"): "drift-map #46",
    ("count", "redamon.wiki/Data-Export-and-Import.md", "settings:180+"): "drift-map #49",
    ("count", "redamon.wiki/Home.md", "recon presets:21"): "drift-map #46",
    ("count", "redamon.wiki/Home.md", "settings:328+"): "drift-map #49",
    ("count", "redamon.wiki/Home.md", "node types:22"): "drift-map #48",
    ("count", "redamon.wiki/Home.md", "settings:245+"): "drift-map #49",
    ("count", "redamon.wiki/MCP-Server.md", "settings:717"): "drift-map #49",
    ("count", "redamon.wiki/Project-Settings-Reference.md", "recon presets:21"): "drift-map #46",
    ("count", "redamon.wiki/Recon-Pipeline-Workflow.md", "settings:196+"): "drift-map #49",
    ("count", "redamon.wiki/Recon-Presets.md", "settings:328+"): "drift-map #49",
    ("count", "redamon.wiki/Recon-Presets.md", "settings:196+"): "drift-map #49",
    ("count", "redamon.wiki/Recon-Presets.md", "recon presets:21"): "drift-map #46",
    ("count", "redamon.wiki/VHost-and-SNI-Enumeration.md", "recon presets:22"): "drift-map #46",
}


def _prose_lines(text: str):
    """(line number, line) outside fenced code, with inline code blanked."""
    fenced = False
    for i, line in enumerate(text.split("\n"), 1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield i, re.sub(r"`[^`]*`", lambda m: " " * len(m.group(0)), line)


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lowercased, punctuation but - and _ dropped,
    each space a hyphen (so " - " becomes "---")."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


_ANCHORS: dict[Path, set[str]] = {}


def _anchors(path: Path) -> set[str]:
    if path not in _ANCHORS:
        seen: dict[str, int] = {}
        found: set[str] = set()
        fenced = False
        for line in path.read_text(encoding="utf-8", errors="replace").split("\n"):
            if _FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            m = _HEADING.match(line)
            if m:
                base = _slug(m.group(2))
                n = seen.get(base, 0)
                found.add(base if n == 0 else f"{base}-{n}")
                seen[base] = n + 1
            found.update(_EXPLICIT_ANCHOR.findall(line))
        _ANCHORS[path] = found
    return _ANCHORS[path]


def _tracked_paths() -> set[str]:
    import subprocess

    files = subprocess.run(["git", "-C", str(REPO_ROOT), "ls-files"], capture_output=True,
                           text=True, check=True).stdout.split("\n")
    out = {f for f in files if f}
    for f in list(out):
        parent = Path(f).parent
        while str(parent) != ".":
            out.add(str(parent))
            parent = parent.parent
    return out


def _docs_findings() -> dict[tuple[str, str, str], str]:
    """(kind, file, target) -> what is wrong, for every check above."""
    import shutil
    from urllib.parse import unquote

    if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    tracked = _tracked_paths()
    pages = {p.stem: p for p in WIKI.rglob("*.md") if ".git" not in p.parts}
    top_pages = sorted(WIKI.glob("*.md"))
    repo_docs = [REPO_ROOT / f for f in sorted(tracked)
                 if f.endswith(".md") and (f in _REPO_DOC_FILES or f.startswith("docs/readmes/"))]
    findings: dict[tuple[str, str, str], str] = {}

    def wiki_target_error(page: str, anchor: str) -> str | None:
        page = unquote(page)
        if page not in pages:
            return f"no wiki page {page}"
        if anchor and unquote(anchor).lower() not in _anchors(pages[page]):
            return f"no anchor #{anchor} in wiki page {page}"
        return None

    for doc in repo_docs + top_pages:
        rel = str(doc.relative_to(REPO_ROOT))
        in_wiki = doc.parent == WIKI
        text = doc.read_text(encoding="utf-8", errors="replace")
        for lineno, line in _prose_lines(text):
            for m in _IMAGE.finditer(line):
                target = (m.group(1) or m.group(2) or "").split("#")[0]
                if target and not re.match(r"^(https?:|data:)", target) \
                        and not (doc.parent / unquote(target)).resolve().exists():
                    findings[("image", rel, target)] = f"{rel}:{lineno}: image {target} does not exist"
            for m in _LINK.finditer(line):
                target = m.group(1)
                page_part, _, anchor = target.partition("#")
                wiki_url = re.match(re.escape(_GH) + r"/wiki/?([^#?]*)", target)
                repo_url = re.match(re.escape(_GH) + r"/(?:blob|tree)/[^/]+/([^#?]+)", target)
                if wiki_url:
                    error = wiki_target_error(wiki_url.group(1) or "Home", anchor)
                    if error:
                        findings[("wiki-link", rel, target)] = f"{rel}:{lineno}: {error}"
                elif repo_url:
                    if unquote(repo_url.group(1)).strip("/") not in tracked:
                        findings[("repo-url", rel, target)] = \
                            f"{rel}:{lineno}: {repo_url.group(1)} is not in the repository"
                elif re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                    continue
                elif not page_part:
                    if anchor and unquote(anchor).lower() not in _anchors(doc):
                        findings[("anchor", rel, target)] = f"{rel}:{lineno}: no anchor #{anchor} in this file"
                elif in_wiki and "/" not in page_part and "." not in page_part:
                    error = wiki_target_error(page_part, anchor)
                    if error:
                        findings[("wiki-link", rel, target)] = f"{rel}:{lineno}: {error}"
                else:
                    dest = (doc.parent / unquote(page_part)).resolve()
                    if anchor and dest.suffix == ".md" and dest.exists() \
                            and unquote(anchor).lower() not in _anchors(dest):
                        findings[("anchor", rel, target)] = f"{rel}:{lineno}: no anchor #{anchor} in {page_part}"
        if rel in _COUNTS_NOT_CHECKED:
            continue
        for lineno, line in _prose_lines(text):
            for kind, pattern, only_in, real in _COUNT_CLAIMS:
                if only_in and doc.name not in only_in:
                    continue
                for m in pattern.finditer(line):
                    if re.search(r"\btop\s+$", line[: m.start()], re.I) \
                            or (rel, m.group(0)) in _NOT_A_COUNT_OF_THE_SET:
                        continue
                    claimed, floor, truth = int(m.group(1)), bool(m.group(2)), real()
                    if not (truth * 0.9 <= claimed <= truth if floor else claimed == truth):
                        findings[("count", rel, f"{kind}:{m.group(1)}{m.group(2)}")] = \
                            f"{rel}:{lineno}: '{m.group(0)}', but there are {truth} {kind}"
    return findings


def test_p21_docs_links_anchors_images_and_counts_hold():
    findings = _docs_findings()
    new = sorted(msg for key, msg in findings.items() if key not in _DOCS_DRIFT)
    assert new == [], "\n".join(new)


def test_p21_the_docs_drift_allowlist_only_shrinks():
    """An entry wave 3 fixed must leave _DOCS_DRIFT, or the guard would excuse a
    regression at the same place later."""
    findings = _docs_findings()
    fixed = sorted(f"{key} ({item})" for key, item in _DOCS_DRIFT.items() if key not in findings)
    assert fixed == [], "no longer broken, drop from _DOCS_DRIFT:\n" + "\n".join(fixed)


def test_p21_the_counts_are_read_from_the_code():
    """A count source that reads zero would make every claim check meaningless."""
    assert _recon_preset_count() > 20
    assert _mcp_preset_count() > 20
    assert _node_type_count() > 30
    assert _settings_count() > 500
