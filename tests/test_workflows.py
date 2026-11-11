"""The CI and release workflows: every action pinned to a commit, one publish path.

A moving tag (`@v4`) can be retargeted, and the release job holds `id-token: write` for
PyPI trusted publishing: whoever moves the tag could mint the OIDC token and publish
amazing-gmail-mcp. So every `uses:` is a full commit SHA with its `# vX.Y.Z` comment,
Dependabot moves the pins weekly, and release-please.yml's chained job is the only publisher.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$", re.MULTILINE)
_PINNED_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}")
_VERSION_COMMENT_RE = re.compile(r"\s+# v[0-9]+\.[0-9]+\.[0-9]+")


def test_there_are_workflows_to_check() -> None:
    assert {path.name for path in WORKFLOWS} == {"ci.yml", "release-please.yml"}


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_to_a_commit_sha_with_its_version(workflow: Path) -> None:
    uses = _USES_RE.findall(workflow.read_text(encoding="utf-8"))
    assert uses, workflow.name
    for action, rest in uses:
        assert _PINNED_RE.fullmatch(action), f"{workflow.name}: {action} is not pinned to a full commit SHA"
        assert _VERSION_COMMENT_RE.fullmatch(rest), f"{workflow.name}: {action} has no `# vX.Y.Z` comment"


def test_dependabot_moves_the_action_pins_weekly() -> None:
    text = (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert re.search(r"package-ecosystem:\s*github-actions", text)
    assert re.search(r"interval:\s*weekly", text)


def test_release_please_is_the_only_publish_path() -> None:
    assert not (REPO_ROOT / ".github" / "workflows" / "publish.yml").exists()
    publishers = [path.name for path in WORKFLOWS if "uv publish" in path.read_text(encoding="utf-8")]
    assert publishers == ["release-please.yml"]
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        assert "publish.yml" not in text, path.name
        assert not re.search(r"^\s*release:\s*$", text, re.MULTILINE), f"{path.name} triggers on a release event"
