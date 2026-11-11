"""The CI and release workflows: every action pinned to a commit, one publish path.

A moving tag (`@v4`) can be retargeted, and the release job holds `id-token: write` for
PyPI trusted publishing: whoever moves the tag could mint the OIDC token and publish
amazing-gmail-mcp. So every `uses:` is a full commit SHA with its `# vX.Y.Z` comment,
Dependabot moves the pins weekly, and release-please.yml's chained job is the only publisher.

Two more invariants of the release workflow: release-please-action gets no `release-type`
input, so it reads release-please-config.json and the manifest (with the input it builds its
config from the inputs alone, and a breaking change would cut 1.0.0); and the one job that
holds `id-token: write` runs setup-uv with `enable-cache: false`, so it never restores a cache
another job saved.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-please.yml"
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$", re.MULTILINE)
_PINNED_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}")
_VERSION_COMMENT_RE = re.compile(r"\s+# v[0-9]+\.[0-9]+\.[0-9]+")
# The workflows are block YAML with 2-space indents: a job id sits at 2 spaces under `jobs:`,
# a step's `- ` at 6. Splitting on those keeps the test free of a YAML parser.
_JOB_KEY_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)
_STEP_START_RE = re.compile(r"^      - ", re.MULTILINE)
_ID_TOKEN_WRITE_RE = re.compile(r"^\s+id-token:\s*write\s*$", re.MULTILINE)
_ENABLE_CACHE_FALSE_RE = re.compile(r"^\s+enable-cache:\s*false\s*$", re.MULTILINE)


def _jobs(text: str) -> dict[str, str]:
    """The `jobs:` section as {job id: its block}."""
    _, sep, section = text.partition("\njobs:\n")
    assert sep, "no top-level `jobs:` section"
    keys = list(_JOB_KEY_RE.finditer(section))
    ends = [key.start() for key in keys[1:]] + [len(section)]
    return {key.group(1): section[key.end() : end] for key, end in zip(keys, ends, strict=True)}


def _steps(job: str) -> list[str]:
    """A job block's steps, each from its `- ` to the next one."""
    starts = [match.start() for match in _STEP_START_RE.finditer(job)]
    return [job[start:end] for start, end in zip(starts, starts[1:] + [len(job)], strict=True)]


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


def test_release_please_reads_its_config_and_manifest() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    steps = [step for job in _jobs(text).values() for step in _steps(job)]
    actions = [step for step in steps if "googleapis/release-please-action@" in step]
    assert len(actions) == 1, "release-please.yml runs release-please-action exactly once"
    assert not re.search(r"^\s*release-type:", text, re.MULTILINE), (
        "a `release-type` input makes the action ignore release-please-config.json"
    )

    config = json.loads((REPO_ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    package = config["packages"]["."]
    assert package["release-type"] == "python"
    # Pre-1.0: a feat bumps the patch and a breaking change bumps the minor, never 1.0.0.
    assert package["bump-minor-pre-major"] is True
    assert package["bump-patch-for-minor-pre-major"] is True

    manifest = json.loads((REPO_ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert manifest == {".": pyproject["project"]["version"]}


def test_the_oidc_job_never_restores_a_shared_uv_cache() -> None:
    oidc_jobs: dict[tuple[str, str], str] = {}
    for workflow in WORKFLOWS:
        text = workflow.read_text(encoding="utf-8")
        header, _, _ = text.partition("\njobs:\n")
        assert "id-token" not in header, f"{workflow.name} grants id-token to every job"
        for name, job in _jobs(text).items():
            if _ID_TOKEN_WRITE_RE.search(job):
                oidc_jobs[(workflow.name, name)] = job
    assert list(oidc_jobs) == [("release-please.yml", "publish")]

    setup_uv = [step for step in _steps(oidc_jobs[("release-please.yml", "publish")]) if "astral-sh/setup-uv@" in step]
    assert setup_uv, "the publish job sets up uv"
    for step in setup_uv:
        assert _ENABLE_CACHE_FALSE_RE.search(step), "setup-uv in the OIDC job needs `enable-cache: false`"
