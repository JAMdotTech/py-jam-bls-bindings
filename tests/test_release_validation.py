"""Release-retry authorization rejects unvalidated or substituted artifacts."""
import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "validate_release_run", Path(__file__).resolve().parents[1] / "scripts/validate_release_run.py"
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def fixture():
    run = {"id": 123, "repository": {"full_name": "owner/repo", "id": 456},
           "head_repository": {"full_name": "owner/repo"}, "path": ".github/workflows/release.yml",
           "event": "push", "head_branch": "v0.1.0", "head_sha": "a" * 40,
           "status": "completed", "conclusion": "failure"}
    names = ["source"]
    for runner, platform, arch in validator.TARGETS:
        names.append(f"wheels ({runner}, {platform}, {arch})")
        names.extend(f"installed ({version}, {runner}, {platform}, {arch})"
                     for version in ("3.12", "3.13", "3.14"))
    jobs = {"total_count": len(names), "jobs": [
        {"name": name, "status": "completed", "conclusion": "success"} for name in names]}
    artifacts = {"total_count": 5, "artifacts": []}
    for index, name in enumerate(["sdist"] + [f"wheel-{p}-{a}" for _, p, a in validator.TARGETS]):
        artifacts["artifacts"].append({"id": index + 1, "name": name, "expired": False,
            "digest": "sha256:" + "b" * 64,
            "workflow_run": {"id": 123, "head_sha": "a" * 40, "head_branch": "v0.1.0",
                             "repository_id": 456, "head_repository_id": 456}})
    return run, jobs, artifacts


def validate(data):
    return validator.validate_run(*data, "owner/repo", "v0.1.0", "a" * 40)


def test_failed_publisher_does_not_invalidate_successful_validation():
    result = validate(fixture())
    assert {a["id"] for a in result["artifacts"]} == set(range(1, 6))
    assert result["head_sha"] == "a" * 40


@pytest.mark.parametrize("field,value", [
    ("path", ".github/workflows/other.yml"), ("event", "pull_request"),
    ("head_branch", "main"), ("head_sha", "c" * 40), ("status", "in_progress"),
])
def test_wrong_run_identity_is_rejected(field, value):
    data = fixture(); data[0][field] = value
    with pytest.raises(ValueError): validate(data)


def test_fork_identity_is_rejected():
    data = fixture(); data[0]["head_repository"]["full_name"] = "other/repo"
    with pytest.raises(ValueError, match="Fork"): validate(data)


@pytest.mark.parametrize("conclusion", ["failure", "skipped", "cancelled"])
def test_required_checks_must_have_passed(conclusion):
    data = fixture(); data[1]["jobs"][-1]["conclusion"] = conclusion
    with pytest.raises(ValueError, match="did not pass"): validate(data)


def test_missing_matrix_job_is_rejected():
    data = fixture(); data[1]["jobs"].pop(); data[1]["total_count"] -= 1
    with pytest.raises(ValueError, match="Missing"): validate(data)


def test_duplicate_matrix_job_is_rejected():
    data = fixture(); data[1]["jobs"].append(deepcopy(data[1]["jobs"][0])); data[1]["total_count"] += 1
    with pytest.raises(ValueError, match="Duplicate"): validate(data)


def test_incomplete_api_response_is_rejected():
    data = fixture(); data[1]["total_count"] += 1
    with pytest.raises(ValueError, match="Incomplete"): validate(data)


@pytest.mark.parametrize("mutation", ["expired", "wrong_run", "wrong_sha", "missing_digest", "duplicate"])
def test_artifact_identity_and_completeness(mutation):
    data = fixture(); artifact = data[2]["artifacts"][0]
    if mutation == "expired": artifact["expired"] = True
    elif mutation == "wrong_run": artifact["workflow_run"]["id"] = 124
    elif mutation == "wrong_sha": artifact["workflow_run"]["head_sha"] = "c" * 40
    elif mutation == "missing_digest": artifact.pop("digest")
    elif mutation == "duplicate": artifact["name"] = data[2]["artifacts"][1]["name"]
    with pytest.raises(ValueError): validate(data)


@pytest.mark.parametrize("tag", ["v0.1.0", "pypi/v0.1.0"])
def test_release_tag_namespace(tag):
    assert validator.release_version(tag) == "0.1.0"


@pytest.mark.parametrize("tag", ["main", "pypi/main", "pypi/v0.1", "other/v0.1.0", "pypi/v0.1.0/extra"])
def test_release_tag_rejects_non_version_refs(tag):
    with pytest.raises(ValueError, match="version tag"):
        validator.release_version(tag)
