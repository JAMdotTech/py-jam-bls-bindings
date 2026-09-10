"""Authorize immutable artifacts from a fully validated tag workflow for retry.

No artifacts are rebuilt here. The original publish job may have failed, but
all required source, wheel, and installed-wheel jobs must have succeeded.
"""
import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

TARGETS = (
    ("ubuntu-24.04", "linux", "x86_64"),
    ("ubuntu-24.04-arm", "linux", "aarch64"),
    ("macos-15-intel", "macos", "x86_64"),
    ("macos-15", "macos", "arm64"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_run(run, jobs, artifacts, repository, tag, tag_sha, installed_prefix="installed"):
    require(run["repository"]["full_name"] == repository, "Wrong run repository")
    require(run["head_repository"]["full_name"] == repository, "Fork run is not publishable")
    require(run["path"] == ".github/workflows/release.yml", "Wrong release workflow")
    require(run["event"] == "push", "Only original tag-push runs are publishable")
    require(run["head_branch"] == tag, "Run does not match requested tag")
    require(run["head_sha"] == tag_sha, "Tag commit does not match validated run")
    require(run["status"] == "completed", "Original run is still active")
    required_jobs = {"source"}
    required_jobs.update(f"wheels ({runner}, {platform}, {arch})" for runner, platform, arch in TARGETS)
    required_jobs.update(
        f"{installed_prefix} ({version}, {runner}, {platform}, {arch})"
        for version in ("3.12", "3.13", "3.14") for runner, platform, arch in TARGETS
    )
    require(jobs["total_count"] == len(jobs["jobs"]), "Incomplete job response")
    by_name = {}
    for job in jobs["jobs"]:
        require(job["name"] not in by_name, "Duplicate job name")
        by_name[job["name"]] = job
    require(required_jobs <= by_name.keys(), "Missing required validation job")
    for name in required_jobs:
        job = by_name[name]
        require(job["status"] == "completed" and job["conclusion"] == "success",
                f"Required validation did not pass: {name}")
    expected_artifacts = {"sdist"} | {f"wheel-{platform}-{arch}" for _, platform, arch in TARGETS}
    require(artifacts["total_count"] == len(artifacts["artifacts"]), "Incomplete artifact response")
    names = [artifact["name"] for artifact in artifacts["artifacts"]]
    require(len(names) == len(set(names)) and set(names) == expected_artifacts,
            "Expected exactly one sdist and four platform wheel artifacts")
    selected = sorted(artifacts["artifacts"], key=lambda artifact: artifact["name"])
    for artifact in selected:
        require(not artifact["expired"], "Release artifact expired")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", "")) is not None,
                "Release artifact has no SHA256 identity")
        identity = artifact["workflow_run"]
        require(identity["id"] == run["id"] and identity["head_sha"] == tag_sha
                and identity["head_branch"] == tag
                and identity["repository_id"] == run["repository"]["id"]
                and identity["head_repository_id"] == run["repository"]["id"],
                "Artifact does not belong to the validated tag run")
    return {
        "repository": repository, "tag": tag, "head_sha": tag_sha, "run_id": run["id"],
        "artifacts": [{key: artifact[key] for key in ("id", "name", "digest")} for artifact in selected],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("tag")
    parser.add_argument("--installed-job-prefix", default="installed")
    args = parser.parse_args()
    require(re.fullmatch(r"[1-9][0-9]*", args.run_id) is not None, "Invalid run ID")
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", args.tag) is not None,
            "Expected a version tag")
    repository = os.environ["GITHUB_REPOSITORY"]
    api_base = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    def api(path):
        request = Request(f"{api_base}/repos/{repository}/{path}", headers={
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        })
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    tag_object = api(f"git/ref/tags/{quote(args.tag, safe='')}")["object"]
    for _ in range(10):
        if tag_object["type"] == "commit":
            break
        require(tag_object["type"] == "tag", "Tag does not resolve to a commit")
        tag_object = api(f"git/tags/{tag_object['sha']}")["object"]
    require(tag_object["type"] == "commit", "Too many nested annotated tags")
    run = api(f"actions/runs/{args.run_id}")
    jobs = api(f"actions/runs/{args.run_id}/jobs?per_page=100")
    artifacts = api(f"actions/runs/{args.run_id}/artifacts?per_page=100")
    validated = validate_run(run, jobs, artifacts, repository, args.tag, tag_object["sha"],
                             args.installed_job_prefix)
    print(json.dumps(validated, indent=2))
    Path("validated-release-run.json").write_text(json.dumps(validated, indent=2) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write("artifact_ids=" + ",".join(str(a["id"]) for a in validated["artifacts"]) + "\n")


if __name__ == "__main__":
    main()
