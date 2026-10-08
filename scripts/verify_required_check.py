#!/usr/bin/env python3
"""Reviewer-side source check for the required Actions check (interim, read-only).

Until the dedicated App publishes epsilon/trusted-merge, any workflow can report a
check named trusted-security-pilot from the shared GitHub Actions app. Before
approving or merging, confirm through GitHub's own run metadata that every such
check on the PR head came from a pull_request_target run of the trusted workflow
for exactly that head. One foreign or manual run on the head blocks.

Such a run executes the workflow file from the PR's base branch, which run metadata
does not record; each run is therefore also bound to this PR's head branch, and any
PR in any state with the same SHA, head repository and branch that targets another
base or has a base-retarget timeline event blocks. This is an interim metadata
check; the dedicated publisher additionally requires cryptographic attestations.
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_harness.trusted_publisher import validate_run_base, related_pull_path, head_scope

REQUIRED_CHECK = "trusted-security-pilot"
ACTIONS_APP_ID = 15368
WORKFLOW_PATH = ".github/workflows/security.yml"
BASE_BRANCH = "main"
SHA = re.compile(r"[0-9a-f]{40}")


class Denied(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Denied(code)


def verify(api, repo, number, pages):
    pr = api(f"repos/{repo}/pulls/{number}")
    head = pr["head"]["sha"]
    need(pr["state"] == "open" and SHA.fullmatch(head), "PR_NOT_OPEN")
    listing = api(f"repos/{repo}/commits/{head}/check-runs?check_name={REQUIRED_CHECK}&filter=all&per_page=100")
    need(listing["total_count"] == len(listing["check_runs"]), "CHECK_RUNS_TRUNCATED")
    checks = [c for c in listing["check_runs"] if c["name"] == REQUIRED_CHECK]
    need(checks, "REQUIRED_CHECK_MISSING")
    sources = []
    pull_requests = pages(related_pull_path(f"repos/{repo}", pr) + "&per_page=100")
    histories = {p["number"]: pages(f"repos/{repo}/issues/{p['number']}/timeline?per_page=100")
                 for p in pull_requests if head_scope(p) == head_scope(pr)}
    for check in checks:
        # A same-named check from another app is not what the ruleset counts, but it
        # still signals tampering on this head.
        need(check["app"]["id"] == ACTIONS_APP_ID and check["head_sha"] == head, "FOREIGN_CHECK_SOURCE")
        runs = api(f"repos/{repo}/actions/runs?check_suite_id={check['check_suite']['id']}&per_page=100")["workflow_runs"]
        need(len(runs) == 1, "CHECK_RUN_SOURCE_AMBIGUOUS")
        run = runs[0]
        need(run["event"] == "pull_request_target" and run["path"] == WORKFLOW_PATH
             and run["head_sha"] == head, "UNTRUSTED_CHECK_SOURCE")
        try:
            validate_run_base(run, pr, pull_requests, BASE_BRANCH, histories)
        except ValueError as exc:
            raise Denied(str(exc)) from None
        sources.append({"check_run_id": check["id"], "run_id": run["id"], "run_attempt": run["run_attempt"],
                        "status": check["status"], "conclusion": check["conclusion"]})
    latest = max(checks, key=lambda c: (c.get("started_at") or "", c["id"]))
    need(latest["status"] == "completed" and latest["conclusion"] == "success", "LATEST_CHECK_NOT_SUCCESS")
    return {"decision": "ALLOW", "head_sha": head, "sources": sources}


def gh_api(path):
    return reader().api('/' + path)


def gh_pages(path):
    return reader().pages('/' + path)


_reader = None


def reader():
    global _reader
    if _reader is None:
        from security_harness.github_readonly import ReadOnlyGitHub
        _reader = ReadOnlyGitHub()
    return _reader


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="chinchiang/MultiAgentEpsilon")
    parser.add_argument("--pr", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) or args.pr <= 0:
        raise SystemExit("invalid repository or PR number")
    try:
        result = verify(gh_api, args.repo, args.pr, gh_pages)
    except Denied as exc:
        result = {"decision": "BLOCK", "code": str(exc)}
    except Exception as exc:
        result = {"decision": "BLOCK", "code": "VERIFICATION_ERROR", "error_type": type(exc).__name__}
    print(json.dumps(result, indent=2))
    return 0 if result["decision"] == "ALLOW" else 1


if __name__ == "__main__":
    sys.exit(main())
