#!/usr/bin/env python3
"""Detect protected changes against a trusted base; remote enforcement is separate.

In CI execute the base-ref copy of this file. A required trusted workflow/ruleset
must protect this job itself; candidate-controlled YAML cannot prove that property.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
from security_harness.trusted_publisher import (identities, pr_commit_identities, validate_review, Denied,
                                               validate_run_base, related_pull_path, head_scope)


def protected_changes(names):
    # Fixture imports and operating instructions are part of the trusted baseline.
    # No path exemption may authorize a future host-executed evaluator change.
    return list(names)


def approved_review(pr, reviews, head, base, reviewers, permissions, excluded=()):
    """An approval counts only from a listed, write-capable reviewer who is not the
    author or a known pusher. Exclusions may only remove approvals, never add them."""
    if pr["state"] != "open" or pr["head"]["sha"] != head or pr["base"]["sha"] != base:
        return None
    try:
        ids = validate_review(pr, reviews, permissions, {"reviewers": reviewers}, set(excluded))
    except Denied:
        return None
    review = next(r for r in reviews if r["id"] == ids[0])
    return {"review_id": review["id"], "reviewer": review["user"]["login"], "commit_id": head}


def live_approval(number, head, base):
    policy = json.loads((ROOT / "security/trust-policy.json").read_text())
    repo = policy["repository"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid trusted repository")
    def api(path, pages=False):
        args = ["gh", "api", f"repos/{repo}/{path}"]
        if pages:
            # gh 2.46 (the cloud runtime) predates --slurp. Stream one JSON
            # object per line across all pages; review text remains JSON-escaped.
            args += ["--paginate", "--jq", ".[] | @json"]
        output = subprocess.check_output(args, encoding="utf-8", timeout=30, stderr=subprocess.DEVNULL)
        return [json.loads(line) for line in output.splitlines() if line] if pages else json.loads(output)
    pr = api(f"pulls/{number}")
    reviews = api(f"pulls/{number}/reviews?per_page=100", pages=True)
    candidates = {r["user"]["login"] for r in reviews
                  if r["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")}
    permissions = {}
    for login in sorted(candidates):
        if not re.fullmatch(r"[A-Za-z0-9-]+", login):
            continue
        permissions[login] = api(f"collaborators/{login}/permission")["role_name"]
    # Commit identities are self-asserted, so they are used only to exclude reviewers;
    # the ruleset's native last-push approval remains the authoritative pusher check.
    commit = api(f"commits/{head}")
    excluded = (identities(commit.get("author"), commit.get("committer"))
                | pr_commit_identities(api(f"pulls/{number}/commits?per_page=100", pages=True), head))
    run_id = os.environ.get("GITHUB_RUN_ID")
    if run_id:
        if not re.fullmatch(r"[1-9][0-9]*", run_id):
            raise ValueError("invalid run identity")
        run = api(f"actions/runs/{run_id}")
        excluded |= identities(run.get("actor"), run.get("triggering_actor"))
        pulls = api(related_pull_path("", pr).lstrip("/") + "&per_page=100", pages=True)
        histories = {p["number"]: api(f"issues/{p['number']}/timeline?per_page=100", pages=True)
                     for p in pulls if head_scope(p) == head_scope(pr)}
        validate_run_base(run, pr, pulls, "main", histories)
    return approved_review(pr, reviews, head, base, policy["baseline_reviewers"], permissions, excluded)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="audit file in the trusted workflow workspace")
    parser.add_argument("--pr", type=int, help="resolve independent, exact-head baseline approval through GitHub")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.base):
        raise ValueError("base must be an immutable commit SHA")
    run = candidate_git.run(args.candidate, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                            "--name-only", "-z", args.base, "HEAD", capture_output=True, check=True, timeout=20)
    changed = protected_changes([name for name in run.stdout.decode().split("\0") if name])
    head = candidate_git.head(args.candidate)
    approval = None
    approval_error = None
    if args.pr:
        try:
            approval = live_approval(args.pr, head, args.base)
        except Exception as exc:
            approval_error = type(exc).__name__
    blocked = approval_error is not None or (bool(changed) and approval is None)
    evidence = {"schema_version": 2, "base_sha": args.base, "candidate_sha": head,
                "protected_changes": changed, "decision": "BLOCK" if changed else "ALLOW"}
    evidence.update(decision="BLOCK" if blocked else "ALLOW", baseline_approval=approval,
                    approval_error=approval_error, policy="trusted base remains authoritative for this run")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence))
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
