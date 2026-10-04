#!/usr/bin/env python3
"""Detect protected changes against a trusted base; remote enforcement is separate.

In CI execute the base-ref copy of this file. A required trusted workflow/ruleset
must protect this job itself; candidate-controlled YAML cannot prove that property.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def protected_changes(names):
    # New execution/configuration entry points are protected by default.
    return [name for name in names if not (
        (name.startswith("fixture_app/") and name.endswith(".py")) or
        (name.startswith("docs/") and name.endswith(".md")) or name == "README.md")]


def approved_review(pr, reviews, head, base, reviewers):
    if pr["state"] != "open" or pr["head"]["sha"] != head or pr["base"]["sha"] != base:
        return None
    latest = {}
    for review in sorted(reviews, key=lambda r: r["id"]):
        if review["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[review["user"]["login"]] = review
    for login, review in latest.items():
        if (login in reviewers and login != pr["user"]["login"] and
                review["state"] == "APPROVED" and review["commit_id"] == head):
            return {"review_id": review["id"], "reviewer": login, "commit_id": head}
    return None


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
        output = subprocess.check_output(args, text=True, timeout=30, stderr=subprocess.DEVNULL)
        return [json.loads(line) for line in output.splitlines() if line] if pages else json.loads(output)
    pr = api(f"pulls/{number}")
    reviews = api(f"pulls/{number}/reviews?per_page=100", pages=True)
    return approved_review(pr, reviews, head, base, policy["baseline_reviewers"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="audit file in the trusted workflow workspace")
    parser.add_argument("--pr", type=int, help="resolve independent, exact-head baseline approval through GitHub")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.base):
        raise ValueError("base must be an immutable commit SHA")
    run = subprocess.run(["git", "-C", str(args.candidate), "diff", "--no-renames", "--name-only", "-z", args.base, "HEAD"],
                         capture_output=True, check=True, timeout=20)
    changed = protected_changes([name for name in run.stdout.decode().split("\0") if name])
    head = subprocess.check_output(["git", "-C", str(args.candidate), "rev-parse", "HEAD"], text=True, timeout=10).strip()
    approval = None
    approval_error = None
    if changed and args.pr:
        try:
            approval = live_approval(args.pr, head, args.base)
        except Exception as exc:
            approval_error = type(exc).__name__
    blocked = bool(changed) and approval is None
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
