#!/usr/bin/env python3
"""Write evaluator-owned source bindings; never import candidate code."""
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_harness import candidate_git


def commit(path):
    value = candidate_git.head(path)
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("invalid commit")
    return value


def main():
    root = Path(__file__).resolve().parents[1]
    candidate = root.parent / "candidate"
    evidence = {"schema_version": 1, "repository": os.environ["GITHUB_REPOSITORY"],
                "repository_id": int(os.environ["GITHUB_REPOSITORY_ID"]),
                "run_id": int(os.environ["GITHUB_RUN_ID"]),
                "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                "event": os.environ["GITHUB_EVENT_NAME"],
                "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
                "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
                "pr_number": int(os.environ.get("PR_NUMBER", "0")),
                "base_sha": commit(root), "candidate_sha": commit(candidate)}
    output = root.parent / "audit/ci-provenance.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
