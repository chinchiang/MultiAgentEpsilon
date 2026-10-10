#!/usr/bin/env python3
"""寫入 evaluator 擁有的來源綁定；不可匯入候選程式。

Write evaluator-owned source bindings; never import candidate code."""
import argparse
import json
import os
import re
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_harness import candidate_git


def commit(path):
    value = candidate_git.head(path)
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("invalid commit")
    return value


REQUIRED_ENVIRONMENT = ("GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                        "GITHUB_EVENT_NAME", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA")


def provenance(evaluator, candidate, environ=os.environ):
    """由 GitHub Actions 環境與兩個 checkout 的 HEAD 組成來源綁定；寫入與自我檢查共用。

Source binding from the Actions environment and both checkouts' HEADs; shared by the
    writer and the evidence self-check."""
    return {"schema_version": 1, "repository": environ["GITHUB_REPOSITORY"],
            "repository_id": int(environ["GITHUB_REPOSITORY_ID"]),
            "run_id": int(environ["GITHUB_RUN_ID"]),
            "run_attempt": int(environ["GITHUB_RUN_ATTEMPT"]),
            "event": environ["GITHUB_EVENT_NAME"],
            "workflow_ref": environ["GITHUB_WORKFLOW_REF"],
            "workflow_sha": environ["GITHUB_WORKFLOW_SHA"],
            "pr_number": int(environ.get("PR_NUMBER", "0")),
            "base_sha": commit(evaluator), "candidate_sha": commit(candidate)}


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    missing = [name for name in REQUIRED_ENVIRONMENT if not os.environ.get(name)]
    if missing:
        # 僅能在 GitHub Actions 中執行。 / Only meaningful inside GitHub Actions.
        print("GitHub Actions environment missing / 缺少 GitHub Actions 環境: " + ", ".join(missing), file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    evidence = provenance(root, root.parent / "candidate")
    output = root.parent / "audit/ci-provenance.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
