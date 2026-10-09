#!/usr/bin/env python3
"""CI 自我檢查本次上傳證據是否符合專用發布器契約。依 upload-artifact 的方式封裝 trusted/artifacts 與 audit，再使用發布器的解包與驗證邏輯，讓證據漂移在產生當下就失敗。GitHub 審查、執行清單與設定 pins 仍由發布器驗證。

CI self-check: would the dedicated publisher accept the evidence this run uploads?

Zips trusted/artifacts/ and audit/ the way upload-artifact does and runs the
publisher's own unpack and artifact contract, so evidence/contract drift fails the
run that produced it instead of surfacing only after deployment. GitHub metadata
(reviews, run listing, settings pins) remains the publisher's job.
"""
import argparse
import hashlib
import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
from security_harness.results import subject_digest, write_json
from security_harness.trusted_publisher import Denied, strict_json, unpack_evidence, validate_evidence


def commit(path):
    return candidate_git.head(path)


def artifact_zip(workspace):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for top in ("trusted/artifacts", "audit"):
            base = workspace / top
            for path in sorted(base.rglob("*")) if base.is_dir() else ():
                if path.is_file() and not path.is_symlink():
                    archive.write(path, path.relative_to(workspace).as_posix())
    return data.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    workspace = ROOT.parent
    candidate = args.candidate.resolve()
    result = {"decision": "BLOCK", "code": "NOT_STARTED"}
    try:
        example = strict_json((ROOT / "security/trusted-publisher.example.json").read_bytes())
        settings = {"evaluator_sha": commit(ROOT), "evaluator_digest": subject_digest(ROOT),
                    "policy_digest": hashlib.sha256((ROOT / "security/policy.json").read_bytes()).hexdigest(),
                    "minimum_regression_tests": example["minimum_regression_tests"]}
        gate_policy = strict_json((ROOT / "security/policy.json").read_bytes())
        provenance = {"schema_version": 1, "repository": os.environ["GITHUB_REPOSITORY"],
                      "repository_id": int(os.environ["GITHUB_REPOSITORY_ID"]),
                      "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                      "event": os.environ["GITHUB_EVENT_NAME"], "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
                      "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"], "pr_number": int(os.environ.get("PR_NUMBER", "0")),
                      "base_sha": settings["evaluator_sha"], "candidate_sha": commit(candidate)}
        files = unpack_evidence(artifact_zip(workspace))
        tests = validate_evidence(settings, gate_policy, files, provenance=provenance,
                                  candidate_sha=provenance["candidate_sha"], subject=subject_digest(candidate),
                                  now=datetime.now(timezone.utc))
        result = {"decision": "ALLOW", "code": "PUBLISHABLE", "tests": tests,
                  "candidate_sha": provenance["candidate_sha"], "evaluator_sha": settings["evaluator_sha"]}
    except Denied as exc:
        result["code"] = str(exc)
    except Exception as exc:
        result.update(code="SELF_CHECK_ERROR", error_type=type(exc).__name__)
    write_json(args.output, result)
    print(json.dumps(result))
    return 0 if result["decision"] == "ALLOW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
