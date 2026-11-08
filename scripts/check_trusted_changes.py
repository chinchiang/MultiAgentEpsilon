#!/usr/bin/env python3
"""對可信 base 偵測受保護變更；遠端強制執行須另驗收。CI 必須執行 base 版本，並以可信必要工作流程或規則集保護此工作；候選控制的 YAML 不能證明自身可信。

Detect protected changes against a trusted base; remote enforcement is separate.

In CI execute the base-ref copy of this file. A required trusted workflow/ruleset
must protect this job itself; candidate-controlled YAML cannot prove that property.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
from security_harness.github_readonly import GitHubReader, ReadOnlyGitHub
from security_harness.github_http import Denied
from security_harness.github_trust import GitHubTrust, approved_review as approved_review


def protected_changes(names):
    # Fixture 匯入與操作文件均屬可信基準。 / Fixture imports and operating instructions are part of the trusted baseline.
    # 不能以路徑豁免授權日後在 host 執行的 evaluator 變更。 / No path exemption may authorize a future host-executed evaluator change.
    return list(names)


def live_approval(number, head, base, refusals=None):
    policy = json.loads((ROOT / "security/trust-policy.json").read_text())
    # 此 guard 只實作獨立審查；政策若要求其他模式必須拒絕。 / This guard only implements independent review;
    # refuse a policy that asks for anything else.
    if policy.get("schema_version") != 1 or policy.get("require_independent_author") is not True:
        raise ValueError("unsupported trust policy")
    repo = policy["repository"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid trusted repository")
    reader = GitHubReader(ReadOnlyGitHub(), repo)
    return GitHubTrust(reader).baseline_approval(number, head, base, policy["baseline_reviewers"],
                                                 os.environ.get("GITHUB_RUN_ID"), refusals)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="可信 base 的完整 commit SHA / full trusted base commit SHA")
    parser.add_argument("--candidate", type=Path, required=True, help="候選 checkout，只作資料 / candidate checkout, data only")
    parser.add_argument("--output", type=Path, help="可信工作流程內的稽核檔案 / audit file in the trusted workflow workspace")
    parser.add_argument("--pr", type=int, help="透過 GitHub 核對獨立且精確對應 head 的基準核准 / resolve independent, exact-head baseline approval through GitHub")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.base):
        raise ValueError("base must be an immutable commit SHA")
    run = candidate_git.run(args.candidate, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                            "--name-only", "-z", args.base, "HEAD", capture_output=True, check=True, timeout=20)
    changed = protected_changes([name for name in run.stdout.decode().split("\0") if name])
    head = candidate_git.head(args.candidate)
    approval = None
    approval_error = None
    refusals = []
    if args.pr:
        try:
            approval = live_approval(args.pr, head, args.base, refusals)
        except Denied as exc:
            # 拒絕碼是固定診斷碼，可記入稽核檔。 / A refusal code is a fixed diagnostic code, safe to record.
            approval_error = f"Denied:{exc}"
        except Exception as exc:
            approval_error = type(exc).__name__
    blocked = approval_error is not None or (bool(changed) and approval is None)
    evidence = {"schema_version": 2, "base_sha": args.base, "candidate_sha": head,
                "protected_changes": changed, "decision": "BLOCK" if blocked else "ALLOW",
                "baseline_approval": approval, "approval_error": approval_error,
                # 沒有核准時的固定診斷碼，例如 INDEPENDENT_APPROVAL_MISSING。 / The fixed diagnostic code when no
                # approval counts, such as INDEPENDENT_APPROVAL_MISSING.
                "approval_refusal": refusals[0] if refusals else None,
                "policy": "trusted base remains authoritative for this run"}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence))
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
