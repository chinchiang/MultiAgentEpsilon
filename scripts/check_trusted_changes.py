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
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
from security_harness.github_readonly import GitHubReader, ReadOnlyGitHub
from security_harness.trusted_publisher import (identities, pr_commit_identities, validate_review, Denied,
                                               validate_run_base, related_pull_path, run_base_history)


def protected_changes(names):
    # Fixture 匯入與操作文件均屬可信基準。 / Fixture imports and operating instructions are part of the trusted baseline.
    # 不能以路徑豁免授權日後在 host 執行的 evaluator 變更。 / No path exemption may authorize a future host-executed evaluator change.
    return list(names)


def approved_review(pr, reviews, head, base, reviewers, permissions, excluded=()):
    """只採計清單內具寫入權限、非作者或已知推送者的核准；排除名單只能移除核准，不能新增授權。

An approval counts only from a listed, write-capable reviewer who is not the
    author or a known pusher. Exclusions may only remove approvals, never add them."""
    if pr["state"] != "open" or pr["head"]["sha"] != head or pr["base"]["sha"] != base:
        return None
    try:
        ids = validate_review(pr, reviews, permissions, {"reviewers": reviewers}, set(excluded))
    except Denied:
        return None
    review = next(r for r in reviews if r["id"] == ids[0])
    return {"review_id": review["id"], "reviewer": review["user"]["login"], "commit_id": head}


def parse_time(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def live_approval(number, head, base):
    policy = json.loads((ROOT / "security/trust-policy.json").read_text())
    # 此 guard 只實作獨立審查；政策若要求其他模式必須拒絕。 / This guard only implements independent review;
    # refuse a policy that asks for anything else.
    if policy.get("schema_version") != 1 or policy.get("require_independent_author") is not True:
        raise ValueError("unsupported trust policy")
    repo = policy["repository"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid trusted repository")
    reader = GitHubReader(ReadOnlyGitHub(), repo)
    pr = reader.get(f"pulls/{number}")
    # 提交身分可自報，真正擋下審查者自我核准的是規則集的最後推送核准；規則被關掉時不得放行。 / Commit identities
    # are self-asserted, so the ruleset's last-push approval is what stops self-approval; refuse when it is off.
    rules = reader.items("rules/branches/main")
    if not any(rule.get("type") == "pull_request" and isinstance(rule.get("parameters"), dict)
               and rule["parameters"].get("require_last_push_approval") is True for rule in rules):
        raise Denied("LAST_PUSH_APPROVAL")
    reviews = reader.items(f"pulls/{number}/reviews")
    # 只合併 base 的推送不會讓核准失效，GitHub 還會把 commit_id 改指新 head；改以伺服器記錄的推送時間判定。
    # / A base-only push keeps approvals and GitHub re-points their commit_id; judge by the server-recorded push time.
    ref = pr["head"]["ref"]
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", ref):
        raise Denied("HEAD_REF")
    # activity 以 cursor 分頁、忽略 page，只讀由新到舊的第一頁。每筆 activity 都會移動分支，head 未變時最新一筆就是
    # head 的推送；不在第一頁即視為不明。 / Activity is cursor-paged and ignores page, so read only the newest-first
    # first page. Every activity moves the branch, so while the head is unchanged the newest one is the head push;
    # a head push beyond the first page counts as unknown.
    pushes = [parse_time(a["timestamp"]) for a in reader.get(f"activity?ref=refs/heads/{ref}&direction=desc")
              if a.get("after") == head]
    if not pushes:
        raise Denied("LAST_PUSH_UNKNOWN")
    pushed = max(pushes)
    reviews = [{**r, "state": "DISMISSED"} if r["state"] == "APPROVED" and parse_time(r["submitted_at"]) <= pushed
               else r for r in reviews]
    candidates = {r["user"]["login"] for r in reviews
                  if r["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")}
    permissions = {}
    for login in sorted(candidates):
        if not re.fullmatch(r"[A-Za-z0-9-]+", login):
            continue
        permissions[login] = reader.get(f"collaborators/{login}/permission")["role_name"]
    # 提交身分可自報，因此只能排除審查者， / Commit identities are self-asserted, so they are used only to exclude reviewers;
    # 真實推送者仍由規則集原生最後推送核准檢查判定。 / the ruleset's native last-push approval remains the authoritative pusher check.
    commit = reader.get(f"commits/{head}")
    excluded = (identities(commit.get("author"), commit.get("committer"))
                | pr_commit_identities(reader.items(f"pulls/{number}/commits"), head))
    run_id = os.environ.get("GITHUB_RUN_ID")
    if run_id:
        if not re.fullmatch(r"[1-9][0-9]*", run_id):
            raise ValueError("invalid run identity")
        run = reader.get(f"actions/runs/{run_id}")
        excluded |= identities(run.get("actor"), run.get("triggering_actor"))
        pulls = reader.items(related_pull_path("", pr).lstrip("/"))
        validate_run_base(run, pr, pulls, "main", run_base_history(reader, pr, pulls))
    return approved_review(pr, reviews, head, base, policy["baseline_reviewers"], permissions, excluded)


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
    if args.pr:
        try:
            approval = live_approval(args.pr, head, args.base)
        except Denied as exc:
            # 拒絕碼是固定診斷碼，可記入稽核檔。 / A refusal code is a fixed diagnostic code, safe to record.
            approval_error = f"Denied:{exc}"
        except Exception as exc:
            approval_error = type(exc).__name__
    blocked = approval_error is not None or (bool(changed) and approval is None)
    evidence = {"schema_version": 2, "base_sha": args.base, "candidate_sha": head,
                "protected_changes": changed, "decision": "BLOCK" if blocked else "ALLOW",
                "baseline_approval": approval, "approval_error": approval_error,
                "policy": "trusted base remains authoritative for this run"}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence))
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
