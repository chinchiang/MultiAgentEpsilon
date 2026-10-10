#!/usr/bin/env python3
"""準備不可變的部署輸入，不含憑證或遠端寫入。部署擁有者須選擇已獨立審查的 main 提交；產生檔案不代表核准、服務部署或檢查發布。

Prepare immutable deployment inputs without credentials or remote writes.

The deployment owner must select an independently reviewed main commit. Preparing
these files does not establish approval, install a service, or publish a check.
"""
import argparse
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
from security_harness.results import subject_digest, validate_policy, executable_bits
from security_harness.trusted_publisher import GITHUB_ACTIONS_APP_ID, Denied, need, strict_json, validate_settings


def archive_digest(data):
    """git archive 會套用 export-ignore/subst；必須核對實際部署位元組，而不只核對來源工作樹乾淨。

git archive honors export-ignore/subst; verify bytes actually being deployed,
    not just the clean worktree from which the archive command was invoked."""
    need(len(data) <= 20 * 1024**2, "ARCHIVE_LIMIT")
    files, names = [], set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and ".." not in path.parts and "\\" not in member.name,
                 "ARCHIVE_ENTRY")
            if member.isdir():
                continue
            need(member.isfile() and member.name not in names and len(files) < 200
                 and member.size <= 1024**2, "ARCHIVE_ENTRY")
            names.add(member.name)
            stream = archive.extractfile(member)
            need(stream is not None, "ARCHIVE_ENTRY")
            with stream:
                content = stream.read(1024**2 + 1)
            need(len(content) == member.size, "ARCHIVE_ENTRY")
            files.append({"path": member.name, "type": "file", "executable_bits": executable_bits(member.mode),
                          "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    encoded = json.dumps({"format": "worktree-manifest-v1", "files": sorted(files, key=lambda f: f["path"])},
                         sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    return "worktree-manifest-v1:sha256:" + hashlib.sha256(encoded).hexdigest()


def prepare(root, output, evaluator_sha, app_id=None, installation_id=None):
    root, output = Path(root).resolve(), Path(output).absolute()
    need(not output.resolve().is_relative_to(root), "OUTPUT_MUST_BE_EXTERNAL")
    need(candidate_git.head(root) == evaluator_sha, "EVALUATOR_SHA_MISMATCH")
    status = candidate_git.run(root, "status", "--porcelain", "--untracked-files=all",
                               capture_output=True, text=True, check=True, timeout=20)
    need(not status.stdout, "EVALUATOR_NOT_CLEAN")
    for value in (app_id, installation_id):
        need(value is None or type(value) is int and value > 0, "APP_IDENTIFIERS")
    need(app_id != GITHUB_ACTIONS_APP_ID, "SHARED_ACTIONS_APP")
    raw_policy = (root / "security/policy.json").read_bytes()
    policy = strict_json(raw_policy)
    validate_policy(policy)
    settings = strict_json((root / "security/trusted-publisher.example.json").read_bytes())
    trust = strict_json((root / "security/trust-policy.json").read_bytes())
    need(settings["repository"] == trust["repository"] and settings["reviewers"] == trust["baseline_reviewers"],
         "TRUST_POLICY_MISMATCH")
    settings.update(evaluator_sha=evaluator_sha, evaluator_digest=subject_digest(root),
                    policy_digest=hashlib.sha256(raw_policy).hexdigest(),
                    app_id=app_id, installation_id=installation_id)
    configured = app_id is not None and installation_id is not None
    if configured:
        validate_settings(settings, policy)
    archive = candidate_git.run(root, "archive", "--format=tar", evaluator_sha,
                                capture_output=True, check=True, timeout=30).stdout
    need(archive_digest(archive) == settings["evaluator_digest"], "ARCHIVE_MANIFEST")
    need(subject_digest(root) == settings["evaluator_digest"] and candidate_git.head(root) == evaluator_sha,
         "EVALUATOR_CHANGED")
    status = candidate_git.run(root, "status", "--porcelain", "--untracked-files=all",
                               capture_output=True, text=True, check=True, timeout=20)
    need(not status.stdout, "EVALUATOR_CHANGED")
    summary = {"prepared": True, "deployed": False, "approval_verified": False,
               "configuration_complete": configured, "evaluator_sha": evaluator_sha,
               "minimum_regression_tests": settings["minimum_regression_tests"],
               "missing": [name for name in ("app_id", "installation_id") if settings[name] is None]}
    payloads = {"publisher.json": (json.dumps(settings, indent=2) + "\n").encode(),
                "gate-policy.json": raw_policy, "app.tar": archive,
                "preparation.json": (json.dumps(summary, indent=2) + "\n").encode()}
    # 拒絕既有目錄，避免覆寫部署 pin 或私鑰。 / Refuse an existing directory rather than overwrite a deployed pin or key.
    output.mkdir(mode=0o700)
    for name, data in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(data)
        (output / name).chmod(0o400)
    checksums = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n"
                        for name, data in sorted(payloads.items()))
    (output / "SHA256SUMS").write_text(checksums)
    (output / "SHA256SUMS").chmod(0o400)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evaluator-sha", required=True)
    parser.add_argument("--app-id", type=int)
    parser.add_argument("--installation-id", type=int)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(ROOT, args.output_dir, args.evaluator_sha, args.app_id, args.installation_id)
    except Exception as exc:
        result = {"prepared": False, "deployed": False,
                  "code": str(exc) if isinstance(exc, Denied) else "PREPARATION_ERROR"}
    print(json.dumps(result))
    return 0 if result["prepared"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
