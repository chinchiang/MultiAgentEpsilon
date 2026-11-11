"""專用 App 發布器驗證遠端資料，不執行候選內容。程式與政策須在候選工作流程外唯讀部署，仍需原生審查、檢查與事件傳遞；本工具不是簽署或代管服務，GitHub 成功檢查也不會自動到期。

Dedicated-App publisher: validate remote data, never execute candidate contents.

Deploy this code and its policy read-only outside candidate workflows. Native
review/check rules and event delivery remain required; this is not a signing or
hosting service, and success cannot expire automatically in GitHub Checks.
"""
import base64
import copy
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import time
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from . import guard_evidence
from .github_http import Denied, GitHub, need, strict_json
from .github_readonly import GitHubReader
from .github_trust import (GITHUB_ACTIONS_APP_ID, GitHubTrust, head_scope, review_decision, run_scope,
                           validate_run_base as validate_run_base)
from .inputs import excluded
from .limits import LIMITS
from .supervision import child_environment
from .workflow_contract import ATTESTATION, COMPLETION, EVALUATION, JOBS, MUTATION, evidence_artifact
from .results import EVIDENCE_VERSION, decide, seeded_defects, validate_cases, validate_policy

# 冷快取時每個來源檔需要一次 blob 請求，預算須高於檔案上限。 / A cold cache costs one blob request per source
# file, so the call budget must exceed the file ceiling.
MAX_SOURCE_FILES = 500

SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MANIFEST = re.compile(r"worktree-manifest-v1:sha256:[0-9a-f]{64}")


def validate_settings(settings, gate_policy):
    need(type(settings.get("schema_version")) is int and settings["schema_version"] == 1, "SETTINGS_SCHEMA")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", settings.get("repository", "")), "REPOSITORY")
    for key in ("repository_id", "app_id", "installation_id", "workflow_id", "minimum_regression_tests"):
        need(type(settings.get(key)) is int and settings[key] > 0, "SETTINGS_INCOMPLETE")
    need(settings["app_id"] != GITHUB_ACTIONS_APP_ID, "SHARED_ACTIONS_APP")
    need(settings.get("base_branch") == "main" and settings.get("check_name") == "epsilon/trusted-merge", "CHECK_SCOPE")
    need(settings.get("workflow_path") == ".github/workflows/security.yml", "WORKFLOW_PATH")
    need(SHA.fullmatch(settings.get("evaluator_sha") or ""), "UNAPPROVED_EVALUATOR")
    need(MANIFEST.fullmatch(settings.get("evaluator_digest") or ""), "EVALUATOR_DIGEST")
    need(DIGEST.fullmatch(settings.get("policy_digest") or ""), "POLICY_DIGEST")
    need(isinstance(settings.get("attestation_verifier"), str)
         and Path(settings["attestation_verifier"]).is_absolute()
         and DIGEST.fullmatch(settings.get("attestation_verifier_sha256") or ""), "ATTESTATION_SETTINGS")
    reviewers = settings.get("reviewers")
    need(isinstance(reviewers, list) and reviewers and len(set(reviewers)) == len(reviewers)
         and all(isinstance(r, str) and re.fullmatch(r"[A-Za-z0-9-]+", r) for r in reviewers), "REVIEWERS")
    validate_policy(gate_policy)


def reject_newer_runs(run, newer_runs, head):
    # 不同 fork 可共用 SHA；只有相同儲存庫／分支的評估 / SHA alone is shared across forks. Only the same repository/branch evaluation
    # 能取代此 run，同 SHA 較新 run 缺身分時故障即阻擋。 / supersedes this run; missing identity on a same-SHA newer run fails closed.
    for other in newer_runs:
        need(type(other.get("id")) is int and SHA.fullmatch(other.get("head_sha") or ""), "RUN_LISTING")
        if other["id"] > run["id"] and other["head_sha"] == head:
            need(other.get("head_branch") and (other.get("head_repository") or {}).get("id"), "RUN_LISTING_IDENTITY")
            if run_scope(other) == run_scope(run):
                raise Denied("NEWER_RUN_EXISTS")


def unpack_evidence(data):
    need(len(data) <= 16 * 1024**2, "ARTIFACT_COMPRESSED_LIMIT")
    result = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        need(len(entries) <= 1000 and sum(e.file_size for e in entries) <= 32 * 1024**2, "ARTIFACT_EXPANDED_LIMIT")
        names = set()
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            need(entry.filename not in names and not path.is_absolute() and ".." not in path.parts
                 and "\\" not in entry.filename and not stat.S_ISLNK(mode)
                 and not entry.flag_bits & 1 and entry.file_size <= 8 * 1024**2, "ARTIFACT_ENTRY")
            names.add(entry.filename)
            if not entry.is_dir() and (path.name in ("report.json", "pytest.xml", "latest.txt", "ci-provenance.json", "trusted-guard.json")):
                result[entry.filename] = archive.read(entry)
    return result


def validate_pr(pr, settings):
    need(pr.get("state") == "open" and pr.get("draft") is False, "PR_NOT_REVIEWABLE")
    need(pr["base"]["repo"]["id"] == settings["repository_id"]
         and pr["base"]["repo"]["full_name"] == settings["repository"]
         and pr["base"]["ref"] == settings["base_branch"], "PR_REPOSITORY")
    need(pr["base"]["sha"] == settings["evaluator_sha"], "BASE_NOT_APPROVED")
    need(SHA.fullmatch(pr["head"]["sha"]), "CANDIDATE_SHA")


# 步驟名稱的唯一來源是 workflow_contract。 / workflow_contract is the only source of step names.
REQUIRED_STEPS = EVALUATION.steps
MUTATION_STEPS = MUTATION.steps
COMPLETION_STEP = COMPLETION.steps[0]
CLEANUP_KEYS = ("completed", "temporary_directory_removed", "run_directory_removed", "process_group_terminated")


def evidence_file(files, name):
    need(name in files, "EVIDENCE_FILE_MISSING")
    return files[name]


def expected_provenance(settings, run_id, run_attempt, pr_number, base_sha, candidate_sha):
    return {"schema_version": 1, "repository": settings["repository"], "repository_id": settings["repository_id"],
            "run_id": run_id, "run_attempt": run_attempt, "event": "pull_request_target",
            "workflow_ref": settings["repository"] + "/" + settings["workflow_path"] + "@refs/heads/main",
            "workflow_sha": settings["evaluator_sha"], "pr_number": pr_number,
            "base_sha": base_sha, "candidate_sha": candidate_sha}


def validate_evidence(settings, gate_policy, files, *, provenance, candidate_sha, subject, now):
    """發布器與 CI 共用純 artifact 契約。修正版報告評估候選，缺陷版是 evaluator 自我測試，因此負例綁定 evaluator 摘要與歷史，不綁候選。

Artifact-only contract, shared by the publisher and the CI self-check.

    The fixed report evaluates the candidate. The seeded-defect report is the
    evaluator's self-test (expect_block runs the trusted tree's vulnerable variant),
    so it is bound to the evaluator digest and evaluator history, never the candidate.
    """
    need(strict_json(evidence_file(files, "audit/ci-provenance.json")) == provenance, "PROVENANCE_MISMATCH")
    xml = evidence_file(files, "trusted/artifacts/pytest.xml")
    need(len(xml) <= 2 * 1024**2 and b"<!DOCTYPE" not in xml.upper() and b"<!ENTITY" not in xml.upper(), "JUNIT_LIMIT")
    tree = ElementTree.fromstring(xml)
    need(tree.tag in ("testsuite", "testsuites"), "JUNIT_ROOT")
    suites = [tree] if tree.tag == "testsuite" else tree.findall("testsuite")
    need(bool(suites), "NO_REGRESSIONS")
    identities = set()
    for suite in suites:
        cases = suite.findall("testcase")
        # 每項測試須有唯一識別；重複項目不能灌高已通過數量。
        # Require unique test identities; duplicate entries cannot inflate coverage.
        for case in cases:
            identity = (case.get('classname'), case.get('name'))
            need(all(type(v) is str and v.strip() for v in identity)
                 and identity not in identities, 'JUNIT_IDENTITY')
            identities.add(identity)
        need(all(re.fullmatch(r'0|[1-9][0-9]*', suite.get(k, ''))
                 for k in ('tests', 'failures', 'errors', 'skipped')), 'JUNIT_COUNTS')
        need(len(cases) == int(suite.get("tests", "0"))
             and all(not any(c.find(tag) is not None for tag in ("failure", "error", "skipped")) for c in cases), "JUNIT_CASES")
    counts = {k: sum(int(s.get(k, "0")) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
    need(counts["tests"] >= settings["minimum_regression_tests"]
         and counts["failures"] == counts["errors"] == counts["skipped"] == 0, "REGRESSION_FAILURE")
    latest = evidence_file(files, "trusted/artifacts/latest.txt").decode().strip()
    need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", latest), "LATEST_POINTER")
    report = strict_json(evidence_file(files, f"trusted/artifacts/{latest}/report.json"))
    need(report.get("schema_version") == EVIDENCE_VERSION and report.get("operation") == "security"
         and report.get("variant") == "fixed" and report.get("run_id") == latest
         and report.get("execution") == "COMPLETED" and report.get("decision") == "ALLOW"
         and not report.get("errors"), "REPORT_NOT_ALLOW")
    need(report.get("subject_digest") == subject and report.get("evaluator_digest") == settings["evaluator_digest"]
         and report.get("policy_digest") == settings["policy_digest"], "REPORT_DIGEST")
    cleanup = report.get("cleanup", {})
    need(all(cleanup.get(k) is True for k in CLEANUP_KEYS) and cleanup.get("error_type") is None, "CLEANUP_INCOMPLETE")
    need(decide(report["records"], gate_policy, subject, settings["policy_digest"], now, run_id=latest)["decision"] == "ALLOW", "GATE_REJECTED")
    scan = next(r for r in report["records"] if r["gate"] == "G2")
    need(scan["evidence"]["coverage"].get("history_head") == candidate_sha, "HISTORY_SHA")
    reports = [strict_json(data) for path, data in files.items()
               if path.startswith("trusted/artifacts/") and path.endswith("/report.json")]
    negative = [r for r in reports if r.get("operation") == "security" and r.get("variant") == "vulnerable"]
    need(len(negative) == 1, "NEGATIVE_EVIDENCE_MISSING")
    negative = negative[0]
    need(negative.get("schema_version") == EVIDENCE_VERSION and negative.get("execution") == "COMPLETED"
         and negative.get("decision") == "BLOCK" and not negative.get("errors")
         and negative.get("subject_digest") == settings["evaluator_digest"]
         and negative.get("evaluator_digest") == settings["evaluator_digest"]
         and negative.get("policy_digest") == settings["policy_digest"], "NEGATIVE_BINDING")
    negative_cleanup = negative.get("cleanup", {})
    need(all(negative_cleanup.get(k) is True for k in CLEANUP_KEYS)
         and negative_cleanup.get("error_type") is None, "NEGATIVE_CLEANUP")
    normalized = copy.deepcopy(negative["records"])
    auth = [r for r in normalized if r.get("gate") == "AUTH"]
    seeded = seeded_defects(gate_policy["gate_contracts"]["AUTH"])
    need(len(auth) == 1 and auth[0].get("findings") == len(seeded) and isinstance(auth[0].get("cases"), list)
         and {c.get("case") for c in auth[0]["cases"] if isinstance(c, dict) and c.get("passed") is False} == seeded,
         "NEGATIVE_FINDINGS")
    validate_cases(auth[0]["cases"], gate_policy["gate_contracts"]["AUTH"])
    auth[0]["findings"] = 0
    for case in auth[0]["cases"]:
        case["passed"] = True
    need(decide(normalized, gate_policy, settings["evaluator_digest"], settings["policy_digest"], now,
                run_id=negative["run_id"])["decision"] == "ALLOW", "NEGATIVE_GATES")
    negative_scan = next(r for r in normalized if r["gate"] == "G2")
    need(negative_scan["evidence"]["coverage"].get("history_head") == settings["evaluator_sha"], "NEGATIVE_HISTORY")
    return counts["tests"]


def validate_bundle(settings, gate_policy, pr, run, newer_runs, jobs, files, reviews, permissions, subject, now,
                    push, commit_identities=()):
    validate_settings(settings, gate_policy)
    validate_pr(pr, settings)
    need(run["repository"]["id"] == settings["repository_id"]
         and run["repository"]["full_name"] == settings["repository"], "RUN_REPOSITORY")
    # pull_request_target 從 PR 的 base 分支執行此路徑， / A pull_request_target run executes this path from the PR's *base* branch, and the
    # run 未記錄 base；其他分支修改副本也有相同 workflow_id／path， / run does not record which base: workflow_id/path also match a modified copy on
    # 因此 collect 前由 validate_run_base 綁定此 PR。 / another branch. validate_run_base binds the run to this PR before collection.
    need(run["workflow_id"] == settings["workflow_id"] and run["path"] == settings["workflow_path"]
         and run["event"] == "pull_request_target", "RUN_SOURCE")
    need(run["status"] == "completed" and run["conclusion"] == "success", "RUN_NOT_SUCCESS")
    # GitHub 將 pull_request_target run 與 check suite 記在 PR head， / GitHub reports pull_request_target runs (and their check suites) on the PR head
    # evaluator commit 則由下方可信 workflow provenance 綁定。 / commit; the evaluator commit is bound below via the trusted workflow's provenance.
    need(run["head_sha"] == pr["head"]["sha"], "RUN_SHA")
    need(type(run["run_attempt"]) is int and run["run_attempt"] >= 1, "RUN_ATTEMPT")
    reject_newer_runs(run, newer_runs, pr["head"]["sha"])
    named = {j["name"]: j for j in jobs}
    need(len(jobs) == len(named) == len(JOBS)
         and set(named) == {j.name for j in JOBS}
         and all(j["conclusion"] == "success" for j in jobs), "JOB_SOURCE")
    steps = {s["name"]: s["conclusion"] for s in named[EVALUATION.name]["steps"]}
    need(all(steps.get(s) == "success" for s in REQUIRED_STEPS), "REQUIRED_STEP_INCOMPLETE")
    mutation = {s["name"]: s["conclusion"] for s in named[MUTATION.name]["steps"]}
    need(all(mutation.get(s) == "success" for s in MUTATION_STEPS), "MUTATION_STEP_INCOMPLETE")
    signing = named[ATTESTATION.name]["steps"]
    need(any(s["name"] == ATTESTATION.steps[0] and s["conclusion"] == "success"
             for s in signing), "ATTESTATION_STEP_INCOMPLETE")
    completion = named[COMPLETION.name]['steps']
    need(any(s['name'] == COMPLETION_STEP and s['conclusion'] == 'success'
             for s in completion), 'COMPLETION_STEP_INCOMPLETE')
    approvals = review_decision(pr, reviews, permissions, settings["reviewers"], commit_identities, push)
    guard = guard_evidence.validate(strict_json(evidence_file(files, "audit/trusted-guard.json")),
                                    pr["base"]["sha"], pr["head"]["sha"])
    if guard["protected_changes"]:
        approval = guard["baseline_approval"]
        # guard 記錄的必須是該審查者對現行 head 的一筆真實核准，且同一審查者現在仍被採計；審查者對同一 head 再按一次
        # Approve 只換掉最新一筆的 ID，不必整輪重跑。 / The guard's record must be a real approval of the current head by
        # that reviewer, and the same reviewer must still count now; approving the same head again only changes the
        # latest review ID and needs no rerun.
        recorded = [r for r in reviews if r.get("id") == approval["review_id"]]
        counted = {r["user"]["login"] for r in reviews if r.get("id") in approvals}
        need(len(recorded) == 1 and recorded[0]["state"] == "APPROVED"
             and recorded[0]["user"]["login"] == approval["reviewer"]
             and recorded[0]["commit_id"] == pr["head"]["sha"] == approval["commit_id"]
             and approval["reviewer"] in counted and approval["reviewer"] in settings["reviewers"],
             "BASELINE_APPROVAL")
    provenance = expected_provenance(settings, run["id"], run["run_attempt"], pr["number"],
                                     pr["base"]["sha"], pr["head"]["sha"])
    tests = validate_evidence(settings, gate_policy, files, provenance=provenance,
                              candidate_sha=pr["head"]["sha"], subject=subject, now=now)
    return {"head_sha": pr["head"]["sha"], "base_sha": pr["base"]["sha"], "run_id": run["id"],
            "run_attempt": run["run_attempt"], "subject_digest": subject, "review_ids": approvals, "tests": tests}


def installation_client(settings, key_file):
    key = Path(key_file)
    info = key.lstat()
    need(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 16384, "PRIVATE_KEY_FILE")
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")
    now = int(time.time())
    unsigned = encode(b'{"alg":"RS256","typ":"JWT"}') + b"." + encode(json.dumps(
        {"iat": now-60, "exp": now+480, "iss": str(settings["app_id"])}, separators=(",", ":")).encode())
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)], input=unsigned,
                               capture_output=True, check=True, timeout=10).stdout
    client = GitHub((unsigned + b"." + encode(signature)).decode())
    need(client.api("/app")["id"] == settings["app_id"], "APP_IDENTITY")
    installation = client.api(f"/app/installations/{settings['installation_id']}")
    need(installation["app_id"] == settings["app_id"] and installation.get("suspended_at") is None
         and installation["account"]["login"].lower() == settings["repository"].split("/")[0].lower(), "INSTALLATION_IDENTITY")
    permissions = {"actions": "read", "contents": "read", "pull_requests": "read", "checks": "write",
                   "attestations": "read"}
    response = client.api(f"/app/installations/{settings['installation_id']}/access_tokens", "POST",
                          {"repository_ids": [settings["repository_id"]], "permissions": permissions})
    granted = response.get("permissions", {})
    need(all(granted.get(k) == v for k, v in permissions.items())
         and all(v != "write" or k == "checks" for k, v in granted.items()), "TOKEN_PERMISSIONS")
    return GitHub(response["token"])


def remote_subject(reader, sha, blob_cache=None):
    """blob_cache 將已驗證 Git blob ID 對應 SHA-256；快取前核對內容定址，命中快取不會改變摘要。

blob_cache maps verified Git blob IDs to SHA-256. Blob IDs are content
    addresses checked below before caching, so a cache hit cannot change a digest."""
    tree = reader.get(f"git/trees/{sha}?recursive=1")
    need(tree.get("truncated") is False, "SOURCE_TREE_TRUNCATED")
    contents = {} if blob_cache is None else blob_cache
    files, total = [], 0
    for entry in sorted(tree["tree"], key=lambda e: e["path"]):
        if entry["type"] == "tree":
            continue
        path = PurePosixPath(entry["path"])
        need(not any(f["path"] == entry["path"] for f in files), "DUPLICATE_SOURCE_PATH")
        need(entry["type"] == "blob" and entry["mode"] in ("100644", "100755")
             and not path.is_absolute() and ".." not in path.parts and not excluded(Path(entry["path"])), "SOURCE_INPUT")
        size = entry["size"]
        total += size
        # GitHub JSON／base64 回應採獨立且刻意較低的 / GitHub's JSON/base64 response has a separate, deliberately lower
        # 大小上限，不沿用掃描器串流檔案上限。 / ceiling than the scanner's streaming file allowance.
        need(type(size) is int and 0 <= size <= min(LIMITS.max_file_bytes, 1024**2)
             and total <= min(LIMITS.max_input_bytes, 20 * 1024**2)
             and len(files) < min(LIMITS.max_files, MAX_SOURCE_FILES), "SOURCE_LIMIT")
        blob_sha = entry["sha"]
        need(SHA.fullmatch(blob_sha), "BLOB_SHA")
        if blob_sha not in contents:
            blob = reader.get(f"git/blobs/{blob_sha}")
            need(blob["encoding"] == "base64" and blob["size"] == size, "BLOB_METADATA")
            data = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
            need(len(data) == size and hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest() == blob_sha, "BLOB_CONTENT")
            contents[blob_sha] = hashlib.sha256(data).hexdigest()
        files.append({"path": entry["path"], "type": "file", "executable_bits": 0o111 if entry["mode"] == "100755" else 0,
                      "size": size, "sha256": contents[blob_sha]})
    need(bool(files), "EMPTY_SOURCE")
    value = json.dumps({"format": "worktree-manifest-v1", "files": files},
                       sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    return "worktree-manifest-v1:sha256:" + hashlib.sha256(value).hexdigest()


def head_runs(reader, settings, head):
    return reader.items(f"actions/workflows/{settings['workflow_id']}/runs?event=pull_request_target&head_sha={head}",
                        key="workflow_runs")


def open_config(path, owner_uid):
    """逐層開啟可信目錄 descriptor；僅保護檔案擁有者，無法防止可寫上層目錄或中途符號連結的替換。

Walk trusted directory descriptors; a file's owner alone cannot protect it
    from replacement through a writable parent or an intermediate symlink."""
    need(".." not in path.parts, "CONFIG_PARENT")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            try:
                next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            except OSError:
                raise Denied("CONFIG_PARENT") from None
            os.close(directory)
            directory = next_directory
            info = os.fstat(directory)
            # root 擁有的 sticky 目錄可保護其 root 子目錄。 / Root-owned sticky directories (e.g. /tmp) protect root-owned children.
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            need(info.st_uid in (0, owner_uid) and (not info.st_mode & 0o022 or sticky_root), "CONFIG_PARENT")
        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)


def verify_artifact_attestation(reader, settings, run, raw):
    """以固定驗證器處理密碼學，再把已驗證 SLSA 綁定精確 run attempt；artifact JSON 本身不是來源身分。離線 bundle 避免子程序取得安裝權杖或模型金鑰。

Use a pinned verifier for cryptography, then bind its verified SLSA statement
    to the precise run attempt. Artifact JSON is never itself a source identity.
    Offline bundles avoid giving the subprocess the installation token or model keys.
    """
    from .processes import bounded_output
    binary = Path(settings["attestation_verifier"])
    fd = open_config(binary, 0)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
             and info.st_mode & 0o111 and info.st_size <= 128 * 1024**2, "ATTESTATION_VERIFIER_FILE")
        need(hashlib.file_digest(stream, "sha256").hexdigest() == settings["attestation_verifier_sha256"],
             "ATTESTATION_VERIFIER_DIGEST")
    digest = hashlib.sha256(raw).hexdigest()
    # cursor 分頁的第一頁，GitHub 預設 30 筆；截斷只會少證明，無法多出證明。 / The first cursor page, 30 by GitHub's
    # default; truncation can only drop attestations, never add one.
    response = reader.get(f"attestations/sha256:{digest}")
    attestations = response.get("attestations")
    need(isinstance(attestations, list) and 0 < len(attestations) < 30, "ATTESTATION_MISSING_OR_TRUNCATED")
    bundles = b"\n".join(json.dumps(a["bundle"], separators=(",", ":")).encode() for a in attestations)
    need(len(bundles) <= 2 * 1024**2, "ATTESTATION_LIMIT")
    env = child_environment(os.environ, {"TMPDIR"})
    env.update(GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1")
    with tempfile.TemporaryDirectory(prefix="epsilon-attestation-") as directory:
        env.update(XDG_CACHE_HOME=directory + "/cache", GH_CONFIG_DIR=directory + "/config")
        artifact, bundle = Path(directory) / "evidence.zip", Path(directory) / "bundle.jsonl"
        artifact.write_bytes(raw)
        bundle.write_bytes(bundles)
        command = [str(binary), "attestation", "verify", str(artifact), "--bundle", str(bundle),
                   "--repo", settings["repository"], "--signer-workflow",
                   settings["repository"] + "/" + settings["workflow_path"],
                   "--signer-digest", settings["evaluator_sha"], "--source-ref", "refs/heads/main",
                   "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1",
                   "--format", "json"]
        try:
            verified = strict_json(bounded_output(command, b"", timeout=90, limit=2 * 1024**2, env=env))
        except Exception:
            raise Denied("ATTESTATION_VERIFICATION_FAILED") from None
    need(isinstance(verified, list) and bool(verified), "ATTESTATION_VERIFICATION_FAILED")
    invocation = f"https://github.com/{settings['repository']}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
    for proof in verified:
        statement = proof.get("verificationResult", {}).get("statement", {})
        metadata = statement.get("predicate", {}).get("runDetails", {}).get("metadata", {})
        if (statement.get("predicateType") == "https://slsa.dev/provenance/v1"
                and metadata.get("invocationId") == invocation
                and any(s.get("digest", {}).get("sha256") == digest for s in statement.get("subject", []))):
            return
    raise Denied("ATTESTATION_RUN_MISMATCH")


def collect(client, settings, number, run_id, gate_policy, blob_cache=None):
    repo = settings["repository"]
    reader = GitHubReader(client, repo)
    pr = reader.get(f"pulls/{number}")
    validate_pr(pr, settings)
    head = pr["head"]["sha"]
    run = reader.get(f"actions/runs/{run_id}")
    workflow = reader.get(f"actions/workflows/{settings['workflow_id']}")
    need(workflow["path"] == settings["workflow_path"] and workflow["state"] == "active", "WORKFLOW_IDENTITY")
    runs = head_runs(reader, settings, head)
    need(any(r["id"] == run_id for r in runs), "RUN_NOT_LISTED")
    jobs = reader.items(f"actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs", key="jobs")
    artifacts = reader.items(f"actions/runs/{run_id}/artifacts", key="artifacts")
    name = evidence_artifact(run_id, run['run_attempt'])
    selected = [a for a in artifacts if a["name"] == name and not a["expired"]]
    need(len(selected) == 1 and selected[0]["size_in_bytes"] <= 16 * 1024**2, "ARTIFACT_IDENTITY")
    artifact = selected[0]
    need(artifact["workflow_run"]["id"] == run_id, "ARTIFACT_RUN")
    # zip 會重新導向至儲存體，只能直接經傳輸層下載。 / The zip redirects to blob storage, so only the transport can fetch it.
    raw = client.raw(f"https://api.github.com/repos/{repo}/actions/artifacts/{artifact['id']}/zip", limit=16 * 1024**2)
    advertised_digest = artifact.get("digest")
    need(advertised_digest == "sha256:" + hashlib.sha256(raw).hexdigest(), "ARTIFACT_DIGEST")
    verify_artifact_attestation(reader, settings, run, raw)
    evidence = GitHubTrust(reader).publication_review(number, pr, run, settings["base_branch"])
    subject = remote_subject(reader, head, blob_cache)
    proof = validate_bundle(settings, gate_policy, pr, run, runs, jobs, unpack_evidence(raw), evidence.reviews,
                            evidence.permissions, subject, datetime.now(timezone.utc), evidence.push,
                            evidence.commit_identities)
    proof["excluded_identities"] = sorted(evidence.commit_identities)
    return proof


def discover_run(reader, settings, pr):
    head = pr["head"]["sha"]
    runs = [r for r in head_runs(reader, settings, head)
            if run_scope(r) == head_scope(pr) and r.get("path") == settings["workflow_path"]]
    need(bool(runs), "RUN_MISSING")
    return max(r["id"] for r in runs)


# 只有 GitHub 限流時無法發布而需退避；自身呼叫預算用完是驗證失敗，必須取代舊綠燈。 / Only GitHub throttling
# blocks publishing and needs back-off; exhausting our own call budget is a verification failure that must
# replace an earlier green.
THROTTLED = ("GITHUB_RATE_LIMIT",)


def publish(client, settings, gate_policy, number, run_id=None, state=None):
    """僅在已驗證結果改變時發布 completed 檢查，不發布會造成必要檢查閃動的 in_progress。狀態保存 blob 快取、上次結果與限流退避期限；退避期間無法發布。

Publish one completed check only when the verified outcome changes.

    No in_progress placeholder is posted: re-verification every cycle would make the
    required check flap. state persists the blob cache, the last published outcome
    and a back-off deadline after GitHub throttling (nothing can be posted then).
    """
    state = {} if state is None else state
    prefix = "/repos/" + settings["repository"]
    reader = GitHubReader(client, settings["repository"])
    try:
        pr = reader.get(f"pulls/{number}")
    except Denied as exc:
        if str(exc) in THROTTLED:
            state["backoff_until"] = int(time.time()) + 900
        raise
    need(SHA.fullmatch(pr["head"]["sha"]) and pr["base"]["repo"]["id"] == settings["repository_id"], "CHECK_TARGET")
    head = pr["head"]["sha"]
    try:
        if run_id is None:
            run_id = discover_run(reader, settings, pr)
        proof = collect(client, settings, number, run_id, gate_policy, state.setdefault("blobs", {}))
        need(proof["head_sha"] == head, "HEAD_CHANGED")
        # 發布成功前立即重新查核可變 PR、審查與最新 attempt。 / Recheck mutable PR/reviews/latest attempt immediately before green.
        fresh = reader.get(f"pulls/{number}")
        validate_pr(fresh, settings)
        need(fresh["head"]["sha"] == head, "HEAD_CHANGED")
        run = reader.get(f"actions/runs/{run_id}")
        need(run["run_attempt"] == proof["run_attempt"] and run["status"] == "completed"
             and run["conclusion"] == "success" and run["head_sha"] == head, "RUN_CHANGED")
        trust = GitHubTrust(reader)
        trust.run_base(fresh, settings["base_branch"]).validate(run)
        reject_newer_runs(run, head_runs(reader, settings, head), head)
        need(trust.review_ids(number, fresh, settings["reviewers"], set(proof["excluded_identities"]),
                              settings["base_branch"]) == proof["review_ids"], "REVIEW_CHANGED")
        conclusion, code = "success", "VERIFIED"
    except Denied as exc:
        if str(exc) in THROTTLED:
            state["backoff_until"] = int(time.time()) + 900
            raise
        conclusion, code, proof = "failure", str(exc), None
    except Exception:
        conclusion, code, proof = "failure", "VERIFICATION_ERROR", None
    outcome = {"head_sha": head, "conclusion": conclusion, "code": code,
               "run_id": proof["run_id"] if proof else None, "run_attempt": proof["run_attempt"] if proof else None,
               "review_ids": proof["review_ids"] if proof else None}
    last = state.get("published")
    if isinstance(last, dict) and last.get("check_run_id") and {k: last.get(k) for k in outcome} == outcome:
        check_id = last["check_run_id"]
    else:
        result = client.api(prefix + "/check-runs", "POST", {
            "name": settings["check_name"], "head_sha": head, "status": "completed", "conclusion": conclusion,
            "external_id": f"epsilon:{number}:{outcome['run_id']}",
            "output": {"title": "Trusted verification " + conclusion, "summary": code}})
        need(result["app"]["id"] == settings["app_id"] and result["head_sha"] == head
             and result["conclusion"] == conclusion, "PUBLISH_READBACK")
        check_id = result["id"]
        state["published"] = {**outcome, "check_run_id": check_id}
    return {"decision": "ALLOW" if conclusion == "success" else "BLOCK", "code": code,
            "check_run_id": check_id, "app_id": settings["app_id"], "head_sha": head, "proof": proof}
