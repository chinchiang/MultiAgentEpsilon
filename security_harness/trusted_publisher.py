"""Dedicated-App publisher: validate remote data, never execute candidate contents.

Deploy this code and its policy read-only outside candidate workflows. Native
review/check rules and event delivery remain required; this is not a signing or
hosting service, and success cannot expire automatically in GitHub Checks.
"""
import base64
import copy
import hashlib
import io
import json
import re
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from .inputs import excluded
from .limits import LIMITS
from .results import decide, validate_cases, validate_policy

SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MANIFEST = re.compile(r"worktree-manifest-v1:sha256:[0-9a-f]{64}")


class Denied(ValueError):
    """Only fixed diagnostic codes may leave the publisher."""


def need(condition, code):
    if not condition:
        raise Denied(code)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(_):
        raise Denied("NONFINITE_JSON")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def validate_settings(settings, gate_policy):
    need(type(settings.get("schema_version")) is int and settings["schema_version"] == 1, "SETTINGS_SCHEMA")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", settings.get("repository", "")), "REPOSITORY")
    for key in ("repository_id", "app_id", "installation_id", "workflow_id", "minimum_regression_tests"):
        need(type(settings.get(key)) is int and settings[key] > 0, "SETTINGS_INCOMPLETE")
    need(settings["app_id"] != 15368, "SHARED_ACTIONS_APP")
    need(settings.get("base_branch") == "main" and settings.get("check_name") == "epsilon/trusted-merge", "CHECK_SCOPE")
    need(settings.get("workflow_path") == ".github/workflows/security.yml", "WORKFLOW_PATH")
    need(SHA.fullmatch(settings.get("evaluator_sha") or ""), "UNAPPROVED_EVALUATOR")
    need(MANIFEST.fullmatch(settings.get("evaluator_digest") or ""), "EVALUATOR_DIGEST")
    need(DIGEST.fullmatch(settings.get("policy_digest") or ""), "POLICY_DIGEST")
    reviewers = settings.get("reviewers")
    need(isinstance(reviewers, list) and reviewers and len(set(reviewers)) == len(reviewers)
         and all(isinstance(r, str) and re.fullmatch(r"[A-Za-z0-9-]+", r) for r in reviewers), "REVIEWERS")
    validate_policy(gate_policy)


def reject_newer_runs(run, newer_runs, number):
    for other in newer_runs:
        if other["id"] <= run["id"]:
            continue
        associations = other.get("pull_requests", [])
        # Unknown association cannot authorize reuse of an older green result.
        need(bool(associations), "NEWER_RUN_AMBIGUOUS")
        need(not any(p["number"] == number for p in associations), "NEWER_RUN_EXISTS")


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


def validate_review(pr, reviews, permissions, settings, push_actor):
    latest = {}
    ids = set()
    for review in sorted(reviews, key=lambda r: r["id"]):
        need(type(review["id"]) is int and review["id"] not in ids, "REVIEW_ID")
        ids.add(review["id"])
        if review["state"] in ("APPROVED", "DISMISSED", "CHANGES_REQUESTED"):
            latest[review["user"]["login"]] = review
    allowed = []
    for login, review in latest.items():
        role = permissions.get(login)
        need(role in ("read", "triage", "write", "maintain", "admin"), "REVIEW_PERMISSION_UNKNOWN")
        capable = role in ("write", "maintain", "admin")
        need(not (capable and review["state"] == "CHANGES_REQUESTED"), "CHANGES_REQUESTED")
        if (login in settings["reviewers"] and login not in (pr["user"]["login"], push_actor)
                and capable and review["state"] == "APPROVED" and review["commit_id"] == pr["head"]["sha"]):
            allowed.append(review["id"])
    need(bool(allowed), "INDEPENDENT_APPROVAL_MISSING")
    return allowed


def validate_bundle(settings, gate_policy, pr, run, newer_runs, jobs, files, reviews, permissions, subject, now):
    validate_settings(settings, gate_policy)
    validate_pr(pr, settings)
    need(run["repository"]["id"] == settings["repository_id"]
         and run["repository"]["full_name"] == settings["repository"], "RUN_REPOSITORY")
    need(run["workflow_id"] == settings["workflow_id"] and run["path"] == settings["workflow_path"]
         and run["event"] == "pull_request_target", "RUN_SOURCE")
    need(run["status"] == "completed" and run["conclusion"] == "success", "RUN_NOT_SUCCESS")
    # pull_request_target executes the base commit. Never accept a candidate
    # commit as proof of which evaluator GitHub actually ran.
    need(run["head_sha"] == settings["evaluator_sha"], "RUN_SHA")
    need(type(run["run_attempt"]) is int and run["run_attempt"] >= 1, "RUN_ATTEMPT")
    reject_newer_runs(run, newer_runs, pr["number"])
    need(len(jobs) == 1 and jobs[0]["name"] == "trusted-security-pilot"
         and jobs[0]["conclusion"] == "success", "JOB_SOURCE")
    steps = {s["name"]: s["conclusion"] for s in jobs[0]["steps"]}
    required_steps = ("Record evaluator-owned CI provenance", "Check protected changes and exact-head independent approval",
                      "Evaluator regressions and isolation adversarial checks", "Prove seeded defect still blocks",
                      "Evaluate candidate through external oracle", "Remove evaluator regression database",
                      "Reap cancelled security runs", "Retain evaluator-owned evidence")
    need(all(steps.get(s) == "success" for s in required_steps), "REQUIRED_STEP_INCOMPLETE")
    provenance = strict_json(files["audit/ci-provenance.json"])
    expected = {"schema_version": 1, "repository": settings["repository"], "repository_id": settings["repository_id"],
                "run_id": run["id"], "run_attempt": run["run_attempt"], "event": "pull_request_target",
                "workflow_ref": settings["repository"] + "/" + settings["workflow_path"] + "@refs/heads/main",
                "workflow_sha": settings["evaluator_sha"], "pr_number": pr["number"],
                "base_sha": pr["base"]["sha"], "candidate_sha": pr["head"]["sha"]}
    need(provenance == expected, "PROVENANCE_MISMATCH")
    approvals = validate_review(pr, reviews, permissions, settings, run["actor"]["login"])
    guard = strict_json(files["audit/trusted-guard.json"])
    need(guard.get("schema_version") == 2 and guard.get("decision") == "ALLOW"
         and guard.get("base_sha") == pr["base"]["sha"] and guard.get("candidate_sha") == pr["head"]["sha"]
         and guard.get("approval_error") is None, "TRUSTED_GUARD")
    if guard.get("protected_changes"):
        approval = guard.get("baseline_approval") or {}
        need(approval.get("review_id") in approvals and approval.get("reviewer") in settings["reviewers"]
             and approval.get("commit_id") == pr["head"]["sha"], "BASELINE_APPROVAL")
    xml = files["trusted/artifacts/pytest.xml"]
    need(len(xml) <= 2 * 1024**2 and b"<!DOCTYPE" not in xml.upper() and b"<!ENTITY" not in xml.upper(), "JUNIT_LIMIT")
    tree = ElementTree.fromstring(xml)
    need(tree.tag in ("testsuite", "testsuites"), "JUNIT_ROOT")
    suites = [tree] if tree.tag == "testsuite" else tree.findall("testsuite")
    need(bool(suites), "NO_REGRESSIONS")
    for suite in suites:
        cases = suite.findall("testcase")
        need(len(cases) == int(suite.get("tests", "0"))
             and all(not any(c.find(tag) is not None for tag in ("failure", "error", "skipped")) for c in cases), "JUNIT_CASES")
    counts = {k: sum(int(s.get(k, "0")) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
    need(counts["tests"] >= settings["minimum_regression_tests"]
         and counts["failures"] == counts["errors"] == counts["skipped"] == 0, "REGRESSION_FAILURE")
    latest = files["trusted/artifacts/latest.txt"].decode().strip()
    need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", latest), "LATEST_POINTER")
    report = strict_json(files[f"trusted/artifacts/{latest}/report.json"])
    need(report.get("schema_version") == 3 and report.get("operation") == "security"
         and report.get("variant") == "fixed" and report.get("run_id") == latest
         and report.get("execution") == "COMPLETED" and report.get("decision") == "ALLOW"
         and not report.get("errors"), "REPORT_NOT_ALLOW")
    need(report.get("subject_digest") == subject and report.get("evaluator_digest") == settings["evaluator_digest"]
         and report.get("policy_digest") == settings["policy_digest"], "REPORT_DIGEST")
    cleanup = report.get("cleanup", {})
    need(all(cleanup.get(k) is True for k in ("completed", "temporary_directory_removed", "run_directory_removed", "process_group_terminated"))
         and cleanup.get("error_type") is None, "CLEANUP_INCOMPLETE")
    need(decide(report["records"], gate_policy, subject, settings["policy_digest"], now, run_id=latest)["decision"] == "ALLOW", "GATE_REJECTED")
    scan = next(r for r in report["records"] if r["gate"] == "G2")
    need(scan["evidence"]["coverage"].get("history_head") == pr["head"]["sha"], "HISTORY_SHA")
    reports = [strict_json(data) for path, data in files.items()
               if path.startswith("trusted/artifacts/") and path.endswith("/report.json")]
    negative = [r for r in reports if r.get("operation") == "security" and r.get("variant") == "vulnerable"]
    need(len(negative) == 1, "NEGATIVE_EVIDENCE_MISSING")
    negative = negative[0]
    need(negative.get("schema_version") == 3 and negative.get("execution") == "COMPLETED"
         and negative.get("decision") == "BLOCK" and not negative.get("errors")
         and negative.get("subject_digest") == subject
         and negative.get("evaluator_digest") == settings["evaluator_digest"]
         and negative.get("policy_digest") == settings["policy_digest"], "NEGATIVE_BINDING")
    negative_cleanup = negative.get("cleanup", {})
    need(all(negative_cleanup.get(k) is True for k in ("completed", "temporary_directory_removed", "run_directory_removed", "process_group_terminated"))
         and negative_cleanup.get("error_type") is None, "NEGATIVE_CLEANUP")
    normalized = copy.deepcopy(negative["records"])
    auth = [r for r in normalized if r.get("gate") == "AUTH"]
    need(len(auth) == 1 and auth[0].get("findings") == 5
         and sum(c.get("passed") is False for c in auth[0].get("cases", [])) == 5, "NEGATIVE_FINDINGS")
    validate_cases(auth[0]["cases"], gate_policy["gate_contracts"]["AUTH"])
    auth[0]["findings"] = 0
    for case in auth[0]["cases"]:
        case["passed"] = True
    need(decide(normalized, gate_policy, subject, settings["policy_digest"], now, run_id=negative["run_id"])["decision"] == "ALLOW", "NEGATIVE_GATES")
    negative_scan = next(r for r in normalized if r["gate"] == "G2")
    need(negative_scan["evidence"]["coverage"].get("history_head") == pr["head"]["sha"], "NEGATIVE_HISTORY")
    return {"head_sha": pr["head"]["sha"], "base_sha": pr["base"]["sha"], "run_id": run["id"],
            "run_attempt": run["run_attempt"], "subject_digest": subject, "review_ids": approvals, "tests": counts["tests"]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, token):
        self.token = token
        self.calls = 0
        self.deadline = time.monotonic() + 240
        self.opener = urllib.request.build_opener(NoRedirect())

    def raw(self, url, method="GET", payload=None, authenticated=True, limit=2 * 1024**2):
        parsed = urllib.parse.urlsplit(url)
        need(parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port in (None, 443), "API_URL")
        need(not authenticated or parsed.netloc == "api.github.com", "AUTH_DESTINATION")
        self.calls += 1
        need(self.calls <= 300 and time.monotonic() < self.deadline, "API_BUDGET")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if payload is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, headers=headers, method=method,
                                     data=None if payload is None else json.dumps(payload).encode())
        try:
            with self.opener.open(req, timeout=min(20, max(1, self.deadline-time.monotonic()))) as response:
                data = response.read(limit + 1)
                need(len(data) <= limit, "API_RESPONSE_LIMIT")
                return data
        except urllib.error.HTTPError as exc:
            if exc.code == 302 and authenticated and method == "GET" and re.fullmatch(
                    r"https://api.github.com/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/artifacts/[0-9]+/zip", url):
                location = exc.headers.get("Location", "")
                host = urllib.parse.urlsplit(location).hostname or ""
                need(host.endswith(".blob.core.windows.net"), "ARTIFACT_REDIRECT_HOST")
                # Installation/JWT credentials must never follow storage redirects.
                return self.raw(location, authenticated=False, limit=limit)
            raise Denied("GITHUB_HTTP_" + str(exc.code)) from None

    def api(self, path, method="GET", payload=None):
        need(path.startswith("/") and not path.startswith("//"), "API_PATH")
        return strict_json(self.raw("https://api.github.com" + path, method, payload))

    def pages(self, path):
        result = []
        for page in range(1, 11):
            separator = "&" if "?" in path else "?"
            items = self.api(path + separator + f"per_page=100&page={page}")
            need(isinstance(items, list), "PAGINATION_TYPE")
            result.extend(items)
            if len(items) < 100:
                return result
        raise Denied("PAGINATION_LIMIT")


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
    permissions = {"actions": "read", "contents": "read", "pull_requests": "read", "checks": "write"}
    response = client.api(f"/app/installations/{settings['installation_id']}/access_tokens", "POST",
                          {"repository_ids": [settings["repository_id"]], "permissions": permissions})
    granted = response.get("permissions", {})
    need(all(granted.get(k) == v for k, v in permissions.items())
         and all(v != "write" or k == "checks" for k, v in granted.items()), "TOKEN_PERMISSIONS")
    return GitHub(response["token"])


def remote_subject(client, repo, sha):
    tree = client.api(f"/repos/{repo}/git/trees/{sha}?recursive=1")
    need(tree.get("truncated") is False, "SOURCE_TREE_TRUNCATED")
    files, contents, total = [], {}, 0
    for entry in sorted(tree["tree"], key=lambda e: e["path"]):
        if entry["type"] == "tree":
            continue
        path = PurePosixPath(entry["path"])
        need(not any(f["path"] == entry["path"] for f in files), "DUPLICATE_SOURCE_PATH")
        need(entry["type"] == "blob" and entry["mode"] in ("100644", "100755")
             and not path.is_absolute() and ".." not in path.parts and not excluded(Path(entry["path"])), "SOURCE_INPUT")
        size = entry["size"]
        total += size
        # GitHub's JSON/base64 response has a separate, deliberately lower
        # ceiling than the scanner's streaming file allowance.
        need(type(size) is int and 0 <= size <= min(LIMITS.max_file_bytes, 1024**2)
             and total <= min(LIMITS.max_input_bytes, 20 * 1024**2)
             and len(files) < min(LIMITS.max_files, 200), "SOURCE_LIMIT")
        blob_sha = entry["sha"]
        need(SHA.fullmatch(blob_sha), "BLOB_SHA")
        if blob_sha not in contents:
            blob = client.api(f"/repos/{repo}/git/blobs/{blob_sha}")
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


def collect(client, settings, number, run_id, gate_policy):
    repo = settings["repository"]
    prefix = f"/repos/{repo}"
    pr = client.api(f"{prefix}/pulls/{number}")
    validate_pr(pr, settings)
    run = client.api(f"{prefix}/actions/runs/{run_id}")
    workflow = client.api(f"{prefix}/actions/workflows/{settings['workflow_id']}")
    need(workflow["path"] == settings["workflow_path"] and workflow["state"] == "active", "WORKFLOW_IDENTITY")
    runs = client.api(f"{prefix}/actions/workflows/{settings['workflow_id']}/runs?event=pull_request_target&per_page=100")
    need(runs["workflow_runs"] and any(r["id"] == run_id for r in runs["workflow_runs"]), "RUN_NOT_RECENT")
    jobs = client.api(f"{prefix}/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs?per_page=100")
    need(jobs["total_count"] == len(jobs["jobs"]), "JOBS_TRUNCATED")
    artifacts = client.api(f"{prefix}/actions/runs/{run_id}/artifacts?per_page=100")
    need(artifacts["total_count"] == len(artifacts["artifacts"]), "ARTIFACTS_TRUNCATED")
    name = f"trusted-security-{run_id}-{run['run_attempt']}"
    selected = [a for a in artifacts["artifacts"] if a["name"] == name and not a["expired"]]
    need(len(selected) == 1 and selected[0]["size_in_bytes"] <= 16 * 1024**2, "ARTIFACT_IDENTITY")
    artifact = selected[0]
    need(artifact["workflow_run"]["id"] == run_id, "ARTIFACT_RUN")
    raw = client.raw("https://api.github.com" + prefix + f"/actions/artifacts/{artifact['id']}/zip", limit=16 * 1024**2)
    advertised_digest = artifact.get("digest")
    need(advertised_digest == "sha256:" + hashlib.sha256(raw).hexdigest(), "ARTIFACT_DIGEST")
    reviews = client.pages(f"{prefix}/pulls/{number}/reviews")
    logins = {r["user"]["login"] for r in reviews if r["state"] in ("APPROVED", "DISMISSED", "CHANGES_REQUESTED")}
    permissions = {login: client.api(f"{prefix}/collaborators/{urllib.parse.quote(login, safe='')}/permission")["role_name"] for login in logins}
    twins = client.pages(f"{prefix}/commits/{pr['head']['sha']}/pulls")
    need([p["number"] for p in twins if p["state"] == "open" and p["head"]["sha"] == pr["head"]["sha"]] == [number], "SHARED_PR_HEAD")
    subject = remote_subject(client, repo, pr["head"]["sha"])
    proof = validate_bundle(settings, gate_policy, pr, run, runs["workflow_runs"], jobs["jobs"],
                            unpack_evidence(raw), reviews, permissions, subject, datetime.now(timezone.utc))
    return proof


def discover_run(client, settings, number):
    runs = client.api(f"/repos/{settings['repository']}/actions/workflows/{settings['workflow_id']}/runs?event=pull_request_target&per_page=100")
    associated = [r for r in runs["workflow_runs"] if any(p["number"] == number for p in r.get("pull_requests", []))]
    need(bool(associated), "RUN_ASSOCIATION_MISSING")
    return max(r["id"] for r in associated)


def publish(client, settings, gate_policy, number, run_id=None):
    prefix = "/repos/" + settings["repository"]
    pr = client.api(f"{prefix}/pulls/{number}")
    need(SHA.fullmatch(pr["head"]["sha"]) and pr["base"]["repo"]["id"] == settings["repository_id"], "CHECK_TARGET")
    head = pr["head"]["sha"]
    check = client.api(prefix + "/check-runs", "POST", {"name": settings["check_name"], "head_sha": head,
        "status": "in_progress", "external_id": f"epsilon:{number}:{run_id}",
        "output": {"title": "Validating trusted source", "summary": "Verification is incomplete; do not merge."}})
    need(check["app"]["id"] == settings["app_id"] and check["head_sha"] == head, "CHECK_APP_IDENTITY")
    try:
        if run_id is None:
            run_id = discover_run(client, settings, number)
        proof = collect(client, settings, number, run_id, gate_policy)
        need(proof["head_sha"] == head, "HEAD_CHANGED")
        # Recheck mutable PR/reviews/latest attempt immediately before green.
        fresh = client.api(f"{prefix}/pulls/{number}")
        validate_pr(fresh, settings)
        need(fresh["head"]["sha"] == head, "HEAD_CHANGED")
        run = client.api(f"{prefix}/actions/runs/{run_id}")
        need(run["run_attempt"] == proof["run_attempt"] and run["status"] == "completed"
             and run["conclusion"] == "success", "RUN_CHANGED")
        newest = client.api(f"{prefix}/actions/workflows/{settings['workflow_id']}/runs?event=pull_request_target&per_page=100")
        reject_newer_runs(run, newest["workflow_runs"], number)
        reviews = client.pages(f"{prefix}/pulls/{number}/reviews")
        permissions = {r["user"]["login"]: client.api(f"{prefix}/collaborators/{urllib.parse.quote(r['user']['login'], safe='')}/permission")["role_name"]
                       for r in reviews if r["state"] in ("APPROVED", "DISMISSED", "CHANGES_REQUESTED")}
        need(validate_review(fresh, reviews, permissions, settings, run["actor"]["login"]) == proof["review_ids"], "REVIEW_CHANGED")
        conclusion, code = "success", "VERIFIED"
    except Exception as exc:
        conclusion = "failure"
        code = str(exc) if isinstance(exc, Denied) else "VERIFICATION_ERROR"
        proof = None
    result = client.api(f"{prefix}/check-runs/{check['id']}", "PATCH", {
        "status": "completed", "conclusion": conclusion,
        "output": {"title": "Trusted verification " + conclusion, "summary": code}})
    need(result["app"]["id"] == settings["app_id"] and result["head_sha"] == head
         and result["conclusion"] == conclusion, "PUBLISH_READBACK")
    return {"decision": "ALLOW" if conclusion == "success" else "BLOCK", "code": code,
            "check_run_id": check["id"], "app_id": settings["app_id"], "head_sha": head, "proof": proof}
