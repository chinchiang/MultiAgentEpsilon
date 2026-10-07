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
from .results import decide, seeded_defects, validate_cases, validate_policy

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


def reject_newer_runs(run, newer_runs, head):
    # GitHub omits pull_requests for fork heads, so association cannot be the key:
    # unrelated (e.g. outsider fork) runs must not block, and any newer evaluation of
    # this exact head supersedes the older green result.
    for other in newer_runs:
        need(type(other.get("id")) is int and SHA.fullmatch(other.get("head_sha") or ""), "RUN_LISTING")
        if other["id"] > run["id"] and other["head_sha"] == head:
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


def validate_review(pr, reviews, permissions, settings, excluded):
    """excluded: identities that touched the head (run actors, commit author/committer).
    They are self-asserted or event-scoped, so they may only remove approvals; the
    ruleset's native last-push approval stays authoritative for the actual pusher."""
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
        if (login in settings["reviewers"] and login != pr["user"]["login"] and login not in excluded
                and capable and review["state"] == "APPROVED" and review["commit_id"] == pr["head"]["sha"]):
            allowed.append(review["id"])
    need(bool(allowed), "INDEPENDENT_APPROVAL_MISSING")
    return allowed


REQUIRED_STEPS = ("Record evaluator-owned CI provenance", "Check protected changes and exact-head independent approval",
                  "Evaluator regressions and isolation adversarial checks", "Prove seeded defect still blocks",
                  "Evaluate candidate through external oracle", "Remove evaluator regression database",
                  "Reap cancelled security runs", "Retain evaluator-owned evidence")
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
    """Artifact-only contract, shared by the publisher and the CI self-check.

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
    for suite in suites:
        cases = suite.findall("testcase")
        need(len(cases) == int(suite.get("tests", "0"))
             and all(not any(c.find(tag) is not None for tag in ("failure", "error", "skipped")) for c in cases), "JUNIT_CASES")
    counts = {k: sum(int(s.get(k, "0")) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
    need(counts["tests"] >= settings["minimum_regression_tests"]
         and counts["failures"] == counts["errors"] == counts["skipped"] == 0, "REGRESSION_FAILURE")
    latest = evidence_file(files, "trusted/artifacts/latest.txt").decode().strip()
    need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", latest), "LATEST_POINTER")
    report = strict_json(evidence_file(files, f"trusted/artifacts/{latest}/report.json"))
    need(report.get("schema_version") == 3 and report.get("operation") == "security"
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
    need(negative.get("schema_version") == 3 and negative.get("execution") == "COMPLETED"
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
                    commit_identities=()):
    validate_settings(settings, gate_policy)
    validate_pr(pr, settings)
    need(run["repository"]["id"] == settings["repository_id"]
         and run["repository"]["full_name"] == settings["repository"], "RUN_REPOSITORY")
    # A pull_request_target run executes this path from the PR's *base* branch, and the
    # run does not record which base: workflow_id/path also match a modified copy on
    # another branch. validate_run_base binds the run to this PR before collection.
    need(run["workflow_id"] == settings["workflow_id"] and run["path"] == settings["workflow_path"]
         and run["event"] == "pull_request_target", "RUN_SOURCE")
    need(run["status"] == "completed" and run["conclusion"] == "success", "RUN_NOT_SUCCESS")
    # GitHub reports pull_request_target runs (and their check suites) on the PR head
    # commit; the evaluator commit is bound below via the trusted workflow's provenance.
    need(run["head_sha"] == pr["head"]["sha"], "RUN_SHA")
    need(type(run["run_attempt"]) is int and run["run_attempt"] >= 1, "RUN_ATTEMPT")
    reject_newer_runs(run, newer_runs, pr["head"]["sha"])
    need(len(jobs) == 1 and jobs[0]["name"] == "trusted-security-pilot"
         and jobs[0]["conclusion"] == "success", "JOB_SOURCE")
    steps = {s["name"]: s["conclusion"] for s in jobs[0]["steps"]}
    need(all(steps.get(s) == "success" for s in REQUIRED_STEPS), "REQUIRED_STEP_INCOMPLETE")
    excluded = {person["login"] for person in (run.get("actor"), run.get("triggering_actor"))
                if isinstance(person, dict) and person.get("login")} | set(commit_identities)
    approvals = validate_review(pr, reviews, permissions, settings, excluded)
    guard = strict_json(evidence_file(files, "audit/trusted-guard.json"))
    need(guard.get("schema_version") == 2 and guard.get("decision") == "ALLOW"
         and guard.get("base_sha") == pr["base"]["sha"] and guard.get("candidate_sha") == pr["head"]["sha"]
         and guard.get("approval_error") is None, "TRUSTED_GUARD")
    if guard.get("protected_changes"):
        approval = guard.get("baseline_approval") or {}
        need(approval.get("review_id") in approvals and approval.get("reviewer") in settings["reviewers"]
             and approval.get("commit_id") == pr["head"]["sha"], "BASELINE_APPROVAL")
    provenance = expected_provenance(settings, run["id"], run["run_attempt"], pr["number"],
                                     pr["base"]["sha"], pr["head"]["sha"])
    tests = validate_evidence(settings, gate_policy, files, provenance=provenance,
                              candidate_sha=pr["head"]["sha"], subject=subject, now=now)
    return {"head_sha": pr["head"]["sha"], "base_sha": pr["base"]["sha"], "run_id": run["id"],
            "run_attempt": run["run_attempt"], "subject_digest": subject, "review_ids": approvals, "tests": tests}


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


def remote_subject(client, repo, sha, blob_cache=None):
    """blob_cache maps verified Git blob IDs to SHA-256. Blob IDs are content
    addresses checked below before caching, so a cache hit cannot change a digest."""
    tree = client.api(f"/repos/{repo}/git/trees/{sha}?recursive=1")
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


def head_runs(client, settings, head):
    listing = client.api(f"/repos/{settings['repository']}/actions/workflows/{settings['workflow_id']}"
                         f"/runs?event=pull_request_target&head_sha={head}&per_page=100")
    need(listing["total_count"] == len(listing["workflow_runs"]), "RUNS_TRUNCATED")
    return listing["workflow_runs"]


def identities(*people):
    return {p["login"] for p in people if isinstance(p, dict) and isinstance(p.get("login"), str)}


def validate_run_base(run, pr, pull_requests, base_branch):
    """Bind a pull_request_target run to this PR's base without trusting run evidence.

    The same head can be opened against another branch whose copy of the workflow writes
    its own green evidence. PRs cannot be deleted, so any PR in any state that shares
    the head with another base is visible here; and a twin from a different head branch
    yields a run whose head branch differs from this PR's.
    """
    head = pr["head"]["sha"]
    head_repo = (pr["head"].get("repo") or {}).get("id")
    need(head_repo is not None and run.get("head_branch") == pr["head"].get("ref")
         and (run.get("head_repository") or {}).get("id") == head_repo, "RUN_HEAD_BRANCH")
    need(isinstance(pull_requests, list) and any(p.get("number") == pr["number"] for p in pull_requests),
         "PR_LISTING_INCOMPLETE")
    need(all(p["base"]["ref"] == base_branch and p["base"]["repo"]["id"] == pr["base"]["repo"]["id"]
             for p in pull_requests if p["head"]["sha"] == head), "FOREIGN_BASE_PR")


PR_COMMIT_LIMIT = 250  # GitHub lists at most 250 commits for a pull request.


def pr_commit_identities(commits, head):
    """Accounts GitHub attributes any PR commit to. Self-asserted, so only ever used to
    exclude approvers: a reviewer who pushed earlier commits is not independent."""
    need(isinstance(commits, list) and 0 < len(commits) < PR_COMMIT_LIMIT, "PR_COMMITS_TRUNCATED")
    need(all(isinstance(c, dict) for c in commits) and commits[-1].get("sha") == head, "PR_COMMITS_HEAD")
    return set().union(*(identities(c.get("author"), c.get("committer")) for c in commits))


def collect(client, settings, number, run_id, gate_policy, blob_cache=None):
    repo = settings["repository"]
    prefix = f"/repos/{repo}"
    pr = client.api(f"{prefix}/pulls/{number}")
    validate_pr(pr, settings)
    head = pr["head"]["sha"]
    run = client.api(f"{prefix}/actions/runs/{run_id}")
    workflow = client.api(f"{prefix}/actions/workflows/{settings['workflow_id']}")
    need(workflow["path"] == settings["workflow_path"] and workflow["state"] == "active", "WORKFLOW_IDENTITY")
    runs = head_runs(client, settings, head)
    need(any(r["id"] == run_id for r in runs), "RUN_NOT_LISTED")
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
    twins = client.pages(f"{prefix}/commits/{head}/pulls")
    need([p["number"] for p in twins if p["state"] == "open" and p["head"]["sha"] == head] == [number], "SHARED_PR_HEAD")
    validate_run_base(run, pr, client.pages(f"{prefix}/pulls?state=all"), settings["base_branch"])
    commit = client.api(f"{prefix}/commits/{head}")
    commit_identities = (identities(commit.get("author"), commit.get("committer"))
                         | pr_commit_identities(client.pages(f"{prefix}/pulls/{number}/commits"), head))
    subject = remote_subject(client, repo, head, blob_cache)
    proof = validate_bundle(settings, gate_policy, pr, run, runs, jobs["jobs"], unpack_evidence(raw), reviews,
                            permissions, subject, datetime.now(timezone.utc), commit_identities)
    proof["excluded_identities"] = sorted(commit_identities)
    return proof


def discover_run(client, settings, head):
    runs = [r for r in head_runs(client, settings, head)
            if r.get("head_sha") == head and r.get("path") == settings["workflow_path"]]
    need(bool(runs), "RUN_MISSING")
    return max(r["id"] for r in runs)


THROTTLED = ("GITHUB_HTTP_403", "GITHUB_HTTP_429", "API_BUDGET")


def publish(client, settings, gate_policy, number, run_id=None, state=None):
    """Publish one completed check only when the verified outcome changes.

    No in_progress placeholder is posted: re-verification every cycle would make the
    required check flap. state persists the blob cache, the last published outcome
    and a back-off deadline after GitHub throttling (nothing can be posted then).
    """
    state = {} if state is None else state
    prefix = "/repos/" + settings["repository"]
    pr = client.api(f"{prefix}/pulls/{number}")
    need(SHA.fullmatch(pr["head"]["sha"]) and pr["base"]["repo"]["id"] == settings["repository_id"], "CHECK_TARGET")
    head = pr["head"]["sha"]
    try:
        if run_id is None:
            run_id = discover_run(client, settings, head)
        proof = collect(client, settings, number, run_id, gate_policy, state.setdefault("blobs", {}))
        need(proof["head_sha"] == head, "HEAD_CHANGED")
        # Recheck mutable PR/reviews/latest attempt immediately before green.
        fresh = client.api(f"{prefix}/pulls/{number}")
        validate_pr(fresh, settings)
        need(fresh["head"]["sha"] == head, "HEAD_CHANGED")
        run = client.api(f"{prefix}/actions/runs/{run_id}")
        need(run["run_attempt"] == proof["run_attempt"] and run["status"] == "completed"
             and run["conclusion"] == "success" and run["head_sha"] == head, "RUN_CHANGED")
        validate_run_base(run, fresh, client.pages(f"{prefix}/pulls?state=all"), settings["base_branch"])
        reject_newer_runs(run, head_runs(client, settings, head), head)
        reviews = client.pages(f"{prefix}/pulls/{number}/reviews")
        permissions = {r["user"]["login"]: client.api(f"{prefix}/collaborators/{urllib.parse.quote(r['user']['login'], safe='')}/permission")["role_name"]
                       for r in reviews if r["state"] in ("APPROVED", "DISMISSED", "CHANGES_REQUESTED")}
        excluded = identities(run.get("actor"), run.get("triggering_actor")) | set(proof["excluded_identities"])
        need(validate_review(fresh, reviews, permissions, settings, excluded) == proof["review_ids"], "REVIEW_CHANGED")
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
