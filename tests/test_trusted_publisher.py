import base64
import copy
import hashlib
import io
import json
import stat
import urllib.error
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from security_harness import trusted_publisher as publisher
from security_harness.results import result, subject_digest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def bundle():
    now = datetime.now(timezone.utc)
    policy = json.loads((ROOT / "security/policy.json").read_text())
    settings = {"schema_version": 1, "repository": "owner/repo", "repository_id": 10,
                "app_id": 42, "installation_id": 12, "base_branch": "main", "workflow_id": 99,
                "workflow_path": ".github/workflows/security.yml", "evaluator_sha": "a"*40,
                "evaluator_digest": "worktree-manifest-v1:sha256:" + "e"*64,
                "policy_digest": "f"*64, "minimum_regression_tests": 360,
                "reviewers": ["reviewer"], "check_name": "epsilon/trusted-merge"}
    pr = {"number": 5, "state": "open", "draft": False, "user": {"login": "author"},
          "base": {"ref": "main", "sha": "a"*40, "repo": {"id": 10, "full_name": "owner/repo"}},
          "head": {"sha": "b"*40}}
    # Observed on GitHub: a pull_request_target run (and its check suite) carries the
    # PR head SHA; the workflow file and evaluator come from the default branch.
    run = {"id": 100, "run_attempt": 1, "repository": {"id": 10, "full_name": "owner/repo"},
           "workflow_id": 99, "path": settings["workflow_path"], "event": "pull_request_target",
           "head_sha": "b"*40, "status": "completed", "conclusion": "success",
           "actor": {"login": "author"}, "triggering_actor": {"login": "author"}, "pull_requests": [{"number": 5}]}
    steps = ["Record evaluator-owned CI provenance", "Check protected changes and exact-head independent approval",
             "Evaluator regressions and isolation adversarial checks", "Prove seeded defect still blocks",
             "Evaluate candidate through external oracle", "Remove evaluator regression database",
             "Reap cancelled security runs", "Retain evaluator-owned evidence"]
    jobs = [{"name": "trusted-security-pilot", "conclusion": "success",
             "steps": [{"name": n, "conclusion": "success"} for n in steps]}]
    review = {"id": 11, "state": "APPROVED", "commit_id": "b"*40, "user": {"login": "reviewer"}}
    subject = "worktree-manifest-v1:sha256:" + "c"*64
    run_id = "11111111-1111-4111-8111-111111111111"
    records = [result("G1", "COMPLETED", "scan", 23, 0, subject, "f"*64, "synthetic", run_id=run_id),
               result("G2", "COMPLETED", "scan", 1, 0, subject, "f"*64, "synthetic", run_id=run_id,
                      evidence={"coverage": {"status": "COMPLETE", "selected_files": 1, "selected_bytes": 1,
                      "scanned_leaves": 1, "scanned_bytes": 1, "expanded_bytes": 0, "archives": 0,
                      "history_blobs": 1, "unsupported_files": 0, "history_head": "b"*40}}),
               result("AUTH", "COMPLETED", "test", len(policy["gate_contracts"]["AUTH"]["case_ids"]), 0, subject, "f"*64, "synthetic", run_id=run_id,
                      cases=[{"case": n, "passed": True} for n in policy["gate_contracts"]["AUTH"]["case_ids"]])]
    for record in records:
        record["created_at"] = now.isoformat()
    report = {"schema_version": 3, "operation": "security", "variant": "fixed", "run_id": run_id,
              "execution": "COMPLETED", "decision": "ALLOW", "errors": [], "subject_digest": subject,
              "evaluator_digest": settings["evaluator_digest"], "policy_digest": "f"*64, "records": records,
              "cleanup": {"completed": True, "temporary_directory_removed": True,
                          "run_directory_removed": True, "process_group_terminated": True, "error_type": None}}
    provenance = {"schema_version": 1, "repository": "owner/repo", "repository_id": 10, "run_id": 100,
                  "run_attempt": 1, "event": "pull_request_target", "workflow_sha": "a"*40,
                  "workflow_ref": "owner/repo/.github/workflows/security.yml@refs/heads/main",
                  "pr_number": 5, "base_sha": "a"*40, "candidate_sha": "b"*40}
    guard = {"schema_version": 2, "decision": "ALLOW", "base_sha": "a"*40, "candidate_sha": "b"*40,
             "protected_changes": ["security/policy.json"], "approval_error": None,
             "baseline_approval": {"review_id": 11, "reviewer": "reviewer", "commit_id": "b"*40}}
    files = {"audit/ci-provenance.json": json.dumps(provenance).encode(),
             "audit/trusted-guard.json": json.dumps(guard).encode(),
             "trusted/artifacts/latest.txt": run_id.encode(),
             "trusted/artifacts/pytest.xml": b'<testsuites><testsuite tests="360" failures="0" errors="0" skipped="0">' +
                 b'<testcase name="synthetic"/>'*360 + b'</testsuite></testsuites>',
             f"trusted/artifacts/{run_id}/report.json": json.dumps(report).encode()}
    # expect_block runs the evaluator's own vulnerable variant: its subject and history
    # are the evaluator's (digest e…, base a…), never the candidate's (c…, b…).
    negative = copy.deepcopy(report)
    negative_id = "22222222-2222-4222-8222-222222222222"
    negative.update(variant="vulnerable", decision="BLOCK", run_id=negative_id,
                    subject_digest=settings["evaluator_digest"])
    for record in negative["records"]:
        record["run_id"] = negative_id
        record["subject_digest"] = settings["evaluator_digest"]
    negative["records"][1]["evidence"]["coverage"]["history_head"] = "a"*40
    seeded = set(policy["gate_contracts"]["AUTH"]["seeded_defect_case_ids"])
    negative["records"][2]["findings"] = len(seeded)
    for case in negative["records"][2]["cases"]:
        case["passed"] = case["case"] not in seeded
    files[f"trusted/artifacts/{negative_id}/report.json"] = json.dumps(negative).encode()
    return {"settings": settings, "gate_policy": policy, "pr": pr, "run": run, "newer_runs": [run],
            "jobs": jobs, "files": files, "reviews": [review], "permissions": {"reviewer": "write"},
            "subject": subject, "now": now}


def mutate_json(bundle, filename, change):
    value = publisher.strict_json(bundle["files"][filename])
    change(value)
    bundle["files"][filename] = json.dumps(value).encode()


def test_verified_bundle_requires_remote_source_current_review_and_complete_evidence(bundle):
    proof = publisher.validate_bundle(**bundle)
    assert proof["head_sha"] == "b"*40 and proof["review_ids"] == [11] and proof["tests"] == 360


@pytest.mark.parametrize("attack", ["app", "repo", "workflow", "event", "failed_run", "draft", "base",
                                    "head", "evaluator_run_source", "attempt", "new_run", "step_skipped", "foreign_job",
                                    "author", "push_actor", "triggering_actor", "commit_author",
                                    "read_role", "triage_role", "unknown_role", "stale_review",
                                    "dismissed", "changes_requested", "guard", "guard_review", "policy", "subject",
                                    "evaluator", "history", "missing_case", "duplicate_case", "gate_error", "stale_gate",
                                    "future_gate", "cleanup", "failed_tests", "zero_tests", "skipped_tests", "junit_entity"])
def test_spoofed_or_stale_evidence_never_passes(bundle, attack):
    report_path = next(p for p in bundle["files"] if "11111111" in p)
    if attack == "app": bundle["settings"]["app_id"] = 15368
    elif attack == "repo": bundle["run"]["repository"]["id"] = 20
    elif attack == "workflow": bundle["run"]["workflow_id"] = 1000
    elif attack == "event": bundle["run"]["event"] = "workflow_dispatch"
    elif attack == "failed_run": bundle["run"]["conclusion"] = "failure"
    elif attack == "draft": bundle["pr"]["draft"] = True
    elif attack == "base": bundle["pr"]["base"]["sha"] = "d"*40
    elif attack == "head": bundle["pr"]["head"]["sha"] = "d"*40
    elif attack == "evaluator_run_source": bundle["run"]["head_sha"] = "a"*40
    elif attack == "attempt": bundle["run"]["run_attempt"] = 2
    elif attack == "new_run": bundle["newer_runs"] = [bundle["run"], {"id": 101, "head_sha": "b"*40, "pull_requests": []}]
    elif attack == "step_skipped": bundle["jobs"][0]["steps"][1]["conclusion"] = "skipped"
    elif attack == "foreign_job": bundle["jobs"][0]["name"] = "fake"
    elif attack == "author": bundle["pr"]["user"]["login"] = "reviewer"
    elif attack == "push_actor": bundle["run"]["actor"]["login"] = "reviewer"
    elif attack == "triggering_actor": bundle["run"]["triggering_actor"]["login"] = "reviewer"
    elif attack == "commit_author": bundle["commit_identities"] = {"reviewer"}
    elif attack in ("read_role", "triage_role", "unknown_role"):
        bundle["permissions"]["reviewer"] = {"read_role": "read", "triage_role": "triage", "unknown_role": "custom"}[attack]
    elif attack == "stale_review": bundle["reviews"][0]["commit_id"] = "d"*40
    elif attack in ("dismissed", "changes_requested"):
        bundle["reviews"].append({**bundle["reviews"][0], "id": 12,
                                  "state": "DISMISSED" if attack == "dismissed" else "CHANGES_REQUESTED"})
    elif attack == "guard": mutate_json(bundle, "audit/trusted-guard.json", lambda d: d.update(decision="BLOCK"))
    elif attack == "guard_review": mutate_json(bundle, "audit/trusted-guard.json", lambda d: d["baseline_approval"].update(review_id=999))
    elif attack in ("policy", "subject", "evaluator"):
        field = {"policy": "policy_digest", "subject": "subject_digest", "evaluator": "evaluator_digest"}[attack]
        mutate_json(bundle, report_path, lambda d: d.update({field: "wrong"}))
    elif attack == "history": mutate_json(bundle, report_path, lambda d: d["records"][1]["evidence"]["coverage"].update(history_head="d"*40))
    elif attack == "missing_case": mutate_json(bundle, report_path, lambda d: d["records"][2]["cases"].pop())
    elif attack == "duplicate_case": mutate_json(bundle, report_path, lambda d: d["records"][2]["cases"].__setitem__(1, d["records"][2]["cases"][0]))
    elif attack == "gate_error": mutate_json(bundle, report_path, lambda d: d["records"][0].update(execution="ERROR"))
    elif attack in ("stale_gate", "future_gate"):
        date = bundle["now"] + timedelta(seconds=-4000 if attack == "stale_gate" else 100)
        mutate_json(bundle, report_path, lambda d: d["records"][0].update(created_at=date.isoformat()))
    elif attack == "cleanup": mutate_json(bundle, report_path, lambda d: d["cleanup"].update(process_group_terminated=False))
    elif attack in ("failed_tests", "zero_tests", "skipped_tests"):
        bundle["files"]["trusted/artifacts/pytest.xml"] = {
            "failed_tests": b'<testsuite tests="360" failures="1"/>', "zero_tests": b'<testsuite tests="0"/>',
            "skipped_tests": b'<testsuite tests="360" skipped="1"/>'}[attack]
    elif attack == "junit_entity": bundle["files"]["trusted/artifacts/pytest.xml"] = b'<!DOCTYPE x [<!ENTITY x "x">]><testsuite tests="360"/>'
    with pytest.raises(publisher.Denied):
        publisher.validate_bundle(**bundle)


@pytest.mark.parametrize("field", ["candidate_sha", "base_sha", "workflow_sha", "workflow_ref", "pr_number", "run_id", "run_attempt"])
def test_provenance_cannot_bind_another_pr_or_evaluator(bundle, field):
    mutate_json(bundle, "audit/ci-provenance.json", lambda d: d.update({field: "wrong"}))
    with pytest.raises(publisher.Denied, match="PROVENANCE_MISMATCH"):
        publisher.validate_bundle(**bundle)


@pytest.mark.parametrize("name", ["../report.json", "/report.json", "trusted\\report.json"])
def test_artifact_traversal_is_rejected_without_extracting(name):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive: archive.writestr(name, "{}")
    with pytest.raises(publisher.Denied, match="ARTIFACT_ENTRY"):
        publisher.unpack_evidence(data.getvalue())


def test_artifact_symlink_and_duplicate_names_are_rejected():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        entry = zipfile.ZipInfo("report.json")
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, "/etc/passwd")
    with pytest.raises(publisher.Denied): publisher.unpack_evidence(data.getvalue())
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("report.json", "{}")
        with pytest.warns(UserWarning): archive.writestr("report.json", "{}")
    with pytest.raises(publisher.Denied): publisher.unpack_evidence(data.getvalue())


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}'])
def test_ambiguous_json_rejected(text):
    with pytest.raises(publisher.Denied): publisher.strict_json(text)


def test_remote_manifest_matches_local_without_executing_source(tmp_path):
    (tmp_path / "README.md").write_text("synthetic\n")
    (tmp_path / "run.sh").write_text("do not execute\n")
    (tmp_path / "run.sh").chmod(0o755)
    entries, blobs = [], {}
    for path in sorted(tmp_path.iterdir()):
        data = path.read_bytes()
        sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        entries.append({"path": path.name, "type": "blob", "mode": "100755" if path.name == "run.sh" else "100644",
                        "size": len(data), "sha": sha})
        blobs[sha] = {"encoding": "base64", "size": len(data), "content": base64.b64encode(data).decode()}
    class Client:
        def api(self, path):
            return {"tree": entries, "truncated": False} if "/trees/" in path else blobs[path.split("/")[-1]]
    assert publisher.remote_subject(Client(), "owner/repo", "a"*40) == subject_digest(tmp_path)
    entries[0]["mode"] = "120000"
    with pytest.raises(publisher.Denied, match="SOURCE_INPUT"):
        publisher.remote_subject(Client(), "owner/repo", "a"*40)


def test_storage_redirect_never_receives_app_token():
    requests = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return b"archive"
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            if len(requests) == 1:
                raise urllib.error.HTTPError(request.full_url, 302, "redirect",
                    {"Location": "https://fixture.blob.core.windows.net/evidence?signed=synthetic"}, None)
            return Response()
    client = publisher.GitHub("synthetic-app-token")
    client.opener = Opener()
    assert client.raw("https://api.github.com/repos/owner/repo/actions/artifacts/1/zip") == b"archive"
    assert requests[0].get_header("Authorization") == "Bearer synthetic-app-token"
    assert requests[1].get_header("Authorization") is None


def test_arbitrary_redirect_and_authenticated_non_github_destinations_denied():
    client = publisher.GitHub("synthetic")
    with pytest.raises(publisher.Denied, match="AUTH_DESTINATION"):
        client.raw("https://example.invalid/evidence")
    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "https://example.invalid/"}, None)
    client.opener = Opener()
    with pytest.raises(publisher.Denied, match="ARTIFACT_REDIRECT_HOST"):
        client.raw("https://api.github.com/repos/owner/repo/actions/artifacts/1/zip")


def test_verification_error_publishes_failure_and_hides_exception_text(bundle, monkeypatch):
    writes = []
    class Client:
        def api(self, path, method="GET", payload=None):
            if method == "GET": return bundle["pr"]
            writes.append(copy.deepcopy(payload))
            return {"id": 30, "app": {"id": 42}, "head_sha": "b"*40, "conclusion": payload.get("conclusion")}
    def fail(*args): raise RuntimeError("credential-like-sensitive-diagnostic")
    monkeypatch.setattr(publisher, "collect", fail)
    report = publisher.publish(Client(), bundle["settings"], bundle["gate_policy"], 5, 100)
    # One completed check per outcome: no in_progress placeholder that makes the required check flap.
    assert len(writes) == 1 and writes[0]["status"] == "completed" and writes[0]["conclusion"] == "failure"
    assert report["decision"] == "BLOCK" and report["code"] == "VERIFICATION_ERROR"
    assert "sensitive" not in json.dumps(writes) + json.dumps(report)


def test_unchanged_outcome_is_not_reposted_but_a_change_is(bundle, monkeypatch):
    writes = []
    class Client:
        def api(self, path, method="GET", payload=None):
            if method == "GET": return bundle["pr"]
            writes.append(payload)
            return {"id": 30 + len(writes), "app": {"id": 42}, "head_sha": "b"*40, "conclusion": payload["conclusion"]}
    code = {"value": "RUN_MISSING"}
    def deny(*args): raise publisher.Denied(code["value"])
    monkeypatch.setattr(publisher, "collect", deny)
    state = {}
    first = publisher.publish(Client(), bundle["settings"], bundle["gate_policy"], 5, 100, state)
    again = publisher.publish(Client(), bundle["settings"], bundle["gate_policy"], 5, 100, state)
    assert len(writes) == 1 and first["check_run_id"] == again["check_run_id"] == 31
    code["value"] = "GATE_REJECTED"
    publisher.publish(Client(), bundle["settings"], bundle["gate_policy"], 5, 100, state)
    assert len(writes) == 2 and state["published"]["code"] == "GATE_REJECTED"


@pytest.mark.parametrize("code", ["GITHUB_HTTP_403", "GITHUB_HTTP_429", "API_BUDGET"])
def test_throttling_backs_off_without_posting(bundle, monkeypatch, code):
    writes = []
    class Client:
        def api(self, path, method="GET", payload=None):
            if method == "GET": return bundle["pr"]
            writes.append(payload)
    def throttled(*args): raise publisher.Denied(code)
    monkeypatch.setattr(publisher, "collect", throttled)
    state = {}
    with pytest.raises(publisher.Denied, match=code):
        publisher.publish(Client(), bundle["settings"], bundle["gate_policy"], 5, 100, state)
    assert writes == [] and state["backoff_until"] > datetime.now(timezone.utc).timestamp()


def test_unrelated_fork_runs_do_not_block_but_a_newer_same_head_run_does(bundle):
    # GitHub leaves pull_requests empty for fork heads; that must not be a denial lever.
    bundle["newer_runs"] = [bundle["run"], {"id": 500, "head_sha": "d"*40, "pull_requests": []}]
    assert publisher.validate_bundle(**bundle)["run_id"] == 100
    bundle["newer_runs"].append({"id": 501, "head_sha": "b"*40, "pull_requests": []})
    with pytest.raises(publisher.Denied, match="NEWER_RUN_EXISTS"):
        publisher.validate_bundle(**bundle)


def test_blob_cache_skips_refetch_without_changing_the_manifest(tmp_path):
    (tmp_path / "README.md").write_text("synthetic\n")
    data = (tmp_path / "README.md").read_bytes()
    sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    fetched = []
    class Client:
        def api(self, path):
            if "/trees/" in path:
                return {"tree": [{"path": "README.md", "type": "blob", "mode": "100644", "size": len(data), "sha": sha}],
                        "truncated": False}
            fetched.append(path)
            return {"encoding": "base64", "size": len(data), "content": base64.b64encode(data).decode()}
    cache = {}
    first = publisher.remote_subject(Client(), "owner/repo", "a"*40, cache)
    second = publisher.remote_subject(Client(), "owner/repo", "a"*40, cache)
    assert first == second == subject_digest(tmp_path) and len(fetched) == 1
    assert cache == {sha: hashlib.sha256(data).hexdigest()}


def test_example_reviewers_match_the_ci_guard_policy():
    example = json.loads((ROOT / "security/trusted-publisher.example.json").read_text())
    trust = json.loads((ROOT / "security/trust-policy.json").read_text())
    assert example["reviewers"] == trust["baseline_reviewers"]


def test_publisher_state_file_rejects_tampered_cache(tmp_path):
    from scripts.publish_trusted_check import load_state
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"blobs": {"a"*40: "not-a-digest"}, "backoff_until": "soon",
                                 "published": {"check_run_id": 1}}))
    loaded = load_state(state)
    assert loaded["blobs"] == {} and "backoff_until" not in loaded and loaded["published"] == {"check_run_id": 1}
    state.write_text("{")
    assert load_state(state) == {}
    assert load_state(tmp_path / "absent.json") == {}


def test_unconfigured_example_cannot_issue_live_token(bundle):
    settings = json.loads((ROOT / "security/trusted-publisher.example.json").read_text())
    with pytest.raises(publisher.Denied, match="SETTINGS_INCOMPLETE"):
        publisher.validate_settings(settings, bundle["gate_policy"])


@pytest.mark.parametrize("attack", ["missing", "error", "findings", "swapped_failure", "history", "candidate_history", "candidate_subject",
                                    "cleanup", "missing_case", "invalid_case_type", "fake_junit_count"])
def test_seeded_defect_must_have_real_complete_negative_evidence(bundle, attack):
    path = next(p for p in bundle["files"] if "22222222" in p)
    if attack == "missing": del bundle["files"][path]
    elif attack == "error": mutate_json(bundle, path, lambda d: d.update(execution="ERROR"))
    elif attack == "findings": mutate_json(bundle, path, lambda d: d["records"][2].update(findings=4))
    elif attack == "swapped_failure":
        def swap(d):
            cases = d["records"][2]["cases"]
            failing = next(c for c in cases if not c["passed"])
            passing = next(c for c in cases if c["passed"])
            failing["passed"], passing["passed"] = True, False
        mutate_json(bundle, path, swap)
    elif attack == "history": mutate_json(bundle, path, lambda d: d["records"][1]["evidence"]["coverage"].update(history_head="d"*40))
    # A negative run against the candidate proves nothing about the evaluator's oracle.
    elif attack == "candidate_history": mutate_json(bundle, path, lambda d: d["records"][1]["evidence"]["coverage"].update(history_head="b"*40))
    elif attack == "candidate_subject":
        def rebind(d):
            d["subject_digest"] = bundle["subject"]
            for record in d["records"]:
                record["subject_digest"] = bundle["subject"]
        mutate_json(bundle, path, rebind)
    elif attack == "cleanup": mutate_json(bundle, path, lambda d: d["cleanup"].update(completed=False))
    elif attack == "missing_case": mutate_json(bundle, path, lambda d: d["records"][2]["cases"].pop())
    elif attack == "invalid_case_type": mutate_json(bundle, path, lambda d: d["records"][2]["cases"][-1].update(passed="true"))
    elif attack == "fake_junit_count": bundle["files"]["trusted/artifacts/pytest.xml"] = b'<testsuite tests="360"/>'
    with pytest.raises(ValueError): publisher.validate_bundle(**bundle)


@pytest.mark.parametrize("change", ["none", "head", "rerun", "new_run", "review_dismissed", "review_permission",
                                    "foreign_base", "run_branch"])
def test_publication_rechecks_mutable_state_before_green(bundle, monkeypatch, change):
    writes = []
    gets = 0
    run = copy.deepcopy(bundle["run"])
    reviews = copy.deepcopy(bundle["reviews"])
    fresh = copy.deepcopy(bundle["pr"])
    fresh["head"].update(ref="feature", repo={"id": 10})
    run.update(head_branch="feature", head_repository={"id": 10})
    if change == "head": fresh["head"]["sha"] = "d"*40
    if change == "rerun": run["run_attempt"] = 2
    if change == "run_branch": run["head_branch"] = "other-feature"
    if change == "review_dismissed": reviews.append({**reviews[0], "id": 12, "state": "DISMISSED"})
    class Client:
        def api(self, path, method="GET", payload=None):
            nonlocal gets
            if method != "GET":
                writes.append(copy.deepcopy(payload))
                return {"id": 30, "app": {"id": 42}, "head_sha": "b"*40, "conclusion": payload.get("conclusion")}
            if path.endswith("/pulls/5"):
                gets += 1
                return bundle["pr"] if gets == 1 else fresh
            if "/actions/runs/" in path: return run
            if "/actions/workflows/" in path:
                assert "head_sha=" + "b"*40 in path
                listing = [run, {"id": 101, "head_sha": "b"*40}] if change == "new_run" else [run]
                return {"total_count": len(listing), "workflow_runs": listing}
            if "/permission" in path: return {"role_name": "read" if change == "review_permission" else "write"}
            raise AssertionError("unexpected request")
        def pages(self, path):
            if path.endswith("/pulls?state=all"):
                twin = copy.deepcopy(fresh)
                twin.update(number=6, state="closed")
                twin["base"]["ref"] = "untrusted"
                return [fresh, twin] if change == "foreign_base" else [fresh]
            return reviews
    monkeypatch.setattr(publisher, "collect", lambda *args: {
        "head_sha": "b"*40, "base_sha": "a"*40, "run_id": 100, "run_attempt": 1, "review_ids": [11],
        "excluded_identities": []})
    report = publisher.publish(Client(), bundle["settings"], bundle["gate_policy"], 5, 100)
    assert len(writes) == 1 and writes[0]["status"] == "completed"
    assert writes[-1]["conclusion"] == ("success" if change == "none" else "failure")
    assert report["decision"] == ("ALLOW" if change == "none" else "BLOCK")


@pytest.mark.parametrize("attack", ["writable_parent", "symlink_parent"])
def test_live_config_rejects_replaceable_parent(tmp_path, attack):
    import os
    from scripts.publish_trusted_check import read_config
    folder = tmp_path / "config"
    folder.mkdir()
    config = folder / "publisher.json"
    config.write_text("{}")
    config.chmod(0o444)
    if attack == "writable_parent":
        folder.chmod(0o777)
    else:
        link = tmp_path / "linked"
        link.symlink_to(folder, target_is_directory=True)
        config = link / config.name
    with pytest.raises(publisher.Denied, match="CONFIG_PARENT"):
        read_config(config, live=True, owner_uid=os.getuid())


def test_config_validation_is_available_before_installing_root_owned_paths(tmp_path):
    from scripts.publish_trusted_check import read_config
    config = tmp_path / "publisher.json"
    config.write_text("{}")
    assert read_config(config, live=False) == b"{}"


def base_binding(twin=None, branch="feature", listed=True):
    pr = {"number": 5, "base": {"ref": "main", "repo": {"id": 10}},
          "head": {"sha": "b"*40, "ref": "feature", "repo": {"id": 10}}}
    run = {"head_branch": branch, "head_repository": {"id": 10}}
    prs = ([pr] if listed else []) + ([twin] if twin else [])
    return run, pr, prs


@pytest.mark.parametrize("twin,branch,code", [
    ({"number": 6, "base": {"ref": "evil", "repo": {"id": 10}}, "head": {"sha": "b"*40}}, "feature", "FOREIGN_BASE_PR"),
    ({"number": 6, "base": {"ref": "main", "repo": {"id": 77}}, "head": {"sha": "b"*40}}, "feature", "FOREIGN_BASE_PR"),
    (None, "twin", "RUN_HEAD_BRANCH"),
])
def test_run_from_a_same_head_pr_into_another_base_is_refused(twin, branch, code):
    with pytest.raises(publisher.Denied, match=code):
        publisher.validate_run_base(*base_binding(twin, branch), "main")


def test_run_base_binding_accepts_the_only_pr_and_fails_closed_on_missing_listing():
    publisher.validate_run_base(*base_binding(), "main")
    with pytest.raises(publisher.Denied, match="PR_LISTING_INCOMPLETE"):
        publisher.validate_run_base(*base_binding(listed=False), "main")
    run, pr, prs = base_binding()
    pr["head"]["repo"] = None  # deleted fork: the head repository cannot be bound
    with pytest.raises(publisher.Denied, match="RUN_HEAD_BRANCH"):
        publisher.validate_run_base(run, pr, prs, "main")
