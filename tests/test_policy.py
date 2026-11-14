from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path

import pytest

from security_harness.results import decide, result
from tests.dependency_evidence import clean_evidence

POLICY = json.loads((Path(__file__).resolve().parents[1] / "security/policy.json").read_text())
NOW = datetime.now(timezone.utc)


def records():
    output = [result(g, "COMPLETED", "test" if g == "AUTH" else "scan", 3, 0, "subject", "policy", "tested", run_id="run")
              for g in POLICY["required_gates"]]
    output[0]["packages"], output[0]["sca"] = clean_evidence(3, NOW)
    output[-1]["cases"] = [{"case": c, "passed": True} for c in POLICY["gate_contracts"]["AUTH"]["case_ids"]]
    output[-1]["coverage_count"] = len(output[-1]["cases"])
    output[1]['evidence'] = {'coverage': {'status': 'COMPLETE', 'selected_files': 3,
        'selected_bytes': 30, 'scanned_leaves': 3, 'scanned_bytes': 30, 'expanded_bytes': 30,
        'archives': 0, 'history_blobs': 0, 'unsupported_files': 0, 'history_head': 'a' * 40}, 'findings': []}
    for row in output:
        row["created_at"] = NOW.isoformat()
    return output


def judge(rows, policy=POLICY):
    return decide(rows, policy, "subject", "policy", NOW, run_id="run")["decision"]


def test_zero_findings_with_coverage_is_allowed():
    assert judge(records()) == "ALLOW"


@pytest.mark.parametrize('head', [None, '', 'HEAD', 'A' * 40, 'a' * 39])
def test_history_required_scan_without_history_identity_blocks(head):
    rows = records()
    rows[1]['evidence']['coverage']['history_head'] = head
    assert judge(rows) == "BLOCK"
    del rows[1]['evidence']['coverage']['history_head']
    assert judge(rows) == "BLOCK"


@pytest.mark.parametrize('field,value', [('status','INCOMPLETE'), ('selected_files',1),
                                       ('unsupported_files',1), ('scanned_bytes',True)])
def test_scan_coverage_cannot_be_replaced_with_positive_target_count(field, value):
    rows = records()
    rows[1]['evidence']['coverage'][field] = value
    assert judge(rows) == 'BLOCK'


@pytest.mark.parametrize("field,value", [
    ("execution", "ERROR"), ("execution", "TIMEOUT"), ("execution", "NOT_RUN"),
    ("execution", "invented"), ("coverage_count", 0), ("coverage_count", -1),
    ("coverage_count", True), ("findings", 1), ("findings", -1),
    ("findings", "0"), ("subject_digest", "wrong"), ("policy_digest", "proposed-policy"),
    pytest.param("created_at", (NOW-timedelta(hours=2)).isoformat(), id="expired"),
    pytest.param("created_at", (NOW+timedelta(seconds=1)).isoformat(), id="future"),
    ("created_at", "2026-01-01"), ("kind", "unknown"), ("schema_version", True),
    ("run_id", "another-run"), ("kind", "test"), ("schema_version", 1),
    ("schema_version", 2), ("subject_digest_format", "legacy"),
])
def test_bad_evidence_blocks(field, value):
    rows = records()
    rows[0][field] = value
    assert judge(rows) == "BLOCK"


def test_missing_duplicate_unknown_and_malformed_blocks():
    rows = records()
    assert judge(rows[:-1]) == "BLOCK"
    assert judge(rows + [deepcopy(rows[0])]) == "BLOCK"
    assert judge(rows + [None]) == "BLOCK"
    rows[0]["gate"] = "new-gate"
    assert judge(rows) == "BLOCK"
    assert judge([], {"required_gates": [], "max_evidence_age_seconds": 3600}) == "BLOCK"


@pytest.mark.parametrize("mutation", ["single", "duplicate", "unknown", "wrong-summary", "hidden-failure", "nonstring", "scan-kind"])
def test_incomplete_or_inconsistent_case_evidence_blocks(mutation):
    rows = records()
    auth = rows[-1]
    if mutation == "single":
        auth["cases"] = auth["cases"][:1]
        auth["coverage_count"] = 1
    elif mutation == "duplicate":
        auth["cases"] = [auth["cases"][0]] * 14
    elif mutation == "unknown":
        auth["cases"][0]["case"] = "invented"
    elif mutation == "wrong-summary":
        auth["coverage_count"] = 1
    elif mutation == "hidden-failure":
        auth["cases"][0]["passed"] = False
    elif mutation == "nonstring":
        auth["cases"][0]["case"] = ["invalid"]
    else:
        auth["kind"] = "scan"
    assert judge(rows) == "BLOCK"


@pytest.mark.parametrize("seeded", [None, [], ["not a case"], ["anonymous denied", "anonymous denied"],
                                    "all", "every case"])
def test_seeded_defect_manifest_must_be_a_strict_subset_of_required_cases(seeded):
    policy = deepcopy(POLICY)
    contract = policy["gate_contracts"]["AUTH"]
    if seeded == "every case":
        contract["seeded_defect_case_ids"] = list(contract["case_ids"])
    elif seeded is None:
        del contract["seeded_defect_case_ids"]
    else:
        contract["seeded_defect_case_ids"] = seeded
    assert judge(records(), policy) == "BLOCK"


@pytest.mark.parametrize('listed,count', [([], 1), ([{'rule': 'r'}], 0), (None, 0), ('x', 0)])
def test_secret_scan_summary_must_match_its_finding_list(listed, count):
    rows = records()
    rows[1]['evidence']['findings'] = listed
    rows[1]['findings'] = count
    assert judge(rows) == 'BLOCK'


def reasons(rows):
    return decide(rows, POLICY, "subject", "policy", NOW, run_id="run")["reasons"]


def unfinished(execution, index=-1):
    rows = records()
    rows[index].update(execution=execution, coverage_count=0, findings=0)
    rows[index].pop("cases", None)
    return rows


@pytest.mark.parametrize("execution", ["ERROR", "TIMEOUT", "CANCELLED", "NOT_RUN"])
def test_unfinished_gate_blocks_and_names_its_execution_state(execution):
    # 基礎設施逾時或錯誤不得與證據不符共用同一句理由。 / An infrastructure timeout or error must not share the
    # reason given to mismatched evidence.
    result = decide(unfinished(execution), POLICY, "subject", "policy", NOW, run_id="run")
    assert result["decision"] == "BLOCK"
    assert result["reasons"] == [f"AUTH: {execution}"]


@pytest.mark.parametrize("index,gate", [(0, POLICY["required_gates"][0]), (1, POLICY["required_gates"][1])])
def test_unfinished_scan_gate_needs_no_coverage_evidence_to_name_its_state(index, gate):
    rows = unfinished("ERROR", index)
    rows[index].pop("evidence", None)
    rows[index].pop("sca", None)
    assert reasons(rows) == [f"{gate}: ERROR"]


@pytest.mark.parametrize("field,value", [
    ("run_id", "another-run"), ("subject_digest", "wrong"), ("policy_digest", "proposed-policy"),
    ("schema_version", True), ("coverage_count", -1), ("coverage_count", False), ("findings", -1),
    ("kind", "scan"), ("subject_digest_format", "legacy"),
    pytest.param("created_at", (NOW - timedelta(hours=2)).isoformat(), id="expired"),
    pytest.param("created_at", (NOW + timedelta(seconds=1)).isoformat(), id="future"),
])
def test_unfinished_gate_with_wrong_binding_is_still_invalid_evidence(field, value):
    rows = unfinished("TIMEOUT")
    rows[-1][field] = value
    assert reasons(rows) == ["AUTH: invalid, missing, stale or mismatched evidence"]


def test_completed_gate_without_coverage_is_invalid_evidence():
    rows = records()
    rows[-1].update(coverage_count=0, cases=[])
    assert reasons(rows) == ["AUTH: invalid, missing, stale or mismatched evidence"]
    rows = records()
    rows[1]["coverage_count"] = 0
    assert reasons(rows) == [f"{POLICY['required_gates'][1]}: invalid, missing, stale or mismatched evidence"]


def test_unfinished_gate_with_findings_reports_both():
    rows = unfinished("ERROR")
    rows[-1]["findings"] = 1
    assert reasons(rows) == ["AUTH: ERROR", "AUTH: confirmed findings"]


def test_evidence_age_boundaries_are_inclusive_for_unfinished_gates():
    limit = POLICY["max_evidence_age_seconds"]
    rows = unfinished("TIMEOUT")
    rows[-1]["created_at"] = (NOW - timedelta(seconds=limit)).isoformat()
    assert reasons(rows) == ["AUTH: TIMEOUT"]
    rows[-1]["created_at"] = NOW.isoformat()
    assert reasons(rows) == ["AUTH: TIMEOUT"]
