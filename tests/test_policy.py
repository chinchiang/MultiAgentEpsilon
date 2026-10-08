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
        'archives': 0, 'history_blobs': 0, 'unsupported_files': 0, 'history_head': 'a' * 40}}
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
    ("created_at", (NOW-timedelta(hours=2)).isoformat()),
    ("created_at", (NOW+timedelta(seconds=1)).isoformat()),
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
