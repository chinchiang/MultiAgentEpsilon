from copy import deepcopy
from datetime import datetime, timezone, timedelta

import pytest

from security_harness.results import decide, result

POLICY = {"required_gates": ["G1", "G2", "AUTH"], "max_evidence_age_seconds": 3600}
NOW = datetime.now(timezone.utc)


def records():
    output = [result(g, "COMPLETED", "test" if g == "AUTH" else "scan", 3, 0, "subject", "policy", "tested")
              for g in POLICY["required_gates"]]
    for row in output:
        row["created_at"] = NOW.isoformat()
    return output


def judge(rows, policy=POLICY):
    return decide(rows, policy, "subject", "policy", NOW)["decision"]


def test_zero_findings_with_coverage_is_allowed():
    assert judge(records()) == "ALLOW"


@pytest.mark.parametrize("field,value", [
    ("execution", "ERROR"), ("execution", "TIMEOUT"), ("execution", "NOT_RUN"),
    ("execution", "invented"), ("coverage_count", 0), ("coverage_count", -1),
    ("coverage_count", True), ("findings", 1), ("findings", -1),
    ("findings", "0"), ("subject_digest", "wrong"), ("policy_digest", "proposed-policy"),
    ("created_at", (NOW-timedelta(hours=2)).isoformat()),
    ("created_at", (NOW+timedelta(seconds=1)).isoformat()),
    ("created_at", "2026-01-01"), ("kind", "unknown"), ("schema_version", True),
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
