import json
from pathlib import Path

import pytest

from fixture_app.app import database_url, connect
from security_harness.authorization import run_authorization
from security_harness.authorization import response_body
import httpx


@pytest.mark.integration
def test_identical_oracle_rejects_vulnerable_and_accepts_fixed():
    dsn = database_url()  # Missing PostgreSQL is a failure, never a silent skip.
    vulnerable = run_authorization(dsn, "vulnerable")
    fixed = run_authorization(dsn, "fixed")
    contract = json.loads((Path(__file__).resolve().parents[1] / "security/policy.json").read_text())["gate_contracts"]["AUTH"]
    assert len(vulnerable) == len(fixed) == len(contract["case_ids"]) == 18
    failed = {x["case"] for x in vulnerable if not x["passed"]}
    assert failed == set(contract["seeded_defect_case_ids"]) == {
        "bob: unauthorized read denied without data",
        "bob: unauthorized write denied without side effect",
        "carol: unauthorized read denied without data",
        "carol: unauthorized write denied without side effect",
        "admin cross-tenant denied",
        "admin cross-tenant write denied without side effect"}
    assert all(x["passed"] for x in fixed)


def test_external_database_refused_before_connect():
    with pytest.raises(ValueError):
        connect("postgresql://user@192.0.2.1/production", "epsilon_" + "a" * 16)


def test_duplicate_json_key_cannot_hide_private_response_data():
    response = httpx.Response(404, content=b'{"detail":"private","detail":"item not found"}')
    with pytest.raises(ValueError, match="duplicate"):
        response_body(response)
