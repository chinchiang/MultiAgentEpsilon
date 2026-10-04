import pytest

from fixture_app.app import database_url, connect
from security_harness.authorization import run_authorization


@pytest.mark.integration
def test_identical_oracle_rejects_vulnerable_and_accepts_fixed():
    dsn = database_url()  # Missing PostgreSQL is a failure, never a silent skip.
    vulnerable = run_authorization(dsn, "vulnerable")
    fixed = run_authorization(dsn, "fixed")
    assert len(vulnerable) == len(fixed) == 14
    failed = {x["case"] for x in vulnerable if not x["passed"]}
    assert failed == {"bob: unauthorized read denied without data",
                      "bob: unauthorized write denied without side effect",
                      "carol: unauthorized read denied without data",
                      "carol: unauthorized write denied without side effect",
                      "admin cross-tenant denied"}
    assert all(x["passed"] for x in fixed)


def test_external_database_refused_before_connect():
    with pytest.raises(ValueError):
        connect("postgresql://user@192.0.2.1/production", "epsilon_" + "a" * 16)
