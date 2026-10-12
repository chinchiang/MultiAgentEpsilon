import json
from pathlib import Path

import pytest

from fixture_app.app import database_url, connect
from security_harness.authorization import run_authorization
from security_harness.authorization import response_body
import httpx


@pytest.mark.integration
def test_identical_oracle_rejects_vulnerable_and_accepts_fixed():
    dsn = database_url()  # 缺少 PostgreSQL 必須失敗，不可默默略過。 / Missing PostgreSQL is a failure, never a silent skip.
    vulnerable = run_authorization(dsn, "vulnerable")
    fixed = run_authorization(dsn, "fixed")
    contract = json.loads((Path(__file__).resolve().parents[1] / "security/policy.json").read_text())["gate_contracts"]["AUTH"]
    assert len(vulnerable) == len(fixed) == len(contract["case_ids"]) == 44
    failed = {x["case"] for x in vulnerable if not x["passed"]}
    assert failed == set(contract["seeded_defect_case_ids"]) == {
        "bob: unauthorized read denied without data",
        "bob: unauthorized write denied without side effect",
        "carol: unauthorized read denied without data",
        "carol: unauthorized write denied without side effect",
        "admin cross-tenant denied",
        "admin cross-tenant write denied without side effect",
        "bob: unauthorized delete denied without side effect",
        "carol: unauthorized delete denied without side effect",
        "admin cross-tenant delete denied without side effect"}
    assert all(x["passed"] for x in fixed)


def test_external_database_refused_before_connect():
    with pytest.raises(ValueError, match='^only\\ the\\ disposable\\ loopback\\ fixture\\ database\\ is\\ allowed$'):
        connect("postgresql://user@192.0.2.1/production", "epsilon_" + "a" * 16)


def test_duplicate_json_key_cannot_hide_private_response_data():
    response = httpx.Response(404, content=b'{"detail":"private","detail":"item not found"}')
    with pytest.raises(ValueError, match="duplicate"):
        response_body(response)


DATE = ('date', 'Mon, 12 Oct 2026 04:40:29 GMT')
JSON_HEADERS = [DATE, ('server', 'uvicorn'), ('content-type', 'application/json')]


@pytest.mark.parametrize('status, headers, content', [
    (404, [*JSON_HEADERS, ('content-length', '27')], b'{"detail":"item not found"}'),
    (204, JSON_HEADERS, b''),
    (200, [*JSON_HEADERS, ('content-length', '2'), ('Connection', 'close')], b'[]'),
    (404, [('Date', DATE[1]), ('Server', 'uvicorn'), ('Content-Type', 'application/json'),
           ('Content-Length', '27')], b'{"detail":"item not found"}'),
])
def test_fixture_contract_headers_are_accepted(status, headers, content):
    from security_harness.authorization import headers_match
    assert headers_match(httpx.Response(status, headers=headers, content=content))


@pytest.mark.parametrize('headers, content', [
    ([*JSON_HEADERS, ('content-length', '27'), ('x-item', 'carol-private')], b'{"detail":"item not found"}'),
    ([*JSON_HEADERS, ('content-length', '27'), ('set-cookie', 'owner=carol')], b'{"detail":"item not found"}'),
    ([*JSON_HEADERS, ('content-length', '27'), ('content-type', 'text/plain')], b'{"detail":"item not found"}'),
    ([DATE, ('server', 'carol-private'), ('content-type', 'application/json'), ('content-length', '27')],
     b'{"detail":"item not found"}'),
    ([('date', 'carol-private'), ('server', 'uvicorn'), ('content-type', 'application/json'),
      ('content-length', '27')], b'{"detail":"item not found"}'),
    ([DATE, ('server', 'uvicorn'), ('content-type', 'application/json; carol-private'),
      ('content-length', '27')], b'{"detail":"item not found"}'),
    ([*JSON_HEADERS, ('content-length', '28')], b'{"detail":"item not found"}'),
    ([*JSON_HEADERS, ('content-length', '0')], b''),
    ([*JSON_HEADERS, ('transfer-encoding', 'chunked')], b'{"detail":"item not found"}'),
    ([*JSON_HEADERS, ('content-length', '27'), ('connection', 'carol-private')], b'{"detail":"item not found"}'),
    ([*JSON_HEADERS, ('content-length', '27'), ('connection', 'close'), ('connection', 'close')],
     b'{"detail":"item not found"}'),
    ([DATE, ('server', 'uvicorn'), ('content-length', '27')], b'{"detail":"item not found"}'),
])
def test_data_hidden_in_response_headers_fails_the_case(headers, content):
    # 本文正確不足以通過；標頭夾帶資料或偏離契約都算失敗。 / A correct body is not enough; data or drift in headers fails the case.
    from security_harness.authorization import headers_match
    assert not headers_match(httpx.Response(404, headers=headers, content=content))


@pytest.mark.integration
def test_oracle_queries_fail_fast_when_candidate_holds_a_table_lock():
    import time
    import psycopg
    from security_harness import fixture_database
    from security_harness.authorization import snapshot
    dsn = database_url()
    schema, _ = fixture_database.seed(dsn)
    try:
        with fixture_database.connect(dsn, schema) as holder:
            holder.execute("LOCK TABLE items IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            with pytest.raises(psycopg.errors.LockNotAvailable, match='lock timeout'):
                snapshot(dsn, schema, fixture_database.connect)
            assert time.monotonic() - started < 10
    finally:
        fixture_database.cleanup(dsn, schema)


@pytest.mark.integration
def test_oracle_search_path_resolves_builtins_before_fixture_schema():
    from security_harness import fixture_database
    dsn = database_url()
    schema, _ = fixture_database.seed(dsn)
    try:
        with fixture_database.connect(dsn, schema) as conn:
            assert conn.execute("SELECT current_schemas(false) AS s").fetchone()["s"] == ["pg_catalog", schema]
            assert conn.execute("SELECT count(*) AS n FROM items").fetchone()["n"] == 3
    finally:
        fixture_database.cleanup(dsn, schema)
