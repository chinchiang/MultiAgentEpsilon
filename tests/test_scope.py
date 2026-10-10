import json
from pathlib import Path

import pytest

from security_harness.scope import validate_roe

ROE = json.loads((Path(__file__).resolve().parents[1] / "security/roe.json").read_text())


def test_supported_scope():
    assert validate_roe(ROE)["llm_calls"] is False


@pytest.mark.parametrize("field,value", [
    ("http_hosts", ["example.com"]), ("database_name", "production"),
    ("max_cases", 0), ("max_seconds", 121), ("max_seconds", True),
    ("allow_redirects", True), ("external_callback", True), ("llm_calls", True),
])
def test_scope_expansion_rejected(field, value):
    with pytest.raises(ValueError):
        validate_roe({**ROE, field: value})


MODEL_ROE = json.loads((Path(__file__).resolve().parents[1] / "security/model-roe.json").read_text())


@pytest.mark.parametrize('providers', [['unknown'], ['gemini', 'unknown'], ['mock-anything'],
                                      ['gemini', 'gemini'], [None], [], 'gemini'])
def test_unknown_or_duplicate_provider_cannot_escape_the_roe(providers):
    from security_harness.scope import validate_model_roe
    with pytest.raises(ValueError):
        validate_model_roe(MODEL_ROE, providers)


def test_security_gates_and_model_calls_keep_separate_rules_of_engagement():
    from security_harness.scope import validate_model_roe
    assert validate_roe(ROE)["llm_calls"] is False
    assert validate_model_roe(MODEL_ROE, ["gemini", "mock-review-a"])["data_class"] == "synthetic"


@pytest.mark.parametrize("field,value", [
    ("llm_calls", False), ("data_class", "production"), ("security_gate_effect", "BLOCK"),
    ("allowed_live_providers", []), ("allowed_live_providers", ["gemini", "unknown"]),
    ("max_calls_per_run", 17), ("max_calls_per_run", True), ("schema_version", 2),
])
def test_model_roe_expansion_rejected(field, value):
    from security_harness.scope import validate_model_roe
    with pytest.raises(ValueError):
        validate_model_roe({**MODEL_ROE, field: value}, ["gemini"])


def test_model_roe_must_list_every_live_provider():
    from security_harness.scope import validate_model_roe
    with pytest.raises(ValueError):
        validate_model_roe({**MODEL_ROE, "allowed_live_providers": ["gemini"]}, ["gemini", "bedrock"])


def test_live_review_cli_refuses_without_a_valid_model_roe(tmp_path, monkeypatch):
    import scripts.model_review as review
    import scripts.model_smoke as smoke
    monkeypatch.setattr(smoke, "ROOT", tmp_path)  # 此處沒有 security/model-roe.json。 / no security/model-roe.json there
    monkeypatch.setattr("sys.argv", ["model_review", "--provider", "gemini", "--live", "--case", "B01"])
    created = []
    monkeypatch.setattr(review, "initial_report", lambda *args: created.append(args))
    with pytest.raises(SystemExit) as exit_info:
        review.main()
    # 在任何報告、預算預留或供應商呼叫前產生 argparse 錯誤。 / argparse error before any report, budget reservation or provider call exists.
    assert exit_info.value.code == 2 and created == []


@pytest.mark.parametrize("cap,planned,allowed", [(16, 16, True), (4, 4, True), (4, 5, False), (1, 12, False),
                                                 (4, -1, False), (4, True, False)])
def test_planned_live_calls_must_fit_the_reviewed_per_run_cap(cap, planned, allowed):
    from security_harness.scope import validate_model_roe
    roe = {**MODEL_ROE, "max_calls_per_run": cap}
    if allowed:
        assert validate_model_roe(roe, ["gemini"], planned) is roe
    else:
        with pytest.raises(ValueError):
            validate_model_roe(roe, ["gemini"], planned)


@pytest.mark.parametrize("version", [True, 1.0, "1", None])
def test_rules_of_engagement_schema_version_is_an_exact_integer(version):
    from security_harness.scope import validate_model_roe, validate_roe
    roe = json.loads((Path(__file__).resolve().parents[1] / "security/roe.json").read_text())
    with pytest.raises(ValueError):
        validate_roe({**roe, "schema_version": version})
    with pytest.raises(ValueError):
        validate_model_roe({**MODEL_ROE, "schema_version": version}, ["mock"])


@pytest.mark.parametrize("raw", ['[]', '{"schema_version": true, "entries": []}', '"text"'])
def test_binary_allowlist_shape_is_checked_before_use(tmp_path, raw):
    from security_harness.scan_content import load_binary_allowlist
    path = tmp_path / "binary-allowlist.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        load_binary_allowlist(path)
