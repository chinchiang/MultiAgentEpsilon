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
    monkeypatch.setattr(smoke, "ROOT", tmp_path)  # no security/model-roe.json there
    monkeypatch.setattr("sys.argv", ["model_review", "--provider", "gemini", "--live", "--case", "B01"])
    created = []
    monkeypatch.setattr(review, "initial_report", lambda *args: created.append(args))
    with pytest.raises(SystemExit) as exit_info:
        review.main()
    # argparse error before any report, budget reservation or provider call exists.
    assert exit_info.value.code == 2 and created == []
