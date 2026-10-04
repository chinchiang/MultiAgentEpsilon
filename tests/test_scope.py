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
