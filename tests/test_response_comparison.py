"""oracle 的 JSON 比對必須同時比較型別。

The oracle's JSON comparison must compare types as well as values."""
import json

import pytest


@pytest.mark.parametrize("actual,expected", [
    (1, True), (True, 1), (1.0, 1), ({"id": 1.0}, {"id": 1}), ([1], [True]), ({"a": 1, "b": 2}, {"a": 1}),
    ([1, 2], [1]), (None, {}), ("1", 1)])
def test_response_comparison_is_type_strict(actual, expected):
    from security_harness.authorization import same
    assert not same(actual, expected)


def test_response_comparison_accepts_identical_json():
    from security_harness.authorization import same
    value = {"detail": [{"loc": ["body", "owner"], "ctx": {"le": 1}, "input": None, "ok": True}]}
    assert same(json.loads(json.dumps(value)), value)
