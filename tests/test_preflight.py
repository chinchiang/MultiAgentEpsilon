import json
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from security_harness.preflight import PreflightError, check_metadata, parse_lock, validate_package_policy, verify

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)
HASH = "a" * 64
POLICY = {"schema_version": 1, "allowed_registry": "https://pypi.org", "allowed_packages": ["example"],
          "minimum_package_age_days": 7, "allowed_artifact_host": "files.pythonhosted.org"}
RECORD = {"name": "example", "version": "1.0", "hashes": {HASH}}
META = {"info": {"name": "example", "version": "1.0"}, "urls": [
    {"digests": {"sha256": HASH}, "url": "https://files.pythonhosted.org/example.whl",
     "packagetype": "bdist_wheel", "yanked": False, "upload_time_iso_8601": "2026-01-01T00:00:00Z"}]}


def test_valid_pinned_wheel():
    assert check_metadata(RECORD, META, POLICY, NOW)["wheel_only_required"]


@pytest.mark.parametrize("field,value", [
    ("url", "https://attacker.invalid/example.whl"),
    ("url", "http://files.pythonhosted.org/example.whl"),
    ("url", "https://user@files.pythonhosted.org/example.whl"),
    ("yanked", True), ("packagetype", "sdist"),
    ("upload_time_iso_8601", (NOW-timedelta(days=1)).isoformat()),
    ("digests", {"sha256": "b" * 64}),
])
def test_artifact_failure_blocks(field, value):
    metadata = deepcopy(META)
    metadata["urls"][0][field] = value
    with pytest.raises(PreflightError, match='^(?:example:\\ artifact\\ inside\\ cooling\\ period|example:\\ lock\\ hash\\ not\\ published\\ by\\ registry|example:\\ no\\ approved\\ wheel;\\ source\\ builds\\ forbidden|example:\\ unexpected\\ artifact\\ origin|example:\\ yanked\\ artifact)$'):
        check_metadata(RECORD, metadata, POLICY, NOW)


@pytest.mark.parametrize("body", ["", "example>=1", "-e .", "--extra-index-url https://example.org",
                                 "example @ https://example.org/a.whl", "example==1.0"])
def test_unlocked_or_executable_input_refused(tmp_path, body):
    path = tmp_path / "requirements.lock"
    path.write_text(body)
    with pytest.raises(PreflightError, match='^(?:empty\\ or\\ duplicate\\ lock\\ entries|lock\\ must\\ contain\\ only\\ exact\\ pins\\ and\\ SHA\\-256\\ hashes)$'):
        parse_lock(path)


def test_unknown_and_registry_failure_do_not_pass(tmp_path):
    path = tmp_path / "requirements.lock"
    path.write_text("example==1.0 --hash=sha256:" + HASH)
    def unavailable(*args):
        raise TimeoutError("registry unavailable")
    with pytest.raises(TimeoutError, match='^registry\\ unavailable$'):
        verify(path, POLICY, fetch=unavailable, now=NOW)
    with pytest.raises(PreflightError, match='^invalid\\ package\\ policy$'):
        verify(path, {**POLICY, "allowed_packages": []}, fetch=lambda *args: META, now=NOW)
    assert len(verify(path, POLICY, fetch=lambda *args: META, now=NOW)) == 1


def test_duplicate_packages_rejected(tmp_path):
    path = tmp_path / "requirements.lock"
    path.write_text(("example==1.0 --hash=sha256:" + HASH + "\n") * 2)
    with pytest.raises(PreflightError, match='^empty\\ or\\ duplicate\\ lock\\ entries$'):
        parse_lock(path)


def test_repository_policy_is_a_valid_package_policy():
    validate_package_policy(json.loads((Path(__file__).resolve().parents[1] / "security/policy.json").read_text()))


@pytest.mark.parametrize("change", [
    {"allowed_packages": "fastapi"},            # 字串會變成子字串比對。 / A string would become a substring match.
    {"allowed_packages": ["Example"]}, {"allowed_packages": ["example", "example"]}, {"allowed_packages": [1]},
    {"minimum_package_age_days": 0}, {"minimum_package_age_days": -7}, {"minimum_package_age_days": 7.0},
    {"minimum_package_age_days": True}, {"allowed_registry": "https://mirror.invalid"},
    {"allowed_artifact_host": "evil.invalid"}, {"schema_version": 2}, {"schema_version": True},
])
def test_weakened_package_policy_refused_before_any_registry_call(tmp_path, change):
    path = tmp_path / "requirements.lock"
    path.write_text("example==1.0 --hash=sha256:" + HASH)
    def never(*args):
        raise AssertionError("registry must not be contacted")
    with pytest.raises(PreflightError, match="invalid package policy"):
        verify(path, {**POLICY, **change}, fetch=never, now=NOW)


def test_missing_package_policy_field_refused():
    for key in POLICY:
        with pytest.raises(PreflightError, match="invalid package policy"):
            validate_package_policy({k: v for k, v in POLICY.items() if k != key})


def test_registry_version_mismatch_alone_is_refused():
    meta = deepcopy(META)
    meta["info"]["version"] = "2.0"
    with pytest.raises(PreflightError, match="registry identity mismatch"):
        check_metadata(RECORD, meta, POLICY, NOW)


def test_cooling_period_boundary_is_exact():
    meta = deepcopy(META)
    boundary = NOW - timedelta(days=POLICY["minimum_package_age_days"])
    meta["urls"][0]["upload_time_iso_8601"] = boundary.isoformat()
    assert check_metadata(RECORD, meta, POLICY, NOW)["approved_hash_count"] == 1
    meta["urls"][0]["upload_time_iso_8601"] = (boundary + timedelta(seconds=1)).isoformat()
    with pytest.raises(PreflightError, match="inside cooling period"):
        check_metadata(RECORD, meta, POLICY, NOW)


@pytest.mark.parametrize("days,valid", [(1, True), (365, True), (0, False), (366, False)])
def test_cooling_period_policy_range_is_inclusive(days, valid):
    policy = {**POLICY, "minimum_package_age_days": days}
    if valid:
        validate_package_policy(policy)
    else:
        with pytest.raises(PreflightError, match="invalid package policy"):
            validate_package_policy(policy)
