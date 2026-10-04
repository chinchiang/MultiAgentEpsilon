import json
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from security_harness.preflight import PreflightError, check_metadata, parse_lock, verify

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)
HASH = "a" * 64
POLICY = {"allowed_registry": "https://pypi.org", "allowed_packages": ["example"],
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
    with pytest.raises(PreflightError):
        check_metadata(RECORD, metadata, POLICY, NOW)


@pytest.mark.parametrize("body", ["", "example>=1", "-e .", "--extra-index-url https://example.org",
                                 "example @ https://example.org/a.whl", "example==1.0"])
def test_unlocked_or_executable_input_refused(tmp_path, body):
    path = tmp_path / "requirements.lock"
    path.write_text(body)
    with pytest.raises(PreflightError):
        parse_lock(path)


def test_unknown_and_registry_failure_do_not_pass(tmp_path):
    path = tmp_path / "requirements.lock"
    path.write_text("example==1.0 --hash=sha256:" + HASH)
    def unavailable(*args):
        raise TimeoutError("registry unavailable")
    with pytest.raises(TimeoutError):
        verify(path, POLICY, fetch=unavailable, now=NOW)
    with pytest.raises(PreflightError):
        verify(path, {**POLICY, "allowed_packages": []}, fetch=lambda *args: META, now=NOW)
    assert len(verify(path, POLICY, fetch=lambda *args: META, now=NOW)) == 1


def test_duplicate_packages_rejected(tmp_path):
    path = tmp_path / "requirements.lock"
    path.write_text(("example==1.0 --hash=sha256:" + HASH + "\n") * 2)
    with pytest.raises(PreflightError):
        parse_lock(path)
