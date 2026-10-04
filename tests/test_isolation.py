import shutil
from pathlib import Path

import pytest
from security_harness.isolation import run_isolated

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.integration
def test_external_oracle_rejects_defect_and_accepts_fixed():
    vulnerable = run_isolated(ROOT, "vulnerable")
    fixed = run_isolated(ROOT, "fixed")
    assert len(vulnerable["cases"]) == len(fixed["cases"]) == 14
    assert sum(not c["passed"] for c in vulnerable["cases"]) == 5
    assert all(c["passed"] for c in fixed["cases"])
    assert fixed["isolation"]["network"] == "none"
    assert fixed["isolation"]["user"] == "10001:10001"


@pytest.mark.integration
def test_candidate_cannot_access_oracle_socket_credentials_or_egress(tmp_path):
    shutil.copytree(ROOT / "fixture_app", tmp_path / "fixture_app", ignore=shutil.ignore_patterns("__pycache__"))
    # These assertions run in the actual candidate container during import.
    (tmp_path / "fixture_app/__init__.py").write_text('''
import importlib.util
import os
import socket
from pathlib import Path
assert importlib.util.find_spec("security_harness") is None
assert not Path("/var/run/docker.sock").exists()
assert not Path("/artifacts").exists()
assert not os.environ.get("GITHUB_TOKEN")
assert not os.environ.get("HTTPS_PROXY")
for name in ("/opt/epsilon/server.py", "/candidate/fixture_app/app.py"):
    try:
        with open(name, "a") as stream:
            stream.write("modified")
    except OSError:
        pass
    else:
        raise AssertionError("candidate could modify readonly input")
try:
    socket.create_connection(("203.0.113.1", 9), timeout=0.2)
except OSError:
    pass
else:
    raise AssertionError("candidate has IP egress")
''')
    result = run_isolated(tmp_path)
    assert all(c["passed"] for c in result["cases"])
