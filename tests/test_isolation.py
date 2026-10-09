import shutil
import json
import hashlib
import socket
from pathlib import Path

import pytest
from security_harness.isolation import run_isolated
from security_harness import isolation

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.integration
def test_external_oracle_rejects_defect_and_accepts_fixed():
    vulnerable = run_isolated(ROOT, "vulnerable")
    fixed = run_isolated(ROOT, "fixed")
    contract = json.loads((ROOT / "security/policy.json").read_text())["gate_contracts"]["AUTH"]
    assert len(vulnerable["cases"]) == len(fixed["cases"]) == len(contract["case_ids"])
    assert {c["case"] for c in vulnerable["cases"] if not c["passed"]} == set(contract["seeded_defect_case_ids"])
    assert all(c["passed"] for c in fixed["cases"])
    assert fixed["isolation"]["network"] == "none"
    assert fixed["isolation"]["user"] == "10001:10001"
    assert "/run/http" not in fixed["isolation"]["mount_destinations"]
    assert fixed["isolation"]["candidate_lock_sha256"] == fixed["isolation"]["runtime_lock_sha256"]


@pytest.mark.integration
def test_candidate_cannot_access_oracle_socket_credentials_or_egress(tmp_path):
    shutil.copytree(ROOT / "fixture_app", tmp_path / "fixture_app", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(ROOT / "requirements.lock", tmp_path / "requirements.lock")
    # 這些斷言在真實候選容器匯入時執行。 / These assertions run in the actual candidate container during import.
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


def test_candidate_dependency_change_refused_before_container_start(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    paths = {"requirements.lock": "lock_sha256", "security/runtime/server.py": "server_sha256",
             "scripts/build_runtime.py": "builder_sha256", "security/runtime/request.py": "request_sha256"}
    runtime = {"image_id": "unused", "base_image": json.loads((ROOT / "security/tools.lock.json").read_text())["python_runtime"]["image"]}
    for name, key in paths.items():
        target = baseline / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
        runtime[key] = hashlib.sha256(target.read_bytes()).hexdigest()
    (baseline / "security/tools.lock.json").write_bytes((ROOT / "security/tools.lock.json").read_bytes())
    (baseline / ".state").mkdir()
    (baseline / ".state/runtime-image.json").write_text(json.dumps(runtime))
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "requirements.lock").write_text("changed dependency lock")
    monkeypatch.setattr(isolation, "ROOT", baseline)
    def forbidden(*a, **kw):
        pytest.fail("mismatched dependency must not start a container")
    monkeypatch.setattr(isolation, "docker", forbidden)
    with pytest.raises(ValueError, match="candidate lock differs"):
        run_isolated(candidate)


@pytest.mark.integration
def test_candidate_socket_symlink_never_connects_host_endpoint(tmp_path):
    candidate = tmp_path / "candidate"
    shutil.copytree(ROOT / "fixture_app", candidate / "fixture_app", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(ROOT / "requirements.lock", candidate / "requirements.lock")
    # 此路徑只存在 host，不掛入候選容器。 / This path is present only on the host, never mounted into the candidate.
    target = tmp_path / "host.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(target))
        listener.listen(1)
        listener.settimeout(0.1)
        app = candidate / "fixture_app/app.py"
        source = app.read_text()
        source = source.replace('    def health():\n',
            '    def health():\n'
            '        endpoint = Path("/tmp/epsilon-http.sock")\n'
            '        endpoint.unlink()\n'
            f'        endpoint.symlink_to({str(target)!r})\n')
        app.write_text(source)
        with pytest.raises(RuntimeError, match="container HTTP request failed"):
            run_isolated(candidate)
        with pytest.raises(socket.timeout):
            listener.accept()
