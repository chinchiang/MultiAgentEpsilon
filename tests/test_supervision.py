"""每個子程序都只收到同一份基本環境加上自己角色的名稱，在真正的啟動路徑上觀察。

Every child process receives the one base environment plus its own role's names, observed on the real launch path."""
import asyncio
import json
import shutil
import sys
import uuid

import pytest

# 基本程序、語系、代理與 CA 變數；值為合成值。 / Basic process, locale, proxy and CA variables, with synthetic values.
BASE = {"PATH": "/usr/bin:/bin", "HOME": "/home/synthetic", "USER": "synthetic", "LOGNAME": "synthetic",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "LC_CTYPE": "C.UTF-8", "TZ": "UTC",
        "HTTP_PROXY": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128",
        "NO_PROXY": "localhost", "ALL_PROXY": "socks5://proxy.invalid:1080",
        "http_proxy": "http://proxy.invalid:3128", "https_proxy": "http://proxy.invalid:3128",
        "no_proxy": "localhost", "all_proxy": "socks5://proxy.invalid:1080",
        "SSL_CERT_FILE": "/etc/ssl/synthetic.pem", "SSL_CERT_DIR": "/etc/ssl/certs",
        "REQUESTS_CA_BUNDLE": "/etc/ssl/synthetic-bundle.pem"}
# 權杖、金鑰、libpq 設定、角色以外的 AWS 名稱，以及大小寫混用的代理名稱都不可傳下去。 / Tokens, keys, libpq settings,
# AWS names outside a role, and mixed-case proxy names never pass.
DROPPED = {"GH_TOKEN": "synthetic-github-token", "GITHUB_TOKEN": "synthetic-actions-token",
           "GEMINI_API_KEY": "synthetic-gemini-key", "PGPASSWORD": "synthetic-pg-password",
           "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/synthetic", "Http_Proxy": "http://attacker.invalid:3128"}
DUMP = [sys.executable, '-c',
        'import json,os; from pathlib import Path; Path("child-env.json").write_text(json.dumps(dict(os.environ)))']


def security_worker(tmp_path, monkeypatch, request):
    from security_harness import isolation
    from security_harness.audit import AuditRun
    from security_harness.lifecycle import supervise
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    supervise(tmp_path, AuditRun(tmp_path, 'security'), DUMP, 10)
    return json.loads((tmp_path / 'child-env.json').read_text())


def model_worker(tmp_path, monkeypatch, request):
    from scripts.model_smoke import initial_report
    from security_harness.llm import lifecycle as life
    report = initial_report(['mock'], str(uuid.uuid4()))
    life.persist(tmp_path / 'artifacts' / report['run_id'] / 'report.json', report)
    life.supervise(tmp_path, report, DUMP, 10)
    return json.loads((tmp_path / 'child-env.json').read_text())


def aws_cli(tmp_path, monkeypatch, request):
    from security_harness.lifecycle import prepare_run, run_directory, temporary_directory
    from tests.test_model_gateway import cli_fixture
    run_id = str(uuid.uuid4())
    prepare_run(tmp_path, run_id, operation='model-smoke')
    try:
        cli = cli_fixture(tmp_path, "import json, os\nprint(json.dumps(dict(os.environ)))\n")
        cli.run_directory = run_directory(tmp_path, run_id)
        return asyncio.run(cli.converse('ap-southeast-1', {'modelId': 'synthetic'}))
    finally:
        shutil.rmtree(temporary_directory(run_id), ignore_errors=True)


def attestation_verifier(tmp_path, monkeypatch, request):
    # 證明驗證器只在子程序邊界替換；在同一邊界記錄它收到的環境。 / The attestation verifier is substituted only at the
    # subprocess boundary; record the environment it receives at that same boundary.
    from security_harness import processes
    from security_harness import trusted_publisher as publisher
    from tests.test_trusted_publisher import publishable_repository
    bundle = request.getfixturevalue('bundle')
    github, _ = publishable_repository(bundle, tmp_path, monkeypatch)
    answer, seen = processes.bounded_output, {}
    def record(*args, **kwargs):
        seen.update(kwargs['env'])
        return answer(*args, **kwargs)
    monkeypatch.setattr(processes, 'bounded_output', record)
    publisher.collect(github, bundle['settings'], 5, 100, bundle['gate_policy'])
    return seen


@pytest.mark.parametrize('child,role', [
    (security_worker, {"DOCKER_CONFIG": "/home/synthetic/.docker"}),
    (model_worker, {}),
    (aws_cli, {"AWS_PROFILE": "synthetic-profile", "AWS_MAX_ATTEMPTS": "1"}),
    (attestation_verifier, {"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}),
], ids=['security-worker', 'model-worker', 'aws-cli', 'attestation-verifier'])
def test_every_child_receives_the_base_environment_and_its_role_names_only(tmp_path, monkeypatch, request,
                                                                           child, role):
    for name, value in {**BASE, **DROPPED, "DOCKER_CONFIG": "/home/synthetic/.docker",
                        "AWS_PROFILE": "synthetic-profile"}.items():
        monkeypatch.setenv(name, value)
    seen = child(tmp_path, monkeypatch, request)
    assert {k: seen.get(k) for k in BASE} == BASE
    assert {k: seen.get(k) for k in role} == role
    assert not set(DROPPED) & set(seen)
