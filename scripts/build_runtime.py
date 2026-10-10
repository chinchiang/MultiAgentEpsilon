#!/usr/bin/env python3
"""以已驗證 wheels 離線建置可信 runtime，不採用候選 Dockerfile。

Build the trusted runtime offline from verified wheels; never use a candidate Dockerfile."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.audit import AuditRun
from security_harness.preflight import canonical
from security_harness.processes import docker_command, docker_environment
from security_harness.results import write_json

# 只供 evaluator 測試使用，不進入候選 runtime 映像。 / Evaluator test tooling only; kept out of the candidate runtime image.
TEST_ONLY = frozenset({'pytest', 'iniconfig', 'packaging', 'pluggy', 'pygments'})


def runtime_requirements(text):
    """從已核准 lock 移除測試工具；保留其餘項目的版本與雜湊原文。

Drop test-only tooling from the approved lock, keeping every other pin and hash verbatim."""
    blocks, current = [], None
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith('#'):
            current = [line]
            blocks.append(current)
        elif current is not None and line.strip().startswith('--hash='):
            current.append(line)
    kept, dropped = [], set()
    for block in blocks:
        name = canonical(block[0].split('==', 1)[0].split('[', 1)[0])
        (dropped.add(name) if name in TEST_ONLY else kept.append('\n'.join(block)))
    if dropped != TEST_ONLY:
        raise ValueError('approved lock no longer matches the test-only package set')
    return '\n'.join(kept) + '\n', sorted(dropped)


def build(audit):
    audit.stage("runtime-build")
    image = json.loads((ROOT / 'security/tools.lock.json').read_text())['python_runtime']['image']
    with tempfile.TemporaryDirectory(prefix='epsilon-runtime-') as directory:
        context = Path(directory)
        runtime_lock, excluded = runtime_requirements((ROOT / 'requirements.lock').read_text())
        (context / 'requirements.lock').write_text(runtime_lock)
        shutil.copyfile(ROOT / 'security/runtime/server.py', context / 'server.py')
        shutil.copyfile(ROOT / 'security/runtime/request.py', context / 'request.py')
        shutil.copytree(ROOT / '.state/wheels', context / 'wheels')
        (context / 'Dockerfile').write_text(f'''FROM {image}
COPY wheels /wheels
COPY requirements.lock /requirements.lock
RUN python -m pip --isolated install --no-index --find-links=/wheels --only-binary=:all: --no-deps --require-hashes --root-user-action=ignore -r /requirements.lock && python -m pip --isolated check && rm -rf /wheels /requirements.lock
COPY --chmod=0444 server.py /opt/epsilon/server.py
COPY --chmod=0444 request.py /opt/epsilon/request.py
RUN chmod 0755 /opt/epsilon
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/opt/epsilon/server.py"]
''')
        env = {**docker_environment(), 'BUILDX_CONFIG': str(ROOT / '.state/buildx')}
        subprocess.run(docker_command('build', '--network=none', '--tag', 'epsilon-trusted-runtime:local', str(context)),
                       check=True, env=env, timeout=600)
    image_id = subprocess.check_output(docker_command('image', 'inspect', 'epsilon-trusted-runtime:local', '--format', '{{.Id}}'),
                                       text=True, env=docker_environment(), timeout=30).strip()
    write_json(ROOT / '.state/runtime-image.json', {'image_id': image_id, 'base_image': image,
        'lock_sha256': hashlib.sha256((ROOT / 'requirements.lock').read_bytes()).hexdigest(),
        'excluded_test_packages': excluded,
        'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'request_sha256': hashlib.sha256((ROOT / 'security/runtime/request.py').read_bytes()).hexdigest(),
        'server_sha256': hashlib.sha256((ROOT / 'security/runtime/server.py').read_bytes()).hexdigest()})
    audit.data['runtime_image_id'] = image_id
    print('Trusted offline runtime built:', image_id)


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    audit = AuditRun(ROOT, 'runtime-build')
    try:
        build(audit)
        audit.data.update(decision='ALLOW', reasons=[])
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
    return audit.finish()


if __name__ == '__main__':
    raise SystemExit(main())
