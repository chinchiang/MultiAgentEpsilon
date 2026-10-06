#!/usr/bin/env python3
"""Build the trusted runtime offline from verified wheels; never use a candidate Dockerfile."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.audit import AuditRun


def build(audit):
    audit.data["stage"] = "runtime-build"
    image = json.loads((ROOT / 'security/tools.lock.json').read_text())['python_runtime']['image']
    with tempfile.TemporaryDirectory(prefix='epsilon-runtime-') as directory:
        context = Path(directory)
        shutil.copyfile(ROOT / 'requirements.lock', context / 'requirements.lock')
        shutil.copyfile(ROOT / 'security/runtime/server.py', context / 'server.py')
        shutil.copyfile(ROOT / 'security/runtime/request.py', context / 'request.py')
        shutil.copytree(ROOT / '.state/wheels', context / 'wheels')
        (context / 'Dockerfile').write_text(f'''FROM {image}
COPY wheels /wheels
COPY requirements.lock /requirements.lock
RUN python -m pip --isolated install --no-index --find-links=/wheels --only-binary=:all: --no-deps --require-hashes -r /requirements.lock && rm -rf /wheels
COPY --chmod=0444 server.py /opt/epsilon/server.py
COPY --chmod=0444 request.py /opt/epsilon/request.py
RUN chmod 0755 /opt/epsilon
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/opt/epsilon/server.py"]
''')
        env = {**os.environ, 'BUILDX_CONFIG': str(ROOT / '.state/buildx')}
        subprocess.run(['docker', 'build', '--network=none', '--tag', 'epsilon-trusted-runtime:local', str(context)], check=True, env=env)
    image_id = subprocess.check_output(['docker', 'image', 'inspect', 'epsilon-trusted-runtime:local', '--format', '{{.Id}}'], text=True).strip()
    (ROOT / '.state/runtime-image.json').write_text(json.dumps({'image_id': image_id, 'base_image': image,
        'lock_sha256': hashlib.sha256((ROOT / 'requirements.lock').read_bytes()).hexdigest(),
        'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'request_sha256': hashlib.sha256((ROOT / 'security/runtime/request.py').read_bytes()).hexdigest(),
        'server_sha256': hashlib.sha256((ROOT / 'security/runtime/server.py').read_bytes()).hexdigest()}) + '\n')
    audit.data['runtime_image_id'] = image_id
    print('Trusted offline runtime built:', image_id)


def main():
    audit = AuditRun(ROOT, 'runtime-build')
    try:
        build(audit)
        audit.data.update(decision='ALLOW', reasons=[])
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
    return audit.finish()


if __name__ == '__main__':
    raise SystemExit(main())
