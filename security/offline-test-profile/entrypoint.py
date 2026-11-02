"""受審閱映像的隔離探測與候選測試入口。

Reviewed-image isolation probe and candidate-test entrypoint.
"""
import errno
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import sys
import tarfile
import time
sys.path.insert(0, '/opt/supplemental')
from runtime_guard import verify as verify_runtime


def probe():
    profile = verify_runtime()
    status = Path('/proc/self/status').read_text()
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    assert os.getuid() == 10001 and os.getgid() == 10001
    assert int(fields['CapEff'].strip(), 16) == 0
    assert fields['NoNewPrivs'].strip() == '1'
    for name in ('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'AWS_ACCESS_KEY_ID'):
        assert name not in os.environ
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
        assert not os.environ.get(name)
    assert not Path('/var/run/docker.sock').exists()
    assert not Path('/home/runner').exists()
    for path in ('/opt/supplemental/write-probe', '/source/write-probe'):
        try:
            with open(path, 'w') as stream:
                stream.write('unexpected')
        except OSError as exc:
            assert exc.errno in (errno.EROFS, errno.EACCES)
        else:
            raise AssertionError('read-only mount was writable')
    with socket.socket() as connection:
        connection.settimeout(1)
        assert connection.connect_ex(('192.0.2.1', 443)) != 0
    Path('/results/isolation.json').write_text(json.dumps({
        'uid': os.getuid(), 'gid': os.getgid(), 'effective_capabilities': 0,
        'no_new_privileges': True, 'readonly_root_and_source': True,
        'ip_egress_blocked': True, 'credentials_and_docker_socket_absent': True,
        'classification': 'UNTRUSTED_SUPPLEMENTAL',
        'offline_test_profile': profile,
    }))


def main():
    probe()
    os.umask(0o077)
    work = Path('/work/repository')
    work.mkdir()
    # 不執行 tar 的候選連結、特殊檔案或路徑穿越。 / Reject links, special files and path traversal.
    with tarfile.open('/source/source.tar', 'r:') as archive:
        members = archive.getmembers()
        assert len(members) <= 2000 and sum(m.size for m in members) <= 32 * 1024 * 1024
        for member in members:
            path = PurePosixPath(member.name)
            assert member.isfile() and not path.is_absolute() and '..' not in path.parts
            target = work.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source:
                target.write_bytes(source.read())
            target.chmod(0o700 if member.mode & 0o111 else 0o600)
    Path('/work/home').mkdir()
    # 清除所有繼承環境後才執行候選程式。 / Clear inherited environment before executing candidate code.
    env = {
        'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/home', 'TMPDIR': '/tmp',
        'LD_LIBRARY_PATH': '/usr/local/lib', 'LANG': 'C.UTF-8', 'PYTHONUTF8': '1',
        'PYTHONPATH': '/opt/supplemental', 'PYTHONDONTWRITEBYTECODE': '1',
        'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1',
        'GIT_TEMPLATE_DIR': '/usr/local/share/git-core/templates',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    }
    with open('/results/test-output.txt', 'wb') as log:
        return subprocess.run([
            sys.executable, '-m', 'pytest', '-p', 'supplemental_manifest',
            'scratch/controlled_migration', 'tests/test_check_docs.py', '-q',
            '--junitxml=/results/migration-tests.xml',
        ], cwd=work, env=env, timeout=300, stdout=log, stderr=subprocess.STDOUT).returncode


if __name__ == '__main__':
    try:
        code = main()
    except Exception as exc:
        code = 125
        Path('/results/entrypoint-error.txt').write_text(type(exc).__name__)
    Path('/results/done.json').write_text(json.dumps({'exit_code': code}))
    # 保持 tmpfs 存活供控制器限量讀取；host 最後會移除這個專屬容器。
    # Keep tmpfs alive for bounded collection; the host always removes its own container.
    time.sleep(600)
