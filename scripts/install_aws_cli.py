#!/usr/bin/env python3
"""Install the reviewed AWS CLI release outside the application environment.

The archive pin was established from AWS's official detached PGP signature.
Reusing an existing installation never replaces it with a different version.
"""
import hashlib
import io
import json
import platform
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def unpack(body, pin, directory):
    if len(body) > 100 * 1024**2 or hashlib.sha256(body).hexdigest() != pin['archive_sha256']:
        raise ValueError('AWS_ARCHIVE_DIGEST')
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        entries = archive.infolist()
        if len(entries) > 10000 or sum(e.file_size for e in entries) > 512 * 1024**2:
            raise ValueError('AWS_ARCHIVE_LIMIT')
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in entry.filename:
                raise ValueError('AWS_ARCHIVE_ENTRY')
        archive.extractall(directory)
        for entry in entries:
            if not entry.is_dir():
                (directory / entry.filename).chmod(0o755 if (entry.external_attr >> 16) & 0o111 else 0o644)


def main():
    pin = json.loads((ROOT / 'security/tools.lock.json').read_text())['aws_cli']
    binary = ROOT / '.tools/aws-bin/aws'
    try:
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise ValueError('AWS_PLATFORM')
        if not binary.exists():
            with urllib.request.urlopen(pin['url'], timeout=60) as response:
                body = response.read(100 * 1024**2 + 1)
            with tempfile.TemporaryDirectory(prefix='epsilon-aws-install-') as temp:
                directory = Path(temp)
                unpack(body, pin, directory)
                subprocess.run([str(directory / 'aws/install'), '-i', str(ROOT / '.tools/aws-cli'),
                                '-b', str(ROOT / '.tools/aws-bin')], check=True, capture_output=True, timeout=120)
        version = subprocess.check_output([str(binary), '--version'], text=True, stderr=subprocess.DEVNULL, timeout=10)
        if not version.startswith('aws-cli/' + pin['version'] + ' '):
            raise ValueError('AWS_VERSION')
    except Exception:
        print(json.dumps({'installed': False, 'code': 'AWS_INSTALLATION_INVALID'}))
        return 1
    print(json.dumps({'installed': True, 'version': pin['version'], 'executable': str(binary)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
