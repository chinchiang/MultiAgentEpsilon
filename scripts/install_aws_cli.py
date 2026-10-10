#!/usr/bin/env python3
"""在應用環境之外安裝已審查 AWS CLI。封存 pin 由 AWS 官方分離式 PGP 簽章建立；重用既有安裝時不可換成其他版本。

Install the reviewed AWS CLI release outside the application environment.

The archive pin was established from AWS's official detached PGP signature.
Reusing an existing installation never replaces it with a different version.
"""
import argparse
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


def executable_digest(binary):
    return hashlib.sha256(Path(binary).resolve(strict=True).read_bytes()).hexdigest()


def installed_matches(binary, marker, pin):
    """重用前核對安裝時記錄的封存 pin 與實際執行檔雜湊。

Before reuse, compare the archive pin and executable digest recorded at installation."""
    try:
        record = json.loads(Path(marker).read_text())
    except (OSError, ValueError):
        return False
    return (isinstance(record, dict) and record.get('archive_sha256') == pin['archive_sha256']
            and record.get('version') == pin['version']
            and record.get('executable_sha256') == executable_digest(binary))


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    pin = json.loads((ROOT / 'security/tools.lock.json').read_text())['aws_cli']
    binary = ROOT / '.tools/aws-bin/aws'
    marker = ROOT / '.tools/aws-cli.installed.json'
    try:
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise ValueError('AWS_PLATFORM')
        if binary.exists() and not installed_matches(binary, marker, pin):
            # 既有安裝無法證明來自已驗證封存；不可重用。 / An existing install that cannot be tied to the verified archive is not reused.
            raise ValueError('AWS_INSTALLATION_UNVERIFIED')
        if not binary.exists():
            with urllib.request.urlopen(pin['url'], timeout=60) as response:
                body = response.read(100 * 1024**2 + 1)
            with tempfile.TemporaryDirectory(prefix='epsilon-aws-install-') as temp:
                directory = Path(temp)
                unpack(body, pin, directory)
                subprocess.run([str(directory / 'aws/install'), '-i', str(ROOT / '.tools/aws-cli'),
                                '-b', str(ROOT / '.tools/aws-bin')], check=True, capture_output=True, timeout=120)
            marker.write_text(json.dumps({'version': pin['version'], 'archive_sha256': pin['archive_sha256'],
                                          'executable_sha256': executable_digest(binary)}) + '\n')
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
