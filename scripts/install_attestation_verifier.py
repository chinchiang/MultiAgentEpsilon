#!/usr/bin/env python3
"""只下載已審查的 CLI 執行檔，不解開任意封存路徑。

Download only the reviewed CLI binary; never unpack arbitrary archive paths."""
import argparse
import hashlib
import io
import json
import platform
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verified_binary(body, pin):
    if len(body) > 40 * 1024**2 or hashlib.sha256(body).hexdigest() != pin['archive_sha256']:
        raise ValueError('ARCHIVE_DIGEST')
    name = 'gh_' + pin['version'] + '_linux_amd64/bin/gh'
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        member = archive.getmember(name)
        if not member.isfile() or member.size > 128 * 1024**2:
            raise ValueError('BINARY_ENTRY')
        with archive.extractfile(member) as stream:
            binary = stream.read(128 * 1024**2 + 1)
    if hashlib.sha256(binary).hexdigest() != pin['binary_sha256']:
        raise ValueError('BINARY_DIGEST')
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('Only the reviewed Linux x86_64 release is supported.')
    pin = json.loads((ROOT / 'security/tools.lock.json').read_text())['github_cli']
    try:
        with urllib.request.urlopen(pin['url'], timeout=45) as response:
            binary = verified_binary(response.read(40 * 1024**2 + 1), pin)
        # 此工具不可覆寫既有正式部署 pins。 / Existing deployed pins must never be overwritten by this helper.
        with args.output.open('xb') as stream:
            stream.write(binary)
        args.output.chmod(0o755)
    except Exception:
        parser.exit(1, 'Verifier download or integrity validation failed.\n')
    print(json.dumps({'version': pin['version'], 'binary_sha256': pin['binary_sha256'],
                      'installed': str(args.output), 'deployment_verified': False}))


if __name__ == '__main__':
    main()
