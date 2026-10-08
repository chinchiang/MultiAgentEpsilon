"""Offline evidence fixtures; they never query a public database."""
import tempfile
from pathlib import Path
from security_harness.dependencies import scan


def clean_evidence(count, now=None):
    names = [f'example{i}' for i in range(count)]
    packages = [{'name': n, 'version': '1.0', 'approved_hashes': ['a' * 64]} for n in names]
    with tempfile.TemporaryDirectory() as directory:
        lock = Path(directory) / 'requirements.lock'
        lock.write_text(''.join(n + '==1.0 --hash=sha256:' + 'a' * 64 + '\n' for n in names))
        evidence = scan(lock, fetch=lambda *args: {}, now=now)
    return packages, evidence
