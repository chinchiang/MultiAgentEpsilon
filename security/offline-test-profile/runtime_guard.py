"""候選執行前驗證測試專用環境。 / Verify the test-only environment before candidate execution."""
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sysconfig


def verify(*, contract_path=Path('/opt/supplemental/runtime-contract.json'), gh_path=Path('/usr/local/bin/gh')):
    contract = json.loads(contract_path.read_text())
    distributions = list(importlib.metadata.distributions())
    installed = {d.metadata['Name'].lower(): d.version for d in distributions}
    if len(installed) != len(distributions):
        raise ValueError('DUPLICATE_PACKAGE_DISTRIBUTION')
    if installed != contract['packages']:
        raise ValueError('RUNTIME_PACKAGE_INVENTORY')
    for module in ('pip', 'ensurepip'):
        if importlib.util.find_spec(module) is not None:
            raise ValueError('BUILD_TOOL_PRESENT')
    if any(shutil.which(name) for name in ('pip', 'pip3', 'pip3.12')):
        raise ValueError('PIP_ENTRYPOINT_PRESENT')
    if (Path(sysconfig.get_path('stdlib'))/'ensurepip').exists():
        raise ValueError('ENSUREPIP_PRESENT')
    gh = gh_path
    if gh.is_symlink() or hashlib.sha256(gh.read_bytes()).hexdigest() != contract['gh_deny_sha256']:
        raise ValueError('GH_SENTINEL_DIGEST')
    probe = subprocess.run([str(gh), '--version'], capture_output=True, timeout=3)
    if probe.returncode != 126 or probe.stdout or probe.stderr != contract['gh_deny_stderr'].encode():
        raise ValueError('GH_SENTINEL_BEHAVIOR')
    return {'classification': 'OFFLINE_TEST_PROFILE_ONLY', 'runtime_package_count': len(installed),
            'build_tools_absent': True, 'gh_denies_execution': True,
            'contract_sha256': hashlib.sha256(contract_path.read_bytes()).hexdigest()}
