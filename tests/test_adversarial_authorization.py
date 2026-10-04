"""Reviewed synthetic regressions must produce AUTH findings in real isolation."""
import json
import shutil
from pathlib import Path

import pytest
from security_harness.isolation import run_isolated
from security_harness.results import decide, result, validate_cases

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "security/policy.json").read_text())

MUTATIONS = {'wrong_password_accepted': ('if not user or not hmac.compare_digest(actual, '
                             'user["password_hash"]):',
                             'if not user:'),
 'cross_tenant_404_leak': ('if row is None or (variant == "fixed" and not '
                           'permitted(row, user)):\n'
                           '            raise HTTPException(404, "item not '
                           'found")',
                           'if row is None or (variant == "fixed" and not '
                           'permitted(row, user)):\n'
                           '            if user["role"] == "admin" and row is '
                           'not None:\n'
                           '                raise HTTPException(404, '
                           'detail={"leaked": row})\n'
                           '            raise HTTPException(404, "item not '
                           'found")'),
 'export_nested_cross_tenant_leak': ('return conn.execute("SELECT * FROM items '
                                     'WHERE tenant=%s ORDER BY id", '
                                     '(user["tenant"],)).fetchall()',
                                     'rows = conn.execute("SELECT * FROM items '
                                     'WHERE tenant=%s ORDER BY id", '
                                     '(user["tenant"],)).fetchall()\n'
                                     '            other = conn.execute("SELECT '
                                     '* FROM items WHERE tenant<>%s", '
                                     '(user["tenant"],)).fetchall()\n'
                                     '            return [{**row, "leaked": '
                                     'other} for row in rows]'),
 'denied_write_changes_other_row': ('if not row:\n'
                                    '            raise HTTPException(404, '
                                    '"item not found")',
                                    'if not row:\n'
                                    '            with connect(dsn, schema) as '
                                    'conn:\n'
                                    '                conn.execute("UPDATE '
                                    "items SET value='unexpected-side-effect' "
                                    'WHERE id=3")\n'
                                    '            raise HTTPException(404, '
                                    '"item not found")')}

EXPECTED = {
    'wrong_password_accepted': {'wrong password denied without session'},
    'cross_tenant_404_leak': {'admin cross-tenant denied'},
    'export_nested_cross_tenant_leak': {'admin export tenant-scoped'},
    'denied_write_changes_other_row': {'bob: unauthorized write denied without side effect',
                                     'carol: unauthorized write denied without side effect'},
}

@pytest.mark.integration
@pytest.mark.parametrize('mutation', list(MUTATIONS))
def test_real_candidate_mutations_are_blocked(tmp_path, mutation):
    shutil.copytree(ROOT / 'fixture_app', tmp_path / 'fixture_app', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copyfile(ROOT / 'requirements.lock', tmp_path / 'requirements.lock')
    app = tmp_path / 'fixture_app/app.py'
    source = app.read_text()
    old, new = MUTATIONS[mutation]
    assert source.count(old) == 1, 'mutation must still apply to the actual candidate'
    app.write_text(source.replace(old, new))
    observed = run_isolated(tmp_path)
    cases = observed['cases']
    validate_cases(cases, POLICY['gate_contracts']['AUTH'])
    failures = {c['case'] for c in cases if not c['passed']}
    assert failures == EXPECTED[mutation]
    # Connect the real observations to the policy decision, without pretending to run G1/G2.
    policy = {**POLICY, 'required_gates': ['AUTH'], 'gate_contracts': {'AUTH': POLICY['gate_contracts']['AUTH']}}
    record = result('AUTH', 'COMPLETED', 'test', len(cases), len(failures), 'subject', 'policy',
                    'real isolated mutation', run_id='mutation', cases=cases)
    assert decide([record], policy, 'subject', 'policy', run_id='mutation')['decision'] == 'BLOCK'
