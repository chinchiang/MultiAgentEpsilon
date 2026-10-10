"""已審查的合成缺陷回歸必須在真實隔離環境產生 AUTH findings。

Reviewed synthetic regressions must produce AUTH findings in real isolation."""
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
 # 寫入條件中的 admin 分支越過租戶邊界。 / The admin branch of the write predicate escapes the tenant boundary.
 'admin_cross_tenant_write': ("UPDATE items SET value=%s WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') RETURNING *",
                              "UPDATE items SET value=%s WHERE id=%s AND ((tenant=%s AND owner=%s) OR %s='admin') RETURNING *"),
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

MUTATIONS.update({
    'expired_session_accepted': (' AND s.expires_at>now()', ''),
    # 寫入端點自行查 session，未驗證到期與缺少身分。 / The write endpoint resolves sessions itself, ignoring expiry and missing identity.
    'patch_weaker_session_check': (
        'def update_item(item_id: ItemId, body: Update, user=Depends(principal)):\n'
        '        with connect(dsn, schema) as conn:\n',
        'def update_item(item_id: ItemId, body: Update, authorization: str = Header(default="")):\n'
        '        with connect(dsn, schema) as conn:\n'
        '            user = conn.execute("SELECT u.id,u.tenant,u.role FROM sessions s JOIN users u ON u.id=s.user_id '
        'WHERE s.token_hash=%s", (hashlib.sha256(authorization[7:].encode()).hexdigest(),)).fetchone() '
        'or {"id": "", "tenant": "", "role": ""}\n'),
    # 回應後才排程的跨租戶寫入；舊 oracle 的前後快照看不到。 / A cross-tenant write scheduled after the response,
    # invisible to per-request before/after snapshots.
    'delayed_cross_tenant_write': (
        '        if not row:\n            raise HTTPException(404, "item not found")\n\n    return app',
        '        if not row:\n            raise HTTPException(404, "item not found")\n'
        '        if user["role"] == "admin":\n'
        '            def later():\n'
        '                with connect(dsn, schema) as conn:\n'
        '                    conn.execute("UPDATE items SET value=\'delayed-side-effect\' WHERE id=3")\n'
        '            __import__("threading").Timer(0.3, later).start()\n\n    return app'),
    'admin_cross_tenant_delete': (
        "DELETE FROM items WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') RETURNING *",
        "DELETE FROM items WHERE id=%s AND ((tenant=%s AND owner=%s) OR %s='admin') RETURNING *"),
})

EXPECTED = {
    'expired_session_accepted': {'expired session read denied', 'expired session logout denied',
                                 'expired session delete denied', 'expired session write denied',
                                 'expired session export denied'},
    'patch_weaker_session_check': {'anonymous write denied', 'forged bearer write denied',
                                   'expired session write denied', 'logged-out session write denied'},
    'delayed_cross_tenant_write': {'no delayed or out-of-band state changes'},
    'admin_cross_tenant_delete': {'admin cross-tenant delete denied without side effect'},
    'wrong_password_accepted': {'wrong password denied without session'},
    'cross_tenant_404_leak': {'admin cross-tenant denied'},
    'export_nested_cross_tenant_leak': {'admin export tenant-scoped'},
    'admin_cross_tenant_write': {'admin cross-tenant write denied without side effect'},
    'denied_write_changes_other_row': {'bob: unauthorized write denied without side effect',
                                     'carol: unauthorized write denied without side effect',
                                     'admin cross-tenant write denied without side effect'},
}

@pytest.mark.integration
@pytest.mark.parametrize('mutation', list(MUTATIONS))
def test_real_candidate_mutations_are_blocked(tmp_path, mutation):
    shutil.copytree(ROOT / 'fixture_app', tmp_path / 'fixture_app', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copyfile(ROOT / 'requirements.lock', tmp_path / 'requirements.lock')
    app = tmp_path / 'fixture_app/app.py'
    source = app.read_text()
    old, new = MUTATIONS[mutation]
    assert source.count(old) == (2 if mutation == 'denied_write_changes_other_row' else 1), 'mutation must still apply to the actual candidate'
    app.write_text(source.replace(old, new, 1))
    observed = run_isolated(tmp_path)
    cases = observed['cases']
    validate_cases(cases, POLICY['gate_contracts']['AUTH'])
    failures = {c['case'] for c in cases if not c['passed']}
    assert failures == EXPECTED[mutation]
    # 把真實觀察接到政策判定，不假裝已執行 G1／G2。 / Connect the real observations to the policy decision, without pretending to run G1/G2.
    policy = {**POLICY, 'required_gates': ['AUTH'], 'gate_contracts': {'AUTH': POLICY['gate_contracts']['AUTH']}}
    record = result('AUTH', 'COMPLETED', 'test', len(cases), len(failures), 'subject', 'policy',
                    'real isolated mutation', run_id='mutation', cases=cases)
    assert decide([record], policy, 'subject', 'policy', run_id='mutation')['decision'] == 'BLOCK'
