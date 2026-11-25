"""已審查的合成缺陷回歸必須在真實隔離環境產生 AUTH findings。

Reviewed synthetic regressions must produce AUTH findings in real isolation."""
import json
import shutil
from pathlib import Path

import pytest
from security_harness.isolation import run_isolated
from security_harness.results import decide, result, seeded_defects, validate_cases

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
    # 只擋舊 oracle 用過的假權杖，以及曾發出或仍在資料表中的權杖；其他從未見過的權杖一律當成 admin。既有的過期與登出
    # 案例都看不到，只有隨機權杖探測能發現。 / Rejects only the old oracle's forged token and tokens it issued or still
    # stores; any never-seen token becomes admin. Expired and logged-out cases cannot see it; only the random probe can.
    'unknown_token_admin_fallback': [(
        '            token = secrets.token_urlsafe(32)\n',
        '            token = secrets.token_urlsafe(32)\n'
        '            issued.add(hashlib.sha256(token.encode()).hexdigest())\n'), (
        '    def principal(',
        '    issued = set()\n\n    def principal('), (
        '        if not user:\n            raise HTTPException(401, "authentication required")\n        return user',
        '        if not user and authorization != "Bearer invalid" and token_hash not in issued:\n'
        '            with connect(dsn, schema) as conn:\n'
        '                known = conn.execute("SELECT 1 FROM sessions WHERE token_hash=%s", (token_hash,)).fetchone()\n'
        '            if not known:\n'
        '                user = {"id": "admin", "tenant": "t1", "role": "admin"}\n'
        '        if not user:\n            raise HTTPException(401, "authentication required")\n        return user')],
    # 契約外、未驗證身分的 PUT 後門。 / An unauthenticated PUT backdoor outside the contract.
    'unauthenticated_put_route': (
        '\n    return app',
        '\n    @app.put("/items/{item_id}")\n'
        '    def put_item(item_id: int, body: dict):\n'
        '        with connect(dsn, schema) as conn:\n'
        '            conn.execute("UPDATE items SET value=%s WHERE id=%s", (str(body.get("value")), item_id))\n'
        '        return {}\n\n    return app'),
    # 契約外的建立路由。 / A create route outside the contract.
    'hidden_create_route': (
        '\n    return app',
        '\n    @app.post("/items", status_code=201)\n'
        '    def create_item(body: dict):\n'
        '        return {"created": True}\n\n    return app'),
    'delayed_cross_tenant_write': (
        '        if not row:\n            raise HTTPException(404, "item not found")\n\n    return app',
        '        if not row:\n            raise HTTPException(404, "item not found")\n'
        '        if user["role"] == "admin":\n'
        '            def later():\n'
        '                with connect(dsn, schema) as conn:\n'
        '                    conn.execute("UPDATE items SET value=\'delayed-side-effect\' WHERE id=3")\n'
        '            __import__("threading").Timer(0.3, later).start()\n\n    return app'),
    # 本文正確，但被拒絕的讀取把他人資料放進回應標頭。 / A correct body, but the denied read leaks the row through a response header.
    'denied_read_header_leak': (
        'permitted(row, user)):\n            raise HTTPException(404, "item not found")\n        return row',
        'permitted(row, user)):\n'
        '            raise HTTPException(404, "item not found", headers={"X-Item": row["value"]} if row else None)\n'
        '        return row'),
    # 只在收到 variant="fixed" 時表現正確；正式呼叫（不帶 variant）走的是有漏洞的預設路徑。 /
    # Behaves only when told variant="fixed"; the production call (no variant) takes the vulnerable default.
    'variant_gated_backdoor': ('variant: str = "fixed"', 'variant: str = "vulnerable"'),
    'admin_cross_tenant_delete': (
        "DELETE FROM items WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') RETURNING *",
        "DELETE FROM items WHERE id=%s AND ((tenant=%s AND owner=%s) OR %s='admin') RETURNING *"),
})

MUTATIONS.update({
    # PATCH 接受 tenant 欄位，擁有者可把自己的項目搬到別的租戶。 / PATCH accepts a tenant field, so an owner can move
    # an item into another tenant.
    'tenant_mass_assignment': [(
        '    value: str = Field(min_length=1, max_length=128, pattern=NO_NUL)\n',
        '    value: str = Field(min_length=1, max_length=128, pattern=NO_NUL)\n'
        '    tenant: str | None = None\n'), (
        "UPDATE items SET value=%s WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') RETURNING *\", (body.value, item_id,",
        "UPDATE items SET value=%s, tenant=COALESCE(%s, tenant) WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') "
        "RETURNING *\", (body.value, body.tenant, item_id,")],
    # 匿名可呼叫的 /health 多回傳所有租戶的項目。 / The anonymous /health also returns every tenant's items.
    'health_leaks_items': (
        '        return {"ready": count == 4, "synthetic_fixture": True, "fixture_id": schema}',
        '        with connect(dsn, schema) as conn:\n'
        '            items = conn.execute("SELECT * FROM items ORDER BY id").fetchall()\n'
        '        return {"ready": count == 4, "synthetic_fixture": True, "fixture_id": schema, "items": items}'),
})

MUTATIONS.update({
    # 最後一次管理員刪除後，背景送出一個在資料庫端延遲數秒才提交的跨租戶寫入；候選程序被終止後，該敘述仍在
    # PostgreSQL 內執行。 / After the last admin delete, a background cross-tenant write is sent that the database
    # commits seconds later; the statement keeps running inside PostgreSQL after the candidate process is killed.
    'write_outlives_kill': (
        '        if not row:\n            raise HTTPException(404, "item not found")\n\n    return app',
        '        if not row:\n            raise HTTPException(404, "item not found")\n'
        '        if user["role"] == "admin":\n'
        '            def later():\n'
        '                with connect(dsn, schema) as conn:\n'
        '                    conn.execute("UPDATE items SET value=\'late-side-effect\' WHERE id=3 "\n'
        '                                 "AND (SELECT true FROM pg_sleep(4))")\n'
        '            __import__("threading").Thread(target=later, daemon=True).start()\n\n    return app'),
})

MUTATIONS.update({
    # 密碼只要與任一使用者的雜湊相符就放行；隨機密碼仍被拒，現有案例看不到。 / A password matching any user's hash is
    # accepted; random passwords are still refused, so the existing cases cannot see it.
    'cross_user_password_accepted': (
        '            if not user or not hmac.compare_digest(actual, user["password_hash"]):',
        '            hashes = conn.execute("SELECT salt, password_hash FROM users").fetchall()\n'
        '            if not user or not any(hmac.compare_digest(password_hash(body.password, row["salt"]), '
        'row["password_hash"]) for row in hashes):'),
    # 請求標頭自稱的角色覆寫資料庫中的角色。 / A role claimed in a request header overrides the stored role.
    'role_header_grants_admin': [(
        '    def principal(authorization: str | None = Header(default=None)):',
        '    def principal(authorization: str | None = Header(default=None), x_role: str | None = Header(default=None)):'), (
        '        if not user:\n            raise HTTPException(401, "authentication required")\n        return user',
        '        if not user:\n            raise HTTPException(401, "authentication required")\n'
        '        return {**user, "role": x_role or user["role"]}')],
    # 匯出端點接受查詢參數指定租戶。 / The export endpoint takes the tenant from a query parameter.
    'tenant_query_widens_export': [(
        '    def export(user=Depends(principal)):',
        '    def export(user=Depends(principal), tenant: str | None = None):'), (
        '(user["tenant"],)).fetchall()',
        '(tenant or user["tenant"],)).fetchall()')],
    # 只服務第一個租戶；第二租戶的擁有者讀不到自己的資料。 / Serves only the first tenant, so a second-tenant owner cannot
    # read their own data.
    'first_tenant_only': (
        '        return row and row["tenant"] == user["tenant"] and (',
        '        return row and row["tenant"] == user["tenant"] == "t1" and ('),
})

MUTATIONS.update({
    # 接受自帶身分宣告的未簽章權杖（JWT 的 alg none 類型）。 / Accepts an unsigned token carrying its own claims (the
    # JWT "alg none" class).
    'unsigned_token_accepted': (
        '        token_hash = hashlib.sha256(authorization[7:].encode()).hexdigest()\n'
        '        with connect(dsn, schema) as conn:\n            user = conn.execute("SELECT u.id',
        '        if authorization.count(".") == 2:\n'
        '            import base64\n'
        '            try:\n'
        '                claims = json.loads(base64.urlsafe_b64decode(authorization[7:].split(".")[1] + "=="))\n'
        '                return {"id": claims["sub"], "tenant": claims["tenant"], "role": claims["role"]}\n'
        '            except Exception:\n'
        '                pass\n'
        '        token_hash = hashlib.sha256(authorization[7:].encode()).hexdigest()\n'
        '        with connect(dsn, schema) as conn:\n            user = conn.execute("SELECT u.id'),
    # 沒有權杖時改信任請求標頭自稱的使用者。 / Without a token it trusts the user a request header claims.
    # 權杖就是使用者名稱：知道帳號就等於已登入。 / The token is the username: knowing an account is being signed in.
    'token_is_user_id': (
        '            token = secrets.token_urlsafe(32)\n',
        '            token = user["id"]\n'),
    # 權杖由使用者名稱與固定字串算出，夠長但每次登入都相同。 / The token derives from the username and a constant: long
    # enough, yet the same at every login.
    'deterministic_token': (
        '            token = secrets.token_urlsafe(32)\n',
        '            token = hashlib.sha256((user["id"] + "-fixed-pepper").encode()).hexdigest()\n'),
    # 權杖是遞增計數器：各不相同，但短到可以猜。 / The token is a counter: distinct, but short enough to guess.
    'counter_token': [(
        '            token = secrets.token_urlsafe(32)\n',
        '            sequence.append(1)\n            token = str(len(sequence))\n'), (
        '    def principal(',
        '    sequence = []\n\n    def principal(')],
    'header_identity_fallback': [(
        '    def principal(authorization: str | None = Header(default=None)):',
        '    def principal(authorization: str | None = Header(default=None), x_user: str | None = Header(default=None)):\n'
        '        if not authorization and x_user:\n'
        '            with connect(dsn, schema) as conn:\n'
        '                claimed = conn.execute("SELECT id,tenant,role FROM users WHERE id=%s", (x_user,)).fetchone()\n'
        '            if claimed:\n'
        '                return claimed')],
    # 管理員可以改寫租戶欄位；一般使用者仍得到與原本相同的輸入錯誤。 / An admin may rewrite the tenant field while
    # a member still gets the same input error as before.
    'admin_tenant_reassignment': [(
        '    value: str = Field(min_length=1, max_length=128, pattern=NO_NUL)\n',
        '    value: str = Field(min_length=1, max_length=128, pattern=NO_NUL)\n'
        '    tenant: str | None = None\n'), (
        '        with connect(dsn, schema) as conn:\n            if variant == "vulnerable":\n'
        '                # 刻意植入',
        '        if body.tenant is not None and user["role"] != "admin":\n'
        '            raise HTTPException(422, [{"type": "extra_forbidden", "loc": ["body", "tenant"],\n'
        '                                       "msg": "Extra inputs are not permitted", "input": body.tenant}])\n'
        '        with connect(dsn, schema) as conn:\n            if variant == "vulnerable":\n'
        '                # 刻意植入'), (
        "UPDATE items SET value=%s WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') RETURNING *\", (body.value, item_id,",
        "UPDATE items SET value=%s, tenant=COALESCE(%s, tenant) WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') "
        "RETURNING *\", (body.value, body.tenant, item_id,")],
    # 依覆寫標頭改變請求方法。 / Rewrites the request method from an override header.
    'method_override_honored': (
        '    @app.get("/health")\n',
        '    @app.middleware("http")\n'
        '    async def method_override(request, call_next):\n'
        '        override = request.headers.get("x-http-method-override")\n'
        '        if override:\n'
        '            request.scope["method"] = override.upper()\n'
        '        return await call_next(request)\n\n'
        '    @app.get("/health")\n'),
    # 不存在的項目回應與無權讀取不同，可用來列舉編號。 / A missing item answers differently from a forbidden one, which
    # enumerates ids.
    'missing_item_distinguishable': (
        '        if row is None or (variant == "fixed" and not permitted(row, user)):\n'
        '            raise HTTPException(404, "item not found")\n        return row',
        '        if row is None:\n'
        '            raise HTTPException(404, "no such item")\n'
        '        if row is None or (variant == "fixed" and not permitted(row, user)):\n'
        '            raise HTTPException(404, "item not found")\n        return row'),
    # 匯出結果以租戶為鍵快取，刪除後仍回傳舊資料。 / Export results are cached per tenant and keep serving old data
    # after deletes.
    'export_served_from_cache': [(
        '    @app.get("/admin/export")\n',
        '    export_cache = {}\n\n    @app.get("/admin/export")\n'), (
        '            return conn.execute("SELECT * FROM items WHERE tenant=%s ORDER BY id", (user["tenant"],)).fetchall()',
        '            rows = conn.execute("SELECT * FROM items WHERE tenant=%s ORDER BY id", (user["tenant"],)).fetchall()\n'
        '        return export_cache.setdefault(user["tenant"], rows)')],
})

EXPECTED = {
    'cross_user_password_accepted': {"another user's password denied without session"},
    'unsigned_token_accepted': {'unsigned self-describing token denied'},
    'token_is_user_id': {'bearer naming a user denied', 'login tokens are distinct and at least 32 characters'},
    'deterministic_token': {'login tokens are distinct and at least 32 characters'},
    'counter_token': {'login tokens are distinct and at least 32 characters'},
    'header_identity_fallback': {'identity outside the session cannot authenticate'},
    'admin_tenant_reassignment': {'admin cannot reassign tenant'},
    'method_override_honored': {'method override header cannot delete'},
    'missing_item_distinguishable': {'missing item indistinguishable from forbidden'},
    'export_served_from_cache': {'admin export reflects deletions'},
    'role_header_grants_admin': {'role header cannot grant admin'},
    'tenant_query_widens_export': {'tenant query cannot widen admin export'},
    'first_tenant_only': {'second-tenant owner reads own data'},
    'write_outlives_kill': {'no delayed or out-of-band state changes'},
    'tenant_mass_assignment': {'tenant field cannot be reassigned', 'admin cannot reassign tenant'},
    'health_leaks_items': {'health exposes only readiness'},
    'variant_gated_backdoor': seeded_defects(POLICY['gate_contracts']['AUTH']),
    'expired_session_accepted': {'expired session read denied', 'expired session logout denied',
                                 'expired session delete denied', 'expired session write denied',
                                 'expired session export denied'},
    'patch_weaker_session_check': {'anonymous write denied', 'forged bearer write denied',
                                   'expired session write denied', 'logged-out session write denied'},
    'delayed_cross_tenant_write': {'no delayed or out-of-band state changes'},
    'unknown_token_admin_fallback': {'random bearer token denied', 'unsigned self-describing token denied',
                                     'bearer naming a user denied'},
    'unauthenticated_put_route': {'unlisted item method rejected without side effect'},
    'hidden_create_route': {'unlisted item create not found'},
    'denied_read_header_leak': {'bob: unauthorized read denied without data',
                                'carol: unauthorized read denied without data', 'admin cross-tenant denied'},
    'admin_cross_tenant_delete': {'admin cross-tenant delete denied without side effect'},
    # 不驗密碼的登入，隨機密碼與別人的密碼都會放行。 / A login that checks no password admits a random one and
    # someone else's alike.
    'wrong_password_accepted': {'wrong password denied without session',
                                "another user's password denied without session"},
    'cross_tenant_404_leak': {'admin cross-tenant denied'},
    # 兩個匯出案例比對同一份內容，夾帶他租戶資料時都會失敗。 / Both export cases compare the same content, so a
    # nested cross-tenant leak fails each.
    'export_nested_cross_tenant_leak': {'admin export tenant-scoped', 'tenant query cannot widen admin export'},
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
    # 多處修改的變體以 (old, new) 清單表示。 / A multi-site mutation is a list of (old, new) pairs.
    pairs = MUTATIONS[mutation] if isinstance(MUTATIONS[mutation], list) else [MUTATIONS[mutation]]
    for old, new in pairs:
        assert source.count(old) == (2 if mutation == 'denied_write_changes_other_row' else 1), 'mutation must still apply to the actual candidate'
        source = source.replace(old, new, 1)
    app.write_text(source)
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
