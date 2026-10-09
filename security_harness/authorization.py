"""可信 oracle：核對完整合成回應契約與測試資料狀態。

Trusted oracle: exact synthetic response contracts and complete fixture state."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets


TABLES = {
    "users": ("id", "tenant", "role", "salt", "password_hash"),
    "items": ("id", "tenant", "owner", "value"),
    "sessions": ("token_hash", "user_id", "expires_at"),
}


def response_body(response):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate response key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("non-JSON response constant")
    return json.loads(response.content, object_pairs_hook=object_pairs,
                      parse_constant=invalid_constant) if response.content else None


def snapshot(dsn, schema, connect):
    with connect(dsn, schema) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        return {table: conn.execute(f"SELECT * FROM {table} ORDER BY {columns[0]}").fetchall()
                for table, columns in TABLES.items()}


def restore(dsn, schema, connect, state):
    """案例失敗後只還原本次合成 schema，避免連鎖失敗。

Restore only this run's synthetic schema after a failed case, avoiding cascades."""
    with connect(dsn, schema) as conn:
        for table in reversed(TABLES):
            conn.execute(f"DELETE FROM {table}")
        for table, columns in TABLES.items():
            with conn.cursor() as cursor:
                cursor.executemany(f"INSERT INTO {table} ({','.join(columns)}) VALUES "
                                   f"({','.join(['%s'] * len(columns))})",
                                   [tuple(row[c] for c in columns) for row in state[table]])


def evaluate(client, dsn, schema, passwords, connect):
    cases = []
    initial = snapshot(dsn, schema, connect)
    seeded_items = [{"id": i, "tenant": tenant, "owner": name, "value": name + "-private"}
                    for i, tenant, name in ((1, "t1", "alice"), (2, "t1", "bob"), (3, "t2", "carol"))]
    if initial["items"] != seeded_items or initial["sessions"]:
        raise ValueError("candidate modified seed before evaluation")

    def check(name, method, path, status, body, *, expected=None, **kwargs):
        before = snapshot(dsn, schema, connect)
        response = getattr(client, method)(path, **kwargs)
        try:
            actual_body = response_body(response)
        except ValueError:
            actual_body = object()
        after = snapshot(dsn, schema, connect)
        passed = response.status_code == status and actual_body == body and after == (expected or before)
        cases.append({"case": name, "passed": passed})
        if not passed:
            restore(dsn, schema, connect, before)

    check("wrong password denied without session", "post", "/login", 401, {"detail": "invalid credentials"},
          json={"username": "bob", "password": secrets.token_urlsafe(32)})
    check("unknown user denied without session", "post", "/login", 401, {"detail": "invalid credentials"},
          json={"username": "absent-" + secrets.token_hex(8), "password": secrets.token_urlsafe(32)})
    headers = {}
    for name, password in passwords.items():
        before = snapshot(dsn, schema, connect)
        response = client.post("/login", json={"username": name, "password": password})
        if response.status_code != 200:
            raise RuntimeError("fixture login failed; cannot evaluate authorization")
        body = response_body(response)
        token = body.get("access_token")
        if set(body) != {"access_token"} or not isinstance(token, str) or not 1 <= len(token) <= 256:
            raise ValueError("invalid login response")
        after = snapshot(dsn, schema, connect)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        new = [row for row in after["sessions"] if row not in before["sessions"]]
        expected = deepcopy(before)
        expected["sessions"] = sorted(before["sessions"] + new, key=lambda row: row["token_hash"])
        if (len(new) != 1 or new[0]["token_hash"] != token_hash or new[0]["user_id"] != name or
                not datetime.now(timezone.utc) < new[0]["expires_at"] <= datetime.now(timezone.utc) + timedelta(minutes=16)
                or after != expected):
            raise ValueError("login changed unexpected fixture state")
        headers[name] = {"Authorization": "Bearer " + token}

    check("anonymous denied", "get", "/items/1", 401, {"detail": "authentication required"})
    check("forged bearer denied", "get", "/items/1", 401, {"detail": "authentication required"},
          headers={"Authorization": "Bearer invalid"})
    check("owner reads own data", "get", "/items/1", 200, seeded_items[0], headers=headers["alice"])
    updated = {**seeded_items[0], "value": "owner-updated"}
    expected = snapshot(dsn, schema, connect)
    expected["items"][0] = updated
    check("owner updates own data", "patch", "/items/1", 200, updated, expected=expected,
          headers=headers["alice"], json={"value": "owner-updated"})
    for actor in ("bob", "carol"):
        check(f"{actor}: unauthorized read denied without data", "get", "/items/1", 404,
              {"detail": "item not found"}, headers=headers[actor])
        check(f"{actor}: unauthorized write denied without side effect", "patch", "/items/1", 404,
              {"detail": "item not found"}, headers=headers[actor], json={"value": "unauthorized-update"})
    check("same-tenant admin delegation allowed", "get", "/items/1", 200, updated, headers=headers["admin"])
    check("admin cross-tenant denied", "get", "/items/3", 404, {"detail": "item not found"}, headers=headers["admin"])
    check("member export denied", "get", "/admin/export", 403, {"detail": "admin required"}, headers=headers["alice"])
    check("admin export tenant-scoped", "get", "/admin/export", 200, [updated, seeded_items[1]], headers=headers["admin"])
    # 管理員委派也是寫入權限：同租戶須成功，跨租戶須阻擋。 / Admin delegation is a write privilege too: it must work in-tenant and stop at the tenant boundary.
    admin_updated = {**seeded_items[1], "value": "admin-updated"}
    expected = snapshot(dsn, schema, connect)
    expected["items"][1] = admin_updated
    check("same-tenant admin write allowed", "patch", "/items/2", 200, admin_updated, expected=expected,
          headers=headers["admin"], json={"value": "admin-updated"})
    check("admin cross-tenant write denied without side effect", "patch", "/items/3", 404,
          {"detail": "item not found"}, headers=headers["admin"], json={"value": "cross-tenant-update"})
    check("owner field cannot be reassigned", "patch", "/items/1", 422,
          {"detail": [{"type": "extra_forbidden", "loc": ["body", "owner"],
                       "msg": "Extra inputs are not permitted", "input": "bob"}]},
          headers=headers["alice"], json={"value": "x", "owner": "bob"})
    before = snapshot(dsn, schema, connect)
    expected = deepcopy(before)
    alice_hash = hashlib.sha256(headers["alice"]["Authorization"][7:].encode()).hexdigest()
    expected["sessions"] = [s for s in before["sessions"] if s["token_hash"] != alice_hash]
    response = client.post("/logout", headers=headers["alice"])
    after_logout = snapshot(dsn, schema, connect)
    denied = client.get("/items/1", headers=headers["alice"])
    try:
        denied_body = response_body(denied)
    except ValueError:
        denied_body = None
    cases.append({"case": "logout revokes session", "passed":
                  response.status_code == 204 and not response.content and after_logout == expected
                  and denied.status_code == 401 and denied_body == {"detail": "authentication required"}
                  and snapshot(dsn, schema, connect) == expected})

    expired = secrets.token_urlsafe(32)
    with connect(dsn, schema) as conn:
        conn.execute("INSERT INTO sessions VALUES (%s,%s,now()-interval '1 minute')",
                     (hashlib.sha256(expired.encode()).hexdigest(), 'bob'))
    expired_headers = {"Authorization": "Bearer " + expired}
    denied_body = {"detail": "authentication required"}
    check("expired session read denied", "get", "/items/2", 401, denied_body, headers=expired_headers)
    check("expired session logout denied", "post", "/logout", 401, denied_body, headers=expired_headers)
    check("anonymous delete denied", "delete", "/items/2", 401, denied_body)
    check("forged bearer delete denied", "delete", "/items/2", 401, denied_body,
          headers={"Authorization": "Bearer invalid"})
    check("expired session delete denied", "delete", "/items/2", 401, denied_body, headers=expired_headers)
    for actor in ('bob', 'carol'):
        check(f"{actor}: unauthorized delete denied without side effect", "delete", "/items/1", 404,
              {"detail": "item not found"}, headers=headers[actor])
    check("admin cross-tenant delete denied without side effect", "delete", "/items/3", 404,
          {"detail": "item not found"}, headers=headers['admin'])
    check("forged bearer logout denied", "post", "/logout", 401, denied_body,
          headers={"Authorization": "Bearer invalid"})
    check("SQL-like username denied without session", "post", "/login", 401,
          {"detail": "invalid credentials"}, json={"username": "' OR '1'='1", "password": "synthetic"})
    literal = "'; DELETE FROM items; --"
    expected = snapshot(dsn, schema, connect)
    expected['items'][1] = {**expected['items'][1], 'value': literal}
    check("SQL-like update remains literal data", "patch", "/items/2", 200, expected['items'][1],
          expected=expected, headers=headers['bob'], json={'value': literal})
    expected = snapshot(dsn, schema, connect)
    expected['items'] = [i for i in expected['items'] if i['id'] != 2]
    check("owner deletes own data", "delete", "/items/2", 204, None, expected=expected, headers=headers['bob'])
    check("repeated delete denied without side effect", "delete", "/items/2", 404,
          {"detail": "item not found"}, headers=headers['bob'])
    expected = snapshot(dsn, schema, connect)
    expected['items'] = [i for i in expected['items'] if i['id'] != 1]
    check("same-tenant admin delete allowed", "delete", "/items/1", 204, None,
          expected=expected, headers=headers['admin'])
    return cases


def run_authorization(dsn: str, variant: str = "fixed") -> list[dict]:
    # 僅供開發的 adapter；可信 CI 使用 isolation.run_isolated。 / Development-only adapter. Trusted CI uses isolation.run_isolated instead.
    from fastapi.testclient import TestClient
    from fixture_app.app import create_app, connect, seed, cleanup
    schema, passwords = seed(dsn)
    try:
        with TestClient(create_app(dsn, schema, variant=variant), follow_redirects=False) as client:
            return evaluate(client, dsn, schema, passwords, connect)
    finally:
        cleanup(dsn, schema)
