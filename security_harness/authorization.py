"""可信 oracle：核對完整合成回應契約與測試資料狀態。

Trusted oracle: exact synthetic response contracts and complete fixture state."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
import time

from .fixture_database import FixtureDatabase, connect as default_connect, seeded_items

# 最後一個案例後的靜置時間，用來攔截延遲寫入。 / Quiet period after the last case, so delayed writes are observed.
SETTLE_SECONDS = 1.0
DRIFT_CASE = "no delayed or out-of-band state changes"
# uvicorn／Starlette 對合成 JSON 契約固定送出的標頭；content-length 只在有本文時出現。 / Headers uvicorn and
# Starlette always send for the synthetic JSON contract; content-length appears only with a body.
RESPONSE_HEADERS = {b"date", b"server", b"content-type"}
DATE_HEADER = re.compile(rb"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} "
                         rb"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT")


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


def headers_match(response, allow=None):
    """標頭也屬於回應契約：只允許固定的 date、server、content-type、相符的 content-length 與單一 connection: close，避免資料藏在標頭。

Headers are part of the response contract: only the fixed date, server and content-type
    plus a matching content-length and one connection: close are allowed, so no data can hide in a header."""
    actual = sorted((name.lower(), value) for name, value in response.headers.raw)
    if (b"connection", b"close") in actual:
        # bridge 每次要求關閉連線，伺服器回送一次相同的逐跳標頭。 / The bridge closes every connection and the server echoes it once.
        actual.remove((b"connection", b"close"))
    expected = RESPONSE_HEADERS | ({b"content-length"} if response.content else set()) | ({b"allow"} if allow else set())
    if [name for name, _ in actual] != sorted(expected):
        return False
    values = dict(actual)
    if allow and values[b"allow"] != allow:
        return False
    return (bool(DATE_HEADER.fullmatch(values[b"date"])) and values[b"server"] == b"uvicorn"
            and values[b"content-type"] == b"application/json"
            and values.get(b"content-length", b"%d" % len(response.content)) == b"%d" % len(response.content))


def same(actual, expected):
    """遞迴比對 JSON 值與型別，避免 1、1.0 與 True 被視為相等。

Recursive JSON equality that also compares types, so 1, 1.0 and True differ."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(same(actual[k], expected[k]) for k in expected)
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(same(a, e) for a, e in zip(actual, expected))
    return actual == expected


def evaluate(client, dsn, schema=None, passwords=None, connect=default_connect, settle=SETTLE_SECONDS, stop=None):
    """stop 在靜置後停止候選（含它在資料庫端的連線），再做最終快照；之後候選不可能再寫入。stop 回傳真值時，
    代表停止當下仍有工作在進行，計為延遲副作用。

When given, stop() halts the candidate (its database sessions included) after the settle period and before the
final snapshot, so no candidate write can arrive after the last comparison. A true result means work was still in
flight when it was stopped and counts as a delayed side effect."""
    db = dsn if isinstance(dsn, FixtureDatabase) else FixtureDatabase(dsn, schema, passwords, connect)
    schema, passwords = db.schema, db.passwords
    cases = []
    initial = db.snapshot()
    initial_items = seeded_items()
    if initial["items"] != initial_items or initial["sessions"]:
        raise ValueError("candidate modified seed before evaluation")
    # oracle 自行維護預期狀態；案例之間的任何變動都是延遲或帶外副作用。 / The oracle owns the expected state;
    # any change between cases is a delayed or out-of-band side effect.
    model = {"state": initial, "drift": False}

    def observe():
        current = db.snapshot()
        if current != model["state"]:
            model["drift"] = True
            db.restore(model["state"])
        return deepcopy(model["state"])

    def check(name, method, path, status, body, *, expected=None, allow=None, **kwargs):
        before = observe()
        response = client.request(method.upper(), path, **kwargs)
        try:
            actual_body = response_body(response)
            body_matches = same(actual_body, body)
        except ValueError:
            body_matches = False
        after = db.snapshot()
        target = expected or before
        passed = response.status_code == status and body_matches and headers_match(response, allow) and after == target
        cases.append({"case": name, "passed": passed})
        if passed:
            model["state"] = target
        else:
            db.restore(before)

    def expect(change):
        """以 oracle 模型為基礎產生預期狀態，不吸收候選造成的漂移。 / Build expectations from the oracle model, never from candidate drift."""
        state = deepcopy(model["state"])
        change(state)
        return state

    check("wrong password denied without session", "post", "/login", 401, {"detail": "invalid credentials"},
          json={"username": "bob", "password": secrets.token_urlsafe(32)})
    check("unknown user denied without session", "post", "/login", 401, {"detail": "invalid credentials"},
          json={"username": "absent-" + secrets.token_hex(8), "password": secrets.token_urlsafe(32)})
    # 別人的密碼也是錯誤密碼：只用隨機密碼測，看不出「任一使用者的密碼都能登入」。 / Someone else's password is a
    # wrong password too; random passwords alone cannot reveal a login that accepts any user's password.
    check("another user's password denied without session", "post", "/login", 401, {"detail": "invalid credentials"},
          json={"username": "bob", "password": passwords["alice"]})
    headers = {}
    for name, password in passwords.items():
        before = observe()
        response = client.post("/login", json={"username": name, "password": password})
        if response.status_code != 200:
            raise RuntimeError("fixture login failed; cannot evaluate authorization")
        body = response_body(response)
        token = body.get("access_token")
        if (set(body) != {"access_token"} or not isinstance(token, str) or not 1 <= len(token) <= 256
                or not headers_match(response)):
            raise ValueError("invalid login response")
        after = db.snapshot()
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        new = [row for row in after["sessions"] if row not in before["sessions"]]
        expected = deepcopy(before)
        expected["sessions"] = sorted(before["sessions"] + new, key=lambda row: row["token_hash"])
        if (len(new) != 1 or new[0]["token_hash"] != token_hash or new[0]["user_id"] != name or
                not datetime.now(timezone.utc) < new[0]["expires_at"] <= datetime.now(timezone.utc) + timedelta(minutes=16)
                or after != expected):
            raise ValueError("login changed unexpected fixture state")
        model["state"] = expected
        headers[name] = {"Authorization": "Bearer " + token}

    check("anonymous denied", "get", "/items/1", 401, {"detail": "authentication required"})
    check("forged bearer denied", "get", "/items/1", 401, {"detail": "authentication required"},
          headers={"Authorization": "Bearer invalid"})
    # 身分只能來自伺服器端的 session：自帶身分宣告的未簽章權杖，以及標頭、cookie、查詢參數自稱的身分，都不算。 /
    # Identity comes only from a server-side session: neither an unsigned token carrying its own claims nor an
    # identity asserted through headers, a cookie or the query string counts.
    claims = base64.urlsafe_b64encode(json.dumps(
        {"sub": "admin", "tenant": "t1", "role": "admin"}, separators=(",", ":")).encode()).rstrip(b"=").decode()
    check("unsigned self-describing token denied", "get", "/admin/export", 401,
          {"detail": "authentication required"}, headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0." + claims + "."})
    check("identity outside the session cannot authenticate", "get", "/admin/export?access_token=admin&user=admin",
          401, {"detail": "authentication required"},
          headers={"X-User": "admin", "X-Tenant": "t1", "X-Forwarded-User": "admin", "Cookie": "session=admin; user=admin"})
    # /health 不需身分，所以也屬於契約：只能回報就緒狀態，不得夾帶其他資料。 / /health needs no identity, so it is
    # part of the contract too: it reports readiness and nothing else.
    check("health exposes only readiness", "get", "/health", 200,
          {"ready": True, "synthetic_fixture": True, "fixture_id": schema})
    check("owner reads own data", "get", "/items/1", 200, initial_items[0], headers=headers["alice"])
    # 允許路徑不能只在第一個租戶成立。 / The allowed path must hold outside the first tenant too.
    check("second-tenant owner reads own data", "get", "/items/3", 200, initial_items[2], headers=headers["carol"])
    updated = {**initial_items[0], "value": "owner-updated"}
    expected = expect(lambda state: state["items"].__setitem__(0, updated))
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
    check("admin export tenant-scoped", "get", "/admin/export", 200, [updated, initial_items[1]], headers=headers["admin"])
    # 身分與範圍只能來自 session：請求自稱的角色或租戶一律不採計。 / Identity and scope come from the session only;
    # a role or tenant the request claims for itself never counts.
    check("role header cannot grant admin", "get", "/admin/export", 403, {"detail": "admin required"},
          headers={**headers["alice"], "X-Role": "admin"})
    check("tenant query cannot widen admin export", "get", "/admin/export?tenant=t2", 200,
          [updated, initial_items[1]], headers=headers["admin"])
    # 管理員委派也是寫入權限：同租戶須成功，跨租戶須阻擋。 / Admin delegation is a write privilege too: it must work in-tenant and stop at the tenant boundary.
    admin_updated = {**initial_items[1], "value": "admin-updated"}
    expected = expect(lambda state: state["items"].__setitem__(1, admin_updated))
    check("same-tenant admin write allowed", "patch", "/items/2", 200, admin_updated, expected=expected,
          headers=headers["admin"], json={"value": "admin-updated"})
    check("admin cross-tenant write denied without side effect", "patch", "/items/3", 404,
          {"detail": "item not found"}, headers=headers["admin"], json={"value": "cross-tenant-update"})
    check("owner field cannot be reassigned", "patch", "/items/1", 422,
          {"detail": [{"type": "extra_forbidden", "loc": ["body", "owner"],
                       "msg": "Extra inputs are not permitted", "input": "bob"}]},
          headers=headers["alice"], json={"value": "x", "owner": "bob"})
    check("tenant field cannot be reassigned", "patch", "/items/1", 422,
          {"detail": [{"type": "extra_forbidden", "loc": ["body", "tenant"],
                       "msg": "Extra inputs are not permitted", "input": "t2"}]},
          headers=headers["alice"], json={"value": "x", "tenant": "t2"})
    # 管理員的寫入權也只到欄位 value：能改租戶就能把資料搬出租戶邊界。 / An admin's write privilege stops at the value
    # field too: reassigning the tenant would carry data across the tenant boundary.
    check("admin cannot reassign tenant", "patch", "/items/2", 422,
          {"detail": [{"type": "extra_forbidden", "loc": ["body", "tenant"],
                       "msg": "Extra inputs are not permitted", "input": "t2"}]},
          headers=headers["admin"], json={"value": "x", "tenant": "t2"})
    before = observe()
    expected = deepcopy(before)
    alice_hash = hashlib.sha256(headers["alice"]["Authorization"][7:].encode()).hexdigest()
    expected["sessions"] = [s for s in before["sessions"] if s["token_hash"] != alice_hash]
    response = client.post("/logout", headers=headers["alice"])
    after_logout = db.snapshot()
    denied = client.get("/items/1", headers=headers["alice"])
    try:
        denied_matches = same(response_body(denied), {"detail": "authentication required"})
    except ValueError:
        denied_matches = False
    logged_out = (response.status_code == 204 and not response.content and headers_match(response)
                  and after_logout == expected and denied.status_code == 401 and denied_matches
                  and headers_match(denied)
                  and db.snapshot() == expected)
    cases.append({"case": "logout revokes session", "passed": logged_out})
    model["state"] = expected
    if not logged_out:
        db.restore(expected)
    denied_body = {"detail": "authentication required"}
    # 撤銷後的權杖對每個需要身分的端點都必須失效。 / A revoked token must fail on every authenticated endpoint.
    check("logged-out session write denied", "patch", "/items/1", 401, denied_body,
          headers=headers["alice"], json={"value": "after-logout"})
    check("logged-out session delete denied", "delete", "/items/1", 401, denied_body, headers=headers["alice"])
    check("logged-out session export denied", "get", "/admin/export", 401, denied_body, headers=headers["alice"])

    expired = secrets.token_urlsafe(32)
    expired_row = {"token_hash": hashlib.sha256(expired.encode()).hexdigest(), "user_id": "bob",
                   "expires_at": datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)}
    observe()
    db.insert_session(expired_row)
    model["state"] = expect(lambda state: state.__setitem__(
        "sessions", sorted(state["sessions"] + [expired_row], key=lambda row: row["token_hash"])))
    expired_headers = {"Authorization": "Bearer " + expired}
    forged = {"Authorization": "Bearer invalid"}
    check("expired session read denied", "get", "/items/2", 401, denied_body, headers=expired_headers)
    # 寫入與匯出也須拒絕匿名、偽造與過期身分。 / Writes and export must also refuse anonymous, forged and expired identities.
    check("anonymous write denied", "patch", "/items/2", 401, denied_body, json={"value": "anonymous-update"})
    check("forged bearer write denied", "patch", "/items/2", 401, denied_body, headers=forged,
          json={"value": "forged-update"})
    check("expired session write denied", "patch", "/items/2", 401, denied_body, headers=expired_headers,
          json={"value": "expired-update"})
    check("anonymous export denied", "get", "/admin/export", 401, denied_body)
    check("forged bearer export denied", "get", "/admin/export", 401, denied_body, headers=forged)
    check("expired session export denied", "get", "/admin/export", 401, denied_body, headers=expired_headers)
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
    # 越界與 NUL 輸入須是可預期的輸入錯誤，而非伺服器錯誤。 / Out-of-range and NUL input must be input errors, not server errors.
    check("out-of-range item id rejected as input error", "get", "/items/2147483648", 422,
          {"detail": [{"type": "less_than_equal", "loc": ["path", "item_id"],
                       "msg": "Input should be less than or equal to 2147483647", "input": "2147483648",
                       "ctx": {"le": 2147483647}}]}, headers=headers['bob'])
    check("NUL byte in update rejected without side effect", "patch", "/items/2", 422,
          {"detail": [{"type": "string_pattern_mismatch", "loc": ["body", "value"],
                       "msg": "String should match pattern '^[^\\x00]*$'", "input": "a\x00b",
                       "ctx": {"pattern": "^[^\\x00]*$"}}]}, headers=headers['bob'], json={"value": "a\x00b"})
    # 黑箱只能證明已知契約；另探測契約外的權杖、方法與路由，必須一律拒絕且無副作用。 / A black box only proves the known
    # contract, so also probe tokens, methods and routes outside it: each must be refused without side effects.
    check("random bearer token denied", "get", "/items/1", 401, denied_body,
          headers={"Authorization": "Bearer " + secrets.token_urlsafe(32)})
    check("unlisted item method rejected without side effect", "put", "/items/3", 405,
          {"detail": "Method Not Allowed"}, allow=b"GET", headers=headers["carol"],
          json={"value": "put-update", "owner": "admin", "tenant": "t1"})
    # 方法只看請求列：覆寫標頭不得把 POST 變成 DELETE。 / The method is the request line's; an override header must
    # not turn a POST into a DELETE.
    check("method override header cannot delete", "post", "/items/3", 405, {"detail": "Method Not Allowed"},
          allow=b"GET", headers={**headers["carol"], "X-HTTP-Method-Override": "DELETE", "X-Method-Override": "DELETE"})
    # 不存在與無權讀取的回應必須相同，否則可用來列舉其他租戶的項目編號。 / A missing item and a forbidden one must
    # answer alike, or the difference enumerates other tenants' item ids.
    check("missing item indistinguishable from forbidden", "get", "/items/999", 404, {"detail": "item not found"},
          headers=headers["bob"])
    check("unlisted item create not found", "post", "/items", 404, {"detail": "Not Found"},
          headers=headers["carol"], json={"id": 9, "value": "created", "owner": "carol", "tenant": "t1"})
    check("unlisted route not found", "get", "/" + secrets.token_hex(8), 404, {"detail": "Not Found"},
          headers=headers["carol"])
    literal = "'; DELETE FROM items; --"
    expected = expect(lambda state: state['items'].__setitem__(1, {**state['items'][1], 'value': literal}))
    check("SQL-like update remains literal data", "patch", "/items/2", 200, expected['items'][1],
          expected=expected, headers=headers['bob'], json={'value': literal})
    expected = expect(lambda state: state.__setitem__('items', [i for i in state['items'] if i['id'] != 2]))
    check("owner deletes own data", "delete", "/items/2", 204, None, expected=expected, headers=headers['bob'])
    check("repeated delete denied without side effect", "delete", "/items/2", 404,
          {"detail": "item not found"}, headers=headers['bob'])
    expected = expect(lambda state: state.__setitem__('items', [i for i in state['items'] if i['id'] != 1]))
    check("same-tenant admin delete allowed", "delete", "/items/1", 204, None,
          expected=expected, headers=headers['admin'])
    # 刪除後的讀取必須反映現況：快取或舊快照不得繼續提供已刪除的資料。 / A read after the deletes must show the current
    # state: no cache or old snapshot may keep serving deleted data.
    check("admin export reflects deletions", "get", "/admin/export", 200, [], headers=headers['admin'])
    # 靜置讓排程中的寫入落地，再停止候選做最終比對，之後不會再有任何寫入。 / Settle so scheduled writes land, then
    # stop the candidate for the final comparison, after which no write can arrive.
    time.sleep(settle)
    # stop 回傳真值代表候選被停止時仍有工作在進行（例如資料庫端還在執行的敘述），視同延遲副作用。 / A true result
    # from stop means the candidate still had work in flight when it was stopped (a statement still running in
    # the database, say), which counts as a delayed side effect.
    if stop is not None and stop():
        model["drift"] = True
    observe()
    cases.append({"case": DRIFT_CASE, "passed": not model["drift"]})
    return cases


def run_authorization(dsn: str, variant: str = "fixed") -> list[dict]:
    """僅供開發：在本機 loopback 以真實 HTTP 執行同一 oracle；可信 CI 使用 isolation.run_isolated。

Development only: the same oracle over real loopback HTTP; trusted CI uses isolation.run_isolated."""
    import socket
    import threading
    import httpx
    import uvicorn
    from fixture_app.app import create_app, connect
    db = FixtureDatabase.create(dsn, connect=connect)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        server = uvicorn.Server(uvicorn.Config(create_app(dsn, db.schema, variant=variant), log_level="error",
                                               access_log=False, lifespan="off"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                if time.monotonic() >= deadline or not thread.is_alive():
                    raise RuntimeError("local fixture server did not start")
                time.sleep(0.02)
            base = "http://127.0.0.1:%d" % listener.getsockname()[1]
            with httpx.Client(base_url=base, timeout=10, trust_env=False, follow_redirects=False) as client:
                return evaluate(client, db)
        finally:
            server.should_exit = True
            thread.join(timeout=10)
    finally:
        listener.close()
        db.cleanup()
