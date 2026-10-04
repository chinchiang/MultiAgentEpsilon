"""Trusted oracle shared by local development and external HTTP evaluation."""


def evaluate(client, dsn, schema, passwords, connect):
    cases = []
    def record(name, condition):
        cases.append({"case": name, "passed": bool(condition)})
    headers = {}
    for name, password in passwords.items():
        response = client.post("/login", json={"username": name, "password": password})
        if response.status_code != 200:
            raise RuntimeError("fixture login failed; cannot evaluate authorization")
        headers[name] = {"Authorization": "Bearer " + response.json()["access_token"]}
    record("anonymous denied", client.get("/items/1").status_code == 401)
    record("forged bearer denied", client.get("/items/1", headers={"Authorization": "Bearer invalid"}).status_code == 401)
    response = client.get("/items/1", headers=headers["alice"])
    record("owner reads own data", response.status_code == 200 and response.json().get("value") == "alice-private")
    response = client.patch("/items/1", headers=headers["alice"], json={"value": "owner-updated"})
    with connect(dsn, schema) as conn:
        value = conn.execute("SELECT value FROM items WHERE id=1").fetchone()["value"]
    record("owner updates own data", response.status_code == 200 and value == "owner-updated")
    for actor in ("bob", "carol"):
        response = client.get("/items/1", headers=headers[actor])
        record(f"{actor}: unauthorized read denied without data", response.status_code == 404 and "owner-updated" not in response.text)
        response = client.patch("/items/1", headers=headers[actor], json={"value": "unauthorized-update"})
        with connect(dsn, schema) as conn:
            value = conn.execute("SELECT value FROM items WHERE id=1").fetchone()["value"]
        record(f"{actor}: unauthorized write denied without side effect", response.status_code == 404 and value == "owner-updated")
        # Restore only this test's synthetic data so the next case is independent.
        with connect(dsn, schema) as conn:
            conn.execute("UPDATE items SET value='owner-updated' WHERE id=1")
    response = client.get("/items/1", headers=headers["admin"])
    record("same-tenant admin delegation allowed", response.status_code == 200)
    record("admin cross-tenant denied", client.get("/items/3", headers=headers["admin"]).status_code == 404)
    record("member export denied", client.get("/admin/export", headers=headers["alice"]).status_code == 403)
    response = client.get("/admin/export", headers=headers["admin"])
    record("admin export tenant-scoped", response.status_code == 200 and {x["id"] for x in response.json()} == {1, 2})
    record("owner field cannot be reassigned", client.patch("/items/1", headers=headers["alice"], json={"value": "x", "owner": "bob"}).status_code == 422)
    record("logout revokes session", client.post("/logout", headers=headers["alice"]).status_code == 204 and client.get("/items/1", headers=headers["alice"]).status_code == 401)
    return cases


def run_authorization(dsn: str, variant: str = "fixed") -> list[dict]:
    # Development-only adapter. Trusted CI uses isolation.run_isolated instead.
    from fastapi.testclient import TestClient
    from fixture_app.app import create_app, connect, seed, cleanup
    schema, passwords = seed(dsn)
    try:
        with TestClient(create_app(dsn, schema, variant=variant), follow_redirects=False) as client:
            return evaluate(client, dsn, schema, passwords, connect)
    finally:
        cleanup(dsn, schema)
