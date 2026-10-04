from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from psycopg.rows import dict_row
from psycopg import sql
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[1]


def database_url() -> str:
    # No arbitrary external DSN: this pilot has one disposable local database.
    return json.loads((ROOT / ".state/db.json").read_text())["dsn"]


def connect(dsn: str, schema: str):
    url = urlsplit(dsn)
    if (url.scheme != "postgresql" or url.hostname != "127.0.0.1"
            or url.path != "/epsilon_fixture" or url.query or url.fragment):
        raise ValueError("only the disposable loopback fixture database is allowed")
    if not re.fullmatch(r"epsilon_[a-f0-9]{16}", schema):
        raise ValueError("invalid fixture schema")
    try:
        conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5)
    except psycopg.Error:
        raise RuntimeError("disposable PostgreSQL unavailable; connection details withheld") from None
    conn.execute(sql.SQL("SET search_path TO {}, pg_catalog").format(sql.Identifier(schema)))
    return conn


def password_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()


def seed(dsn: str) -> tuple[str, dict[str, str]]:
    schema = "epsilon_" + secrets.token_hex(8)
    passwords = {name: secrets.token_urlsafe(24) for name in ("alice", "bob", "carol", "admin")}
    with connect(dsn, schema) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        conn.execute("CREATE TABLE users (id text PRIMARY KEY, tenant text NOT NULL, role text NOT NULL, salt text NOT NULL, password_hash text NOT NULL)")
        conn.execute("CREATE TABLE items (id integer PRIMARY KEY, tenant text NOT NULL, owner text NOT NULL REFERENCES users(id), value text NOT NULL)")
        conn.execute("CREATE TABLE sessions (token_hash text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), expires_at timestamptz NOT NULL)")
        for name, password in passwords.items():
            salt = secrets.token_hex(16)
            conn.execute("INSERT INTO users VALUES (%s,%s,%s,%s,%s)",
                         (name, "t2" if name == "carol" else "t1", "admin" if name == "admin" else "member", salt, password_hash(password, salt)))
        for values in ((1, "t1", "alice", "alice-private"), (2, "t1", "bob", "bob-private"), (3, "t2", "carol", "carol-private")):
            conn.execute("INSERT INTO items VALUES (%s,%s,%s,%s)", values)
    return schema, passwords


def cleanup(dsn: str, schema: str):
    with connect(dsn, schema) as conn:
        conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class Update(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(min_length=1, max_length=128)


def create_app(dsn: str, schema: str, *, variant: str = "fixed") -> FastAPI:
    if variant not in ("fixed", "vulnerable"):
        raise ValueError("unknown fixture variant")
    # Explicit argument only; production server entry point never accepts this toggle.
    app = FastAPI(title="Epsilon synthetic fixture", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health():
        with connect(dsn, schema) as conn:
            count = conn.execute("SELECT count(*) AS count FROM users").fetchone()["count"]
        return {"ready": count == 4, "synthetic_fixture": True, "fixture_id": schema}

    @app.post("/login")
    def login(body: Login):
        with connect(dsn, schema) as conn:
            user = conn.execute("SELECT * FROM users WHERE id=%s", (body.username,)).fetchone()
            # Same KDF cost for absent users; credentials are generated per test run.
            salt = user["salt"] if user else "00" * 16
            actual = password_hash(body.password, salt)
            if not user or not hmac.compare_digest(actual, user["password_hash"]):
                raise HTTPException(401, "invalid credentials")
            token = secrets.token_urlsafe(32)
            conn.execute("INSERT INTO sessions VALUES (%s,%s,now()+interval '15 minutes')",
                         (hashlib.sha256(token.encode()).hexdigest(), user["id"]))
        return {"access_token": token}

    def principal(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer ") or len(authorization) > 256:
            raise HTTPException(401, "authentication required")
        token_hash = hashlib.sha256(authorization[7:].encode()).hexdigest()
        with connect(dsn, schema) as conn:
            user = conn.execute("SELECT u.id,u.tenant,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=%s AND s.expires_at>now()", (token_hash,)).fetchone()
        if not user:
            raise HTTPException(401, "authentication required")
        return user

    @app.post("/logout", status_code=204)
    def logout(user=Depends(principal), authorization: str = Header()):
        with connect(dsn, schema) as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=%s", (hashlib.sha256(authorization[7:].encode()).hexdigest(),))

    def permitted(row, user):
        return row and row["tenant"] == user["tenant"] and (row["owner"] == user["id"] or user["role"] == "admin")

    @app.get("/items/{item_id}")
    def get_item(item_id: int, user=Depends(principal)):
        with connect(dsn, schema) as conn:
            row = conn.execute("SELECT * FROM items WHERE id=%s", (item_id,)).fetchone()
        if row is None or (variant == "fixed" and not permitted(row, user)):
            raise HTTPException(404, "item not found")
        return row

    @app.patch("/items/{item_id}")
    def update_item(item_id: int, body: Update, user=Depends(principal)):
        with connect(dsn, schema) as conn:
            if variant == "vulnerable":
                # Deliberate seeded defect; same oracle must detect this variant.
                row = conn.execute("UPDATE items SET value=%s WHERE id=%s RETURNING *", (body.value, item_id)).fetchone()
            else:
                row = conn.execute("UPDATE items SET value=%s WHERE id=%s AND tenant=%s AND (owner=%s OR %s='admin') RETURNING *", (body.value, item_id, user["tenant"], user["id"], user["role"])).fetchone()
        if not row:
            raise HTTPException(404, "item not found")
        return row

    @app.get("/admin/export")
    def export(user=Depends(principal)):
        if user["role"] != "admin":
            raise HTTPException(403, "admin required")
        with connect(dsn, schema) as conn:
            return conn.execute("SELECT * FROM items WHERE tenant=%s ORDER BY id", (user["tenant"],)).fetchall()

    return app
