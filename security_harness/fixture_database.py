"""可信合成 seed 與資料庫 oracle，不從候選程式匯入。

Trusted synthetic seed and DB oracle; never imported from candidate code."""
import hashlib
import re
import secrets
import psycopg
from psycopg.rows import dict_row
from psycopg import sql


def connect(dsn, schema):
    if not re.fullmatch(r"epsilon_[a-f0-9]{16}", schema):
        raise ValueError("invalid fixture schema")
    # 候選角色可鎖定 items；oracle 查詢須在短時間內失敗而非等到整體逾時。 / The candidate role can lock items;
    # oracle queries must fail fast instead of waiting for the overall timeout.
    conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=3,
                           options="-c statement_timeout=5000 -c lock_timeout=2000")
    # pg_catalog 優先，候選 schema 不能遮蔽內建函式或運算子。 / pg_catalog first: the fixture schema cannot shadow built-ins.
    conn.execute(sql.SQL("SET search_path TO pg_catalog, {}").format(sql.Identifier(schema)))
    return conn


def password_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()


def seed(dsn: str) -> tuple[str, dict[str, str]]:
    schema = "epsilon_" + secrets.token_hex(8)
    passwords = {name: secrets.token_urlsafe(24) for name in ("alice", "bob", "carol", "admin")}
    with connect(dsn, schema) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        # pg_catalog 位於搜尋路徑首位，建立物件須明確指定 schema。 / pg_catalog leads the search path, so creation names the schema.
        for table, columns in (
                ("users", "id text PRIMARY KEY, tenant text NOT NULL, role text NOT NULL, salt text NOT NULL, password_hash text NOT NULL"),
                ("items", "id integer PRIMARY KEY, tenant text NOT NULL, owner text NOT NULL REFERENCES users(id), value text NOT NULL"),
                ("sessions", "token_hash text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), expires_at timestamptz NOT NULL")):
            conn.execute(sql.SQL("CREATE TABLE {} (" + columns + ")").format(sql.Identifier(schema, table)))
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
