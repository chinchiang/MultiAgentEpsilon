"""可信合成 seed 與資料庫 oracle，不從候選程式匯入。

Trusted synthetic seed and DB oracle; never imported from candidate code."""
import hashlib
import re
import secrets
import types
import psycopg
from psycopg.rows import dict_row
from psycopg import sql

CANDIDATE_ROLE = "epsilon_app"
TABLES = {
    "users": ("id", "tenant", "role", "salt", "password_hash"),
    "items": ("id", "tenant", "owner", "value"),
    "sessions": ("token_hash", "user_id", "expires_at"),
}
SEED_ITEMS = ((1, "t1", "alice", "alice-private"), (2, "t1", "bob", "bob-private"), (3, "t2", "carol", "carol-private"))


def seeded_items() -> list[dict]:
    """回傳初始合成 items 紀錄清單。 / Return the initial synthetic item rows."""
    return [{"id": i, "tenant": tenant, "owner": owner, "value": value} for i, tenant, owner, value in SEED_ITEMS]


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


def provision_candidate_role(dsn: str, schema: str, connect=connect) -> str:
    """建立最低權限候選資料庫角色並授權合成資料表，回傳角色密碼。 / Provision the least-privilege candidate database
    role and grant table access on the synthetic schema, returning its password."""
    app_password = secrets.token_hex(24)
    with connect(dsn, schema) as conn:
        conn.execute(sql.SQL("CREATE ROLE epsilon_app LOGIN PASSWORD {}").format(sql.Literal(app_password)))
        conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO epsilon_app").format(sql.Identifier(schema)))
        conn.execute("GRANT SELECT ON users TO epsilon_app")
        conn.execute("GRANT SELECT, UPDATE, DELETE ON items TO epsilon_app")
        conn.execute("GRANT SELECT, INSERT, DELETE ON sessions TO epsilon_app")
    return app_password


def snapshot(dsn, schema, connect=connect):
    """以 REPEATABLE READ 讀取合成資料表快照。 / Read a REPEATABLE READ snapshot of all synthetic tables."""
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


def insert_session(dsn, schema, connect, row: dict):
    """於合成 sessions 資料表寫入單筆測試連線紀錄。 / Insert a synthetic session row into the sessions table."""
    with connect(dsn, schema) as conn:
        conn.execute("INSERT INTO sessions VALUES (%s,%s,%s)", tuple(row[c] for c in TABLES["sessions"]))


def cleanup(dsn: str, schema: str, connect=connect):
    with connect(dsn, schema) as conn:
        conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


class FixtureDatabase:
    """封裝合成資料庫的連線、角色佈建、狀態快照與還原。 / Encapsulate synthetic database connection, role
    provisioning, state snapshots and restoration."""

    def __init__(self, dsn: str, schema: str, passwords: dict[str, str] | None = None, connect=connect):
        self.dsn = dsn
        self.schema = schema
        self.passwords = {} if passwords is None else dict(passwords)
        self.connect = connect

    @classmethod
    def create(cls, dsn: str, connect=None):
        """建立合成 schema 與帳號；`seed` 保持與候選應用逐字相同，注入連線時改以重新綁定 `connect` 的複本執行。 / Create the
        synthetic schema and accounts. `seed` stays verbatim identical to the candidate app's; an injected connection
        runs a copy of it with `connect` rebound."""
        current = globals()["connect"]
        if connect is None or connect is current:
            schema, passwords = seed(dsn)
            return cls(dsn, schema, passwords, connect=current)
        injected = types.FunctionType(seed.__code__, {**globals(), "connect": connect}, "seed")
        schema, passwords = injected(dsn)
        return cls(dsn, schema, passwords, connect=connect)

    def provision_candidate_role(self) -> str:
        return provision_candidate_role(self.dsn, self.schema, self.connect)

    def snapshot(self) -> dict:
        return snapshot(self.dsn, self.schema, self.connect)

    def restore(self, state: dict) -> None:
        restore(self.dsn, self.schema, self.connect, state)

    def insert_session(self, row: dict) -> None:
        insert_session(self.dsn, self.schema, self.connect, row)

    def cleanup(self) -> None:
        cleanup(self.dsn, self.schema, self.connect)
