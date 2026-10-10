"""候選與資料庫皆為無網路容器，oracle 與證據留在 host。只傳入合成資料庫憑證及唯讀 socket 目錄；Linux 容器隔離不代表抵抗 host kernel 漏洞。

Networkless candidate and DB containers; oracle and evidence stay on the host.

Only synthetic DB credentials and a read-only DB socket directory cross the boundary.
This is Linux container isolation, not protection against host-kernel exploits.
"""
import hashlib
import json
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

import psycopg
from psycopg import sql

from .authorization import evaluate
from .fixture_database import connect, seed
from .inputs import input_files
from .lifecycle import valid_run_id
from .container_http import BoundedClient, docker_environment
from .processes import docker_command
from .results import digest_file, read_regular

ROOT = Path(__file__).resolve().parents[1]
PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")


def docker(*args, check=True, timeout=45):
    env = docker_environment()
    return subprocess.run(docker_command(*args),
                          capture_output=True, text=True, check=check, timeout=timeout, env=env)


MEMORY_BYTES = 512 * 1024 * 1024
PIDS_LIMIT = 128
NOFILE_LIMIT = 4096


def run_flags(name, run_id):
    # 不從網路拉映像；本機缺映像時失敗而非在評估期間下載。 / Never pull: a missing local image fails instead of downloading mid-evaluation.
    flags = ["run", "--detach", "--pull=never", "--name", name, "--label", "epsilon.isolated=true",
             "--label", "epsilon.run=" + run_id,
             "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
             "--cpus=1", f"--memory={MEMORY_BYTES}", f"--memory-swap={MEMORY_BYTES}",
             f"--pids-limit={PIDS_LIMIT}", f"--ulimit=nofile={NOFILE_LIMIT}:{NOFILE_LIMIT}", "--log-driver=none"]
    for variable in PROXY_NAMES:
        flags.extend(("--env", variable + "="))
    return flags


def verify_container(data, *, user, image_id=None, image_ref=None):
    """評估前核對 Docker 實際套用的隔離設定，任一不符即拒絕。

Verify the isolation Docker actually applied before evaluation; any mismatch refuses."""
    host, config = data["HostConfig"], data["Config"]
    ulimits = {u["Name"]: (u["Soft"], u["Hard"]) for u in host.get("Ulimits") or []}
    checks = {
        "network": host["NetworkMode"] == "none",
        "readonly_root": host["ReadonlyRootfs"] is True,
        "privileged": host["Privileged"] is False,
        "cap_drop": host["CapDrop"] == ["ALL"] and not host.get("CapAdd"),
        "no_new_privileges": host["SecurityOpt"] == ["no-new-privileges"],
        "memory": host["Memory"] == MEMORY_BYTES and host["MemorySwap"] == MEMORY_BYTES,
        "pids": host["PidsLimit"] == PIDS_LIMIT,
        "cpus": host["NanoCpus"] == 1_000_000_000,
        "nofile": ulimits == {"nofile": (NOFILE_LIMIT, NOFILE_LIMIT)},
        "user": config["User"] == user,
        "image": (image_id is None or data["Image"] == image_id) and (image_ref is None or config["Image"] == image_ref),
    }
    failed = sorted(k for k, ok in checks.items() if not ok)
    if failed:
        raise RuntimeError("isolation configuration mismatch: " + ",".join(failed))
    return {"network": host["NetworkMode"], "readonly_root": host["ReadonlyRootfs"], "user": config["User"],
            "image_id": data["Image"], "mount_destinations": sorted(m["Destination"] for m in data["Mounts"]),
            "verified": sorted(checks)}


def cleanup_run(run_id):
    if not valid_run_id(run_id):
        raise ValueError("invalid isolation run ID")
    # 清理不是安全測試期限；daemon 較慢時應等待，不能遺留容器。 / Cleanup is not a security deadline: a slow daemon must delay it, not leak containers.
    ids = docker("ps", "-aq", "--filter", "label=epsilon.isolated=true", "--filter", "label=epsilon.run=" + run_id, timeout=30).stdout.split()
    if ids:
        docker("rm", "--force", *ids, timeout=30)


def run_isolated(candidate: Path, variant="fixed", run_id=None) -> dict:
    if variant not in ("fixed", "vulnerable"):
        raise ValueError("invalid fixture variant")
    runtime = json.loads((ROOT / ".state/runtime-image.json").read_text())
    tools = json.loads((ROOT / "security/tools.lock.json").read_text())
    if runtime.get("base_image") != tools["python_runtime"]["image"]:
        raise ValueError("trusted runtime base image is stale; rebuild it")
    for path, key in (("requirements.lock", "lock_sha256"), ("security/runtime/server.py", "server_sha256"),
                      ("scripts/build_runtime.py", "builder_sha256"),
                      ("security/runtime/request.py", "request_sha256")):
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != runtime[key]:
            raise ValueError("trusted runtime is stale; rebuild it")
    candidate_lock = digest_file(candidate / "requirements.lock")
    if candidate_lock != runtime["lock_sha256"]:
        raise ValueError("candidate lock differs from tested runtime")
    # 列舉實際來源子樹，避免保留名稱藏入 payload。 / Enumerate the actual source subtree, so reserved names cannot hide payloads.
    source = candidate / "fixture_app"
    if source.is_symlink():
        raise ValueError("candidate source is a symlink")
    run_id = run_id or secrets.token_hex(16)
    if not valid_run_id(run_id):
        raise ValueError("invalid isolation run ID")
    paths = [p for p in input_files(candidate) if p.is_relative_to(source)]
    if not paths or any(p.suffix != ".py" for p in paths) or sum(p.stat().st_size for p in paths) > 1024 * 1024:
        raise ValueError("pilot candidate must contain bounded Python source only")
    names = ["epsilon-isolated-" + secrets.token_hex(8) + suffix for suffix in ("-db", "-app")]
    with tempfile.TemporaryDirectory(prefix="epsilon-iso-") as directory:
        work = Path(directory)
        # 只有 Docker daemon（root）需要進入；其他本機使用者不可替換 socket。 / Only the root Docker daemon enters;
        # other local users cannot plant a socket in the world-writable DB directory.
        work.chmod(0o700)
        (work / "db").mkdir(mode=0o777)
        (work / "db").chmod(0o777)
        (work / "candidate/fixture_app").mkdir(parents=True)
        for path in paths:
            target = work / "candidate/fixture_app" / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(read_regular(path, 1024 * 1024))
            target.chmod(0o444)
        for path in [work / "candidate", *list((work / "candidate").rglob("*"))]:
            if path.is_dir():
                path.chmod(0o755)
        password = secrets.token_hex(24)
        env_file = work / "postgres.env"
        env_file.write_text(f"POSTGRES_USER=epsilon\nPOSTGRES_DB=epsilon_fixture\nPOSTGRES_PASSWORD={password}\nPOSTGRES_INITDB_ARGS=--auth-local=scram-sha-256\nPGHOST=/run/epsilon-db\n")
        env_file.chmod(0o600)
        hba = work / "pg_hba.conf"
        hba.write_text("local all all scram-sha-256\n")
        hba.chmod(0o444)
        dsn = f"postgresql://epsilon:{password}@/epsilon_fixture?host={work / 'db'}"
        cleanup_errors = []
        try:
            db_image = json.loads((ROOT / "security/tools.lock.json").read_text())["postgres"]["image"]
            docker(*run_flags(names[0], run_id), "--user", "999:999", "--env-file", str(env_file),
                   "--mount", f"type=bind,src={work / 'db'},dst=/var/run/postgresql",
                   "--mount", f"type=bind,src={hba},dst=/etc/epsilon-pg_hba.conf,readonly",
                   "--tmpfs", "/var/lib/postgresql/data:rw,uid=999,gid=999,size=256m",
                   "--tmpfs", "/tmp:rw,uid=999,gid=999,size=16m", db_image,
                   "-c", "hba_file=/etc/epsilon-pg_hba.conf", "-c", "listen_addresses=")
            for _ in range(80):
                try:
                    if docker("exec", names[0], "cat", "/proc/1/comm", check=False).stdout.strip() != "postgres":
                        time.sleep(0.25)
                        continue
                    with psycopg.connect(dsn, connect_timeout=1):
                        break
                except psycopg.Error:
                    time.sleep(0.25)
            else:
                raise RuntimeError("isolated database unavailable")
            schema, passwords = seed(dsn)
            app_password = secrets.token_hex(24)
            with connect(dsn, schema) as conn:
                conn.execute(sql.SQL("CREATE ROLE epsilon_app LOGIN PASSWORD {}").format(sql.Literal(app_password)))
                conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
                conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO epsilon_app").format(sql.Identifier(schema)))
                conn.execute("GRANT SELECT ON users TO epsilon_app")
                conn.execute("GRANT SELECT, UPDATE, DELETE ON items TO epsilon_app")
                conn.execute("GRANT SELECT, INSERT, DELETE ON sessions TO epsilon_app")
            settings = work / "fixture.json"
            settings.write_text(json.dumps({"dsn": f"postgresql://epsilon_app:{app_password}@/epsilon_fixture?host=/run/epsilon-db",
                                            "schema": schema, "variant": variant}))
            settings.chmod(0o444)
            docker(*run_flags(names[1], run_id), "--user", "10001:10001", "--tmpfs", "/tmp:rw,uid=10001,gid=10001,size=16m",
                   "--mount", f"type=bind,src={work / 'candidate'},dst=/candidate,readonly",
                   "--mount", f"type=bind,src={work / 'db'},dst=/run/epsilon-db,readonly",
                   "--mount", f"type=bind,src={settings},dst=/run/fixture.json,readonly", runtime["image_id"])
            # 先核對兩個容器的實際組態，再送出任何評估請求。 / Verify both containers' applied configuration before any evaluation request.
            db_isolation = verify_container(json.loads(docker("inspect", names[0]).stdout)[0],
                                            user="999:999", image_ref=db_image)
            app_isolation = verify_container(json.loads(docker("inspect", names[1]).stdout)[0],
                                             user="10001:10001", image_id=runtime["image_id"])
            client = BoundedClient(names[1])
            health_deadline = time.monotonic() + 20
            while time.monotonic() < health_deadline:
                try:
                    health = client.get("/health")
                    if health.status_code == 200 and health.json().get("fixture_id") == schema and health.json().get("ready"):
                        break
                except (RuntimeError, ValueError, TimeoutError, AttributeError, BrokenPipeError):
                    # 非物件 JSON 或提早關閉的管線也只是尚未就緒。 / Non-object JSON or an early-closed pipe means not ready yet.
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("isolated HTTP service unavailable")
            cases = evaluate(client, dsn, schema, passwords, connect)
            evidence = {**app_isolation,
                        "database": db_isolation,
                        "oracle": "host oracle; bounded container HTTP bridge + independent database queries",
                        "candidate_lock_sha256": candidate_lock,
                        "runtime_lock_sha256": runtime["lock_sha256"],
                        "http_socket_namespace": "candidate container only"}
            return {"cases": cases, "isolation": evidence}
        finally:
            for name in reversed(names):
                # 單一容器逾時不能跳過另一個容器的移除。 / One container's timeout must not skip removing the other.
                try:
                    removed = docker("rm", "--force", name, check=False)
                    if removed.returncode and docker("inspect", name, check=False).returncode == 0:
                        cleanup_errors.append(name)
                except subprocess.TimeoutExpired:
                    cleanup_errors.append(name)
            if cleanup_errors:
                raise RuntimeError("isolated resource cleanup failed")
