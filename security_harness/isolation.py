"""Networkless candidate and DB containers; oracle and evidence stay on the host.

Only synthetic DB credentials and a read-only DB socket directory cross the boundary.
This is Linux container isolation, not protection against host-kernel exploits.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import psycopg
from psycopg import sql

from .authorization import evaluate
from .fixture_database import connect, seed
from .inputs import input_files
from .container_http import BoundedClient, docker_environment
from .results import digest_file

ROOT = Path(__file__).resolve().parents[1]
PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")


def docker(*args, check=True, timeout=45):
    env = docker_environment()
    return subprocess.run(["docker", "--host=unix:///var/run/docker.sock", *args],
                          capture_output=True, text=True, check=check, timeout=timeout, env=env)


def run_flags(name, run_id):
    flags = ["run", "--detach", "--name", name, "--label", "epsilon.isolated=true",
             "--label", "epsilon.run=" + run_id,
             "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
             "--cpus=1", "--memory=512m", "--pids-limit=128", "--log-driver=none"]
    for name in PROXY_NAMES:
        flags.extend(("--env", name + "="))
    return flags


def cleanup_run(run_id):
    if not re.fullmatch(r"[a-f0-9-]{32,36}", run_id):
        raise ValueError("invalid isolation run ID")
    # Cleanup is not a security deadline: a slow daemon must delay it, not leak containers.
    ids = docker("ps", "-aq", "--filter", "label=epsilon.isolated=true", "--filter", "label=epsilon.run=" + run_id, timeout=30).stdout.split()
    if ids:
        docker("rm", "--force", *ids, timeout=30)


def run_isolated(candidate: Path, variant="fixed", run_id=None) -> dict:
    if variant not in ("fixed", "vulnerable"):
        raise ValueError("invalid fixture variant")
    runtime = json.loads((ROOT / ".state/runtime-image.json").read_text())
    for path, key in (("requirements.lock", "lock_sha256"), ("security/runtime/server.py", "server_sha256"),
                      ("scripts/build_runtime.py", "builder_sha256"),
                      ("security/runtime/request.py", "request_sha256")):
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != runtime[key]:
            raise ValueError("trusted runtime is stale; rebuild it")
    candidate_lock = digest_file(candidate / "requirements.lock")
    if candidate_lock != runtime["lock_sha256"]:
        raise ValueError("candidate lock differs from tested runtime")
    # Enumerate the actual source subtree, so reserved names cannot hide payloads.
    source = candidate / "fixture_app"
    if source.is_symlink():
        raise ValueError("candidate source is a symlink")
    run_id = run_id or secrets.token_hex(16)
    if not re.fullmatch(r"[a-f0-9-]{32,36}", run_id):
        raise ValueError("invalid isolation run ID")
    paths = [p for p in input_files(candidate) if p.is_relative_to(source)]
    if not paths or any(p.suffix != ".py" for p in paths) or sum(p.stat().st_size for p in paths) > 1024 * 1024:
        raise ValueError("pilot candidate must contain bounded Python source only")
    names = ["epsilon-isolated-" + secrets.token_hex(8) + suffix for suffix in ("-db", "-app")]
    with tempfile.TemporaryDirectory(prefix="epsilon-iso-") as directory:
        work = Path(directory)
        work.chmod(0o755)
        for name in ("db",):
            (work / name).mkdir(mode=0o777)
            (work / name).chmod(0o777)
        (work / "candidate/fixture_app").mkdir(parents=True)
        for path in paths:
            target = work / "candidate/fixture_app" / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
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
                   "--tmpfs", "/tmp:rw,uid=999,gid=999", db_image,
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
                conn.execute("GRANT SELECT, UPDATE ON items TO epsilon_app")
                conn.execute("GRANT SELECT, INSERT, DELETE ON sessions TO epsilon_app")
            settings = work / "fixture.json"
            settings.write_text(json.dumps({"dsn": f"postgresql://epsilon_app:{app_password}@/epsilon_fixture?host=/run/epsilon-db",
                                            "schema": schema, "variant": variant}))
            settings.chmod(0o444)
            docker(*run_flags(names[1], run_id), "--user", "10001:10001", "--tmpfs", "/tmp:rw,uid=10001,gid=10001,size=16m",
                   "--mount", f"type=bind,src={work / 'candidate'},dst=/candidate,readonly",
                   "--mount", f"type=bind,src={work / 'db'},dst=/run/epsilon-db,readonly",
                   "--mount", f"type=bind,src={settings},dst=/run/fixture.json,readonly", runtime["image_id"])
            client = BoundedClient(names[1])
            health_deadline = time.monotonic() + 20
            while time.monotonic() < health_deadline:
                try:
                    health = client.get("/health")
                    if health.status_code == 200 and health.json().get("fixture_id") == schema and health.json().get("ready"):
                        break
                except (RuntimeError, ValueError, TimeoutError):
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("isolated HTTP service unavailable")
            cases = evaluate(client, dsn, schema, passwords, connect)
            data = json.loads(docker("inspect", names[1]).stdout)[0]
            evidence = {"network": data["HostConfig"]["NetworkMode"],
                        "readonly_root": data["HostConfig"]["ReadonlyRootfs"],
                        "user": data["Config"]["User"], "image_id": data["Image"],
                        "mount_destinations": [m["Destination"] for m in data["Mounts"]],
                        "oracle": "host oracle; bounded container HTTP bridge + independent database queries",
                        "candidate_lock_sha256": candidate_lock,
                        "runtime_lock_sha256": runtime["lock_sha256"],
                        "http_socket_namespace": "candidate container only"}
            if evidence["network"] != "none" or not evidence["readonly_root"]:
                raise RuntimeError("isolation configuration mismatch")
            return {"cases": cases, "isolation": evidence}
        finally:
            for name in reversed(names):
                removed = docker("rm", "--force", name, check=False)
                if removed.returncode and docker("inspect", name, check=False).returncode == 0:
                    cleanup_errors.append(name)
            if cleanup_errors:
                raise RuntimeError("isolated resource cleanup failed")
