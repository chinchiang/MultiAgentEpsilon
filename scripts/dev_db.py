#!/usr/bin/env python3
"""僅管理有本工具標籤的暫用 PostgreSQL 容器與本機橋接網路。

Own only a labeled disposable PostgreSQL container and local bridge network."""
import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.processes import docker_command, docker_environment

STATE = ROOT / ".state/db.json"
NAME = "epsilon-fixture-db"
NETWORK = "epsilon-fixture-internal"
LABEL = "epsilon.fixture=synthetic-only"


def docker(*args, check=True):
    return subprocess.run(docker_command(*args), check=check, capture_output=True, text=True, timeout=90,
                          env=docker_environment())


def owned():
    current = docker("inspect", NAME, check=False)
    if current.returncode:
        return None
    data = json.loads(current.stdout)[0]
    if data.get("Config", {}).get("Labels", {}).get("epsilon.fixture") != "synthetic-only":
        raise RuntimeError("container name belongs to another workload")
    return data


def ready():
    for _ in range(60):
        check = docker("exec", NAME, "pg_isready", "-U", "epsilon", "-d", "epsilon_fixture", check=False)
        if check.returncode == 0:
            try:
                with socket.create_connection(("127.0.0.1", 55432), timeout=1):
                    return
            except OSError:
                pass
        time.sleep(0.5)
    raise RuntimeError("PostgreSQL readiness deadline exceeded")


def start():
    current = owned()
    if current:
        if not STATE.exists():
            raise RuntimeError("owned container has no connection state; stop it before rebuilding")
        if not current["State"]["Running"]:
            docker("start", NAME)
        ready()
        print("PostgreSQL fixture already ready")
        return
    network = docker("network", "inspect", NETWORK, check=False)
    if network.returncode:
        docker("network", "create", "--label", LABEL, NETWORK)
    else:
        info = json.loads(network.stdout)[0]
        if info.get("Labels", {}).get("epsilon.fixture") != "synthetic-only":
            raise RuntimeError("network is not the owned fixture network")
    image = json.loads((ROOT / "security/tools.lock.json").read_text())["postgres"]["image"]
    password = secrets.token_hex(24)
    STATE.parent.mkdir(mode=0o700, exist_ok=True)
    env_file = STATE.parent / "postgres.env"
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"POSTGRES_USER=epsilon\nPOSTGRES_DB=epsilon_fixture\nPOSTGRES_PASSWORD={password}\n")
    try:
        docker("run", "--detach", "--name", NAME, "--label", LABEL,
               "--network", NETWORK, "--publish", "127.0.0.1:55432:5432",
               "--user", "999:999", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--cpus=1", "--memory=512m", "--pids-limit=128",
               "--tmpfs", "/var/lib/postgresql/data:rw,uid=999,gid=999,size=256m",
               "--tmpfs", "/var/run/postgresql:rw,uid=999,gid=999",
               "--tmpfs", "/tmp:rw,uid=999,gid=999", "--env-file", str(env_file), image)
        fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"dsn": f"postgresql://epsilon:{password}@127.0.0.1:55432/epsilon_fixture"}, f)
        ready()
    finally:
        env_file.unlink(missing_ok=True)
    print("PostgreSQL fixture ready on loopback port 55432; synthetic data only")


def stop():
    if owned():
        docker("rm", "--force", NAME)
    # 除非擁有權與隔離仍符合預期，否則不移除網路。 / Do not remove networks unless ownership and isolation are still as expected.
    current = docker("network", "inspect", NETWORK, check=False)
    if current.returncode == 0:
        info = json.loads(current.stdout)[0]
        if info.get("Labels", {}).get("epsilon.fixture") == "synthetic-only" and not info.get("Containers"):
            docker("network", "rm", NETWORK)
    STATE.unlink(missing_ok=True)
    print("Owned fixture stopped and disposable data removed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["start", "stop", "status"])
    args = parser.parse_args()
    try:
        if args.action == "start":
            start()
        elif args.action == "stop":
            stop()
        else:
            print("running" if owned() and owned()["State"]["Running"] else "stopped")
    except Exception as exc:
        print(f"Fixture operation failed ({type(exc).__name__}); no credentials printed")
        raise SystemExit(2)
