#!/usr/bin/env python3
"""Start a real HTTP server, verify login and isolation, then remove owned state."""
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import httpx
from fixture_app.app import database_url, seed, cleanup
from security_harness.results import write_json


def main():
    dsn = database_url()
    schema, passwords = seed(dsn)
    process = subprocess.Popen([sys.executable, str(ROOT / "scripts/serve_fixture.py"), "--schema", schema],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with httpx.Client(base_url="http://127.0.0.1:18765", timeout=3, trust_env=False, follow_redirects=False) as client:
            for _ in range(40):
                if process.poll() is not None:
                    raise RuntimeError("HTTP server exited before readiness")
                try:
                    health = client.get("/health")
                    if health.status_code == 200 and health.json().get("fixture_id") == schema and health.json().get("ready"):
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.25)
            else:
                raise RuntimeError("HTTP readiness deadline exceeded")
            tokens = {}
            for name in ("alice", "bob"):
                response = client.post("/login", json={"username": name, "password": passwords[name]})
                response.raise_for_status()
                tokens[name] = {"Authorization": "Bearer " + response.json()["access_token"]}
            own = client.get("/items/1", headers=tokens["alice"])
            denied = client.get("/items/1", headers=tokens["bob"])
            checks = {"database_health": True, "real_http_login": True,
                      "owner_read": own.status_code == 200 and own.json().get("value") == "alice-private",
                      "same_role_other_owner_denied": denied.status_code == 404 and "alice-private" not in denied.text}
            write_json(ROOT / "artifacts/http-smoke.json", {"checks": checks, "transport": "real loopback HTTP"})
            if not all(checks.values()):
                raise RuntimeError("HTTP authorization smoke failed")
            print("HTTP smoke PASS: database health, login, own read, cross-owner denial")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        cleanup(dsn, schema)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"HTTP smoke FAILED ({type(exc).__name__}); no credentials printed")
        raise SystemExit(1)
