#!/usr/bin/env python3
"""Run the fixed synthetic gateway fixture. Live calls are explicit opt-in."""
import argparse
import asyncio
import hashlib
import json
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security_harness.llm.adapters import BedrockAdapter, GeminiAdapter, GLMAdapter
from security_harness.llm.gateway import Gateway, Limits, MockAdapter, ModelError, Request
from security_harness.llm.transport import AwsCLI

FIXTURE = Request(
    system="You are running a synthetic transport check. Follow the user's exact output instruction.",
    user="Reply with exactly EPSILON_SYNTHETIC_OK and no other text.", max_output_tokens=256)


def configured_adapter(provider):
    if provider == "mock":
        return MockAdapter()
    if provider == "gemini":
        return GeminiAdapter(os.environ["GEMINI_MODEL_ID"], os.environ["GEMINI_API_KEY"])
    if provider == "glm":
        return GLMAdapter(os.environ["GLM_MODEL_ID"], os.environ["GLM_CHAT_URL"], os.getenv("GLM_API_KEY"))
    return BedrockAdapter(os.environ["BEDROCK_MODEL_ID"], os.environ["BEDROCK_REGION"],
                          AwsCLI(os.getenv("AWS_CLI_PATH", "aws")))


def implementation_digest():
    paths = [Path(__file__), *sorted((ROOT / "security_harness/llm").glob("*.py"))]
    manifest = [(p.relative_to(ROOT).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()


async def run(providers, output):
    gateway = Gateway(Limits(max_calls=len(providers), reserved_output_tokens=256 * len(providers)))
    report = {"schema_version": 1, "run_id": str(uuid.uuid4()), "advisory_only": True,
              "data_class": "synthetic", "fixture": "fixed-ack-v1",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "implementation_sha256": implementation_digest(), "status": "INCOMPLETE",
              "limits": asdict(gateway.limits), "max_output_tokens_per_call": FIXTURE.max_output_tokens,
              "checks": [], "calls": gateway.evidence}
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    try:
        for provider in providers:
            check = {"provider": provider, "live": provider != "mock", "status": "ERROR", "code": None}
            report["checks"].append(check)
            try:
                adapter = configured_adapter(provider)
            except (KeyError, ModelError):
                check["code"] = "CONFIGURATION"
                continue
            reply = await gateway.generate(adapter, FIXTURE)
            if reply is not None and reply.text.strip() == "EPSILON_SYNTHETIC_OK":
                check["status"] = "SUCCESS"
            else:
                check["code"] = gateway.evidence[-1]["code"] or "FIXTURE_MISMATCH"
        if all(c["status"] == "SUCCESS" for c in report["checks"]):
            report["status"] = "COMPLETE"
    except asyncio.CancelledError:
        report["status"] = "CANCELLED"
    finally:
        report["reserved_calls"] = gateway.calls
        report["reserved_output_tokens"] = gateway.reserved_tokens
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        output.parent.mkdir(parents=True, exist_ok=True)
        # A new output path is required so prior evidence is never overwritten.
        with output.open("x") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    print(json.dumps({"status": report["status"], "checks": report["checks"], "evidence": str(output)}))
    return 0 if report["status"] == "COMPLETE" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("mock", "gemini", "bedrock", "glm"), action="append")
    parser.add_argument("--live", action="store_true", help="permit selected live providers for the fixed synthetic fixture")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    providers = args.provider or ["mock"]
    if len(providers) != len(set(providers)):
        parser.error("duplicate providers are not allowed")
    if any(p != "mock" for p in providers) and not args.live:
        parser.error("live providers require --live")
    output = args.output or ROOT / "artifacts" / f"model-smoke-{uuid.uuid4()}.json"
    if output.exists():
        parser.error("output already exists; choose a new evidence path")
    return asyncio.run(run(providers, output))


if __name__ == "__main__":
    raise SystemExit(main())
