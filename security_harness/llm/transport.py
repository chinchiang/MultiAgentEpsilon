"""Bounded HTTP and AWS CLI transports. No redirects, retries or raw error logs."""
import asyncio
import json
import math
import os
import signal
from urllib.parse import urlsplit

import httpx

from .gateway import ModelError

RESPONSE_BYTES = 131072


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("non-finite JSON")

    def finite(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("non-finite JSON")
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=invalid, parse_float=finite)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise ModelError("INVALID_RESPONSE") from None


def validate_url(url):
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
                parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError("invalid destination")
        return parsed
    except ValueError:
        raise ModelError("CONFIGURATION") from None


class JsonHTTP:
    """The destination comes only from trusted adapter config, never a prompt.

    Injected transport is for offline tests. Production retains proxy/CA trust.
    The gateway supplies the overall deadline, including streaming body reads.
    """

    def __init__(self, transport=None):
        self.transport = transport

    async def post(self, url, headers, payload):
        validate_url(url)
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=10,
                                        follow_redirects=False, trust_env=True) as client:
                async with client.stream("POST", url, headers={**headers, "Accept-Encoding": "identity"},
                                         json=payload) as response:
                    status = response.status_code
                    if 300 <= status < 400:
                        raise ModelError("REDIRECT")
                    if status in (401, 403):
                        raise ModelError("AUTHENTICATION")
                    if status == 429:
                        raise ModelError("RATE_LIMIT")
                    if status != 200:
                        raise ModelError("HTTP_ERROR")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise ModelError("INVALID_RESPONSE")
                    if response.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                        raise ModelError("INVALID_RESPONSE")
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(body) + len(chunk) > RESPONSE_BYTES:
                            raise ModelError("RESPONSE_LIMIT")
                        body.extend(chunk)
                    return strict_json(body)
        except httpx.TimeoutException:
            raise TimeoutError from None
        except httpx.HTTPError:
            raise ModelError("TRANSPORT") from None


class AwsCLI:
    """Use the configured AWS credential chain. No shell or interactive login.

    Request JSON is sent on stdin, not a process argument or temporary file.
    Kill the dedicated process group and reap the CLI on cancellation/timeout.
    """

    def __init__(self, executable="aws", run_directory=None):
        self.executable = executable
        self.run_directory = run_directory

    async def converse(self, region, payload):
        # Prevent configured endpoint overrides from redirecting signed requests.
        env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_ENDPOINT_URL")
               and k not in {"GEMINI_API_KEY", "GLM_API_KEY"}}
        env.update(AWS_EC2_METADATA_DISABLED="true", AWS_MAX_ATTEMPTS="1", AWS_PAGER="",
                   AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_CLI_AUTO_PROMPT="off")
        command = [self.executable, "bedrock-runtime", "converse", "--region", region,
            "--cli-input-json", "file:///dev/stdin", "--output", "json", "--no-cli-pager",
            "--cli-connect-timeout", "10", "--cli-read-timeout", "20"]
        if self.run_directory is not None:
            from .lifecycle import gated_command, register_group
            command = gated_command(command)
        process = await asyncio.create_subprocess_exec(*command,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=env, start_new_session=True)
        try:
            if self.run_directory is not None:
                register_group(self.run_directory, process.pid)
                process.stdin.write(b'G')
            process.stdin.write(json.dumps(payload).encode())
            await process.stdin.drain()
            process.stdin.close()
            body = bytearray()
            while chunk := await process.stdout.read(4096):
                body.extend(chunk)
                if len(body) > RESPONSE_BYTES:
                    raise ModelError("RESPONSE_LIMIT")
            if await process.wait() != 0:
                raise ModelError("PROVIDER_FAILURE")
            return strict_json(body)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
