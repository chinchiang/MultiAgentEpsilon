"""Bounded HTTP and AWS CLI transports. No redirects, retries or raw error logs."""
import asyncio
import fcntl
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
                raise ModelError("INVALID_RESPONSE", "JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def invalid(_):
        raise ModelError("INVALID_RESPONSE", "JSON_NONFINITE")

    def finite(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ModelError("INVALID_RESPONSE", "JSON_NONFINITE")
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=invalid, parse_float=finite)
        if not isinstance(value, dict):
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        return value
    except UnicodeError:
        raise ModelError("INVALID_RESPONSE", "JSON_ENCODING") from None
    except json.JSONDecodeError:
        raise ModelError("INVALID_RESPONSE", "JSON_SYNTAX") from None
    except (ValueError, RecursionError):
        raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA") from None


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

    def __init__(self, transport=None, timeout_seconds=10):
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
            raise ValueError('invalid HTTP timeout')
        self.transport = transport
        self.timeout_seconds = timeout_seconds

    async def post(self, url, headers, payload):
        validate_url(url)
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout_seconds,
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
                    if status == 400:
                        # Diagnose known configuration rejections only. Never
                        # retain provider text, which can echo prompts or secrets.
                        detail = None
                        if (response.headers.get('content-encoding', 'identity').lower() == 'identity' and
                                response.headers.get('content-type', '').split(';')[0].strip() == 'application/json'):
                            body = bytearray()
                            async for chunk in response.aiter_raw():
                                if len(body) + len(chunk) > 8192:
                                    break
                                body.extend(chunk)
                            else:
                                try:
                                    error = strict_json(body).get('error')
                                    message = error.get('message') if isinstance(error, dict) else None
                                    if type(message) is str:
                                        normalized = ''.join(c for c in message.lower() if 'a' <= c <= 'z')
                                        if any(k in normalized for k in ('thinkingconfig', 'thinkinglevel', 'thinkingbudget')):
                                            detail = 'THINKING_CONFIGURATION'
                                        elif any(k in normalized for k in ('responsejsonschema', 'responseschema', 'responsemimetype')):
                                            detail = 'OUTPUT_CONFIGURATION'
                                except ModelError:
                                    pass
                        raise ModelError('HTTP_ERROR', detail)
                    if status != 200:
                        raise ModelError("HTTP_ERROR")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise ModelError("INVALID_RESPONSE", "HTTP_CONTENT_TYPE")
                    if response.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                        raise ModelError("INVALID_RESPONSE", "HTTP_CONTENT_TYPE")
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


AWS_CHILD_ENV = frozenset({"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR",
                           "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
                           "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"})


class AwsCLI:
    """Use the configured AWS credential chain. No shell or interactive login.

    Request JSON uses a sealed anonymous Linux memory file, never a command argument
    or filesystem payload. stdin carries only the registration handshake.
    Kill the dedicated process group and reap the CLI on cancellation/timeout.
    """

    def __init__(self, executable="aws", run_directory=None):
        self.executable = executable
        self.run_directory = run_directory

    async def converse(self, region, payload):
        # Allowlist: the CLI and any credential_process helper see AWS settings and basic
        # process/proxy/CA context only, never unrelated tokens (GH_TOKEN, other providers).
        # Endpoint overrides are excluded so signed requests cannot be redirected.
        env = {k: v for k, v in os.environ.items()
               if (k.startswith("AWS_") and not k.startswith("AWS_ENDPOINT_URL")) or k in AWS_CHILD_ENV}
        env.update(AWS_EC2_METADATA_DISABLED="true", AWS_MAX_ATTEMPTS="1", AWS_PAGER="",
                   AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_CLI_AUTO_PROMPT="off")
        # AWS CLI v2 cannot parse the JSON from a pipe-backed /dev/stdin here.
        # memfd provides a seekable input; seals prevent any child from modifying it.
        # Linux ABI constants are used when the Python build omits their names.
        fd = os.memfd_create("epsilon-aws-input", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with os.fdopen(os.dup(fd), 'wb') as handle:
                handle.write(json.dumps(payload).encode())
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 0x000F)
            input_path = f"file:///proc/self/fd/{fd}"
            command = [self.executable, "bedrock-runtime", "converse", "--region", region,
                "--cli-input-json", input_path, "--output", "json", "--no-cli-pager",
                "--cli-connect-timeout", "10", "--cli-read-timeout", "20"]
            if self.run_directory is not None:
                from .lifecycle import gated_command, register_group
                command = gated_command(command)
            process = await asyncio.create_subprocess_exec(*command,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=env, start_new_session=True,
                pass_fds=(fd,))
        finally:
            os.close(fd)
        try:
            if self.run_directory is not None:
                register_group(self.run_directory, process.pid)
                process.stdin.write(b'G')
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
