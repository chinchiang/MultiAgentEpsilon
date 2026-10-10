"""有限額的 HTTP 與 AWS CLI 傳輸，不重新導向、重試或保存原始錯誤。

Bounded HTTP and AWS CLI transports. No redirects, retries or raw error logs."""
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



class IOTimeout(TimeoutError):
    """單次 HTTP 讀寫逾時，與整體呼叫期限分開記錄。 / A single HTTP I/O timeout, recorded apart from the call deadline."""

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
        if (type(url) is not str or any(ord(c) <= 32 or ord(c) > 126 for c in url)
                or '\\' in url):
            raise ValueError('invalid URL characters')
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or '%' in parsed.netloc
                or parsed.username is not None or parsed.password is not None
                or '?' in url or '#' in url or parsed.port not in (None, 443)):
            raise ValueError("invalid destination")
        return parsed
    except ValueError:
        raise ModelError("CONFIGURATION") from None


class JsonHTTP:
    """目的地僅來自可信 adapter 設定，不取自提示詞。注入 transport 只供離線測試，正式環境保留代理與 CA 信任；gateway 提供涵蓋串流讀取的總期限。

The destination comes only from trusted adapter config, never a prompt.

    Injected transport is for offline tests. Production retains proxy/CA trust.
    The gateway supplies the overall deadline, including streaming body reads.
    """

    def __init__(self, transport=None, timeout_seconds=10):
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
            raise ValueError('invalid HTTP timeout')
        self.transport = transport
        self.timeout_seconds = timeout_seconds
        self.trust_env = True

    def validate(self, url):
        return validate_url(url)

    async def get(self, url, headers):
        return await self.request('GET', url, headers, None)

    async def post(self, url, headers, payload):
        return await self.request('POST', url, headers, payload)

    async def request(self, method, url, headers, payload):
        self.validate(url)
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout_seconds,
                                        follow_redirects=False, trust_env=self.trust_env) as client:
                async with client.stream(method, url, headers={**headers, "Accept-Encoding": "identity"},
                                         json=payload) as response:
                    status = response.status_code
                    if 300 <= status < 400:
                        raise ModelError("REDIRECT")
                    if status in (401, 403):
                        raise ModelError("AUTHENTICATION")
                    if status == 429:
                        raise ModelError("RATE_LIMIT")
                    if status == 400:
                        # 只診斷已知設定拒絕，絕不 / Diagnose known configuration rejections only. Never
                        # 保存可能回顯提示詞或機密的供應商原文。 / retain provider text, which can echo prompts or secrets.
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
            raise IOTimeout from None
        except httpx.HTTPError:
            raise ModelError("TRANSPORT") from None


CLI_DIAGNOSTIC_BYTES = 8192


def cli_failure(stderr):
    """將 AWS CLI 失敗映射為固定分類，不保存可能回顯請求、帳號或 ARN 的原始文字。

Map a failed AWS CLI call to a fixed category. The provider/CLI text itself is
    never kept: it can echo request content, account IDs or ARNs."""
    text = ''.join(c for c in stderr.decode('utf-8', 'replace').lower() if 'a' <= c <= 'z')
    if 'validationexception' in text and 'outputconfig' in text:
        return ModelError('PROVIDER_FAILURE', 'OUTPUT_CONFIGURATION')
    if any(k in text for k in ('expiredtoken', 'unrecognizedclient', 'accessdeniedexception',
                               'invalidclienttokenid', 'tokenhasexpired', 'unabletolocatecredentials')):
        return ModelError('AUTHENTICATION')
    if any(k in text for k in ('throttlingexception', 'toomanyrequests', 'servicequotaexceeded')):
        return ModelError('RATE_LIMIT')
    return ModelError('PROVIDER_FAILURE')


AWS_CHILD_ENV = frozenset({"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR",
                           "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
                           "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"})


class AwsCLI:
    """使用設定的 AWS 憑證鏈，不用 shell 或互動登入。JSON 放在封存的匿名 Linux 記憶體檔案，不經命令參數或檔案系統 payload；stdin 只傳登記握手。取消或逾時時終止專用群組並回收 CLI。

Use the configured AWS credential chain. No shell or interactive login.

    Request JSON uses a sealed anonymous Linux memory file, never a command argument
    or filesystem payload. stdin carries only the registration handshake.
    Kill the dedicated process group and reap the CLI on cancellation/timeout.
    """

    def __init__(self, executable="aws", run_directory=None):
        self.executable = executable
        self.run_directory = run_directory

    async def converse(self, region, payload):
        # 白名單只讓 CLI 與 credential_process 看見 AWS 設定及基本 / Allowlist: the CLI and any credential_process helper see AWS settings and basic
        # 程序／代理／CA 環境，不傳入 GH_TOKEN 或其他供應商權杖。 / process/proxy/CA context only, never unrelated tokens (GH_TOKEN, other providers).
        # 排除端點覆寫，避免已簽署請求被改送其他位置。 / Endpoint overrides are excluded so signed requests cannot be redirected.
        env = {k: v for k, v in os.environ.items()
               if (k.startswith("AWS_") and not k.startswith("AWS_ENDPOINT_URL")) or k in AWS_CHILD_ENV}
        env.update(AWS_EC2_METADATA_DISABLED="true", AWS_MAX_ATTEMPTS="1", AWS_PAGER="",
                   AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_CLI_AUTO_PROMPT="off")
        # 此處 AWS CLI v2 無法解析以管線提供的 /dev/stdin JSON。 / AWS CLI v2 cannot parse the JSON from a pipe-backed /dev/stdin here.
        # memfd 提供可 seek 的輸入，封存可防止子程序修改。 / memfd provides a seekable input; seals prevent any child from modifying it.
        # Python 未提供常數名稱時使用 Linux ABI 常數。 / Linux ABI constants are used when the Python build omits their names.
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
                stderr=asyncio.subprocess.PIPE, env=env, start_new_session=True,
                pass_fds=(fd,))
        finally:
            os.close(fd)
        try:
            if self.run_directory is not None:
                register_group(self.run_directory, process.pid)
                process.stdin.write(b'G')
            await process.stdin.drain()
            process.stdin.close()
            async def read_stdout():
                body = bytearray()
                while chunk := await process.stdout.read(4096):
                    body.extend(chunk)
                    if len(body) > RESPONSE_BYTES:
                        raise ModelError("RESPONSE_LIMIT")
                return body

            async def read_stderr():
                # 只保留小段前綴供分類，其餘持續讀取丟棄， / Keep at most a small prefix for classification; drain the rest
                # 避免大量輸出的 CLI 塞滿管線而阻塞。 / so a chatty CLI cannot block on a full pipe.
                head = bytearray()
                while chunk := await process.stderr.read(4096):
                    if len(head) < CLI_DIAGNOSTIC_BYTES:
                        head.extend(chunk[:CLI_DIAGNOSTIC_BYTES - len(head)])
                return bytes(head)

            body, diagnostic = await asyncio.gather(read_stdout(), read_stderr())
            if await process.wait() != 0:
                raise cli_failure(diagnostic)
            return strict_json(body)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
