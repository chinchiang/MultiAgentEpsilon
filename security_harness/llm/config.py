"""模型供應商設定與目的地授權；可帶金鑰的遠端主機必須列在已審查的模型 RoE。

Model provider configuration and destination authorization.

A remote host that may receive an API key must be listed in the reviewed model
RoE; only LM Studio's literal loopback HTTP needs no entry.
"""
import hashlib
import json
import os
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from .adapters import BedrockAdapter, GeminiAdapter, GLMAdapter
from .gateway import MockAdapter, ModelError
from .lmstudio import LMStudioAdapter
from .transport import AwsCLI

ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER_HOSTS = {"local.example.invalid"}
LOOPBACK = ("127.0.0.1", "::1")


def setting(name, required=True):
    """未設定值與 .env.example 佔位值屬設定錯誤，應在預留呼叫前拒絕，而非歸類為傳輸失敗。

Unset values and the documented .env.example placeholders are configuration
    errors, not transport failures after a reserved call."""
    value = os.environ[name] if required else (os.environ.get(name) or None)
    if value is None:
        return None
    try:
        host = urlsplit(value).hostname
    except ValueError:
        # 不平衡的 [ 等格式錯誤也屬設定錯誤。 / Malformed values such as an unbalanced [ are configuration errors too.
        raise ModelError("CONFIGURATION") from None
    if not value.strip() or value.startswith("replace-with-") or host in PLACEHOLDER_HOSTS:
        raise ModelError("CONFIGURATION")
    return value


def remote_hosts(provider):
    """已審查 RoE 中允許該供應商連線的遠端主機。 / Remote hosts the reviewed RoE authorizes for this provider."""
    roe = json.loads((ROOT / "security/model-roe.json").read_text())
    return set(roe["allowed_remote_hosts"].get(provider, []))


def authorize_destination(provider, url):
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise ModelError("CONFIGURATION") from None
    if provider == "lmstudio" and parts.scheme == "http" and host in LOOPBACK:
        return
    if host is None or host.lower() not in remote_hosts(provider):
        raise ModelError("CONFIGURATION")


def configured_adapter(provider, work=None, http=None):
    if provider == "mock":
        return MockAdapter()
    if provider == "gemini":
        return GeminiAdapter(setting("GEMINI_MODEL_ID"), setting("GEMINI_API_KEY"), http=http)
    if provider == "lmstudio":
        base = setting("LMSTUDIO_BASE_URL")
        authorize_destination(provider, base)
        return LMStudioAdapter(setting("LMSTUDIO_MODEL_ID"), base, setting("LMSTUDIO_API_KEY", False), http=http)
    if provider == "glm":
        url = setting("GLM_CHAT_URL")
        authorize_destination(provider, url)
        return GLMAdapter(setting("GLM_MODEL_ID"), url, setting("GLM_API_KEY", False), http=http)
    if provider != "bedrock":
        raise ModelError("CONFIGURATION")
    executable = os.getenv("AWS_CLI_PATH", "aws")
    if shutil.which(executable) is None:
        raise ModelError("CONFIGURATION")
    return BedrockAdapter(setting("BEDROCK_MODEL_ID"), setting("BEDROCK_REGION"),
                          AwsCLI(executable, run_directory=work))


def implementation_digest():
    """綁定模型實作、套件初始化、共用核心、RoE 與 lock。 / Bind model code, package initializers, shared core, RoE and lock."""
    paths = sorted({ROOT / 'scripts/__init__.py', ROOT / 'security_harness/__init__.py',
                    ROOT / 'requirements.lock', ROOT / 'security/model-roe.json',
                    *ROOT.glob('scripts/model_*.py'), *ROOT.glob('security_harness/**/*.py')})
    manifest = [(p.relative_to(ROOT).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()
