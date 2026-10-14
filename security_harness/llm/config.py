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

from .adapters import BedrockAdapter, DeepSeekAdapter, GeminiAdapter, GLMAdapter
from .gateway import MockAdapter, ModelError
from .lmstudio import LMStudioAdapter
from ..scope import validate_model_roe
from .transport import AwsCLI

ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER_HOSTS = {"local.example.invalid"}
LOOPBACK = ("127.0.0.1", "::1")
# 地端 OpenAI 相容 chat 供應商與其環境變數前綴。 / On-prem OpenAI-compatible chat providers and their setting prefixes.
CHAT_ADAPTERS = {"glm": ("GLM", GLMAdapter), "deepseek": ("DEEPSEEK", DeepSeekAdapter)}


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


def authorize_destination(provider, url, roe):
    """主機清單取自授權時讀到的同一份 RoE，兩次讀取之間換檔無效。 / Hosts come from the same RoE read that was
authorized, so swapping the file between reads has no effect."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise ModelError("CONFIGURATION") from None
    if provider == "lmstudio" and parts.scheme == "http" and host in LOOPBACK:
        return
    if host is None or host.lower() not in roe["allowed_remote_hosts"][provider]:
        raise ModelError("CONFIGURATION")


def authorize_live(provider, roe_sha256):
    """建立任何 live adapter 前，確認磁碟上的 RoE 正是 supervisor 驗證並綁定的那一份，並重新驗證此供應商。 / Before any
live adapter is built, confirm the RoE on disk is exactly the one the supervisor validated and bound, and
revalidate it for this provider; the file can change after the supervisor's check."""
    try:
        data = (ROOT / "security/model-roe.json").read_bytes()
    except OSError:
        raise ModelError("CONFIGURATION") from None
    if hashlib.sha256(data).hexdigest() != roe_sha256:
        raise ModelError("CONFIGURATION")
    try:
        return validate_model_roe(json.loads(data), [provider])
    except ValueError:
        raise ModelError("CONFIGURATION") from None


def configured_adapter(provider, roe_sha256, work=None, http=None):
    if provider == "mock":
        return MockAdapter()
    roe = authorize_live(provider, roe_sha256)
    if provider == "gemini":
        return GeminiAdapter(setting("GEMINI_MODEL_ID"), setting("GEMINI_API_KEY"), http=http)
    if provider == "lmstudio":
        base = setting("LMSTUDIO_BASE_URL")
        authorize_destination(provider, base, roe)
        return LMStudioAdapter(setting("LMSTUDIO_MODEL_ID"), base, setting("LMSTUDIO_API_KEY", False), http=http)
    if provider in CHAT_ADAPTERS:
        prefix, adapter = CHAT_ADAPTERS[provider]
        url = setting(prefix + "_CHAT_URL")
        authorize_destination(provider, url, roe)
        return adapter(setting(prefix + "_MODEL_ID"), url, setting(prefix + "_API_KEY", False), http=http)
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
