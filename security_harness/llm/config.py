"""模型供應商設定與目的地授權；可帶金鑰的遠端主機必須列在已審查的模型 RoE。

Model provider configuration and destination authorization.

A remote host that may receive an API key must be listed in the reviewed model
RoE; only LM Studio's literal loopback HTTP needs no entry.
"""
import ast
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
from .transport import AWS_ALLOWED_ENV, AwsCLI

ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER_HOSTS = {"local.example.invalid"}
LOOPBACK = ("127.0.0.1", "::1")
# 地端 OpenAI 相容 chat 供應商與其環境變數前綴。 / On-prem OpenAI-compatible chat providers and their setting prefixes.
CHAT_ADAPTERS = {"glm": ("GLM", GLMAdapter), "deepseek": ("DEEPSEEK", DeepSeekAdapter)}
# 各供應商在 configured_adapter 讀取的設定名稱；model worker 只收到所選供應商的這些名稱。 / The settings
# configured_adapter reads per provider; the model worker receives only those of the selected providers.
PROVIDER_ENV = {
    "gemini": frozenset({"GEMINI_MODEL_ID", "GEMINI_API_KEY"}),
    "lmstudio": frozenset({"LMSTUDIO_BASE_URL", "LMSTUDIO_MODEL_ID", "LMSTUDIO_API_KEY"}),
    **{provider: frozenset({prefix + "_CHAT_URL", prefix + "_MODEL_ID", prefix + "_API_KEY"})
       for provider, (prefix, _) in CHAT_ADAPTERS.items()},
    "bedrock": frozenset({"BEDROCK_MODEL_ID", "BEDROCK_REGION", "AWS_CLI_PATH"}) | AWS_ALLOWED_ENV,
}


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
    # Bedrock 走 AWS CLI，其讀取逾時取自計畫給此供應商的呼叫期限。 / Bedrock goes through the AWS CLI, whose read
    # timeout comes from the call deadline the plan gives this provider.
    seconds = http.timeout_seconds if http is not None else 20
    return BedrockAdapter(setting("BEDROCK_MODEL_ID"), setting("BEDROCK_REGION"),
                          AwsCLI(executable, run_directory=work, timeout_seconds=seconds))


def imported_modules(path):
    """這個檔案匯入的本專案模組檔（security_harness 與 scripts 之下），含函式內的延後匯入。 / This file's imports that
    are project module files under security_harness and scripts, including imports deferred inside functions."""
    package = path.parent.relative_to(ROOT).parts
    found = set()
    for node in ast.walk(ast.parse(path.read_bytes())):
        if isinstance(node, ast.Import):
            names = [alias.name.split('.') for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = list(package[:len(package) - node.level + 1]) if node.level else []
            base += node.module.split('.') if node.module else []
            # from 套件 import 名稱：名稱可能是子模組。 / from package import name: the name may be a submodule.
            names = [base, *([*base, alias.name] for alias in node.names)]
        else:
            continue
        for parts in names:
            if parts and parts[0] in ('security_harness', 'scripts'):
                for candidate in (ROOT.joinpath(*parts).with_suffix('.py'), ROOT.joinpath(*parts, '__init__.py')):
                    if candidate.is_file():
                        found.add(candidate)
    return found


def implementation_files():
    """模型評測實際用到的程式：模型套件、模型操作入口，以及它們直接或間接匯入的共用模組。與模型評測無關的
    security_harness 模組不在其中，改動它們不會讓既有報告變成無法比較。 / The code the model benchmark actually uses:
    the model package, the model entry points and every shared module they import directly or transitively. Modules
    of security_harness unrelated to the benchmark are left out, so changing them does not make existing reports
    incomparable."""
    files = {ROOT / 'scripts/__init__.py', ROOT / 'security_harness/__init__.py',
             *ROOT.glob('scripts/model_*.py'), *ROOT.glob('security_harness/llm/**/*.py')}
    pending = list(files)
    while pending:
        for module in imported_modules(pending.pop()) - files:
            files.add(module)
            pending.append(module)
    return files


def implementation_digest():
    """綁定模型實作、套件初始化、實際匯入的共用核心、RoE 與 lock。 / Bind model code, package initializers, the shared
    core it actually imports, the RoE and the lock."""
    paths = sorted({ROOT / 'requirements.lock', ROOT / 'security/model-roe.json', *implementation_files()})
    manifest = [(p.relative_to(ROOT).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()
