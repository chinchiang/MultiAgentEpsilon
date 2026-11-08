"""此試點僅允許合成資料的硬性範圍；擴充測試須新增 adapter。

Hard bounds for this synthetic-only pilot. Broader testing needs a new adapter."""
import json
import re


def validate_roe(roe: dict) -> dict:
    if (not isinstance(roe, dict) or type(roe.get("schema_version")) is not int or roe["schema_version"] != 1
            or roe.get("database_name") != "epsilon_fixture"
            or roe.get("http_hosts") != ["127.0.0.1", "localhost", "::1"]
            or roe.get("allow_redirects") is not False
            or roe.get("external_callback") is not False
            or roe.get("llm_calls") is not False
            or type(roe.get("max_cases")) is not int or not 1 <= roe["max_cases"] <= 50
            or type(roe.get("max_seconds")) is not int or not 1 <= roe["max_seconds"] <= 120
            or type(roe.get("max_total_seconds")) is not int or not 1 <= roe["max_total_seconds"] <= 600):
        raise ValueError("RoE exceeds the synthetic loopback pilot's supported scope")
    return roe


MODEL_PROVIDERS = ("gemini", "bedrock", "glm", "deepseek", "lmstudio")
# 模型呼叫期限的程式硬上限；RoE 的期限政策只能在其內設定。 / The code's hard ceilings on model deadlines; the RoE's
# deadline policy can only set values within them.
MODEL_CALL_CEILING = 60
MODEL_RUN_CEILING = 130
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


def validate_model_roe(roe: dict, providers, planned_calls: int = 0) -> dict:
    """模型參考性呼叫採獨立 RoE。security/roe.json 控制安全閘門且 llm_calls 為 false；真實模型除 --live 外仍須明確審查範圍，計畫呼叫數須符合該政策上限，而不只符合程式硬上限。

Separate rules of engagement for advisory model calls.

    security/roe.json governs the security gates and keeps llm_calls false; live model
    calls need this explicit, reviewed scope instead of a bare --live flag. The planned
    live call count must fit the reviewed per-run cap, not only the code's ceiling.
    """
    allowed = roe.get("allowed_live_providers")
    if (not isinstance(providers, (list, tuple)) or not providers
            or any(type(p) is not str for p in providers)
            or len(set(providers)) != len(providers)
            or not set(providers) <= set(MODEL_PROVIDERS) | {'mock', 'mock-review-a', 'mock-review-b'}):
        raise ValueError("unknown or duplicate model provider / 未知或重複的模型供應商")
    live = [p for p in providers if p in MODEL_PROVIDERS]
    if (not isinstance(roe, dict) or type(roe.get("schema_version")) is not int or roe["schema_version"] != 1
            or roe.get("llm_calls") is not True
            or roe.get("data_class") != "synthetic" or roe.get("security_gate_effect") != "NONE"
            or not isinstance(allowed, list) or not allowed or len(set(allowed)) != len(allowed)
            or not set(allowed) <= set(MODEL_PROVIDERS) or not set(live) <= set(allowed)
            or type(roe.get("max_calls_per_run")) is not int or not 1 <= roe["max_calls_per_run"] <= 16
            or type(planned_calls) is not int or not 0 <= planned_calls <= roe["max_calls_per_run"]
            or not valid_remote_hosts(roe.get("allowed_remote_hosts"))
            or not valid_deadline_policy(roe.get("deadline_policy"))):
        raise ValueError("live model calls are outside the approved model RoE")
    return roe


def valid_deadline_policy(policy) -> bool:
    """版本化的期限政策：每次呼叫的預設與各供應商期限、整輪上限，都必須是程式硬上限內的整數秒。

A versioned deadline policy: the default and per-provider call deadlines and the run cap
    must all be whole seconds within the code's hard ceilings."""
    def seconds(value, low, high):
        return type(value) is int and low <= value <= high
    return (isinstance(policy, dict)
            and set(policy) == {"version", "default_call_seconds", "max_call_seconds", "max_total_seconds"}
            and type(policy["version"]) is int and policy["version"] == 1
            and seconds(policy["default_call_seconds"], 1, MODEL_CALL_CEILING)
            and isinstance(policy["max_call_seconds"], dict)
            and set(policy["max_call_seconds"]) <= set(MODEL_PROVIDERS)
            and all(seconds(v, 1, MODEL_CALL_CEILING) for v in policy["max_call_seconds"].values())
            and seconds(policy["max_total_seconds"], 10, MODEL_RUN_CEILING))


def call_seconds(policy, provider) -> int:
    """供應商每次呼叫的期限；mock 與未列出的供應商用預設值。 / One provider's per-call deadline; mocks and unlisted
    providers use the default."""
    return policy["max_call_seconds"].get(provider, policy["default_call_seconds"])


def run_seconds(policy, providers) -> int:
    """整輪期限：逐次期限總和加 10 秒收尾，不超過政策上限。 / The run deadline: the sum of per-call deadlines plus
    10 seconds to finish, capped by the policy."""
    return min(policy["max_total_seconds"], sum(call_seconds(policy, p) for p in providers) + 10)


def valid_remote_hosts(hosts) -> bool:
    """只允許 GLM、DeepSeek 與 LM Studio 的小寫主機名稱清單；不接受萬用字元、位址範圍或 IP 字面值。

Lowercase host-name lists for GLM, DeepSeek and LM Studio only; no wildcards,
    address ranges or IP literals (the last label must contain a letter)."""
    return (isinstance(hosts, dict) and set(hosts) == {"glm", "deepseek", "lmstudio"}
            and all(isinstance(v, list) and len(v) <= 8 and len(set(v)) == len(v)
                    and all(isinstance(h, str) and re.fullmatch(rf"{LABEL}(\.{LABEL})*\.(?=[a-z0-9-]*[a-z]){LABEL}", h)
                            for h in v) for v in hosts.values()))


def load_model_roe(root, providers, planned_calls: int = 0) -> dict:
    return validate_model_roe(json.loads((root / "security/model-roe.json").read_text()), providers, planned_calls)
