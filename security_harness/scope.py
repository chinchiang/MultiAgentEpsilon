"""Hard bounds for this synthetic-only pilot. Broader testing needs a new adapter."""
import json


def validate_roe(roe: dict) -> dict:
    if (roe.get("schema_version") != 1 or roe.get("database_name") != "epsilon_fixture"
            or roe.get("http_hosts") != ["127.0.0.1", "localhost", "::1"]
            or roe.get("allow_redirects") is not False
            or roe.get("external_callback") is not False
            or roe.get("llm_calls") is not False
            or type(roe.get("max_cases")) is not int or not 1 <= roe["max_cases"] <= 50
            or type(roe.get("max_seconds")) is not int or not 1 <= roe["max_seconds"] <= 120
            or type(roe.get("max_total_seconds")) is not int or not 1 <= roe["max_total_seconds"] <= 600):
        raise ValueError("RoE exceeds the synthetic loopback pilot's supported scope")
    return roe


MODEL_PROVIDERS = ("gemini", "bedrock", "glm")


def validate_model_roe(roe: dict, providers, planned_calls: int = 0) -> dict:
    """Separate rules of engagement for advisory model calls.

    security/roe.json governs the security gates and keeps llm_calls false; live model
    calls need this explicit, reviewed scope instead of a bare --live flag. The planned
    live call count must fit the reviewed per-run cap, not only the code's ceiling.
    """
    allowed = roe.get("allowed_live_providers")
    live = [p for p in providers if p in MODEL_PROVIDERS]
    if (roe.get("schema_version") != 1 or roe.get("llm_calls") is not True
            or roe.get("data_class") != "synthetic" or roe.get("security_gate_effect") != "NONE"
            or not isinstance(allowed, list) or not allowed or len(set(allowed)) != len(allowed)
            or not set(allowed) <= set(MODEL_PROVIDERS) or not set(live) <= set(allowed)
            or type(roe.get("max_calls_per_run")) is not int or not 1 <= roe["max_calls_per_run"] <= 16
            or type(planned_calls) is not int or not 0 <= planned_calls <= roe["max_calls_per_run"]):
        raise ValueError("live model calls are outside the approved model RoE")
    return roe


def load_model_roe(root, providers, planned_calls: int = 0) -> dict:
    return validate_model_roe(json.loads((root / "security/model-roe.json").read_text()), providers, planned_calls)
