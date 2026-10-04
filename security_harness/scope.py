"""Hard bounds for this synthetic-only pilot. Broader testing needs a new adapter."""


def validate_roe(roe: dict) -> dict:
    if (roe.get("schema_version") != 1 or roe.get("database_name") != "epsilon_fixture"
            or roe.get("http_hosts") != ["127.0.0.1", "localhost", "::1"]
            or roe.get("allow_redirects") is not False
            or roe.get("external_callback") is not False
            or roe.get("llm_calls") is not False
            or type(roe.get("max_cases")) is not int or not 1 <= roe["max_cases"] <= 50
            or type(roe.get("max_seconds")) is not int or not 1 <= roe["max_seconds"] <= 120):
        raise ValueError("RoE exceeds the synthetic loopback pilot's supported scope")
    return roe
