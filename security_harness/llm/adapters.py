"""Gemini generateContent, OpenAI-compatible GLM chat, and Bedrock Converse."""
import re

from .gateway import ModelError, Reply
from .transport import AwsCLI, JsonHTTP, validate_url


def usage(value, input_key, output_key):
    if value is None:
        return None, None
    if not isinstance(value, dict):
        raise ModelError("INVALID_RESPONSE")
    counts = value.get(input_key), value.get(output_key)
    if any(v is not None and (type(v) is not int or not 0 <= v <= 10000000) for v in counts):
        raise ModelError("INVALID_RESPONSE")
    return counts


def text_parts(parts):
    if not isinstance(parts, list) or not parts:
        raise ModelError("INVALID_RESPONSE")
    texts = []
    for part in parts:
        if not isinstance(part, dict):
            raise ModelError("INVALID_RESPONSE")
        if any(key in part for key in ("functionCall", "toolUse", "executableCode", "codeExecutionResult")):
            raise ModelError("TOOL_REQUEST")
        if set(part) - {"text", "thought", "thoughtSignature"} or type(part.get("text")) is not str:
            raise ModelError("INVALID_RESPONSE")
        if "thought" in part and type(part["thought"]) is not bool:
            raise ModelError("INVALID_RESPONSE")
        if not part.get("thought", False):
            texts.append(part["text"])
    return "".join(texts)


class GeminiAdapter:
    provider = "gemini"
    family = "gemini"

    def __init__(self, model, api_key, http=None):
        # This display-name alias was resolved with the provider's model metadata.
        self.model = {"Gemini 3.8 Flash": "gemini-3.8-flash"}.get(model, model).removeprefix("models/")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.model) or not api_key:
            raise ModelError("CONFIGURATION")
        self._api_key = api_key
        self.http = http or JsonHTTP()

    async def generate(self, request):
        value = await self.http.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            {"x-goog-api-key": self._api_key},
            {"systemInstruction": {"parts": [{"text": request.system}]},
             "contents": [{"role": "user", "parts": [{"text": request.user}]}],
             "generationConfig": {"maxOutputTokens": request.max_output_tokens,
                                  "candidateCount": 1, "temperature": 0}})
        if value.get("promptFeedback", {}).get("blockReason"):
            raise ModelError("REFUSED")
        candidates = value.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1:
            raise ModelError("INVALID_RESPONSE")
        candidate = candidates[0]
        reason = candidate.get("finishReason")
        if reason == "MAX_TOKENS":
            raise ModelError("TRUNCATED")
        if reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"}:
            raise ModelError("REFUSED")
        if reason != "STOP" or candidate.get("content", {}).get("role") != "model":
            raise ModelError("INVALID_RESPONSE")
        text = text_parts(candidate["content"].get("parts"))
        return Reply(text, *usage(value.get("usageMetadata"), "promptTokenCount", "candidatesTokenCount"))


class GLMAdapter:
    provider = "glm"
    family = "glm"

    def __init__(self, model, url, api_key=None, http=None):
        parsed = validate_url(url)
        if parsed.path != "/v1/chat/completions" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", model):
            raise ModelError("CONFIGURATION")
        self.model, self._url, self._api_key = model, url, api_key
        self.http = http or JsonHTTP()

    async def generate(self, request):
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        value = await self.http.post(self._url, headers, {
            "model": self.model, "messages": [{"role": "system", "content": request.system},
                                               {"role": "user", "content": request.user}],
            "max_tokens": request.max_output_tokens, "temperature": 0, "stream": False, "n": 1})
        choices = value.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ModelError("INVALID_RESPONSE")
        choice = choices[0]
        message = choice.get("message", {})
        if message.get("tool_calls") or message.get("function_call") or choice.get("finish_reason") in {"tool_calls", "function_call"}:
            raise ModelError("TOOL_REQUEST")
        if message.get("refusal") or choice.get("finish_reason") == "content_filter":
            raise ModelError("REFUSED")
        if choice.get("finish_reason") == "length":
            raise ModelError("TRUNCATED")
        if (choice.get("finish_reason") != "stop" or message.get("role") != "assistant" or
                type(message.get("content")) is not str):
            raise ModelError("INVALID_RESPONSE")
        return Reply(message["content"], *usage(value.get("usage"), "prompt_tokens", "completion_tokens"))


class BedrockAdapter:
    provider = "bedrock"

    def __init__(self, model, region, cli=None):
        # May be a model ID, inference profile ID or ARN; never infer it from SSO role.
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,2047}", model) or
                not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region)):
            raise ModelError("CONFIGURATION")
        self.model, self.region, self.cli = model, region, cli or AwsCLI()
        self.family = "claude" if "anthropic.claude" in model else "unverified"

    async def generate(self, request):
        value = await self.cli.converse(self.region, {
            "modelId": self.model, "system": [{"text": request.system}],
            "messages": [{"role": "user", "content": [{"text": request.user}]}],
            # Sampling knobs are model-specific; retain the provider default.
            "inferenceConfig": {"maxTokens": request.max_output_tokens}})
        reason = value.get("stopReason")
        if reason == "tool_use":
            raise ModelError("TOOL_REQUEST")
        if reason in {"guardrail_intervened", "content_filtered"}:
            raise ModelError("REFUSED")
        if reason in {"max_tokens", "model_context_window_exceeded"}:
            raise ModelError("TRUNCATED")
        message = value.get("output", {}).get("message", {})
        if reason != "end_turn" or message.get("role") != "assistant":
            raise ModelError("INVALID_RESPONSE")
        text = text_parts(message.get("content"))
        return Reply(text, *usage(value.get("usage"), "inputTokens", "outputTokens"))
