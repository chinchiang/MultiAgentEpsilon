"""Gemini generateContent, OpenAI-compatible GLM chat, and Bedrock Converse."""
import re
import json

from .gateway import ModelError, Reply
from .transport import AwsCLI, JsonHTTP, validate_url
from .output_schema import REVIEW_FORMAT, request_schema


def usage(value, input_key, output_key):
    if value is None:
        return None, None
    if not isinstance(value, dict):
        raise ModelError("INVALID_RESPONSE", "USAGE_SCHEMA")
    counts = value.get(input_key), value.get(output_key)
    if any(v is not None and (type(v) is not int or not 0 <= v <= 10000000) for v in counts):
        raise ModelError("INVALID_RESPONSE", "USAGE_SCHEMA")
    return counts


def text_parts(parts):
    if not isinstance(parts, list) or not parts:
        raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
    texts = []
    for part in parts:
        if not isinstance(part, dict):
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        if any(key in part for key in ("functionCall", "toolUse", "executableCode", "codeExecutionResult")):
            raise ModelError("TOOL_REQUEST")
        if set(part) - {"text", "thought", "thoughtSignature"} or type(part.get("text")) is not str:
            raise ModelError("INVALID_RESPONSE", "UNEXPECTED_CONTENT")
        if "thought" in part and type(part["thought"]) is not bool:
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        if not part.get("thought", False):
            texts.append(part["text"])
    text = "".join(texts)
    if not text.strip():
        raise ModelError("INVALID_RESPONSE", "EMPTY_TEXT")
    return text


def object_field(value, key):
    if not isinstance(value, dict):
        raise ModelError('INVALID_RESPONSE', 'ENVELOPE_SCHEMA')
    if key not in value:
        raise ModelError('INVALID_RESPONSE', 'MISSING_FIELD')
    if not isinstance(value[key], dict):
        raise ModelError('INVALID_RESPONSE', 'ENVELOPE_SCHEMA')
    return value[key]


def reported_model(value):
    """Provider-reported serving model, to detect a floating alias drifting mid-run.
    Malformed values are dropped (unknown), never trusted as identity."""
    return value if type(value) is str and 0 < len(value) <= 256 and value.isprintable() else None


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
        config = {"maxOutputTokens": request.max_output_tokens, "candidateCount": 1, "temperature": 0}
        if request.response_format == REVIEW_FORMAT:
            config.update(responseMimeType='application/json', responseJsonSchema=request_schema(request, 'gemini'))
            # Use LOW for Gemini 3 Flash; MINIMAL was rejected by the live model.
            # Do not send this model-specific
            # option to earlier generations, Pro, or arbitrary model aliases.
            if re.fullmatch(r'gemini-3(?:\.\d+)?-flash(?:-[a-z0-9-]+)?', self.model):
                config['thinkingConfig'] = {'thinkingLevel': 'LOW', 'includeThoughts': False}
        value = await self.http.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            {"x-goog-api-key": self._api_key},
            {"systemInstruction": {"parts": [{"text": request.system}]},
             "contents": [{"role": "user", "parts": [{"text": request.user}]}],
             "generationConfig": config})
        if "promptFeedback" in value and not isinstance(value["promptFeedback"], dict):
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        if value.get("promptFeedback", {}).get("blockReason"):
            raise ModelError("REFUSED")
        if "candidates" not in value:
            raise ModelError("INVALID_RESPONSE", "MISSING_FIELD")
        candidates = value.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1:
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        candidate = candidates[0]
        if not isinstance(candidate, dict):
            raise ModelError('INVALID_RESPONSE', 'ENVELOPE_SCHEMA')
        reason = candidate.get("finishReason")
        if reason == "MAX_TOKENS":
            raise ModelError("TRUNCATED")
        if reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"}:
            raise ModelError("REFUSED")
        content = object_field(candidate, "content")
        if reason != "STOP":
            raise ModelError("INVALID_RESPONSE", "MISSING_FIELD" if reason is None else "STOP_REASON")
        if content.get("role") != "model":
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        text = text_parts(candidate["content"].get("parts"))
        metadata = value.get('usageMetadata')
        inputs, outputs = usage(metadata, 'promptTokenCount', 'candidatesTokenCount')
        _, thoughts = usage(metadata, 'promptTokenCount', 'thoughtsTokenCount')
        if thoughts is not None and outputs is None:
            # Reported thinking without a visible-output count cannot be checked against the budget.
            raise ModelError('INVALID_RESPONSE', 'USAGE_SCHEMA')
        # The output budget covers both visible output and internal thinking.
        return Reply(text, inputs, outputs + (thoughts or 0) if outputs is not None else None,
                     reported_model(value.get('modelVersion')))


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
        if "choices" not in value:
            raise ModelError("INVALID_RESPONSE", "MISSING_FIELD")
        choices = value.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        choice = choices[0]
        message = object_field(choice, "message")
        if message.get("tool_calls") or message.get("function_call") or choice.get("finish_reason") in {"tool_calls", "function_call"}:
            raise ModelError("TOOL_REQUEST")
        if message.get("refusal") or choice.get("finish_reason") == "content_filter":
            raise ModelError("REFUSED")
        if choice.get("finish_reason") == "length":
            raise ModelError("TRUNCATED")
        if choice.get("finish_reason") != "stop":
            raise ModelError("INVALID_RESPONSE", "MISSING_FIELD" if choice.get("finish_reason") is None else "STOP_REASON")
        if (message.get("role") != "assistant" or
                type(message.get("content")) is not str):
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        return Reply(message["content"], *usage(value.get("usage"), "prompt_tokens", "completion_tokens"),
                     reported_model(value.get("model")))


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
        payload = {
            "modelId": self.model, "system": [{"text": request.system}],
            "messages": [{"role": "user", "content": [{"text": request.user}]}],
            # Sampling knobs are model-specific; retain the provider default.
            "inferenceConfig": {"maxTokens": request.max_output_tokens}}
        if request.response_format == REVIEW_FORMAT:
            payload['outputConfig'] = {'textFormat': {
                'type': 'json_schema', 'structure': {'jsonSchema': {
                    'name': 'security_review', 'schema': json.dumps(request_schema(request, 'bedrock'), separators=(',', ':'))}}}}
        value = await self.cli.converse(self.region, payload)
        reason = value.get("stopReason")
        if reason == "tool_use":
            raise ModelError("TOOL_REQUEST")
        if reason in {"guardrail_intervened", "content_filtered"}:
            raise ModelError("REFUSED")
        if reason in {"max_tokens", "model_context_window_exceeded"}:
            raise ModelError("TRUNCATED")
        message = object_field(object_field(value, "output"), "message")
        if reason != "end_turn":
            raise ModelError("INVALID_RESPONSE", "MISSING_FIELD" if reason is None else "STOP_REASON")
        if message.get("role") != "assistant":
            raise ModelError("INVALID_RESPONSE", "ENVELOPE_SCHEMA")
        if 'content' not in message:
            raise ModelError('INVALID_RESPONSE', 'MISSING_FIELD')
        text = text_parts(message['content'])
        return Reply(text, *usage(value.get("usage"), "inputTokens", "outputTokens"))
