"""Provider-independent limits and redacted evidence for advisory model calls."""
import asyncio
import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Protocol

from .output_schema import REVIEW_FORMAT


class ModelError(Exception):
    """Only fixed error codes may cross the evidence boundary."""

    CODES = frozenset({"CONFIGURATION", "TRANSPORT", "HTTP_ERROR", "RATE_LIMIT",
                       "AUTHENTICATION", "REDIRECT", "RESPONSE_LIMIT", "INVALID_RESPONSE",
                       "REFUSED", "TRUNCATED", "TOOL_REQUEST", "PROVIDER_FAILURE"})

    DETAILS = frozenset({'JSON_SYNTAX', 'JSON_ENCODING', 'JSON_DUPLICATE_KEY',
        'JSON_NONFINITE', 'ENVELOPE_SCHEMA', 'MISSING_FIELD', 'UNEXPECTED_CONTENT',
        'EMPTY_TEXT', 'USAGE_SCHEMA', 'STOP_REASON', 'REVIEW_SCHEMA', 'EVIDENCE_MISMATCH',
        'HTTP_CONTENT_TYPE', 'OUTPUT_CONFIGURATION', 'THINKING_CONFIGURATION'})

    def __init__(self, code, detail=None):
        self.code = code if code in self.CODES else "PROVIDER_FAILURE"
        self.detail = detail if type(detail) is str and detail in self.DETAILS else None
        super().__init__(self.code)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Request:
    system: str = field(repr=False)
    user: str = field(repr=False)
    data_class: str = "synthetic"
    max_output_tokens: int = 128
    response_format: str = 'text'


def request_digest(request):
    return digest(json.dumps(
        [request.system, request.user, request.data_class, request.max_output_tokens, request.response_format],
        ensure_ascii=True, separators=(',', ':')))


@dataclass(frozen=True)
class Reply:
    text: str = field(repr=False)
    input_tokens: int | None = None
    output_tokens: int | None = None


class Adapter(Protocol):
    provider: str
    family: str
    model: str

    async def generate(self, request: Request) -> Reply: ...


@dataclass(frozen=True)
class Limits:
    max_calls: int = 3
    reserved_output_tokens: int = 768
    timeout_seconds: float = 30
    max_input_bytes: int = 16384
    max_output_bytes: int = 65536

    def __post_init__(self):
        for value, ceiling in ((self.max_calls, 16), (self.reserved_output_tokens, 8192),
                               (self.max_input_bytes, 16384), (self.max_output_bytes, 65536)):
            if type(value) is not int or not 0 < value <= ceiling:
                raise ValueError("invalid gateway limit")
        if (type(self.timeout_seconds) not in (int, float) or
                not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 60):
            raise ValueError("invalid gateway deadline")


class Gateway:
    """One event-loop instance. Reserve before I/O; no retries or paid fallback.

    Adapters and data classification are trusted caller configuration, not model
    input. A synthetic label is not a DLP detector. The CLI uses a fixed fixture.
    """

    def __init__(self, limits=None):
        self.limits = limits or Limits()
        self.calls = 0
        self.reserved_tokens = 0
        self.evidence = []

    async def generate(self, adapter: Adapter, request: Request) -> Reply | None:
        evidence = {"schema_version": 1, "call_id": str(uuid.uuid4()),
                    "provider": adapter.provider, "family": adapter.family,
                    "model_sha256": digest(adapter.model), "status": "ERROR", "code": None,
                    "request_sha256": None, "response_sha256": None, "diagnostic": None,
                    "input_tokens": None, "output_tokens": None, "advisory_only": True}
        self.evidence.append(evidence)
        started = time.monotonic()
        try:
            if (not isinstance(request, Request) or request.data_class != "synthetic" or
                    type(request.system) is not str or type(request.user) is not str or
                    not request.system or not request.user or
                    type(request.max_output_tokens) is not int or
                    type(request.response_format) is not str or request.response_format not in ('text', REVIEW_FORMAT) or
                    not 0 < request.max_output_tokens <= 4096):
                evidence["code"] = "ROUTING_DENIED"
                return None
            size = len(request.system.encode()) + len(request.user.encode())
            if size > self.limits.max_input_bytes:
                evidence["code"] = "INPUT_LIMIT"
                return None
            evidence["request_sha256"] = request_digest(request)
            if (self.calls >= self.limits.max_calls or self.reserved_tokens +
                    request.max_output_tokens > self.limits.reserved_output_tokens):
                evidence["code"] = "BUDGET_EXHAUSTED"
                return None
            self.calls += 1
            self.reserved_tokens += request.max_output_tokens
            async with asyncio.timeout(self.limits.timeout_seconds):
                reply = await adapter.generate(request)
            if not isinstance(reply, Reply) or type(reply.text) is not str or not reply.text.strip():
                raise ModelError("INVALID_RESPONSE", "EMPTY_TEXT")
            if len(reply.text.encode()) > self.limits.max_output_bytes:
                raise ModelError("RESPONSE_LIMIT")
            for value in (reply.input_tokens, reply.output_tokens):
                if value is not None and (type(value) is not int or not 0 <= value <= 10000000):
                    raise ModelError("INVALID_RESPONSE", "USAGE_SCHEMA")
            if reply.output_tokens is not None and reply.output_tokens > request.max_output_tokens:
                raise ModelError("RESPONSE_LIMIT")
            evidence.update(status="SUCCESS", response_sha256=digest(reply.text),
                            input_tokens=reply.input_tokens, output_tokens=reply.output_tokens)
            return reply
        except asyncio.CancelledError:
            evidence.update(status="CANCELLED", code="CANCELLED")
            raise
        except TimeoutError:
            evidence.update(status="TIMEOUT", code="DEADLINE")
        except ModelError as exc:
            evidence["code"] = exc.code
            evidence["diagnostic"] = exc.detail
        except Exception:
            # Do not serialize exception messages, provider payloads or URLs.
            evidence["code"] = "PROVIDER_FAILURE"
        finally:
            evidence["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        return None


class MockAdapter:
    provider = "mock"
    family = "mock"
    model = "synthetic-contract-v1"

    async def generate(self, request):
        return Reply("EPSILON_SYNTHETIC_OK")
