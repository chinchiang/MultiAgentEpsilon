"""受限的 LM Studio 文字介面；Bounded LM Studio text adapter.

本機 HTTP 僅限明確的 loopback；遠端保留代理與 TLS 驗證。
HTTP is limited to literal loopback; remote HTTPS preserves proxy and CA trust.
"""
import re
from urllib.parse import urlsplit, urlunsplit

from .adapters import chat_reply
from .gateway import ModelError
from .output_schema import REVIEW_FORMAT, request_schema
from .transport import JsonHTTP, validate_url


def endpoint(base):
    """驗證固定服務入口；Validate the fixed service origin and API path."""
    try:
        if (type(base) is not str or any(ord(c) <= 32 or ord(c) > 126 for c in base)
                or any(c in base for c in '\\%?#')):
            raise ValueError()
        p = urlsplit(base)
        if (p.path != '/v1' or p.username is not None or p.password is not None
                or urlunsplit(p) != base):
            raise ValueError()
        if p.scheme == 'https':
            validate_url(base)
            return False
        if (p.scheme != 'http' or p.hostname not in ('127.0.0.1', '::1')
                or p.port is None or not 1024 <= p.port <= 65535):
            raise ValueError()
        return True
    except (ValueError, TypeError):
        raise ModelError('CONFIGURATION') from None


class LMStudioHTTP(JsonHTTP):
    """僅允許已設定的兩個 API；Allow only the two configured API destinations."""

    def __init__(self, base, transport=None, timeout_seconds=30):
        local = endpoint(base)
        super().__init__(transport, timeout_seconds)
        self.base = base
        # 僅同主機 literal loopback 直連；跨主機仍使用平台代理。
        # Direct access applies only to same-host literal loopback, never remote hosts.
        self.trust_env = not local

    def validate(self, url):
        if url not in (self.base + '/models', self.base + '/chat/completions'):
            raise ModelError('CONFIGURATION')
        endpoint(self.base)


class LMStudioAdapter:
    """每次推論先核對模型清單；Check model availability before every inference."""
    provider = 'lmstudio'

    def __init__(self, model, base, api_key=None, http=None):
        endpoint(base)
        if type(model) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', model):
            raise ModelError('CONFIGURATION')
        self.model, self.base, self._api_key = model, base, api_key
        self.family = ('nemotron' if re.match(r'^(?:nvidia/)?nemotron-3-nano-omni(?:$|[-/])', model.lower())
                       else 'unverified')
        # 家族是設定與回報名稱的分類，不是模型權重的密碼學證明。
        # Family is a configured/reported-name classification, not a weight attestation.
        if http is not None and not isinstance(http, LMStudioHTTP):
            # 只轉接離線測試的 transport，仍套用本介面的目的地限制。
            # Reuse only the offline transport while retaining this destination policy.
            http = LMStudioHTTP(base, transport=http.transport, timeout_seconds=http.timeout_seconds)
        self.http = http or LMStudioHTTP(base)
        if self.http.base != base:
            raise ModelError('CONFIGURATION')

    async def generate(self, request):
        headers = {'Authorization': 'Bearer ' + self._api_key} if self._api_key else {}
        listing = await self.http.get(self.base + '/models', headers)
        models = listing.get('data')
        if (listing.get('object') != 'list' or not isinstance(models, list)
                or not 1 <= len(models) <= 256 or any(not isinstance(m, dict) or type(m.get('id')) is not str for m in models)):
            raise ModelError('INVALID_RESPONSE', 'ENVELOPE_SCHEMA')
        ids = [m['id'] for m in models]
        if len(set(ids)) != len(ids) or ids.count(self.model) != 1:
            raise ModelError('CONFIGURATION', 'MODEL_IDENTITY')
        payload = {'model': self.model,
                   'messages': [{'role': 'system', 'content': request.system},
                                {'role': 'user', 'content': request.user}],
                   'max_tokens': request.max_output_tokens, 'temperature': 0, 'stream': False, 'n': 1}
        if request.response_format == REVIEW_FORMAT:
            payload['response_format'] = {'type': 'json_schema', 'json_schema': {
                'name': 'security_review', 'strict': True, 'schema': request_schema(request, 'lmstudio')}}
        value = await self.http.post(self.base + '/chat/completions', headers, payload)
        if value.get('model') != self.model:
            raise ModelError('INVALID_RESPONSE', 'MODEL_IDENTITY')
        return chat_reply(value)
