"""只定義可信輸出格式，不包含案例、oracle 或預期答案。

Trusted output shape only; never includes a case, oracle or expected answer."""

REVIEW_FORMAT = 'security-review-json-v1'


def review_schema(provider='bedrock', source_lines=None):
    # 採用供應商共通支援子集；語意上限、精確引用、 / Use the common provider-supported subset. Semantic limits, exact evidence,
    # 重複鍵與判定／finding 一致性仍由本機強制驗證。 / duplicate keys and verdict/finding consistency remain locally enforced.
    if provider not in ('bedrock', 'gemini', 'lmstudio'):
        raise ValueError('unsupported structured output provider')
    if source_lines is not None and (type(source_lines) is not int or not 1 <= source_lines <= 512):
        raise ValueError('invalid source line count')
    line = {'type': 'integer', 'description': 'A 1-based root-cause source line.'}
    if provider in ('gemini', 'lmstudio'):
        line.update(minimum=1)
        if source_lines is not None:
            line['maximum'] = source_lines
    elif source_lines is not None:
        # Bedrock 拒絕 minimum/maximum，以 enum 列出允許行號。 / Bedrock rejects minimum/maximum, but enum expresses the permitted lines.
        line['enum'] = list(range(1, source_lines + 1))
    schema = {
        'type': 'object', 'additionalProperties': False,
        'required': ['review_id', 'verdict', 'findings', 'reason'],
        'properties': {
            'review_id': {'type': 'string'},
            'verdict': {'type': 'string', 'enum': ['VULNERABLE', 'CLEAN', 'ABSTAIN']},
            'findings': {'type': 'array', 'description': 'At most three findings; empty for CLEAN or ABSTAIN.', 'items': {
                'type': 'object', 'additionalProperties': False,
                'required': ['cwe', 'line', 'evidence', 'rationale'],
                'properties': {
                    'cwe': {'type': 'string', 'enum': ['CWE-89', 'CWE-78', 'CWE-639', 'CWE-22', 'CWE-918']},
                    'line': line,
                    'evidence': {'type': 'string'},
                    'rationale': {'type': 'string', 'description': 'One concise sentence, nonempty, at most 400 characters; preferably under 120.'},
                }}},
            'reason': {'type': 'string', 'description': 'One concise sentence, nonempty, at most 400 characters; preferably under 120.'},
        },
    }
    # Bedrock 的陣列約束只列出 minItems=0/1；真實 / Bedrock documents only minItems=0/1 among array constraints. Its live
    # 驗證器拒絕 maxItems，本機仍維持最多三項 finding。 / validator rejects maxItems; retain the three-finding limit locally.
    if provider in ('gemini', 'lmstudio'):
        schema['properties']['findings']['maxItems'] = 3
    return schema


def request_schema(request, provider):
    import json
    from .gateway import ModelError
    try:
        source = json.loads(request.user)['source']
        if type(source) is not str or not 1 <= len(source.splitlines()) <= 512:
            raise ValueError('invalid synthetic source')
    except (ValueError, KeyError, TypeError):
        raise ModelError('CONFIGURATION') from None
    return review_schema(provider, len(source.splitlines()))
