"""Trusted output shape only; never includes a case, oracle or expected answer."""

REVIEW_FORMAT = 'security-review-json-v1'


def review_schema(provider='bedrock', source_lines=None):
    # Use the common provider-supported subset. Semantic limits, exact evidence,
    # duplicate keys and verdict/finding consistency remain locally enforced.
    if provider not in ('bedrock', 'gemini'):
        raise ValueError('unsupported structured output provider')
    if source_lines is not None and (type(source_lines) is not int or not 1 <= source_lines <= 512):
        raise ValueError('invalid source line count')
    line = {'type': 'integer', 'description': 'A 1-based root-cause source line.'}
    if provider == 'gemini':
        line.update(minimum=1)
        if source_lines is not None:
            line['maximum'] = source_lines
    elif source_lines is not None:
        # Bedrock rejects minimum/maximum, but enum expresses the permitted lines.
        line['enum'] = list(range(1, source_lines + 1))
    return {
        'type': 'object', 'additionalProperties': False,
        'required': ['review_id', 'verdict', 'findings', 'reason'],
        'properties': {
            'review_id': {'type': 'string'},
            'verdict': {'type': 'string', 'enum': ['VULNERABLE', 'CLEAN', 'ABSTAIN']},
            'findings': {'type': 'array', 'maxItems': 3, 'items': {
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
