"""Trusted output shape only; never includes a case, oracle or expected answer."""

REVIEW_FORMAT = 'security-review-json-v1'


def review_schema():
    # Use the common provider-supported subset. Semantic limits, exact evidence,
    # duplicate keys and verdict/finding consistency remain locally enforced.
    return {
        'type': 'object', 'additionalProperties': False,
        'required': ['review_id', 'verdict', 'findings', 'reason'],
        'properties': {
            'review_id': {'type': 'string'},
            'verdict': {'type': 'string', 'enum': ['VULNERABLE', 'CLEAN', 'ABSTAIN']},
            'findings': {'type': 'array', 'items': {
                'type': 'object', 'additionalProperties': False,
                'required': ['cwe', 'line', 'evidence', 'rationale'],
                'properties': {
                    'cwe': {'type': 'string', 'enum': ['CWE-89', 'CWE-78', 'CWE-639', 'CWE-22', 'CWE-918']},
                    'line': {'type': 'integer'},
                    'evidence': {'type': 'string'},
                    'rationale': {'type': 'string', 'description': 'One concise sentence, preferably under 120 characters.'},
                }}},
            'reason': {'type': 'string', 'description': 'One concise sentence, preferably under 120 characters.'},
        },
    }
