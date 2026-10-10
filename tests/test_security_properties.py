"""離線性質測試：有效輸入可通過，違反契約必須拒絕。

Offline properties: valid inputs pass; contract violations must reject."""
from copy import deepcopy
from datetime import timedelta
import json

from hypothesis import given, settings, strategies as st
import pytest
from security_harness.results import validate_cases, seeded_defects
from security_harness.trusted_publisher import strict_json, Denied
from security_harness.llm.benchmark import validate_review, bounded_text
from security_harness.llm.gateway import ModelError
from tests.test_policy import records, judge, NOW, POLICY

PROPERTY = settings(max_examples=80, derandomize=True, database=None, deadline=None)
NAMES = st.lists(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789', min_size=1, max_size=12),
                 min_size=2, max_size=12, unique=True)


@PROPERTY
@given(NAMES, st.booleans())
def test_exact_case_sets_accept_reordering_and_real_booleans(names, passed):
    contract = {'case_ids': names}
    validate_cases([{'case': n, 'passed': passed} for n in reversed(names)], contract)
    with pytest.raises(ValueError, match='^invalid\\ case\\ coverage$'):
        validate_cases([{'case': n, 'passed': int(passed)} for n in names], contract)
    with pytest.raises(ValueError, match='^missing,\\ duplicate\\ or\\ unknown\\ case\\ ID$'):
        validate_cases([{'case': names[0], 'passed': True} for _ in names], contract)


@PROPERTY
@given(NAMES)
def test_seeded_manifest_requires_nonempty_proper_subset(names):
    assert seeded_defects({'case_ids': names, 'seeded_defect_case_ids': names[:-1]}) == set(names[:-1])
    for invalid in ([], names, names + ['outside'], [names[0], names[0]]):
        with pytest.raises(ValueError, match='^invalid\\ seeded\\ defect\\ manifest$'):
            seeded_defects({'case_ids': names, 'seeded_defect_case_ids': invalid})


@PROPERTY
@given(st.integers(min_value=0, max_value=2), st.sampled_from(['ERROR', 'TIMEOUT', 'CANCELLED', 'NOT_RUN']))
def test_noncompleted_gate_can_never_allow(index, status):
    rows = records()
    assert judge(rows) == 'ALLOW'
    rows[index]['execution'] = status
    assert judge(rows) == 'BLOCK'


@PROPERTY
@given(st.sampled_from(['run_id', 'subject_digest', 'policy_digest']),
       st.text(alphabet='abcdef0123456789', min_size=1, max_size=30))
def test_foreign_binding_never_allows(field, value):
    rows = records()
    rows[0][field] = value
    assert judge(rows) == 'BLOCK'


@PROPERTY
@given(st.integers(min_value=1, max_value=100000))
def test_future_and_expired_evidence_never_allows(seconds):
    for age in (-seconds, POLICY['max_evidence_age_seconds'] + seconds):
        rows = records()
        rows[-1]['created_at'] = (NOW - timedelta(seconds=age)).isoformat()
        assert judge(rows) == 'BLOCK'


@PROPERTY
@given(st.text(alphabet='abcXYZ012', min_size=1, max_size=12), st.integers())
def test_duplicate_json_keys_rejected_at_any_depth(key, value):
    encoded = json.dumps(key)
    raw = '{"outer":{' + encoded + ':' + str(value) + ',' + encoded + ':0}}'
    with pytest.raises(Denied, match='^DUPLICATE_JSON_KEY$'):
        strict_json(raw.encode())
    assert strict_json(json.dumps({key: value}).encode()) == {key: value}


@PROPERTY
@given(st.integers(min_value=1, max_value=400))
def test_readable_text_length_and_invisible_boundaries(size):
    assert bounded_text('x' * size)
    assert not bounded_text('x' * 401)
    assert not bounded_text(' ' * size)
    for hidden in ('\x00', '\u202e', '\u200b', '\u034f', '\u3164', '\u2800', '\ufe00', '\ufe0f', '\U000e0100', '\U000e01ef'):
        assert not bounded_text('x' + hidden)


@PROPERTY
@given(st.integers(min_value=1, max_value=20), st.sampled_from(['CLEAN', 'ABSTAIN']))
def test_review_consistency_and_exact_source_reference(lines, verdict):
    case = {'source': '\n'.join('line' + str(i) for i in range(lines))}
    value = {'review_id': 'review', 'verdict': verdict, 'reason': 'checked', 'findings': []}
    assert validate_review(value, case, 'review') == value
    finding = {'cwe': 'CWE-22', 'line': lines, 'evidence': 'line' + str(lines - 1), 'rationale': 'checked'}
    value.update(verdict='VULNERABLE', findings=[finding])
    assert validate_review(value, case, 'review') == value
    for invalid in (0, lines + 1, True, -1):
        forged = deepcopy(value); forged['findings'][0]['line'] = invalid
        with pytest.raises(ModelError, match='^INVALID_RESPONSE$'):
            validate_review(forged, case, 'review')
    for field, replacement in [('evidence', 'fabricated'), ('cwe', 'CWE-0')]:
        forged = deepcopy(value); forged['findings'][0][field] = replacement
        with pytest.raises(ModelError, match='^INVALID_RESPONSE$'):
            validate_review(forged, case, 'review')
    value['findings'] *= 2
    with pytest.raises(ModelError, match='^INVALID_RESPONSE$'):
        validate_review(value, case, 'review')


@PROPERTY
@given(st.integers(min_value=309, max_value=10000), st.sampled_from(['', '-']))
def test_publisher_rejects_floating_point_overflow(exponent, sign):
    with pytest.raises(Denied, match='^NONFINITE_JSON$'):
        strict_json(('{"nested":[{"value":' + sign + '1e' + str(exponent) + '}]}').encode())


@pytest.mark.parametrize('invalid', [None, [], '', {}, [None], [''], ['a', 'a']])
def test_invalid_case_manifest_rejected(invalid):
    with pytest.raises((ValueError, TypeError), match='^invalid\\ required\\ case\\ manifest$'):
        validate_cases([], {'case_ids': invalid})


@pytest.mark.parametrize('seeded', [[''], [None], ['a', 'a']])
def test_invalid_seeded_identity_rejected(seeded):
    with pytest.raises((ValueError, TypeError), match='^invalid\\ seeded\\ defect\\ manifest$'):
        seeded_defects({'case_ids': ['', None, 'a', 'b'], 'seeded_defect_case_ids': seeded})


def test_decision_uses_supplied_clock_at_exact_expiration():
    from datetime import datetime, timezone
    from security_harness.results import decide
    policy = {'required_gates': ['G'], 'gate_contracts': {'G': {'kind': 'scan'}}, 'max_evidence_age_seconds': 30}
    from security_harness.results import result
    now = datetime(2020, 1, 1, tzinfo=timezone.utc)
    row = result('G', 'COMPLETED', 'scan', 1, 0, 's', 'p', 'synthetic', run_id='r')
    row['created_at'] = (now - timedelta(seconds=30)).isoformat()
    assert decide([row], policy, 's', 'p', now, run_id='r')['decision'] == 'ALLOW'
    row['created_at'] = now.isoformat()
    assert decide([row], policy, 's', 'p', now, run_id='r')['decision'] == 'ALLOW'


@pytest.mark.parametrize('field', ['run_id', 'subject_digest', 'policy_digest'])
def test_empty_binding_cannot_be_self_consistent(field):
    from security_harness.results import decide
    rows = records()
    for r in rows:
        r[field] = ''
    bindings = {'subject_digest': 'subject', 'policy_digest': 'policy', 'run_id': 'run'}
    bindings[field] = ''
    assert decide(rows, POLICY, bindings['subject_digest'], bindings['policy_digest'], NOW,
                  run_id=bindings['run_id'])['decision'] == 'BLOCK'


def test_zero_coverage_rejected_without_other_optional_scan_contracts():
    from security_harness.results import decide, result
    policy = {'required_gates': ['G'], 'gate_contracts': {'G': {'kind': 'scan'}}, 'max_evidence_age_seconds': 60}
    row = result('G', 'COMPLETED', 'scan', 0, 0, 's', 'p', 'synthetic', run_id='r')
    assert decide([row], policy, 's', 'p', run_id='r')['decision'] == 'BLOCK'


def test_three_distinct_findings_and_json_byte_limit_are_inclusive():
    from security_harness.llm.benchmark import parse_review
    case = {'source': 'a\nb\nc\nd'}
    findings = [{'cwe': 'CWE-22', 'line': i + 1, 'evidence': c, 'rationale': 'checked'} for i, c in enumerate('abcd')]
    value = {'review_id': 'r', 'verdict': 'VULNERABLE', 'findings': findings[:3], 'reason': 'checked'}
    assert validate_review(value, case, 'r') == value
    value['findings'] = findings
    with pytest.raises(ModelError, match='^INVALID_RESPONSE$'):
        validate_review(value, case, 'r')
    value.update(verdict='CLEAN', findings=[])
    raw = json.dumps(value)
    padded = raw + ' ' * (16384 - len(raw.encode()))
    assert parse_review(padded, case, 'r') == value
    with pytest.raises(ModelError, match='^RESPONSE_LIMIT$'):
        parse_review(padded + ' ', case, 'r')


def test_matching_empty_case_identity_is_still_invalid():
    with pytest.raises(ValueError, match='^invalid\\ required\\ case\\ manifest$'):
        validate_cases([{'case': '', 'passed': True}], {'case_ids': ['']})


@pytest.mark.parametrize('gate', ['UNKNOWN', 1, None, [], {}])
def test_unknown_gate_cannot_be_hidden_beside_valid_records(gate):
    rows = records(); extra = deepcopy(rows[0]); extra['gate'] = gate
    assert judge(rows + [extra]) == 'BLOCK'
