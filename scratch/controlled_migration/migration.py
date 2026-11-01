"""受控遷移協調器（controlled migration coordinator）。預設乾跑。

Remote 公開介面是安全邊界：observe 必須取得完整、即時且已驗證的前置證據；
inspect_outcome 必須查核合併內容與正式 CI，不可將未查核的資料標為 success。
正式介接器與程序保護由 command.py 組裝；本模組只負責協調。
"""
from copy import deepcopy
import time
import re
import sys
from runtime import recovery_signals

SCOPE = {
    'repository': 'chinchiang/MultiAgentEpsilon', 'pr': 64, 'ruleset_id': 24512048,
    'expected_head_sha': 'f7e424b47fed9e4a27d10b2f73b3a6e3278508b7',
    'expected_base_sha': '469ce1850177703bd022a7d65a841dac7dc01994',
}
FIELDS = ('name', 'target', 'enforcement', 'bypass_actors', 'conditions', 'rules')


def preflight_valid(snapshot):
    return (all(snapshot.get(k) == v for k, v in SCOPE.items())
            and all(snapshot.get(k) is True for k in (
                'open', 'review_valid', 'guard_valid',
                'other_protection_absent', 'only_expected_lock_diff'))
            and snapshot.get('draft') is False
            and snapshot.get('ruleset', {}).get('enforcement') == 'active'
            and snapshot.get('ruleset', {}).get('bypass_actors') == []
            and all(k in snapshot.get('ruleset', {}) for k in FIELDS))


def run(plan, remote, *, execute=False, authorization=None, clock=None):
    """乾跑不呼叫 remote；execute 僅接受精確範圍且尚未過期的明確授權。"""
    clock = clock or time
    result = {'status': 'DRY_RUN', 'accepted': False, 'remote_writes': 0,
              'restored': None, 'errors': []}
    if not execute:
        return result
    auth = authorization or {}
    if not (all(plan.get(k) == v and auth.get(k) == v for k, v in SCOPE.items())
            and auth.get('authorized') is True
            and auth.get('maintenance_freeze_confirmed') is True
            and auth.get('backup_recovery_confirmed') is True
            and auth.get('approved_by') and auth.get('approval_reference')
            and isinstance(auth.get('expires_at'), (int, float))
            and clock.time() < auth['expires_at']):
        result['status'] = 'NOT_AUTHORIZED'
        return result
    try:
        snapshot = remote.observe()
    except (Exception, KeyboardInterrupt) as error:
        result['status'] = 'PREFLIGHT_BLOCKED'
        result['errors'].append(type(error).__name__)
        return result
    if not preflight_valid(snapshot) or snapshot['ruleset'] != plan.get('expected_ruleset'):
        result['status'] = 'PREFLIGHT_BLOCKED'
        return result
    original = {key: deepcopy(snapshot['ruleset'][key]) for key in FIELDS}
    disabled = {**deepcopy(original), 'enforcement': 'disabled'}
    if clock.time() >= auth['expires_at']:
        result['status'] = 'NOT_AUTHORIZED'
        return result
    started = clock.monotonic()
    try:
        result['remote_writes'] += 1
        remote.set_ruleset(disabled)
        disabled_readback = remote.read_ruleset()
        if {k: disabled_readback[k] for k in FIELDS} != disabled:
            raise RuntimeError('DISABLE_READBACK_DRIFT')
        refreshed = remote.observe()
        normalized = deepcopy(refreshed)
        normalized['ruleset']['enforcement'] = 'active'
        if not preflight_valid(normalized) or {k: normalized['ruleset'][k] for k in FIELDS} != original:
            raise RuntimeError('PREMERGE_DRIFT')
        if clock.monotonic() - started >= 60 or clock.time() >= auth['expires_at']:
            raise RuntimeError('MERGE_CUTOFF')
        result['remote_writes'] += 1
        remote.merge(SCOPE['expected_head_sha'])
    except (Exception, KeyboardInterrupt) as error:
        result['errors'].append(type(error).__name__)
    finally:
        result['restored'] = False
        result['restore_payload'] = deepcopy(original)
        with recovery_signals():
            while not result['restored']:
                try:
                    result['remote_writes'] += 1
                    remote.set_ruleset(original)
                    readback = remote.read_ruleset()
                    result['restored'] = {k: readback[k] for k in FIELDS} == original
                    if not result['restored']:
                        raise RuntimeError('RESTORE_READBACK_DRIFT')
                except KeyboardInterrupt:
                    result['status'] = 'RECOVERY_REQUIRED'
                    result['errors'].append('RECOVERY_INTERRUPTED_USE_BACKUP')
                    return result
                except Exception as error:
                    result['errors'].append('RESTORE_' + type(error).__name__)
                    result['errors'] = result['errors'][-100:]
                    label = 'RECOVERY_INCIDENT' if clock.monotonic() - started >= 120 else 'RECOVERY_RETRY'
                    print(label+' '+type(error).__name__, file=sys.stderr, flush=True)
                    # 不因 120 秒目標已過而放棄恢復；只重送同一恢復 payload。
                    try:
                        clock.sleep(2)
                    except KeyboardInterrupt:
                        result['status'] = 'RECOVERY_REQUIRED'
                        return result
    result['window_exceeded'] = clock.monotonic() - started >= 120
    try:
        result['outcome'] = remote.inspect_outcome()
    except (Exception, KeyboardInterrupt) as error:
        result['status'] = 'PENDING_ACCEPTANCE'
        result['errors'].append(type(error).__name__)
        return result
    outcome = result['outcome']
    result.update(assess_outcome(outcome))
    return result


def assess_outcome(outcome):
    result = {}
    content_valid = (outcome.get('merged') is True
                     and bool(re.fullmatch('[0-9a-f]{40}', str(outcome.get('merge_sha', ''))))
                     and outcome.get('parents') == [SCOPE['expected_base_sha'], SCOPE['expected_head_sha']]
                     and outcome.get('only_expected_lock_diff') is True)
    result['accepted'] = (content_valid and all(outcome.get(k) == 'success' for k in
                          ('formal_push_ci', 'full_mutation', 'signature')))
    failed = not content_valid or any(outcome.get(k) == 'failure' for k in
                                     ('formal_push_ci', 'full_mutation', 'signature'))
    result['status'] = ('ACCEPTED' if result['accepted'] else
                        'ACCEPTANCE_FAILED' if failed else 'PENDING_ACCEPTANCE')
    return result


def main():
    from command import main as command_main
    return command_main()


if __name__ == '__main__':
    raise SystemExit(main())
