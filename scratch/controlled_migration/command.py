"""受控遷移 CLI。正式操作必須有另外核准、精確綁定本工具的授權檔。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import time
from uuid import uuid4
from migration import FIELDS, SCOPE, run, assess_outcome, preflight_valid
from github_adapter import GhTransport, GitHubAdapter, ROOT, need, strict_json
from runtime import Journal, ProcessLock, ProtectedRemote, sync_json, termination_guard, recovery_signals


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def tool_digests(workspace):
    directory = workspace / 'scratch/controlled_migration'
    return {name: hashlib.sha256((directory/name).read_bytes()).hexdigest()
            for name in ('migration.py', 'command.py', 'github_adapter.py', 'runtime.py')}


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
             and not info.st_mode & 0o077 and info.st_size <= 65536, 'PRIVATE_FILE_REQUIRED')
        return strict_json(stream.read(65537))


def load_plan(workspace):
    directory = workspace / 'scratch/certifi-controlled-migration-20261102'
    reference = json.loads((directory/'reference-ruleset.json').read_text())
    rule = {k: reference[k] for k in FIELDS}
    need(rule['enforcement'] == 'active' and rule['bypass_actors'] == [], 'REFERENCE_RULE')
    return {**SCOPE, 'expected_ruleset': rule}


def valid_receipt(auth, plan, workspace, *, recovery=False):
    valid = (all(auth.get(k) == v for k, v in SCOPE.items())
             and auth.get('authorized') is True and auth.get('approved_by') == 'chinchiang'
             and bool(auth.get('approval_reference'))
             and auth.get('maintenance_freeze_confirmed') is True
             and auth.get('backup_recovery_confirmed') is True
             and bool(auth.get('backup_operator'))
             and auth.get('plan_sha256') == digest(plan)
             and auth.get('tools_sha256') == tool_digests(workspace))
    expires = auth.get('expires_at')
    return (valid and type(expires) in (int, float) and math.isfinite(expires)
            and (recovery or time.time() < expires <= time.time()+600))


def output(value, code=0):
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return code


def clear_active(state):
    (state/'active.json').unlink()
    descriptor = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def recover(remote, original):
    # 到期授權仍允許原範圍的必要恢復；不做合併或任何其他寫入。
    with recovery_signals():
        while True:
            try:
                remote.set_ruleset(original)
                if remote.read_ruleset(recovery=True) == original:
                    return {'status': 'RESTORED', 'restored': True, 'accepted': False}
                print('RECOVERY_READBACK_MISMATCH', file=sys.stderr, flush=True)
            except KeyboardInterrupt:
                return {'status': 'RECOVERY_REQUIRED', 'restored': False, 'accepted': False}
            except Exception as error:
                print('RECOVERY_RETRY '+type(error).__name__, file=sys.stderr, flush=True)
            try:
                time.sleep(2)
            except KeyboardInterrupt:
                return {'status': 'RECOVERY_REQUIRED', 'restored': False, 'accepted': False}


def main(argv=None, *, workspace=ROOT, transport_factory=GhTransport):
    parser = argparse.ArgumentParser(description='指定 PR #64 的受控遷移；預設離線 dry run。')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--authorization', type=Path, help='0600、另行明確核准的授權檔；不接受設計同意。')
    parser.add_argument('--preflight', action='store_true', help='唯讀 GitHub 前置查核。')
    parser.add_argument('--verify-outcome', action='store_true', help='唯讀正式合併與 CI／簽章查核。')
    parser.add_argument('--recover', action='store_true', help='只恢復 active.json 指定的未結案操作，禁止合併。')
    args = parser.parse_args(argv)
    if not any((args.execute, args.preflight, args.verify_outcome, args.recover)):
        return output(run({}, None))
    if (sum((args.preflight, args.verify_outcome, args.recover)) > 1
            or (args.execute and (args.preflight or args.verify_outcome))
            or (args.recover and not args.execute)):
        return output({'status': 'INVALID_MODE'}, 2)
    state = workspace/'scratch/controlled-migration-state'
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with ProcessLock(state/'coordinator.lock'), termination_guard():
            active = state/'active.json'
            if active.exists() and not args.recover:
                return output({'status': 'RECOVERY_REQUIRED', 'active_record': str(active)}, 2)
            if args.execute and args.authorization is None:
                return output({'status': 'NOT_AUTHORIZED'}, 2)
            plan = load_plan(workspace)
            if not args.execute:
                journal = Journal(state/('readonly-'+uuid4().hex[:12]))
                remote = GitHubAdapter(transport_factory(write_enabled=False, evidence=journal), plan['expected_ruleset'])
                if args.preflight:
                    snapshot = remote.observe()
                    need(preflight_valid(snapshot) and snapshot['ruleset'] == plan['expected_ruleset'], 'PREFLIGHT_DRIFT')
                    return output({'status': 'READ_ONLY', 'evidence': snapshot, 'remote_writes': 0,
                                   'evidence_directory': str(journal.directory)})
                need(remote.read_ruleset() == plan['expected_ruleset'], 'PROTECTION_NOT_RESTORED')
                value = remote.inspect_outcome()
                assessment = assess_outcome(value)
                return output({**assessment, 'restored': True, 'evidence': value, 'remote_writes': 0,
                               'evidence_directory': str(journal.directory)},
                              0 if assessment['accepted'] else 3)
            auth = read_private(args.authorization)
            if not valid_receipt(auth, plan, workspace, recovery=args.recover):
                return output({'status': 'NOT_AUTHORIZED'}, 2)
            if args.recover:
                need(active.is_file(), 'NO_ACTIVE_RECOVERY')
                record = read_private(active)
                directory = Path(record['directory'])
                need(directory.parent == state.resolve() and not directory.is_symlink(), 'RECOVERY_DIRECTORY')
                saved_plan = read_private(directory/'plan.json')
                saved_auth = read_private(directory/'authorization.json')
                need(saved_plan == plan and saved_auth == auth, 'RECOVERY_SCOPE')
                saved = read_private(directory/'recovery.json')['ruleset']
                need(saved == plan['expected_ruleset'], 'RECOVERY_RULE_DRIFT')
                journal = Journal.resume(directory)
                remote = ProtectedRemote(GitHubAdapter(transport_factory(write_enabled=True, evidence=journal), saved), journal)
                remote.saved, remote.original = True, saved
                with journal.path.open('r', encoding='utf-8') as stream:
                    raw_events = stream.read(8*1024**2+1)
                need(len(raw_events) <= 8*1024**2, 'RECOVERY_EVENTS_LIMIT')
                try:
                    events = [json.loads(line) for line in raw_events.splitlines()]
                    attempted = any(e.get('event') == 'write_intent' and e.get('operation') == 'ruleset'
                                    and e.get('payload', {}).get('enforcement') == 'disabled' for e in events)
                except (ValueError, TypeError):
                    attempted = True  # 不完整紀錄保守視為可能已送出。
                if attempted:
                    result = recover(remote, saved)
                else:
                    restored = remote.read_ruleset(recovery=True) == saved
                    result = {'status': 'RESTORED' if restored else 'RECOVERY_REQUIRED',
                              'restored': restored, 'accepted': False, 'remote_writes': 0}
            else:
                directory = state/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid4().hex[:8])
                journal = Journal(directory)
                journal.save('plan.json', plan)
                journal.save('authorization.json', auth)
                # 先保存安全恢復基準。即使前置查核期間主機中斷，重啟後也只允許恢復。
                journal.save('recovery.json', {'ruleset': plan['expected_ruleset']})
                sync_json(active, {'directory': str(directory.resolve())})
                remote = ProtectedRemote(GitHubAdapter(transport_factory(write_enabled=True, evidence=journal), plan['expected_ruleset']), journal)
                result = run(plan, remote, execute=True, authorization=auth)
            journal.save('result.json', result)
            if result.get('restored') is True or result.get('remote_writes') == 0:
                clear_active(state)
            return output({**result, 'evidence_directory': str(directory)},
                          0 if result.get('accepted') or (args.recover and result.get('restored'))
                          else 3 if result.get('restored') else 2)
    except (Exception, KeyboardInterrupt) as error:
        return output({'status': 'RECOVERY_REQUIRED' if (state/'active.json').exists() else 'BLOCKED',
                       'error_type': type(error).__name__, 'active_record': str(state/'active.json')}, 2)


if __name__ == '__main__':
    raise SystemExit(main())
