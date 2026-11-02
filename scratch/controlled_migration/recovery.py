"""共用合併保護恢復策略；Shared merge-protection restoration policy."""
from copy import deepcopy
from datetime import datetime
import math
import json
import os
import stat
import sys
import time
from runtime import recovery_signals


def restore_protection(remote, original, *, clock=None, started=None, evidence=None, emit=None):
    """恢復原設定並確認；Restore the original configuration and confirm readback."""
    clock = clock or time
    output = emit or (lambda message: print(message, file=sys.stderr, flush=True))
    def notice(message):
        try:
            output(message)
        except Exception:
            pass  # 告警不可阻擋必要恢復。 / Logging cannot block restoration.
    def monotonic():
        try:
            value = clock.monotonic()
            return value if type(value) in (int, float) else float('nan')
        except (OSError, ValueError, TypeError):
            return float('nan')
    anchor = monotonic()
    age = None
    if started is not None and math.isfinite(started) and math.isfinite(anchor) and anchor >= started:
        age = anchor-started
    elif started is None:
        try:
            timestamp = datetime.fromisoformat((evidence or {})['intent_time'])
            latest = datetime.fromisoformat((evidence or {}).get('latest_intent_time', (evidence or {})['intent_time']))
            now = clock.time()
            if (timestamp.tzinfo is not None and latest.tzinfo is not None
                    and math.isfinite(now) and latest.timestamp() <= now):
                measured = now-timestamp.timestamp()
                if math.isfinite(measured) and measured >= 0:
                    age = measured
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            pass
    summary = {'attempts': 0, 'restored': False, 'incident': False,
               'time_reliable': age is not None, 'elapsed_seconds': None, 'last_error': None, 'errors': []}
    if (evidence or {}).get('possibly_disabled') is False:
        summary['time_reliable'] = True
        try:
            readback = remote.read_ruleset(recovery=True)
            summary['restored'] = {key: readback[key] for key in original} == original
            if not summary['restored']:
                summary['last_error'] = 'RESTORE_READBACK_DRIFT'
        except (Exception, KeyboardInterrupt) as error:
            summary['last_error'] = 'RESTORE_'+type(error).__name__
        if summary['last_error']:
            summary['errors'] = [summary['last_error']]
        return summary

    def update_incident():
        delta = monotonic()-anchor
        if not math.isfinite(delta) or delta < 0:
            summary['time_reliable'] = False
        summary['elapsed_seconds'] = age+delta if summary['time_reliable'] else None
        exceeded = not summary['time_reliable'] or summary['elapsed_seconds'] >= 120
        first = exceeded and not summary['incident']
        summary['incident'] = summary['incident'] or exceeded
        if first:
            notice('RECOVERY_INCIDENT')

    with recovery_signals():
        try:
            while not summary['restored']:
                update_incident()
                try:
                    summary['attempts'] += 1
                    remote.set_ruleset(deepcopy(original))
                    readback = remote.read_ruleset(recovery=True)
                    summary['restored'] = {key: readback[key] for key in original} == original
                    if not summary['restored']:
                        raise RuntimeError('RESTORE_READBACK_DRIFT')
                except Exception as error:
                    summary['last_error'] = 'RESTORE_'+type(error).__name__
                    summary['errors'] = (summary['errors']+[summary['last_error']])[-100:]
                    update_incident()
                    label = 'RECOVERY_INCIDENT' if summary['incident'] else 'RECOVERY_RETRY'
                    notice(label+' '+type(error).__name__)
                    clock.sleep(2)
                update_incident()
        except KeyboardInterrupt:
            summary['last_error'] = 'RECOVERY_INTERRUPTED_USE_BACKUP'
            summary['errors'] = (summary['errors']+[summary['last_error']])[-100:]
    return summary


def read_recovery_evidence(path):
    """可信路徑的有界事件判讀；Bounded event inspection on a trusted path."""
    uncertain = {'possibly_disabled': True, 'intent_time': None, 'corrupt': True}
    if path.is_symlink():
        raise ValueError('JOURNAL_PATH')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
                raise ValueError('JOURNAL_PATH')
            if info.st_size > 8*1024**2:
                return uncertain
            raw = stream.read(8*1024**2+1)
    except OSError:
        return uncertain
    if len(raw) > 8*1024**2:
        return uncertain
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('JOURNAL_DUPLICATE')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('JOURNAL_NUMBER')
    def finite(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError('JOURNAL_NUMBER')
        return parsed
    timestamps = []
    attempted = False
    try:
        for line in raw.decode('utf-8').splitlines():
            event = json.loads(line, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)
            if not isinstance(event, dict) or not isinstance(event.get('event'), str):
                return uncertain
            if event['event'] != 'write_intent':
                continue
            if event.get('operation') not in ('ruleset', 'merge'):
                return uncertain
            if event['operation'] != 'ruleset':
                continue
            payload = event.get('payload')
            if not isinstance(payload, dict) or payload.get('enforcement') not in ('active', 'disabled'):
                return uncertain
            if payload['enforcement'] == 'disabled':
                attempted = True
                timestamp = datetime.fromisoformat(event.get('time'))
                if timestamp.tzinfo is None:
                    return uncertain
                timestamps.append(timestamp)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return uncertain
    return {'possibly_disabled': attempted,
            'intent_time': min(timestamps).isoformat() if timestamps else None,
            'latest_intent_time': max(timestamps).isoformat() if timestamps else None, 'corrupt': False}
