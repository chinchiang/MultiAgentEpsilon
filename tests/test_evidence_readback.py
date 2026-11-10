"""證據讀回不可被特殊檔案卡住；報告目錄可被同 uid 程序改寫。

Evidence read-back must not block on a special file: the report directory is writable by any process under the
same uid."""
import json
import os
import threading

from security_harness.lifecycle import SecurityContainers
from security_harness.llm import lifecycle as model_life


def call_without_blocking(path, function):
    """在執行緒中呼叫；FIFO 讀者會卡在 open，逾時後開寫端解除阻塞並判定失敗。 / Call in a thread; a FIFO reader
    blocks in open, so on timeout open the write end to release it and fail."""
    outcome = {}
    thread = threading.Thread(target=lambda: outcome.setdefault('value', function()), daemon=True)
    thread.start()
    thread.join(5)
    if thread.is_alive():
        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        thread.join(5)
        raise AssertionError('evidence read-back blocked on a FIFO')
    return outcome['value']


def fifo_report(root, run_id):
    folder = root / 'artifacts' / run_id
    folder.mkdir(parents=True)
    os.mkfifo(folder / 'report.json')
    return folder / 'report.json'


def test_security_read_back_does_not_block_on_a_fifo(tmp_path):
    run_id = '11111111-1111-4111-8111-111111111111'
    path = fifo_report(tmp_path, run_id)
    role = SecurityContainers(tmp_path, run_id)
    assert call_without_blocking(path, role.load) == (None, 'ValueError')


def test_model_read_back_does_not_block_on_a_fifo(tmp_path):
    run_id = '22222222-2222-4222-8222-222222222222'
    path = fifo_report(tmp_path, run_id)
    data = call_without_blocking(path, lambda: model_life.read_report(tmp_path, run_id))
    assert data['code'] == 'EVIDENCE_INVALID'


def test_regular_reports_and_symlinks_keep_their_behaviour(tmp_path):
    run_id = '33333333-3333-4333-8333-333333333333'
    folder = tmp_path / 'artifacts' / run_id
    folder.mkdir(parents=True)
    report = folder / 'report.json'
    report.write_text(json.dumps({'run_id': run_id, 'execution': 'COMPLETED'}))
    assert SecurityContainers(tmp_path, run_id).load() == ({'run_id': run_id, 'execution': 'COMPLETED'}, None)
    elsewhere = tmp_path / 'forged.json'
    elsewhere.write_text(report.read_text())
    report.unlink()
    report.symlink_to(elsewhere)
    data, error = SecurityContainers(tmp_path, run_id).load()
    assert data is None and error == 'OSError'
    assert model_life.read_report(tmp_path, run_id)['code'] == 'EVIDENCE_INVALID'
