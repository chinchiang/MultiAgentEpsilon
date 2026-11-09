#!/usr/bin/env python3
"""離線安全核心突變；Offline mutations of trusted security predicates, not untrusted code execution."""
import argparse
import ast
import copy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
from security_harness.results import write_json

TARGETS = {
    'security_harness/results.py': (
        ('validate_cases', 'seeded_defects', 'decide'), ('tests/test_policy.py', 'tests/test_security_properties.py')),
    'security_harness/github_http.py': (
        ('strict_json',), ('tests/test_trusted_publisher.py', 'tests/test_security_properties.py')),
    'security_harness/preflight.py': (
        ('validate_package_policy', 'check_metadata'), ('tests/test_preflight.py',)),
    'security_harness/authorization.py': (
        ('same',), ('tests/test_response_comparison.py',)),
    'security_harness/isolation.py': (
        ('verify_container',), ('tests/test_isolation.py', '-m', 'not integration')),
    'security_harness/scope.py': (
        ('valid_remote_hosts', 'validate_model_roe', 'valid_deadline_policy', 'call_seconds', 'run_seconds'),
        ('tests/test_scope.py', 'tests/test_model_hardening.py::test_model_roe_rejects_malformed_destination_allowlists',
         'tests/test_model_deadlines.py::test_checked_in_model_roe_carries_a_valid_deadline_policy',
         'tests/test_model_deadlines.py::test_deadline_policy_outside_the_code_ceilings_is_refused',
         'tests/test_model_deadlines.py::test_per_provider_deadlines_set_the_call_ceiling_and_the_run_cap',
         'tests/test_model_deadlines.py::test_deadline_policy_boundaries_are_inclusive',
         'tests/test_model_hardening.py::test_model_roe_boundaries_are_inclusive',
         'tests/test_model_hardening.py::test_remote_host_allowlist_size_boundary')),
    'security_harness/supervision.py': (
        ('child_environment',),
        ('tests/test_model_lifecycle.py::test_model_worker_receives_only_the_selected_providers_settings',
         'tests/test_model_hardening.py::test_aws_cli_keeps_its_credential_chain_and_forced_settings_but_no_other_secret')),
    'scripts/run_security.py': (
        ('planned_configuration',),
        ('tests/test_run_evidence.py::test_configuration_changed_after_planning_blocks_before_any_gate',
         'tests/test_run_evidence.py::test_plan_naming_other_configuration_bytes_blocks_before_any_gate',
         'tests/test_run_evidence.py::test_orchestrator_blocks_incomplete_worker_output')),
    # guard 與 publisher 共用的審查規則；只選不呼叫 git 的測試（worker 禁止子程序）。 / Review rules shared by the guard and
    # the publisher; only tests that never call git are selected, since the worker forbids subprocesses.
    'security_harness/github_trust.py': (
        ('validate_review', 'review_decision', 'approved_review', 'pr_commit_identities', 'validate_run_base',
         'GitHubTrust.head_push', 'GitHubTrust.review_ids', 'GitHubTrust.baseline_approval'),
        ('tests/test_github_trust.py', 'tests/test_trusted_publisher.py',
         'tests/test_trusted_changes.py::test_baseline_approval_binds_independent_reviewer_and_current_head',
         'tests/test_trusted_changes.py::test_listed_reviewer_without_write_access_cannot_approve_baseline',
         'tests/test_trusted_changes.py::test_head_commit_identities_only_remove_approvals',
         'tests/test_trusted_changes.py::test_live_approval_resolves_reviewer_permission_through_github',
         'tests/test_trusted_changes.py::test_valid_approval_is_refused_when_last_push_approval_is_not_enforced',
         'tests/test_trusted_changes.py::test_approval_submitted_before_the_head_was_pushed_does_not_count',
         'tests/test_trusted_changes.py::test_unknown_push_time_of_the_head_fails_closed',
         'tests/test_trusted_changes.py::test_long_branch_history_finds_the_head_push_in_one_read',
         'tests/test_trusted_changes.py::test_head_push_beyond_the_newest_activity_page_fails_closed',
         'tests/test_trusted_changes.py::test_reviewer_who_pushed_an_earlier_pr_commit_cannot_approve',
         'tests/test_trusted_changes.py::test_incomplete_pr_commit_listing_fails_closed',
         'tests/test_trusted_changes.py::test_guard_refuses_trust_policy_it_cannot_enforce',
         'tests/test_trusted_changes.py::test_fork_pull_request_is_refused_with_its_own_code',
         'tests/test_trusted_changes.py::test_bot_review_neither_blocks_silently_nor_counts',
         'tests/test_trusted_changes.py::test_head_pusher_cannot_approve_even_when_commits_name_someone_else',
         'tests/test_trusted_changes.py::test_approval_submitted_in_the_same_second_as_the_head_push_does_not_count',
         'tests/test_trusted_changes.py::test_head_ref_outside_the_branch_name_pattern_is_refused',
         'tests/test_trusted_changes.py::test_run_identity_must_be_a_positive_decimal_before_the_run_is_read',
         'tests/test_trusted_changes.py::test_guard_applies_the_publisher_rules_to_drafts_and_shared_heads',
         'tests/test_trusted_changes.py::test_head_push_that_is_not_the_newest_activity_fails_closed',
         'tests/test_trusted_changes.py::test_reviewer_who_pushed_an_earlier_commit_cannot_approve',
         'tests/test_trusted_changes.py::test_stale_pull_request_names_why_it_blocked',
        )),
    # 候選測試數與檢查數下限；純函式測試不呼叫 git。 / The candidate test and check floor; its pure-function tests never
    # call git.
    'security_harness/regression_inventory.py': (
        ('parametrize_cases', 'case_count', 'check_count', 'declared_removals', 'floor_errors'),
        ('tests/test_regression_inventory.py',)),
    'security_harness/llm/benchmark.py': (
        ('bounded_text', 'validate_review', 'parse_review'), ('tests/test_model_benchmark.py', '--deselect=tests/test_model_benchmark.py::test_review_cli_supervision_and_explicit_live_opt_in',
                                                              '--deselect=tests/test_model_benchmark.py::test_review_cli_accepts_large_budgets_only_within_the_total_cap', 'tests/test_security_properties.py')),
}
# 突變總數上限；超過代表目標範圍失控，應拆分而非加長期限。 / Cap on the mutant total; exceeding it means the target set
# grew out of hand and should be split rather than given a longer deadline.
MAX_MUTANTS = 512
SWAPS = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
         ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.In: ast.NotIn, ast.NotIn: ast.In,
         ast.Is: ast.IsNot, ast.IsNot: ast.Is}


def target_functions(tree, functions):
    """頂層函式與類別方法（名稱為 Class.method）。 / Top-level functions and class methods named Class.method."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and f'{node.name}.{item.name}' in functions:
                    yield f'{node.name}.{item.name}', item


def is_guard_statement(node):
    """need(...) 呼叫或 raise Denied(...)：刪掉它就等於拿掉一道檢查。 / A need(...) call or raise Denied(...):
    deleting it removes one check."""
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        return isinstance(node.value.func, ast.Name) and node.value.func.id == 'need'
    if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
        return isinstance(node.exc.func, ast.Name) and node.exc.func.id == 'Denied'
    return False


def delete_statement(tree, target):
    for parent in ast.walk(tree):
        for field in ('body', 'orelse', 'finalbody'):
            statements = getattr(parent, field, None)
            if isinstance(statements, list):
                for index, statement in enumerate(statements):
                    if statement is target:
                        statements[index] = ast.Pass()
                        return
    raise AssertionError('guard statement has no parent list')


def mutations(source, functions):
    tree = ast.parse(source)
    output = []
    for name, function in target_functions(tree, functions):
        positions = {id(n): i for i, n in enumerate(ast.walk(tree))}
        for node in ast.walk(function):
            options = []
            if is_guard_statement(node):
                options = [('delete', 0, None)]
            elif isinstance(node, ast.Compare):
                options = [('compare', i, SWAPS[type(op)]) for i, op in enumerate(node.ops) if type(op) in SWAPS]
            elif isinstance(node, ast.BoolOp):
                options = [('boolean', 0, ast.Or if isinstance(node.op, ast.And) else ast.And)]
            elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                options = [('negation', 0, None)]
            for kind, index, replacement in options:
                changed = copy.deepcopy(tree)
                # 以走訪順序定位，巢狀同型別同起點節點（如 a and b or c）不會混淆。 / Locate by walk order, so nested
                # same-type nodes starting at one column (e.g. a and b or c) cannot be confused.
                match = list(ast.walk(changed))[positions[id(node)]]
                assert type(match) is type(node)
                if kind == 'delete':
                    delete_statement(changed, match)
                elif kind == 'compare':
                    match.ops[index] = replacement()
                elif kind == 'boolean':
                    match.op = replacement()
                else:
                    # 雙重否定保留布林語意，避免 AST 節點替換範圍擴張。 / Double negation flips the original condition without replacing parent nodes.
                    match.operand = ast.UnaryOp(op=ast.Not(), operand=match.operand)
                ast.fix_missing_locations(changed)
                encoded = ast.unparse(changed) + '\n'
                identity = f'{name}:{node.lineno}:{node.col_offset}:{positions[id(node)]}:{kind}:{index}'
                output.append((identity, encoded))
    return output


def classify(returncode, xml_path, baseline_count, expected_ids=None):
    try:
        root = ET.parse(xml_path).getroot()
        cases = list(root.iter('testcase'))
        errors = list(root.iter('error'))
        failures = list(root.iter('failure'))
        skipped = list(root.iter('skipped'))
        identities = [(c.get('classname'), c.get('name')) for c in cases]
        if (any(not all(isinstance(v, str) and v.strip() for v in pair) for pair in identities)
                or len(set(identities)) != len(identities)
                or (expected_ids is not None and set(identities) != expected_ids)):
            return 'ERROR'
        if errors or skipped or len(cases) != baseline_count or not cases:
            return 'ERROR'
        if returncode == 0 and not failures:
            return 'SURVIVED'
        if returncode == 1 and failures:
            return 'KILLED'
    except (OSError, ET.ParseError):
        pass
    return 'ERROR'


def run_tests(snapshot, tests, output, timeout):
    env = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'HOME': str(snapshot),
           'TMPDIR': str(snapshot.parent), 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    worker = snapshot / 'scripts/mutation_worker.py'
    xml = output.with_suffix('.xml')
    with output.open('wb') as log:
        process = subprocess.Popen([sys.executable, '-I', '-B', str(worker), str(snapshot), str(xml), *tests],
                                   cwd=snapshot, env=env, stdout=log, stderr=log, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            if sys.exc_info()[0] is KeyboardInterrupt:
                raise
            return 'TIMEOUT', 0
        finally:
            # 回收遺留群組，即使直接子程序已退出。 / Reap any remaining group even after the direct child exits.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    try:
        count = len(list(ET.parse(xml).getroot().iter('testcase')))
    except (OSError, ET.ParseError):
        count = 0
    return code, count


def run(root, output):
    report = {'schema_version': 1, 'status': 'INCOMPLETE', 'advisory_only': True,
              'scope': {k: list(v[0]) for k, v in TARGETS.items()}, 'mutants': [], 'baselines': [],
              'source_sha256': {}, 'python': sys.version.split()[0],
              'test_tools': {n: importlib.metadata.version(n) for n in ('pytest', 'hypothesis', 'sortedcontainers')},
              'limitations': 'Trusted local predicates only; not a sandbox or full-repository score.'}
    write_json(output, report)
    deadline = time.monotonic() + 1200
    # 固定快照不含 .git、憑證、外部附件或執行產物。 / Fixed snapshot excludes Git metadata, credentials, attachments and runtime artifacts.
    with tempfile.TemporaryDirectory(prefix='epsilon-mutations-') as directory:
        snapshot = Path(directory) / 'source'
        snapshot.mkdir()
        for folder in ('security_harness', 'scripts', 'tests', 'security'):
            for path in (root / folder).rglob('*'):
                if path.is_file() and path.suffix in ('.py', '.json', '.toml') and '__pycache__' not in path.parts:
                    if path.is_symlink():
                        raise ValueError('symlink source refused')
                    dest = snapshot / path.relative_to(root)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(path.read_bytes())
        for name in ('requirements.lock', 'requirements-test.lock', 'pyproject.toml'):
            (snapshot / name).write_bytes((root / name).read_bytes())
        manifest = {p.relative_to(snapshot).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in snapshot.rglob('*') if p.is_file()}
        report['snapshot_sha256'] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        report['source_sha256'] = {n: manifest[n] for n in TARGETS}
        total = 0
        for name, (functions, tests) in TARGETS.items():
            path = snapshot / name
            original = path.read_text()
            mutants = mutations(original, functions)
            total += len(mutants)
            if not mutants or total > MAX_MUTANTS:
                raise ValueError('empty or oversized mutation inventory')
            code, count = run_tests(snapshot, tests, snapshot / 'baseline.log', 30)
            if code != 0 or classify(code, snapshot / 'baseline.xml', count) != 'SURVIVED':
                report['baselines'].append({'target': name, 'tests': count, 'passed': False, 'returncode': code})
                report['baseline_diagnostic'] = (snapshot / 'baseline.log').read_text()[-4000:]
                write_json(output, report)
                raise ValueError('baseline failed')
            baseline_ids = {(c.get('classname'), c.get('name')) for c in ET.parse(snapshot / 'baseline.xml').getroot().iter('testcase')}
            # 排除 AST 重新格式化本身導致失敗的假攔截。 / Rule out kills caused only by AST normalization.
            path.write_text(ast.unparse(ast.parse(original)) + '\n')
            normalized_code, _ = run_tests(snapshot, tests, snapshot / 'normalized.log', 30)
            if classify(normalized_code, snapshot / 'normalized.xml', count, baseline_ids) != 'SURVIVED':
                raise ValueError('normalized baseline failed')
            path.write_text(original)
            report['baselines'].append({'target': name, 'tests': count, 'selection': list(tests),
                                        'passed': True, 'normalized_passed': True})
            for identity, source in mutants:
                if time.monotonic() >= deadline:
                    raise TimeoutError('campaign deadline')
                path.write_text(source)
                log = snapshot / 'mutant.log'
                log.with_suffix('.xml').unlink(missing_ok=True)
                code, _ = run_tests(snapshot, tests, log, min(30, deadline - time.monotonic()))
                status = 'TIMEOUT' if code == 'TIMEOUT' else classify(code, log.with_suffix('.xml'), count, baseline_ids)
                report['mutants'].append({'id': name + ':' + identity, 'status': status,
                    'mutant_sha256': hashlib.sha256(source.encode()).hexdigest()})
                write_json(output, report)
            path.write_text(original)
        if any(not (root / n).is_file() or hashlib.sha256((root / n).read_bytes()).hexdigest() != digest
               for n, digest in manifest.items()):
            raise ValueError('source changed during campaign')
        report['counts'] = {s: sum(m['status'] == s for m in report['mutants'])
                            for s in ('KILLED', 'SURVIVED', 'TIMEOUT', 'ERROR')}
        report['status'] = 'COMPLETE'
        report['mutation_score'] = report['counts']['KILLED'] / len(report['mutants'])
    report['cleanup_completed'] = True
    write_json(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/mutations/report.json',
                        help='突變報告路徑 / mutation report path')
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT) and not args.output.resolve().is_relative_to(ROOT / 'artifacts'):
        parser.error('報告僅可寫入 artifacts 或儲存庫外 / output must be in artifacts or outside repository')
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    try:
        report = run(ROOT, args.output)
    except (Exception, KeyboardInterrupt) as error:
        # 不讓工具故障變成成功攔截。 / Infrastructure failure is never a killed mutant.
        if args.output.exists():
            report = json.loads(args.output.read_text())
            report.update(status='ERROR', error_type=type(error).__name__)
            write_json(args.output, report)
        print('突變測試未完成 / Mutation campaign incomplete:', type(error).__name__)
        # 3 表示基礎設施錯誤，與 argparse 的 2 區分。 / 3 means infrastructure error, distinct from argparse's 2.
        return 3
    print(json.dumps({'status': report['status'], 'counts': report['counts'], 'mutation_score': report['mutation_score']}))
    return 0 if report['counts']['SURVIVED'] == report['counts']['TIMEOUT'] == report['counts']['ERROR'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
