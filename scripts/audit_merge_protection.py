#!/usr/bin/env python3
"""唯讀設定稽核；管理者的觀察不能取代一般開發者的行為驗收。

Read-only configuration audit; never substitutes admin observations for developer probes."""
import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.results import write_json
from security_harness.trusted_publisher import GITHUB_ACTIONS_APP_ID as ACTIONS_APP_ID


def codeowners_reviewers(text):
    """依 base 分支檔案取得 GitHub 對所有路徑（*）要求的擁有者。

Owners GitHub would request for every path ('*'), from the base branch file."""
    rules = {}
    for line in (text or "").splitlines():
        parts = line.split("#", 1)[0].split()
        if parts:
            rules[parts[0]] = {p[1:] for p in parts[1:] if p.startswith("@") and "/" not in p}
    if "*" not in rules:
        return []
    # 保守判定：共同個人擁有者須出現在每個有效規則。 / Conservative: a common personal owner must appear in every effective rule.
    # 團隊解析與完整 glob 語意仍需 GitHub 原生逐路徑審查。 / Team resolution and GitHub's full glob semantics require native per-path review.
    return sorted(set.intersection(*rules.values()))


def inspect_configuration(branch, rulesets, pr, collaborators, reviewers, codeowners=None, publisher_app_id=None):
    active = [r for r in rulesets if r.get('enforcement') == 'active' and r.get('target') == 'branch'
              and any(x in ('~DEFAULT_BRANCH', 'refs/heads/main')
                      for x in r.get('conditions', {}).get('ref_name', {}).get('include', []))
              and not r.get('conditions', {}).get('ref_name', {}).get('exclude')]
    rules = [rule for item in active for rule in item.get('rules', [])]
    kinds = {rule['type'] for rule in rules}
    reviews = [r.get('parameters', {}) for r in rules if r['type'] == 'pull_request']
    checks = [check for r in rules if r['type'] == 'required_status_checks'
              for check in r.get('parameters', {}).get('required_status_checks', [])]
    # 檢查名稱可偽造，只採計預期整合來源。 / A context name alone is forgeable; only the expected integration counts.
    required = [c for c in checks if c.get('context') == 'trusted-security-pilot'
                and c.get('integration_id') == ACTIONS_APP_ID]
    dedicated = [c for c in checks if c.get('context') == 'epsilon/trusted-merge' and publisher_app_id
                 and c.get('integration_id') == publisher_app_id and publisher_app_id != ACTIONS_APP_ID]
    identities = {c['login']: c.get('role_name') for c in collaborators}
    independent = [name for name in reviewers if name != pr['user']['login']
                   and identities.get(name) in ('write', 'maintain', 'admin')]
    owners = codeowners_reviewers(codeowners)
    owner_reviewers = [name for name in owners if name != pr['user']['login']
                       and identities.get(name) in ('write', 'maintain', 'admin')]
    developer = [name for name, role in identities.items() if role in ('write', 'maintain') and name != pr['user']['login']]
    configuration = {
        'main_protected': bool(branch.get('protected')),
        'active_main_ruleset': bool(active),
        # 無規則集寫入權限時 GitHub 省略 bypass_actors；未知不等於沒有。 / GitHub omits bypass_actors for callers without ruleset write access: unknown is not "none".
        'no_bypass': bool(active) and all(isinstance(r.get('bypass_actors'), list) and not r['bypass_actors']
                                          for r in active),
        'no_delete_or_force_push': {'deletion', 'non_fast_forward'} <= kinds,
        'independent_review_required': any(p.get('required_approving_review_count', 0) >= 1
            and p.get('dismiss_stale_reviews_on_push') and p.get('require_code_owner_review')
            and p.get('require_last_push_approval') for p in reviews),
        'required_check_present': bool(required),
        'dedicated_app_check_required': bool(dedicated),
        'base_codeowner_independent_reviewer': bool(owner_reviewers),
        'strict_checks': any(r['type'] == 'required_status_checks' and
                            r.get('parameters', {}).get('strict_required_status_checks_policy') for r in rules),
        'configured_independent_reviewer_available': bool(independent),
        'non_admin_developer_available': bool(developer),
    }
    return {'configuration': configuration, 'independent_reviewers': independent,
            'base_codeowners': owners,
            'developer_candidates': developer, 'required_checks': required,
            'source_binding': ('dedicated App check required' if dedicated else
                               'NOT_VERIFIED: Actions app ID/check name alone is insufficient'),
            'behavioral_probes': {name: 'NOT_RUN' for name in (
                'developer_direct_push_denied', 'unapproved_policy_change_denied',
                'forged_same_name_check_denied', 'stale_head_approval_denied',
                'approval_dismissal_rechecked', 'legitimate_independent_approval_allowed')},
            'acceptance_complete': False, 'decision': 'BLOCK'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    # 不預設舊 PR；稽核對象必須明確指定。 / No stale default PR; the audited pull request must be explicit.
    parser.add_argument('--pr', type=int, required=True, help='要稽核的 PR 編號 / pull request to audit')
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/merge-protection-audit.json',
                        help='稽核證據路徑 / audit evidence path')
    parser.add_argument('--publisher-app-id', type=int, help='完成註冊後的專用 App ID / dedicated App ID, once registered')
    args = parser.parse_args()
    evidence = {'decision': 'BLOCK', 'acceptance_complete': False, 'errors': []}
    try:
        trust = json.loads((ROOT/'security/trust-policy.json').read_text())
        repo = trust['repository']
        from security_harness.github_readonly import ReadOnlyGitHub
        client = ReadOnlyGitHub()
        def api(path, pages=False):
            full = f'/repos/{repo}/{path}'
            return client.pages(full) if pages else client.api(full)
        branch = api('branches/main')
        brief = api('rulesets?includes_parents=true&per_page=100', pages=True)
        rules = [api('rulesets/'+str(r['id'])) for r in brief]
        pr = api(f'pulls/{args.pr}')
        collaborators = api('collaborators?per_page=100', pages=True)
        try:
            owners_file = api('contents/.github/CODEOWNERS?ref=main')
            codeowners = base64.b64decode(owners_file['content']).decode('utf-8')
        except Exception:
            codeowners = None
        evidence.update(inspect_configuration(branch, rules, pr, collaborators, trust['baseline_reviewers'],
                                              codeowners, args.publisher_app_id))
        evidence.update(repository=repo, main_sha=branch['commit']['sha'], candidate_sha=pr['head']['sha'],
                        pr_state=pr['state'], pr_draft=pr['draft'])
    except Exception as exc:
        evidence['errors'].append(type(exc).__name__)
    write_json(args.output, evidence)
    print(f"{evidence['decision']}: {args.output}")
    return 1  # 唯讀命令不能宣稱未執行的行為驗收已通過。 / This read-only command cannot certify behavioral probes it did not execute.


if __name__ == '__main__':
    raise SystemExit(main())
