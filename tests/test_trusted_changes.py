from scripts.check_trusted_changes import protected_changes


def test_candidate_cannot_silently_lower_policy_or_replace_evaluator():
    paths = ["security/policy.json", "security/gitleaks.toml", "scripts/run_security.py",
             "security_harness/results.py", ".github/workflows/security.yml",
             "requirements.lock", "fixture_app/app.py", "docs/README.md"]
    assert protected_changes(paths) == paths[:6]
