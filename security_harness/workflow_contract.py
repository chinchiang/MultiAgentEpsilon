"""可信工作流程的 job、步驟與 artifact 名稱契約；發布程式、驗證工具與合約測試共用這一份。

The trusted workflow's job, step and artifact names, kept in one place for the publisher, the required-check
verifier and the workflow contract tests. GitHub reports a job by its display name, so the publisher matches on
`name`; the workflow and its `needs:` refer to the job `id`."""
from typing import NamedTuple


class Job(NamedTuple):
    id: str
    name: str
    steps: tuple


EVALUATION = Job("evaluation", "trusted-security-evaluation", (
    "Record evaluator-owned CI provenance", "Check protected changes and exact-head independent approval",
    "Bilingual documentation checks / 雙語文件檢查", "Candidate documentation checks / 候選文件檢查",
    "Static checks / 靜態檢查",
    "Evaluator regressions and isolation adversarial checks", "Prove seeded defect still blocks",
    "Evaluate candidate through external oracle", "Remove evaluator regression database",
    "Reap cancelled security runs", "Retain evaluator-owned evidence"))
# 突變測試在獨立 job，有自己的期限。 / Mutation testing runs in its own job with its own deadline.
MUTATION = Job("mutation-tests", "trusted-mutation-tests", ("Offline security mutation checks", "Retain mutation report"))
ATTESTATION = Job("attest-evidence", "Attest evaluator-owned evidence", ("Sign evaluator-owned evidence",))
# 規則集要求的必要檢查就是這個 job 的顯示名稱。 / The ruleset's required check is this job's display name.
COMPLETION = Job("security-completion", "trusted-security-pilot", ("Require evaluator, attestation and mutation success",))
JOBS = (EVALUATION, MUTATION, ATTESTATION, COMPLETION)

REQUIRED_CHECK = COMPLETION.name
# 上傳的 artifact 名稱為「前綴-run_id-run_attempt」。 / Uploaded artifacts are named prefix-run_id-run_attempt.
EVIDENCE_ARTIFACT_PREFIX = "trusted-security"
MUTATION_ARTIFACT_PREFIX = "trusted-mutations"


def evidence_artifact(run_id, run_attempt):
    return f"{EVIDENCE_ARTIFACT_PREFIX}-{run_id}-{run_attempt}"
