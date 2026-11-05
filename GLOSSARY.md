[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# MultiAgentEpsilon 名詞表

本專案在程式、文件與審查中使用的領域名詞。只收已定案的名詞；架構說明見 [架構總覽](docs/architecture-overview.zh-TW.md)。

## GitHub 讀取

**GitHub 傳輸層**：
對 GitHub REST API 送出單一請求並取回原始回應的介接器，受呼叫預算、期限、回應大小上限與權杖目的地限制。
_避免_：client、GitHub API、gh

**GitHub reader**：
綁定單一儲存庫的 GitHub 讀取；回答一定完整（每一頁都讀到、每個總數都核對過），否則拒絕。
_避免_：API wrapper、唯讀 client、`gh api`

**check 來源**：
產生某個 check run 的 workflow run 與其 attempt。重跑會沿用同一個 run、開始新的 attempt，所以 check 來源取自該 check run 自己的 job，而不是 run。
_避免_：run 的 attempt（單獨使用時）、check 的 run

## 受監督執行

**supervisor**：
啟動一次執行、擁有其期限與清理，並在清理完成後才發布判定的父程序。
_避免_：父程序、runner、launcher

**worker**：
在 supervisor 底下實際執行評估或模型呼叫的子程序；只能寫入自己的進度與待定判定，不能自行發布判定。
_避免_：子程序（單獨使用時）、job、executor

**計畫**：
supervisor 在放行 worker 之前就決定、worker 不得更改的事實：評估什麼、依哪份 RoE 與政策、在什麼限額下執行。worker 開始前與 supervisor 收尾時都要核對同一份計畫。
_避免_：設定、config、報告（報告是 worker 產出的證據）

<a id="en"></a>

# MultiAgentEpsilon glossary

Domain terms used in this project's code, documents and reviews. Only settled terms are listed; for the architecture see the [architecture overview](docs/architecture-overview.zh-TW.md#en).

## Reading GitHub

**GitHub transport**:
The adapter that sends one request to the GitHub REST API and returns the raw response, bounded by a call budget, a deadline, a response size limit and the token's allowed destination.
_Avoid_: client, GitHub API, gh

**GitHub reader**:
Read access to one repository's GitHub state whose answers are always complete (every page read, every total checked) or refused.
_Avoid_: API wrapper, read-only client, `gh api`

**Check source**:
The workflow run and run attempt that produced a given check run. A rerun keeps the run but starts a new attempt, so the check source comes from the check run's own job, not from the run.
_Avoid_: the run's attempt (on its own), the check's run

## Supervised runs

**Supervisor**:
The parent process that starts a run, owns its deadline and cleanup, and publishes a decision only after cleanup completes.
_Avoid_: parent, runner, launcher

**Worker**:
The child process that does a run's evaluation or model calls under a supervisor; it may write only its own progress and pending decision, never publish a decision itself.
_Avoid_: child (on its own), job, executor

**Plan**:
The facts a supervisor decides before releasing a worker and the worker may not change: what to evaluate, under which RoE and policy, and within which limits. The worker checks the plan before it starts and the supervisor checks it again when it finishes.
_Avoid_: settings, config, report (the report is the worker's evidence)
