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

**受監督執行**：
由 supervisor 啟動一個 worker 並負責到底的一次執行：在期限與訊號下等它結束，停止它留下的所有程序群組，清除它的資源，最後關閉證據。
_避免_：job、task、子程序執行

**監督結果**：
一次受監督執行如何結束：worker 自行結束（帶結束碼）、逾時、取消、supervisor 出錯或清理失敗。它不表示是否放行；放行與否是判定。
_避免_：判定、verdict、decision

**清理交接**：
worker 結束前留下的待定結果，只有在 supervisor 完成清理之後才能成為正式結果。
_避免_：交接（單獨使用時）、handoff

**執行清冊**：
一次執行的擁有者與其登記程序群組的持久紀錄；擁有者死亡時，janitor 依它回收該執行。
_避免_：復原清冊、run 目錄

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

**Supervised run**:
One run that a supervisor starts a worker for and owns to the end: it waits for the worker under a deadline and signals, stops every process group the worker left, removes its resources and finally closes the evidence.
_Avoid_: job, task, child process run

**Supervision outcome**:
How a supervised run ended: the worker exited on its own (with its exit code), the deadline passed, the run was cancelled, the supervisor failed, or cleanup failed. It never says whether the change is allowed; that is the decision.
_Avoid_: verdict, decision

**Cleanup handoff**:
The pending result a worker leaves before it exits, which becomes the real result only after the supervisor has finished cleanup.
_Avoid_: handoff (on its own)

**Run inventory**:
The durable record of a run's owner and its registered process groups, from which a janitor reaps the run once its owner has died.
_Avoid_: recovery inventory, run directory
