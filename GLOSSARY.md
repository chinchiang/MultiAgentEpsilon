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
