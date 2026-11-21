[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 議題追蹤器：GitHub（Issue tracker: GitHub）

本儲存庫的議題（issues）與規格（specs）存放於 GitHub Issues。所有操作一律使用 `gh` CLI。

## 慣例（Conventions）

- **建立議題**：`gh issue create --title "..." --body "..."`。多行內容請使用 heredoc。
- **讀取議題**：`gh issue view <number> --json number,title,body,labels,comments`。
- **列出議題**：`gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`，並搭配適當的 `--label` 與 `--state` 篩選條件。
- **將議題設為父議題的子議題（sub-issue）**：`gh issue create --parent <parent> ...`，或事後執行 `gh issue edit <parent> --add-sub-issue <child>`（需 `gh` 2.94+）。舊版 `gh`：`gh api --method POST repos/<owner>/<repo>/issues/<parent>/sub_issues -F sub_issue_id=<child-db-id>`（資料庫 ID，同下方 **阻擋關係**）。若未啟用子議題功能，在子議題內容開頭加上 `Part of #<parent>`。
- **阻擋關係（Blocking）**：使用 GitHub **原生議題相依性（native issue dependencies）**作為標準且 UI 可見的表示方式。以 `gh issue create --blocked-by <n>,<n> ...` 或 `gh issue edit <child> --add-blocked-by <blocker>`（需 `gh` 2.94+）建立關聯。舊版 `gh`：`gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`，其中 `<blocker-db-id>` 為阻擋議題的數值**資料庫 ID**（`gh api repos/<owner>/<repo>/issues/<n> --jq .id`，_不是_ `#number` 或 `node_id`）。若無法使用相依性功能，退回在子議題內容開頭加上 `Blocked by: #<n>, #<n>`。當所有阻擋議題皆關閉時，該工作單即解除阻擋。
- **計算未關閉的阻擋議題數**：`gh api repos/<owner>/<repo>/issues/<n> --jq .issue_dependencies_summary.blocked_by`（僅計入開啟中的阻擋議題；0 代表可開始）。`gh issue view <n> --json blockedBy` 也會列出已關閉的阻擋議題，因此需篩選：`--jq '[.blockedBy.nodes[] | select(.state == "OPEN")] | length'`。
- **於議題留言**：`gh issue comment <number> --body "..."`
- **套用／移除標籤**：`gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **關閉議題**：先以 `gh issue comment <number> --body "..."` 張貼說明，再執行 `gh issue close <number>`。對已關閉的議題執行 `gh issue close --comment` 會丟棄留言且仍回傳退出碼 0。

由 `git remote -v` 推斷目標儲存庫；在 clone 目錄內執行時，`gh` 會自動處理。

只在使用者自己的儲存庫建立議題。除非使用者擁有 `mattpocock/skills`（這些技能的來源儲存庫），否則絕不可在該處建立議題。在 fork 中，`gh` 可能會預設指向 upstream 父儲存庫，因此在每次工作階段首次執行 `gh issue create` 前，請先以 `gh repo view --json nameWithOwner` 檢查目標，若非使用者的儲存庫則須先向使用者確認。

## 拉取請求作為檢傷分類入口（Pull requests as a triage surface）

**PRs as a request surface: no.** _（若本儲存庫將外部 PR 視為功能請求，請設為 `yes`；`/triage` 會讀取此旗標。）_

設為 `yes` 時，PR 會使用與議題相同的標籤與狀態，並改用對應的 `gh pr` 命令：

- **讀取 PR**：`gh pr view <number>`，接著執行 `gh pr view <number> --comments`（非 TTY 環境下，`--comments` 只會印出留言而不含本文），並以 `gh pr diff <number>` 取得差異。
- **列出待檢傷分類的外部 PR**：`gh api --paginate 'repos/{owner}/{repo}/pulls?state=open' --jq '.[] | select(.author_association | IN("OWNER","MEMBER","COLLABORATOR") | not) | {number, title, author: .user.login, author_association, labels: [.labels[].name]}'`。
- **留言／標籤／關閉**：`gh pr comment`、`gh pr edit --add-label`/`--remove-label`、`gh pr close`。

GitHub 的議題與 PR 共用編號空間，因此單寫 `#42` 可能是任一者：先以 `gh pr view 42` 解析，失敗時再退回 `gh issue view 42`。

## 當技能指示「發布至議題追蹤器（publish to the issue tracker）」時

建立一個 GitHub 議題。

## 當技能指示「讀取相關工作單（fetch the relevant ticket）」時

依上方 **讀取議題** 的方式讀取。

## 尋路操作（Wayfinding operations）

供 `/wayfinder` 使用。**地圖（map）**為單一議題，並以**子議題（child issues）**作為工作單（tickets）。

- **地圖（Map）**：標有 `wayfinder:map` 的單一議題，內含 Notes／Decisions-so-far／Fog 本文。使用 `gh issue create --label wayfinder:map` 建立。
- **子工作單（Child ticket）**：作為 GitHub 子議題連結至地圖的議題（見 **將議題設為父議題的子議題**）。若未啟用子議題功能，請將子議題加入地圖本文的工作清單，並在子議題本文開頭加上 `Part of #<map>`。標籤：`wayfinder:<type>`（`research`／`prototype`／`grilling`／`task`）。認領後，將工作單指派給負責推進的開發者。
- **阻擋關係（Blocking）**：見慣例中的 **阻擋關係**。
- **前線查詢（Frontier query）**：列出地圖下開啟中的子議題（`gh issue list --state open`，範圍限於地圖的子議題／工作清單），排除任何仍有未關閉阻擋議題（見 **計算未關閉的阻擋議題數**，或 `Blocked by` 行中仍開啟的議題）或已有受指派者的項目；依地圖順序取第一個。
- **認領（Claim）**：`gh issue edit <n> --add-assignee @me`，作為工作階段的第一次寫入。
- **解決（Resolve）**：執行 `gh issue comment <n> --body "<answer>"`，接著 `gh issue close <n>`，最後將脈絡指標（大意＋連結）附加至地圖的 Decisions-so-far。

<a id="en"></a>

# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --json number,title,body,labels,comments`.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Make an issue a sub-issue of a parent**: `gh issue create --parent <parent> ...`, or `gh issue edit <parent> --add-sub-issue <child>` afterwards (`gh` 2.94+). Older `gh`: `gh api --method POST repos/<owner>/<repo>/issues/<parent>/sub_issues -F sub_issue_id=<child-db-id>` (database id, as in **Blocking** below). Without sub-issues, put `Part of #<parent>` at the top of the child body.
- **Blocking**: GitHub's **native issue dependencies**, the canonical, UI-visible representation. Add an edge with `gh issue create --blocked-by <n>,<n> ...` or `gh issue edit <child> --add-blocked-by <blocker>` (`gh` 2.94+). Older `gh`: `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/<owner>/<repo>/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Count open blockers**: `gh api repos/<owner>/<repo>/issues/<n> --jq .issue_dependencies_summary.blocked_by` (open blockers only; 0 means startable). `gh issue view <n> --json blockedBy` also lists closed blockers, so filter it: `--jq '[.blockedBy.nodes[] | select(.state == "OPEN")] | length'`.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: post the explanation with `gh issue comment <number> --body "..."`, then `gh issue close <number>`. On an already-closed issue, `gh issue close --comment` drops the comment and still exits 0.

Infer the repo from `git remote -v`; `gh` does this automatically when run inside a clone.

File issues only into the user's own repo. Never file into `mattpocock/skills` (the repo these skills come from) unless the user owns it. In a fork, `gh` can default to the upstream parent, so before the first `gh issue create` of a session, check the target with `gh repo view --json nameWithOwner` and confirm it with the user if it is not their repo.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number>`, then `gh pr view <number> --comments` (off a TTY, `--comments` prints only the comments, not the body), and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh api --paginate 'repos/{owner}/{repo}/pulls?state=open' --jq '.[] | select(.author_association | IN("OWNER","MEMBER","COLLABORATOR") | not) | {number, title, author: .user.login, author_association, labels: [.labels[].name]}'`.
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either: resolve with `gh pr view 42` and fall back to `gh issue view 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Read it as in **Read an issue** above.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (see **Make an issue a sub-issue of a parent**). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: see **Blocking** under Conventions.
- **Frontier query**: list the map's open children (`gh issue list --state open`, scoped to the map's sub-issues / task list), drop any with an open blocker (see **Count open blockers**, or an open issue in the `Blocked by` line) or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment <n> --body "<answer>"`, then `gh issue close <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
