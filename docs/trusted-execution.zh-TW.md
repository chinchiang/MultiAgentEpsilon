[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 可信執行、基準更新與合併保護

此版本修正覆蓋判定、掃描範圍與早期錯誤證據，並將候選程式移出評分器行程。主分支是否受到 GitHub 保護必須另行讀回驗證；本文件與規則 JSON 不構成已啟用的證據。

## 執行邊界

1. PR 工作流程由 `pull_request_target` 觸發，從 base SHA checkout evaluator。候選 head SHA checkout 到另一目錄，僅由可信工具讀取，不能在 runner 上直接執行候選 bootstrap、pytest、conftest、Dockerfile 或程式。
2. 可信 bootstrap 安裝基準 lock 的 wheels；runtime 以固定 Python image digest、離線網路及 `--require-hashes` 建置。候選來源不能提供建置指令。runtime 記錄 image ID 及 lock／entrypoint／builder 的 hash；修改後須重建。
3. AUTH 將限定的 Python fixture 來源複製成唯讀快照，容器使用非 root UID、唯讀 root filesystem、cap-drop、no-new-privileges、CPU／記憶體／PID 限制與 `--network=none`。
4. 候選只能讀取合成 app 設定、使用唯讀掛載的 PostgreSQL Unix socket，及在容器的限額 tmpfs 建立 HTTP socket；沒有可寫的 host HTTP 目錄。它不取得 DB 管理員密碼、評分器、報告、GitHub token、模型憑證或 Docker socket。
5. PostgreSQL 在另一個無網路容器中使用 SCRAM 認證；app 帳號僅有指定 schema/table 所需權限。host oracle 獨立建置資料與查詢完整 fixture 狀態。唯讀 runtime bridge 在候選容器內發送 HTTP，不跟隨重新導向，拒絕壓縮及超大回應；host 使用限時、限量 Docker exec 串流接收不可信回應，不連接候選控制的 host socket 路徑。bridge 不負責評分。
6. AUTH 超時／取消後，父程序依唯一 run label 清除本次容器；普通結束亦在 finally 清除。錯誤及未完成 gate 保存為 BLOCK。來源或 evaluator 在執行期間持續變動也會 BLOCK。

這是 Linux 容器邊界，仍共用 host kernel，不能宣稱抵抗 kernel／runtime 漏洞。正式敵意多租戶使用仍應採專用短生命週期 VM／microVM、受控 worker 身分與平台隔離。候選合成 app 可以破壞自己的資料或服務，這會導致測試失敗，不可把 app 自報結果當 oracle。

## 案例、輸入與錯誤證據

- `security/policy.json` 的 `gate_contracts` 指定 gate kind 與必要 case ID。AUTH 必須恰好涵蓋唯一集合；數量、findings 與逐案例結果須一致。schema 3 拒絕舊版（schema 1、2）證據及不同 run ID 的混用。G2 另須有候選 repository 本身的 HEAD 歷史（`history_required`）；沒有 `.git`、沒有 commit，或位於外層 repo 之中的子目錄都不能取得 ALLOW。
- 掃描／subject 共用 `security_harness/inputs.py`。只在 repo 根目錄排除生成目錄；Python／pytest 快取為明列例外，已追蹤的保留生成路徑會拒絕。候選容器使用相同清冊的 fixture Python 子集，未納入來源不會掛載。
- Gitleaks 使用重新命名的快照，映射回原始檔名；原始 `.git` 等名字不能觸發工具的隱含略過，候選 inline allow 與 ignore file 不能自行抑制可信掃描。壓縮檔除了展開成員，也掃描容器本身的可讀字串（註解、檔名、extra 欄位、gzip 標頭）；zip 中不屬於任何列出成員的位元組、帶資料的目錄項目，以及 tar 結尾之後的非零資料一律阻擋。
- 對候選 repository 的 git 呼叫一律經 `security_harness/candidate_git.py`：以命令列 `-c` 停用 fsmonitor、hooks 與任何 transport，清除繼承的 `GIT_*` 環境變數，不讀取系統／全域設定，並以明確的 `--git-dir` 指向候選自己的 `.git` 目錄（gitfile 或 symlink 拒絕）。候選的 `.git/config` 是資料，不能讓 host 執行程式。
- Audit envelope 在設定解析之前寫出，subject／policy 尚不可得時保留 null。錯誤只記錄階段與例外型別。報告採原子替換，初始 RUNNING 報告一律 BLOCK；沒有成功完成的證據不得放行。
- `artifacts/latest.txt` 僅索引 security run；其他入口各有 `<operation>-latest.txt`。本機 artifact 未簽章；CI 另以獨立工作簽署上傳 ZIP，保存 7 天，仍不是長期不可竄改證據庫。

## 合法基準更新

所有路徑均須獨立核准，包括 app Python、Markdown 文件及新增 `conftest.py`、Python import 入口、ignore/config、workflow、工具與測試。

受保護變更使用以下流程：

1. 開立 PR，完成差異審閱及候選版本驗證。此時舊基準可以拒絕變更，屬預期行為。
2. `security/trust-policy.json` 中的基準 reviewer 對目前 head SHA 核准；reviewer 必須不同於 PR 作者。核准權限來自 base 版本的政策，不能由 PR 自增 reviewer。
3. 重新執行可信工作流程。guard 即時查詢 GitHub PR 與 reviews，確認仍 open、base/head 相符、最後有效決定為 APPROVED 且 commit_id 相同；核准者必須具 write、maintain 或 admin 權限，PR 中任一 commit 的作者／提交者都不計入（GitHub 最多列出 250 個 PR commit，達上限即拒絕）。查詢失敗、撤回、CHANGES_REQUESTED、權限不足或 head 變動均不授權。
4. 此輪依然由舊 evaluator／policy 執行。核准變更不代表新 evaluator 已自動證明正確；維護者需評估新增政策與測試的驗收證據。合併後的新 commit 才成為下一輪基準。

`pull_request_target` 不會因 review submitted 自動重跑；審核後須 rerun 對應的 head run。**rerun 應由 PR 作者或其他非核准者執行：** 專用發布程式會把 run 的 actor／triggering actor 排除在核准者之外，若由核准者本人按下 rerun，其核准即不計入。證據有效期為 `max_evidence_age_seconds`（3600 秒），超過後需再 rerun。禁止用 PR label、候選檔案或任意 CLI approval 字串取代 GitHub 的即時審核查驗。單人作者不能自行核准自己的 PR；需有合格的獨立 reviewer。

## 首次遷移與 GitHub 管理設定

舊 main 的 guard 不支援此更新流程，且新 workflow 尚未成為預設分支內容。因此第一次採納此版本屬明確的基準遷移：維護者先審查 PR 與手動 workflow 驗證，再採納新基準；不能把舊 guard 的拒絕偽裝成成功。手動 workflow 的 evaluator 由執行者選定 ref，只能當選定版本的測試證據；因此 main 上的 workflow 手動執行時，檢查名稱固定為 `manual-security-evaluation`。注意 `workflow_dispatch` 使用所選 ref 的 YAML：具推送權限者可在自己的分支改掉 job 名稱再手動執行，仍能產生同名檢查。`verify_required_check.py` 會拒絕 `workflow_dispatch` 來源，所以審查者核准前仍須執行它。

`docs/github-main-ruleset.json` 提供最低合併保護候選設定：禁止刪除／強推、獨立 CODEOWNERS 核准、變更後重審、嚴格 required check `trusted-security-pilot`、無 bypass。原訂於基準遷移後才套用；實際上規則集 24512048 在遷移前就已啟用，當時舊 workflow 只會產生 `security-pilot`、CODEOWNERS 也只有作者本人，任何 PR 都無法依規則合併。**首次遷移已於 2026-10-06 完成：** 擁有者暫時停用規則集，合併 #6 與 #7，完成真實流程驗收後恢復規則集（結果見 [里程碑狀態](milestone-status.zh-TW.md)）。當時沒有獨立審查者，因此省略了下列第 1、2 步，由擁有者直接合併。日後若需再次進行基準遷移，依下列程序：

1. 確認獨立審查者具 write 權限（CatGrocery 已於 2026-10-07 讀回為 write）；以 `python3 -I scripts/audit_merge_protection.py` 讀回確認。
2. 審查者審閱可信閘門 PR 的差異、遠端手動 run（`manual-security-evaluation`）的結果，以及 artifact 中 `audit/publishable-evidence.json` 為 PUBLISHABLE，並以審查者帳號核准目前 head。
3. 使用現行 guard 的獨立核准流程，完整重跑正式 CI、核對簽章及必要檢查來源後正常合併。不要把歷史停用規則的遷移方式當成日常操作；若平台設定確實無法支援遷移，先另行設計並審查受控遷移程序。
4. 合併後，main 的 CODEOWNERS 包含兩位審查者，`pull_request_target` workflow 生效：之後的 PR 會在 head 上產生 `trusted-security-pilot`。專用 App 綁定前，每次核准或合併前以 `python3 -I scripts/verify_required_check.py --pr <編號>` 確認該檢查來自可信 workflow 的 `pull_request_target` run。
5. 疊在其上的發布程式與多模型 PR 改以 main 為 base 後，依一般流程審查；它們會由已合併的新 evaluator 評估。

**GitHub Actions app ID + check 名稱仍不唯一綁定 evaluator workflow。** `pull_request_target` 執行的是 PR **base 分支**上的 workflow 檔案，而 run 中繼資料不記錄 base；同一路徑在其他分支的修改版本有相同 workflow ID。因此 `verify_required_check.py` 與發布程式另外要求：run 的 head 分支與 head repository 必須等於此 PR，且任何狀態（含已關閉）的 PR 只要共用同一 head 卻以其他分支為 base，就 BLOCK。PR 無法刪除，所以「開到其他分支、取得綠燈後關閉」的雙胞胎 PR 仍會被看見。較強的做法是以 GitHub artifact attestation（OIDC 簽署的 `security.yml@refs/heads/main` 身分）綁定證據，此項已實作並通過 main 真實簽章驗收。 若要把檢查視為不可偽造的自動閘門，需額外採平台支援的 required workflow，或獨立 GitHub App：App 必須查核 repository、workflow 身分／可信 evaluator SHA、事件、候選 SHA、run attempt、完整報告與結論後，才對候選 SHA 發佈必要檢查。其他 workflow 的 GITHUB_TOKEN 不應能以該 App 身分發佈檢查。此獨立來源機制目前未部署，不能聲稱一般開發者無法偽造同名檢查。

管理驗收至少包含：普通開發者直接 push 失敗、未核准政策修改阻擋、同名假檢查不放行、核准後換 SHA 失效、合法更新成功、規則讀回顯示 active。需使用普通開發者角色，不以 owner/admin 的測試代替。若 ruleset API 回覆 403，程式與 CI 驗證仍可完成，但遠端保護必須維持未完成狀態。

## 本地驗收

```bash
python3 -I scripts/bootstrap.py
python3 -I scripts/build_runtime.py
python3 -I scripts/dev_db.py start
.venv/bin/python -m pytest --junitxml=artifacts/pytest.xml
.venv/bin/python -I scripts/expect_block.py
.venv/bin/python -I scripts/run_security.py
python3 -I scripts/dev_db.py stop
```

隔離回歸會執行缺陷版、修正版，以及在候選匯入時嘗試寫入唯讀來源／入口、讀取 evaluator／Docker socket／token、建立 IP 出向連線的探測。必要結果為：完整 32 案例、缺陷版恰好政策 `seeded_defect_case_ids` 的 9 個 findings／BLOCK、修正版 0 findings／ALLOW。另有錯誤密碼登入、404 洩漏、匯出夾帶跨租戶資料、其他資料列被非法修改，以及 admin 寫入條件越過租戶邊界，加上過期工作階段與跨租戶刪除共七種變體，必須產生指定 AUTH findings；socket 改指向 host 測試端點必須失敗且端點不得收到連線。

候選 lock digest 必須等於已驗證 runtime lock digest；尚不支援任意候選依賴映像建置。受保護變更使用禁用 rename 折疊的 diff，同時判斷刪除與新增路徑。結果 schema 3 使用版本化逐檔 manifest，不能沿用 schema 2 的 gate 證據。

目前管理 API 的實際阻礙、獨立檢查來源需求及遠端負向驗收步驟，見[遠端合併保護設定與驗收缺口](remote-merge-protection.zh-TW.md)。

G2 現在也掃描 HEAD 可達提交的訊息、作者與提交者中繼資料，以及所有標籤名稱與附註標籤內容；標籤指向但 HEAD 不可達的檔案歷史仍不在範圍。原始中繼資料不寫入證據，超過清冊或位元組限制時保持 BLOCK。Git manifest 只使用 Git 儲存的擁有者執行權限分類，避免 checkout umask 不同造成摘要誤差。

Gitfile（linked worktree 或部分 submodule 使用的 `.git` 文字檔）會在檢查候選 repository 時提前拒絕；這是目前輸入格式限制，不是掃描完成或容器執行失敗。請使用一般 clone 的實體 `.git` 目錄，不接受可指向任意 host 路徑的 gitfile。跨開機清理先比較 boot ID，程序登記持久化前的子程序只能等待握手，不能執行候選工作。

<a id="en"></a>

# Trusted execution, baseline updates, and merge protection

Coverage, scan scope, and early-error evidence are enforced, and candidate code runs outside the evaluator process. Documents/rules JSON alone do not prove GitHub enforcement; read back remote settings separately.

## Execution boundary

1. pull_request_target checks out the evaluator from base SHA. Head is separate candidate data, never host-executed bootstrap, pytest, conftest, Dockerfile, or imports.
2. Trusted bootstrap installs baseline locked wheels. Runtime builds offline using a pinned Python image and --require-hashes, never candidate build instructions. Image ID and lock/entrypoint/builder hashes are recorded; changes require rebuilding.
3. AUTH snapshots the limited Python fixture read-only into a non-root, read-only-root, capability-dropped, no-new-privileges, networkless container with CPU/memory/PID limits.
4. Candidate gets only synthetic app settings, read-only PostgreSQL Unix socket mount, and bounded HTTP-socket tmpfs. It has no writable host HTTP directory, DB admin password, evaluator, reports, GitHub/model credentials, or Docker socket.
5. PostgreSQL is a separate networkless SCRAM-authenticated container; app privileges are schema/table-specific. Host oracle seeds and inspects complete state independently. A read-only in-container bridge performs HTTP without redirects/compression/oversized responses. Host receives bounded, timed Docker exec output rather than connecting to candidate-controlled host sockets. Bridge never scores.
6. Parent cleans uniquely labeled containers on timeout/cancel and normal completion. Errors, incomplete gates, or changing source/evaluator block.

Linux containers still share a kernel; this is not kernel/runtime-exploit resistance. Hostile multi-tenancy needs dedicated short-lived VM/microVM workers and platform isolation. Candidate damage to its own synthetic data/service should fail tests; self-reported results are never the oracle.

## Cases, input, and error evidence

Gate contracts specify kind and exact unique AUTH case IDs, consistent counts/findings/per-case results. Schema 3 rejects versions 1/2 and mixed run IDs. G2 requires the candidate's own HEAD history: missing .git/commits or a nested directory inside another repository cannot ALLOW.

Scanning and subject hashing share inputs.py. Generated directories are excluded only at root; Python/pytest caches are explicit exceptions, and tracked reserved generated paths are rejected. Candidate mounts contain only inventoried fixture Python. Gitleaks scans renamed snapshots mapped back to original names: .git names, inline allow comments, and candidate ignore files cannot silently skip trusted scanning. Archive container strings/metadata and expanded members are scanned; unlisted ZIP bytes, data-bearing directory entries, and nonzero trailing TAR bytes block.

Candidate Git calls use candidate_git.py, disabling fsmonitor/hooks/transports with -c, clearing inherited GIT_*, ignoring system/global config, and explicitly selecting a real candidate .git directory. Gitfiles/symlinks are rejected. Candidate configuration is data, never host execution authority.

An audit envelope exists before settings parsing, with null subject/policy when unavailable. Errors retain phase/type only. Atomic initial RUNNING reports stay BLOCK. artifacts/latest.txt indexes security only; other operations have separate indexes. Local artifacts are unsigned; CI separately signs the uploaded ZIP and retains it seven days, not a permanent immutable archive.

## Legitimate baseline updates

Every path requires independent approval, including fixture Python, Markdown, conftest/imports, ignores/configuration, workflows/tools/tests.

1. Open a PR and review its diff/candidate verification; rejection by the old baseline can be expected.
2. A reviewer trusted by base security/trust-policy.json approves the exact current head, distinct from the author. Candidate-added reviewers cannot authorize themselves.
3. Rerun trusted CI. Live guard verifies open PR, matching base/head, latest effective APPROVED decision and commit ID, and write/maintain/admin permissions. Any PR commit author/committer is excluded; reaching GitHub's 250-commit listing cap rejects. Lookup failure, dismissal, CHANGES_REQUESTED, lost permissions, or changed head does not authorize.
4. Evaluation still uses old evaluator/policy. Approval does not prove the new evaluator correct; review its candidate evidence. Only the merged commit becomes the next baseline.

Review submission does not automatically trigger pull_request_target. Rerun the correct head as the author or another non-approver: publisher excludes both original actor and triggering actor. Evidence expires after 3,600 seconds and needs rerun. Labels, candidate files, arbitrary CLI approval strings, or self-approval cannot replace live independent review.

## Initial migration and GitHub administration

The old guard could not adopt this workflow normally; initial migration was explicit, not a disguised pass. Manual workflow_dispatch evaluates the chosen ref and is named manual-security-evaluation. A developer can modify their branch YAML/job names, so a same-name green manual run is not trusted; verify_required_check.py rejects workflow_dispatch.

The minimum rules template requires no deletion/force push/bypass, independent CODEOWNER review, stale-review dismissal, and strict trusted-security-pilot. Ruleset 24512048 was enabled before migration, when old jobs only produced security-pilot and CODEOWNERS contained only the author, preventing normal merges. On October 6 the owner temporarily disabled rules and merged #6/#7 without independent review, then restored enforcement after acceptance. This historical exception is not routine guidance.

For subsequent updates: confirm independent write access (CatGrocery confirmed October 7), review diff/manual candidate run/PUBLISHABLE evidence, approve exact head, then use current guard, full formal CI, signature and source verification for normal merge. If platform constraints genuinely prevent migration, separately design/review a controlled migration instead of reusing historical disablement. CODEOWNERS/main workflow then apply to later PRs. Until dedicated App binding, run verify_required_check.py --pr <number> before approval/merge. Stacked PRs retargeted to main follow normal review and new evaluator rules.

Shared Actions App ID plus check name does not uniquely identify YAML. pull_request_target uses base-branch workflow and run metadata omits base; alternate-base YAML can share workflow ID/path. Publisher/verifier require matching head repository/branch and reject any related PR (including closed ones) targeting another base or ever changing base. Closing a twin PR does not erase it. Implemented GitHub artifact attestation binds security.yml@refs/heads/main and evaluator SHA, with real main signature acceptance. An unforgeable automated required source still needs platform required-workflow support or a dedicated App validating repository/workflow/evaluator/event/candidate/attempt/full evidence. Ordinary GITHUB_TOKEN must not impersonate it. Dedicated source is not deployed; same-name forgery resistance is not claimed.

Acceptance needs actual non-admin direct-push denial, unapproved policy rejection, spoofed-name rejection, stale-SHA rejection, legitimate update success, and active rule readback. Owner tests do not substitute. Administration API 403 leaves remote acceptance incomplete even if local/CI tests pass.

## Local acceptance

```bash
python3 -I scripts/bootstrap.py
python3 -I scripts/build_runtime.py
python3 -I scripts/dev_db.py start
.venv/bin/python -m pytest --junitxml=artifacts/pytest.xml
.venv/bin/python -I scripts/expect_block.py
.venv/bin/python -I scripts/run_security.py
python3 -I scripts/dev_db.py stop
```

Isolation regressions attempt writes to read-only source/entrypoint, reads of evaluator/Docker socket/tokens, and IP egress. Required results: exact 32 cases; fixed zero findings/ALLOW; seeded exact nine policy IDs/BLOCK. Seven additional real-container variants cover wrong-password login, 404 disclosure, cross-tenant export, hidden unrelated-row mutation, admin cross-tenant writes, expired sessions, and cross-tenant deletion. Redirecting the HTTP socket to a host endpoint must fail without contacting that endpoint.

Candidate lock must match verified runtime lock; arbitrary candidate dependency images are unsupported. Protected diffs disable rename collapsing and check both old/new paths. Schema 3 uses versioned per-file manifests. See [remote gaps](remote-merge-protection.zh-TW.md#en).

G2 also scans HEAD-reachable commit messages/authors/committers and all tag names/annotations, but not file history reachable only from tags. Raw metadata is not retained; limits block. Manifest executable classification follows Git owner-executable bits, not checkout umask. Linked-worktree/submodule gitfiles are an explicit unsupported input, not completed scanning or runtime failure; use a normal clone with real .git. Cross-boot cleanup checks boot ID first, and registered children wait for persistent-registration handshake.
