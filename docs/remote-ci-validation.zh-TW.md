# 遠端 CI 驗收與尚未生效的合併保護

驗收日期：2026-10-04（Asia/Taipei）。原始執行索引與 SHA 見 [remote-ci-evidence.json](remote-ci-evidence.json)。

> **歷史紀錄。** 本文保留 2026-10-04 首版 main 的遠端驗收原貌。之後 main 已由規則集 24512048 保護，授權案例與 workflow 也已改版；現況以 [里程碑狀態](milestone-status.zh-TW.md) 開頭的「目前狀態」為準。

## 已實際驗證

| 情境 | GitHub 證據 | 結果 |
|---|---|---|
| main 上完整流程 | [最新基線 run](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37170856594) | 51 項測試通過，0 失敗／錯誤／跳過；實際 Gitleaks、PostgreSQL 與 HTTP smoke 執行。 |
| 正常文件變更 PR | [PR #1 run](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37170578652) | CI 成功；沒有修改 evaluator、policy 或 fixture。 |
| 應用授權退化 PR | [PR #2 run](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37170653595) | 49 項通過、1 項授權測試失敗；不是工具安裝故障造成的假陰性。 |
| 政策移除 AUTH gate | [PR #3 run](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37170656488) | base SHA 的 guard 在目標安裝前拒絕；同時發現早期失敗沒有 artifact 的缺口。 |
| 早期拒絕的證據修正 | [PR #4 run](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37170892081) | guard 正確失敗，後續目標步驟跳過；證據上傳成功，包含 base SHA、candidate SHA、變更路徑與 BLOCK。 |

四個驗證 PR 均已關閉且未合併，遠端測試分支已清理。刻意的授權／政策退化沒有進入 main。GitHub Actions 的 main 報告亦確認：缺陷 fixture 有 5 個授權 findings 並 BLOCK；修正版的 14 個案例無 findings 並 ALLOW。

早期拒絕的證據放在 trusted workflow workspace 的 `audit/`，不要求先安裝目標依賴才產生報告；仍保留「沒有任何證據檔就讓 upload step 失敗」的規則。

## 尚未生效：main 合併保護

**（2026-10-04 當時）main 的 `protected` 為 false，ruleset 清單為空。CI 失敗尚不等於 GitHub 會禁止合併。**

已準備並嘗試建立 [github-main-ruleset.json](github-main-ruleset.json)，API 回覆 HTTP 403 `Resource not accessible by integration`。目前整合能推送程式碼、建立 PR、讀取 Actions 結果；不能據此推論它具有 Repository administration 的寫入權限。

具備相應管理權限的操作者可在 [repo rules 設定](https://github.com/chinchiang/MultiAgentEpsilon/settings/rules) 建立相同規則，或從此專案目錄使用已授權的 GitHub CLI：

```bash
gh api --method POST repos/chinchiang/MultiAgentEpsilon/rulesets \
  --input docs/github-main-ruleset.json
```

這份具體規則要求：main 只能經 PR、至少一位 code owner 審查、推送新 commit 後舊審查失效、最近推送須另獲核准、討論已解決、`security-pilot` 檢查來自 GitHub Actions app 15368 且基線最新，並禁止刪除、force push，沒有 bypass actor。`.github/CODEOWNERS` 指定 repository owner；檔案本身並不啟用審查要求。

套用後必須讀回 branch／ruleset，並以普通開發者角色驗證直接 push、缺審查與失敗 CI 的合併嘗試會被拒絕。當前未取得該角色的測試路徑，也未實作這些繞過驗收，因此不宣稱不可繞過。

## 信任邊界

現有 PR workflow 仍由候選分支的 YAML 觸發。雖然正常流程會執行 base-ref guard，惡意 PR 仍可能刪掉該步驟或偽造相同 job 名稱。只要求某個 Actions app 的同名 check 並不能辨識唯一可信 workflow。

因此 owner review 是目前提案中必要的治理控制；若要求完全自動且能辨識可信 evaluator，還需平台支援的 required workflow 或獨立 GitHub App 等來源綁定，再做偽造同名 status／workflow 替換的驗收。不得把這次政策降級負例成功擴張成所有惡意 YAML 都無法繞過。

本輪公開版本採獨立的 Git 起始歷史；原始附件、內部參考文件與衍生治理表單留於本地，沒有透過祖先 commit 發布。模型服務的內部 URL 也不存入公開 Git。
