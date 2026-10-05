# 遠端合併保護：設定與驗收缺口

更新：擁有者已啟用規則集 24512048，API 讀回 active、main.protected=true、無 bypass，必要檢查仍綁定共用 GitHub Actions App 15368。下列 403 為整合程式操作的歷史結果；手動啟用不會擴充整合程式權限。發布程式與部署範本見[可信檢查來源部署準備](trusted-check-publisher.zh-TW.md)，App 尚未部署。

2026-10-05 實際查詢顯示，`main` 未受保護、規則集為空，PR #5 沒有審查紀錄。CatGrocery 不在協作者名單，權限查詢的 `read` 只是公開儲存庫的基本存取權。以下是待完成的部署及驗收，不是已啟用的證據。

## 管理連線與審查權限

目前連線讀取儲存庫資訊時回報使用者具有 `admin` 角色，但 GitHub App／整合程式的權限另受限制：

| 實際操作 | 回應 | API 要求 |
|---|---|---|
| 讀取 main 分支保護 | 403 Resource not accessible by integration | administration=read |
| PUT collaborators/CatGrocery，permission=push | 403 Resource not accessible by integration | administration=write |
| POST rulesets，enforcement=disabled | 403 Resource not accessible by integration | administration=write |

這是 GitHub 的整合程式授權不足，不是執行環境的自動核准審查拒絕。沒有建立邀請或規則，也沒有測試合併或修改 main。

儲存庫擁有者須在 [GitHub App 安裝設定](https://github.com/settings/installations) 確认目前連線允許存取本儲存庫，並接受該 App 要求的 Administration 讀寫權限。若 App 本身沒有要求該權限，使用者不能單憑儲存庫管理者角色擴充其權杖；需由連線提供者調整 App 權限，或改用支援該權限的管理連線。不要將權杖或 App 私鑰貼到聊天、issue 或儲存庫。

權限生效後，再以 `PUT /repos/chinchiang/MultiAgentEpsilon/collaborators/CatGrocery`、`{"permission":"push"}` 新增協作者。若回傳邀請，CatGrocery 必須先接受；需重新查核協作者名單與 `write`／`maintain`／`admin` 角色後，才算具備有效審查權限。獨立審查者須不同於 PR 作者；普通開發者繞過驗收應使用非管理者的 `write` 身分。

## 必要檢查的可信來源

目前儲存庫位於個人帳號，不能假設可使用組織層級 required workflows。現有 `trusted-security-pilot` 檢查由共用 GitHub Actions App（15368）發布；只綁定該 App 與名稱無法辨認是哪一個工作流程。

建議部署專用 GitHub App，發布另一個必要檢查（例如 `epsilon/trusted-merge`），並把規則綁定到該專用 App 的真實 ID；不得填入虛構 ID，也不能把 15368 當成已完成來源綁定。App 最小權限應依實作使用 Actions、Contents、Pull requests 讀取及 Checks 寫入；一般候選工作流程不得取得 App 私鑰或安裝權杖。

可信發布程式至少應確認：

- 儲存庫與安裝身分、允許的 workflow ID／路徑、事件及預先核准的 evaluator commit；不能信任候選 PR 自行提供的允許清單。
- 目前仍開啟且非草稿的 PR、base/head SHA、最新 run attempt、執行結論、報告的來源／政策／評分器摘要、案例完整性與清理。
- 受保護變更的有效獨立核准，及核准仍對應最新 head。重新推送、審查撤回、要求修改、重新執行、基準變更均需重新核對；不可沿用舊成功結果。
- 錯誤、查詢失敗、報告過期或條件不符時，保持必要檢查未通過。拒絕其他 workflow、其他 App、錯誤 SHA 或偽造 artifact 的同名結果。

App 身分與執行位置尚未提供；已準備受控主機的發布程式與輪詢服務範本，尚無真實部署或即時撤銷驗收。確認部署與驗收後才能新增專用 App 必要檢查。`github-main-ruleset.json` 是最低規則範本，並非完整可信來源方案。

## 部署順序與負向驗收

1. 完成管理連線授權、CatGrocery 接受協作邀請，並對目前候選提交做真正的獨立審查。
2. 依 `trusted-execution.zh-TW.md` 完成首次可信基準遷移；候選政策新增 reviewer 不會自動取得舊基準的信任。
3. 部署並驗證專用檢查來源，確認會對正確 PR head 發布結果，且能在條件失效時撤銷通過狀態。
4. 在隔離的遠端驗收分支套用預定規則：至少一位獨立 CODEOWNER 核准、推送後撤銷舊核准、最後一次推送需他人核准、討論已解決、嚴格必要檢查、禁止刪除與強推、沒有 bypass。
5. 使用真正非管理者身分與非草稿驗收 PR，分別驗證：檢查成功但沒有核准時不能合併；有有效核准但必要檢查失敗時不能合併；核准後換 SHA 不可沿用；其他 App／工作流程偽造同名成功不可放行；直接推送與強推被拒絕；全部合法條件滿足時可合併至驗收分支。
6. 記錄每次操作的身分角色、規則 ID、base/head、核准與檢查身分、HTTP 回應及測試前後分支 SHA。意外放行視為失敗，不刪掉證據；避免以不安全的 main 合併探測取得證據。
7. 驗收通過後啟用 main 規則並完整讀回。區分「隔離分支的行為驗證」與「main 規則讀回」，不以草稿 PR、本地 BLOCK、CI 成功或管理者角色代替普通開發者遠端驗收。

遠端行為驗收仍未執行。main 規則讀回與 PR #5 草稿顯示 blocked，不能代替普通開發者的負向驗收；先在隔離驗收分支確認規則及來源，避免對 main 做可能真的合併成功的探測。
