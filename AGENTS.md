[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 協作指引

## 語言

- 解說與報告使用正體中文、臺灣慣用語；專有名詞使用中／英雙語，例如模組（module）、介面（interface）。
- 程式碼、CLI 命令、路徑與識別名稱保留原文；其他內容僅在確有必要時使用英文。

## 架構報告

- 執行 `improve-codebase-architecture` 時，HTML 報告存放在專案根目錄的 `scratch/architecture-review-<timestamp>.html`，每次使用新檔名。
- 此位置覆寫技能預設的作業系統暫存目錄；完成後提供實際檔案連結。

## 任務完成後

- 清楚區分已完成工作、驗證結果、剩餘問題或風險。
- 按價值排序提供 3 至 5 個可執行的後續選項；以編號列出，最高優先項標示 `[Recommended]`，另提供 `0. 結束，不進行後續操作`。
- 每項說明行動與預期結果；適用時提供實際命令。
- 等待使用者選擇才執行後續工作，接受單一數字作為選擇。
- 破壞性、需特權、涉及安全敏感內容或不可逆的操作，須先取得明確核准。

<a id="en"></a>

# Collaboration instructions

Use Traditional Chinese and Taiwan usage for explanations and reports, with Chinese/English technical terms. Preserve code, commands, paths and identifiers; use English elsewhere only when necessary.

For `improve-codebase-architecture`, save each report to `scratch/architecture-review-<timestamp>.html` under the repository root and provide its file link. This overrides the skill's temporary-directory default.

After each task, distinguish completed work, verification results and remaining issues or risks. Offer 3–5 numbered next steps in value order, mark the first `[Recommended]`, and include `0` to finish. Explain actions and expected outcomes, including commands where applicable. Accept a single number and wait before executing a next step. Obtain explicit approval for destructive, privileged, security-sensitive or irreversible operations.
