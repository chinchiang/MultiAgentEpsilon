[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 協作指引

本檔是代理人協作規則的唯一來源；`CLAUDE.md` 只以 `@AGENTS.md` 匯入本檔、不另寫規則，規則只改本檔。

## 語言

- 解說與報告使用正體中文、臺灣慣用語；專有名詞使用中／英雙語，例如模組（module）、介面（interface）。
- 程式碼、CLI 命令、路徑與識別名稱保留原文；其他內容僅在確有必要時使用英文。

## 代理人路標

- 用語：替程式、測試或概念命名前，查 [GLOSSARY.md](GLOSSARY.md) 的名詞與「避免」清單。
- 雙語：修改文件、docstring 或註解時，依[雙語文件維護規則](docs/documentation-policy.zh-TW.md)。
- 審查：審查 diff 時，套用 [CODING_STANDARDS.md](CODING_STANDARDS.md) 的判斷規則。
- 測試：執行測試、ruff 或文件檢查前，看 [README「開始執行」](README.md#開始執行)。

## 產出位置

- `improve-codebase-architecture` 的 HTML 架構報告存放在專案根目錄的 `scratch/architecture-review-<timestamp>.html`。
- `/handoff` 的交接檔存放在 `scratch/handoff-<timestamp>.md`。
- 每次使用新檔名，完成後提供實際檔案連結。此位置覆寫技能預設的作業系統暫存目錄（`/tmp` 關機即清除）；`scratch/` 不納入版本管理。

## 任務完成後

- 清楚區分已完成工作、驗證結果、剩餘問題或風險。
- 按價值排序提供 3 至 5 個可執行的後續選項；以編號列出，最高優先項標示 `[Recommended]`，另提供 `0. 結束，不進行後續操作`。
- 每項說明行動與預期結果；適用時提供實際命令。
- 等待使用者選擇才執行後續工作，接受單一數字作為選擇。
- 破壞性、需特權、涉及安全敏感內容或不可逆的操作，須先取得明確核准。

<a id="en"></a>

# Collaboration instructions

This file is the only source of agent collaboration rules; `CLAUDE.md` only imports it with `@AGENTS.md` and holds no rules of its own, so edit rules only in this file.

Use Traditional Chinese and Taiwan usage for explanations and reports, with Chinese/English technical terms. Preserve code, commands, paths and identifiers; use English elsewhere only when necessary.

Agent pointers:

- Terms: before naming code, tests or concepts, check [GLOSSARY.md](GLOSSARY.md#en) for the term and its avoid list.
- Both languages: when editing docs, docstrings or comments, follow the [bilingual documentation rules](docs/documentation-policy.zh-TW.md#en).
- Review: when reviewing a diff, apply the judgement rules in [CODING_STANDARDS.md](CODING_STANDARDS.md#en).
- Tests: before running tests, ruff or documentation checks, read the [README "Run the pilot"](README.md#run-the-pilot) section.

Save each `improve-codebase-architecture` report to `scratch/architecture-review-<timestamp>.html` and each `/handoff` file to `scratch/handoff-<timestamp>.md` under the repository root, with a new name every time, and provide the file link. This overrides the skills' temporary-directory default (`/tmp` is cleared on shutdown); `scratch/` is not version-controlled.

After each task, distinguish completed work, verification results and remaining issues or risks. Offer 3–5 numbered next steps in value order, mark the first `[Recommended]`, and include `0` to finish. Explain actions and expected outcomes, including commands where applicable. Accept a single number and wait before executing a next step. Obtain explicit approval for destructive, privileged, security-sensitive or irreversible operations.
