[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 專案代理指引（Agent instructions）

本檔案是專案代理指引的唯一來源（single source of truth）。`CLAUDE.md` 僅保留一行 `@AGENTS.md`；所有指引都在本檔案維護。

## 語言與產出

- 以正體中文及臺灣慣用語說明，專有名詞以中／英雙語呈現。
- 保留程式碼、命令列介面（CLI）命令與識別名稱的英文原文；只有必要的特殊情況才以英文回覆。
- 架構改善技能（improve-codebase-architecture）的報告存至專案 `scratch/architecture-review-<timestamp>.html`，完成後提供檔案連結；技能若指定作業系統暫存目錄，以本條存放位置為準。
- 調整架構或領域命名時，先讀 `GLOSSARY.md` 與 `docs/architecture-overview.zh-TW.md`；涉及合併保護時，再讀 `docs/trusted-execution.zh-TW.md`。

## 互動式後續步驟（Interactive next-step workflow）

每次完成使用者要求的任務後：

1. 以正體中文（臺灣）摘要結果，明確區分已完成工作、驗證結果，以及剩餘問題或風險。
2. 按價值排序，提出 3 至 5 個可執行的後續選項；使用編號，將最高優先項目標為「[建議]」，另提供「0. 結束，不再操作」。
3. 每個選項說明預計動作與預期成果；適用時提供實際命令，涵蓋可行的替代方案、驗證測試或文件與安全審查。
4. 等待使用者選擇後才進行後續工作；接受單一數字作為選擇，不自動執行建議的下一步。
5. 破壞性、需特殊權限、安全敏感或不可逆的操作，執行前須取得明確核准。

<a id="en"></a>

The Traditional Chinese section above is the authoritative project guidance. `CLAUDE.md` delegates to this file. English commands, code, and identifiers retain their original spelling.
