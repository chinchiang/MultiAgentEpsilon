[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 領域文件（Domain Docs）

定義工程技能在探索程式碼庫時，應如何讀取並遵守本儲存庫的領域文件。

## 探索前請先閱讀

- 儲存庫根目錄的 **`GLOSSARY.md`**，或
- 若根目錄存在 **`GLOSSARY-MAP.md`**：它會指向各語境（context）專屬的 `GLOSSARY.md`，請閱讀與主題相關的每一份名詞表。
- **`docs/adr/`**：閱讀與即將修改區域相關的架構決策紀錄（ADR）。在多語境儲存庫中，亦請檢查 `src/<context>/docs/adr/` 下的語境專屬決策。

若上述任何檔案不存在，**請靜默繼續執行**。不要回報檔案缺失，也不要預先建議建立。`/domain-modeling` 技能（透過 `/grill-with-docs` 與 `/improve-codebase-architecture` 觸發）會在名詞或決策實際定案時才延遲建立（lazily create）它們。

## 檔案結構

單一語境儲存庫（Single-context repo，適用於大多數儲存庫）：

```
/
├── GLOSSARY.md
├── docs/adr/
│   ├── 0001-event-sourced-orders.md
│   └── 0002-postgres-for-write-model.md
└── src/
```

多語境儲存庫（Multi-context repo，根目錄存在 `GLOSSARY-MAP.md`）：

```
/
├── GLOSSARY-MAP.md
├── docs/adr/                          ← 系統層級決策
└── src/
    ├── ordering/
    │   ├── GLOSSARY.md
    │   └── docs/adr/                  ← 語境專屬決策
    └── billing/
        ├── GLOSSARY.md
        └── docs/adr/
```

## 使用名詞表的詞彙

當產出內容命名某個領域概念時（在議題標題、重構提案、假設或測試名稱中），請使用 `GLOSSARY.md` 定義的名詞，不要偏移至名詞表明確列出應避免的同義詞。

若需要的概念尚未收錄於名詞表，這是一個訊號：可能正在發明專案不使用的語彙（請重新考慮），或是名詞表確實存在缺口（請記錄下來供 `/domain-modeling` 處理）。

## 標示 ADR 衝突

若產出內容與既有 ADR 衝突，請明確提出而非靜默覆寫：

> _與 ADR-0007（event-sourced orders）衝突，但值得重新討論，因為…_

<a id="en"></a>

# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root, or
- **`GLOSSARY-MAP.md`** at the repo root if it exists: it points at one `GLOSSARY.md` per context. Read each one relevant to the topic.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in. In multi-context repos, also check `src/<context>/docs/adr/` for context-scoped decisions.

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates them lazily when terms or decisions actually get resolved.

## File structure

Single-context repo (most repos):

```
/
├── GLOSSARY.md
├── docs/adr/
│   ├── 0001-event-sourced-orders.md
│   └── 0002-postgres-for-write-model.md
└── src/
```

Multi-context repo (presence of `GLOSSARY-MAP.md` at the root):

```
/
├── GLOSSARY-MAP.md
├── docs/adr/                          ← system-wide decisions
└── src/
    ├── ordering/
    │   ├── GLOSSARY.md
    │   └── docs/adr/                  ← context-specific decisions
    └── billing/
        ├── GLOSSARY.md
        └── docs/adr/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007 (event-sourced orders), but worth reopening because…_
