[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 程式撰寫標準（審查用）

審查者對 diff 套用的判斷規則。能機械檢查的規則已經寫成工具：

- [`scripts/check_docs.py`](scripts/check_docs.py) 檢查：
  - 雙語入口、本機連結、目錄樹、圖表
  - 雙語 docstring
  - 中國大陸用語
  - 名詞表避用的多字詞與四字以上的中文詞（只看 Python 註解與 docstring）
- CI 的 ruff 檢查 F 與 E9。

這份文件只收工具判斷不了的部分；出現衝突時，以工具和下列文件為準。

## 用語

- 領域名詞以 [名詞表](GLOSSARY.md) 為準。以下三類避用詞要看上下文，工具不檢查，審查時逐一確認：
  - 單字詞，例如 `client`、`gh`
  - 帶使用情境的條目，例如「run 的 attempt（單獨使用時）」
  - 名詞表中以反引號標示的條目，例如 `` `gh api` ``
- 測試名稱不在工具檢查範圍內。既有測試 ID 依文件政策維持穩定，即使含避用詞也不要求改名；新的測試名稱由審查者確認用的是名詞表的詞。

## 雙語

- 依[雙語文件維護規則](docs/documentation-policy.zh-TW.md)逐項核對；工具只檢查結構，兩種語言的內容是否一致由審查者確認。

## 證據與失敗

- 證據、報告與輸出只保存例外型別（`type(exc).__name__`）。例外文字、子程序輸出、DSN、URL 與權杖一律不保存。
- 讀不到、解析失敗或身分不符的輸入，以 BLOCK 收尾並保留可回收的狀態；程式要繼續走到能寫出阻擋證據的地方。
- 計畫、政策與 RoE 以 supervisor 持有的值為準。worker 讀回的值只拿來比對，不採用。

## 模組形狀

- 呼叫端必須記住的順序（先停止再讀取、先寫檢查點再刪狀態、先套 rlimit 再讀不可信輸入）放進模組裡，不讓每個呼叫端各寫一份。
- 同一個協定出現第二份實作時就要合併。審查時特別找鍵名、順序或例外處理已經分歧的地方。

## 測試

- 測試走模組的介面與真實程序，觀察可見的行為。
- 替身只放在外部邊界：GitHub 用 [`tests/fake_github.py`](tests/fake_github.py)，docker CLI 用 `tests/test_lifecycle.py` 的 `FakeDocker`。要製造失敗時，優先用真實狀態，例如 symlink 或被持有的鎖。
- 新行為的測試在變更前必須是紅燈；審查時要求附上它在舊程式上失敗的證據。

<a id="en"></a>

# Coding standards (for review)

Judgement rules a reviewer applies to a diff. Rules a machine can check are already tools:

- [`scripts/check_docs.py`](scripts/check_docs.py) checks:
  - language entry points, local links, the repository tree and diagrams
  - bilingual docstrings
  - mainland-Chinese terms
  - the glossary's avoided multi-word terms and Chinese terms of four or more characters (in Python comments and docstrings only)
- CI runs ruff for F and E9.

This file covers only what those tools cannot judge; where they conflict, the tools and the documents below win.

## Terms

- Domain terms follow the [glossary](GLOSSARY.md#en). Three kinds of avoided term depend on context, so the check skips them and the reviewer confirms each one:
  - single words such as `client` or `gh`
  - entries with a usage qualifier such as "the run's attempt (on its own)"
  - glossary entries marked with backticks such as `` `gh api` ``
- Test names are outside the check. Existing test IDs stay stable under the documentation policy even when they use an avoided term; the reviewer confirms that new test names use the glossary's terms.

## Both languages

- Review against the [bilingual documentation rules](docs/documentation-policy.zh-TW.md#en) item by item; the tools check structure only, so the reviewer confirms that both languages say the same thing.

## Evidence and failure

- Evidence, reports and output keep only an exception's type (`type(exc).__name__`). Exception text, subprocess output, DSNs, URLs and tokens are never kept.
- Input that cannot be read, does not parse or names another identity ends as BLOCK and leaves recoverable state; the code continues until it can write the blocking evidence.
- The plan, policy and RoE are the values the supervisor holds. Values a worker read back are compared against them, never adopted.

## Module shape

- An order every caller would have to remember (stop before reading, checkpoint before removing state, rlimits before reading untrusted input) lives inside the module, not in a copy at each caller.
- A protocol with a second implementation gets merged. When reviewing, look for places where key names, ordering or exception handling have already drifted.

## Tests

- Tests go through the module's interface and real processes, and observe visible behaviour.
- Test doubles sit at external seams only: [`tests/fake_github.py`](tests/fake_github.py) for GitHub, and `FakeDocker` in `tests/test_lifecycle.py` for the docker CLI. To cause a failure, prefer real state such as a symlink or a held lock.
- A test for new behaviour is red before the change; when reviewing, ask for evidence that it fails on the old code.
