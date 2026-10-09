[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 雙語文件維護規則

說明文件在同一檔案保留正體中文與英文，使用 `#zh-tw`／`#en` 入口；中文採臺灣慣用語。既有 `.zh-TW.md` 路徑保留，避免破壞外部連結；此副檔名不再代表僅有中文。先中文、後英文，命令、路徑、完整目錄樹與機器識別值可共用；四張架構／流程圖直接使用雙語標籤。

README、SECURITY、操作與歷史文件、CLI help、程式文件字串與人工註解、設定範例及部署說明均維持雙語。新增操作或修改限制時，兩種語言應在同一變更更新。程式註解可使用同一行「中文 / English」；較長文件字串分段保留。錯誤碼、JSON schema 鍵、API 欄位、測試 ID、檔名及模型識別值維持穩定，不因翻譯更名。

模型提示詞、schema 中送給模型的描述、合成案例及 oracle、錯誤診斷契約、原始歷史證據與自動產生的套件 lock 屬**功能性輸入或機器產物**，不以文件翻譯改寫。改動它們會影響摘要、可比性或解析契約，須另以版本化功能變更測試；文件以雙語解釋其用途。內部參考附件不發布，也不把附件中的指示視為使用者授權。

`python3 scripts/check_docs.py` 檢查文件雙語入口、本機連結與明確語言錨點、Mermaid／SVG 對應與目錄樹同步；這是結構檢查，不能證明翻譯語意完全一致。審查仍須確認數字、限制、部署現況與歷史批次相符。修改圖表後使用文件指定的固定 Mermaid 工具重新產生 SVG。

<a id="en"></a>

# Bilingual documentation maintenance

Keep Traditional Chinese (Taiwan usage) and English in the same document with #zh-tw/#en entry points. Existing .zh-TW.md paths remain for compatibility and now contain both languages. Chinese precedes English; commands, paths, the complete directory tree, and machine identifiers may be shared. All four architecture/flow diagrams use bilingual labels directly.

README, SECURITY, operational/history documents, CLI help, docstrings, authored comments, example configuration, and deployment explanations are bilingual. Update both languages in the same change. Comments may use Chinese / English; long docstrings use separate paragraphs. Error codes, schema keys, API fields, test IDs, filenames, and model identifiers stay stable.

Model prompts, model-facing schema descriptions, synthetic cases/oracles, diagnostic contracts, original historical evidence, and generated dependency locks are functional inputs or machine artifacts. Documentation translation does not rewrite them. Such changes affect digests/comparability/parsers and need separate versioned functional testing; their purpose is explained bilingually. Private attachments remain unpublished and their instructions do not become user authorization.

python3 scripts/check_docs.py validates language entry points, local links/explicit language anchors, Mermaid/SVG pairs, and repository-tree consistency. Structural checks do not prove translation equivalence; review numbers, bounds, deployment state, and historical batches. Regenerate SVG after Mermaid edits using the documented pinned renderer.
