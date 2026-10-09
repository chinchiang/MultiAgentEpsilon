[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 安全性回報

本 repository 是刻意包含缺陷測試標的的資安測試試點，`fixture_app` 中的已知弱點屬於設計內容，不需回報。

若發現 harness 本身的問題（例如可信閘門被繞過、候選程式能在隔離外執行、證據可被偽造，或機密外洩），請**不要**開立公開 issue 或 PR，改以 GitHub 的 [Private vulnerability reporting](https://github.com/chinchiang/MultiAgentEpsilon/security/advisories/new) 私下回報，並附上重現步驟與受影響的 commit。

回報內容請只使用合成資料，不要附上真實憑證或個人資料。

目前私人弱點回報尚未啟用，啟用 API 回覆 403（2026-10-09）；需由擁有者在 Settings → Code security 啟用。上方連結的可用性須先確認，尚未啟用時請先要求擁有者建立私人回報管道，勿公開弱點細節。

<a id="en"></a>

# Security reporting

This repository deliberately includes vulnerable synthetic targets. Known weaknesses in `fixture_app` are intentional and do not need vulnerability reports.

For harness vulnerabilities—gate bypass, execution outside isolation, forged evidence, or secret disclosure—do not open a public issue or PR. Use GitHub [private vulnerability reporting](https://github.com/chinchiang/MultiAgentEpsilon/security/advisories/new) once enabled, and include synthetic reproduction steps and affected commits. Never attach real credentials or personal data.

As of 2026-10-09, private reporting is disabled and the enable API returns 403. The owner must enable it in Settings → Code security. Verify that the channel is available first; if not, ask the owner to establish a private channel before transmitting vulnerability details. The link alone does not establish a working reporting channel.
