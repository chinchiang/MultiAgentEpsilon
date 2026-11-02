[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 離線補充測試設定

`security/offline-test-profile/` 是專用於補充回歸的容器映像來源。此映像不是正式遷移映像或部署產物，不會取代 `trusted-security-pilot`。

## 信任與建置

`security/offline-test-profile-trust.json` 位於 profile 目錄之外，固定 `profile.lock.json` 的 SHA-256。可信建置器位於 [`offline_test_profile.py`](../security_harness/offline_test_profile.py)，只讀取目前可信 repo checkout 的設定；CLI [`prepare_offline_test_profile.py`](../scripts/prepare_offline_test_profile.py) 不接受 candidate checkout、Dockerfile 或 trust manifest 路徑參數。

wheel 快取放在 `.state/verified-wheels/offline-test-profile/`，不列入 Git。首次或清除快取後，明確執行以下命令，從已鎖定來源下載指定輪檔；其餘來源、檔名、hash 或重新導向都會拒絕：

```sh
.venv/bin/python -I scripts/cache_offline_test_profile_wheels.py
```

此命令需要 PyPI 下載網路；映像建置仍使用 `--network=none`。建置器會在讀取 wheel metadata 前驗證雜湊、套件名稱／版本及精確清單；來源 proof 是鎖定的 PyPI metadata 快照。變更 profile lock 時，必須同時更新外部信任清冊，並由可信 base commit 的 CODEOWNERS／必要檢查審查。

建立 context（建置內容）：

```sh
.venv/bin/python -I scripts/prepare_offline_test_profile.py \
  --output .state/offline-test-profile/context
```

輸出目錄必須尚未存在。準備程序完成所有檢查後才建立輸出；context 固定時間戳、檔案權限及排序。可用固定 base digest 執行離線 Docker 建置：

```sh
docker buildx build --platform linux/amd64 --network=none --no-cache \
  --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=0 \
  --output type=oci,dest=.state/offline-test-profile/image.oci.tar,rewrite-timestamp=true \
  .state/offline-test-profile/context
```

正式 CI 目前不會自動呼叫這個 CLI。若要接入遠端 CI、變更正式必要檢查或發布映像，須另行設計審查並取得明確授權。

## 回歸與維護

回歸位於 [`test_offline_test_profile.py`](../tests/test_offline_test_profile.py)，涵蓋外部 lock anchor、來源／wheel 篡改、symlink、套件清單、`pip`／`ensurepip` 缺席、`gh` 拒絕行為、測試收集清單及可重現 context。

```sh
.venv/bin/python -m pytest tests/test_offline_test_profile.py
```

更新依賴時，先由可信來源查核 PyPI proof、yanked 狀態、artifact hash 與最低發布冷卻期；人工核准後才能更新精確 lock。不可由候選 workflow 或候選程式自動刷新 trust manifest、略過鎖摘要或自行核准套件。掃描發現及授權義務需依掃描資料庫時間另行評估。

## 界線

profile lock 與其信任清冊本身不構成數位簽章。信任來自受保護的 base commit、可信驗證器、必要 CI 檢查與獨立 CODEOWNER 審查。候選 checkout 只能當測試資料；候選程式只在既有受限容器中執行，輸出一律屬非正式補充證據。

<a id="en"></a>

# Offline Supplemental Test Profile

`security/offline-test-profile/` contains the container-image sources for supplemental regressions. The image is not a production migration or deployment artifact and does not replace `trusted-security-pilot`.

## Trust and build

`security/offline-test-profile-trust.json` lives outside the profile directory and pins the SHA-256 digest of `profile.lock.json`. The trusted builder is [`offline_test_profile.py`](../security_harness/offline_test_profile.py). It reads configuration only from the current trusted repository checkout. The [`prepare_offline_test_profile.py`](../scripts/prepare_offline_test_profile.py) CLI does not accept candidate checkout, Dockerfile, or trust-manifest paths.

The wheel cache lives under `.state/verified-wheels/offline-test-profile/` and is not tracked. Before reading wheel metadata, the builder verifies each digest, package name/version, and the exact wheel inventory. Source proofs are pinned PyPI metadata snapshots. A profile-lock update must also update the external trust manifest and receive review through the trusted base commit's CODEOWNERS and required checks.

After a fresh checkout or cache removal, explicitly fetch the exact locked artifacts:

```sh
.venv/bin/python -I scripts/cache_offline_test_profile_wheels.py
```

This step needs network access to PyPI. The image build itself still uses `--network=none`. Other artifacts, filenames, hashes, or redirects are refused.

Prepare a context:

```sh
.venv/bin/python -I scripts/prepare_offline_test_profile.py \
  --output .state/offline-test-profile/context
```

The output directory must not exist. The preparer creates it only after all checks pass and normalizes timestamps, permissions, and ordering. Build offline with the pinned base digests:

```sh
docker buildx build --platform linux/amd64 --network=none --no-cache \
  --provenance=false --sbom=false --build-arg SOURCE_DATE_EPOCH=0 \
  --output type=oci,dest=.state/offline-test-profile/image.oci.tar,rewrite-timestamp=true \
  .state/offline-test-profile/context
```

Formal CI does not currently invoke this CLI. Remote-CI integration, changes to formal required checks, or image publication require separate design review and explicit authorization.

## Regression and maintenance

Regressions in [`test_offline_test_profile.py`](../tests/test_offline_test_profile.py) cover the external lock anchor, source/wheel tampering, symlinks, package inventory, absence of `pip`/`ensurepip`, `gh` refusal behavior, test collection identity, and reproducible contexts.

```sh
.venv/bin/python -m pytest tests/test_offline_test_profile.py
```

For dependency updates, first verify PyPI proof, yanked status, artifact hashes, and the minimum release cooling period from a trusted source. Update exact locks only after human approval. Candidate workflows or code must never refresh the trust manifest, skip the lock digest, or approve packages automatically. Reassess scan findings and license obligations against the scan database timestamp.

## Boundary

The profile lock and its trust manifest are not digital signatures. Trust comes from the protected base commit, trusted verifier, required CI checks, and independent CODEOWNER review. Candidate checkouts remain test data; candidate code runs only in the existing restricted container, and its output is supplemental, non-formal evidence.
