# PR #10 レビュー対応 修正プラン

## Context

PR #10（`feat-add-cdk-examples`）に対し、3 つのレビュー（Copilot CLI / gpt-5.4、Amazon Q Developer、GitHub Copilot reviewer）から計 13 件の指摘が出た。
本プランは各指摘を実コード・`main.go`・既存 `examples/lambda`（lambroll 版・稼働実績あり）と突き合わせて正否を判定し、**本物の不具合のみを最小変更で修正**するもの。

### 判定の決定的な根拠（実コードで確認済み）

- **`main.go:604` `IAM_MODE` の有効値は `shared`（デフォルト）と `federated` のみ**。`direct` / `assume_role` は実装に存在せず、`direct` 指定時は silently `shared` にフォールバックする。
  → Amazon Q の提案 `['direct','federated','assume_role']` は**誤り**。正は `['shared','federated']`、`direct` は `shared` にリネーム。
- **`main.go:534-547` は全シークレットを env var から読む**（`mustEnv("OIDC_CLIENT_SECRET")` 等。SSM 取得コードは無い）。
  → シークレットを env に渡す必要があり、env 焼き込み時点で平文化は不可避。
- **既存 `examples/lambda` は Function URL `NONE` auth**（`function_url.json:3`）かつ lambroll の `{{ ssm }}` で**デプロイ時に SSM 値を解決して env に焼き込む**確立パターン。
  → Function URL `NONE` は設計上正しく、Amazon Q の CWE-306 は誤検知寄り。シークレット注入は「デプロイ時 SSM 解決 → env」が既存流儀。

### 確定した方針（ユーザー確認済み）

- **シークレット注入: SSM String に統一**（`valueForStringParameter` でデプロイ時解決 → env 注入。`main.go` は不変＝スコープを examples 内に限定）。
- **テスト: 追加しない**（examples の軽量性優先。各修正は `cdk synth` で手動検証）。

---

## 対応サマリ（指摘 → 判定 → 対応）

| # | 指摘元 | 内容 | 判定 | 対応 |
|---|---|---|---|---|
| 1 | Copilot CLI | `ssm-secure` 動的参照を Lambda env で使用→デプロイ失敗 | ✅ 本物(Critical) | String 参照に統一 |
| 2 | Copilot CLI | SecureString を `valueForStringParameter` で参照→解決不可 | ✅ 本物(Critical) | README を String 作成に統一 |
| 3 | Copilot reviewer | 非 federated でも `FEDERATED_ROLE_ARN` SSM 参照＋空文字 put 不可 | ✅ 本物(High) | context 経由・federated 時のみ env 設定 |
| 4 | Copilot reviewer | `iamMode` デフォルト `direct` が `main.go` 未対応 | ✅ 本物(High) | `shared` に変更 |
| 5 | Amazon Q | `iamMode` バリデーション欠如 | ✅ 本物(Medium) | `['shared','federated']` で検証（Q の値は誤りなので不採用） |
| 6 | Copilot CLI | federated で `AssumeRoleWithWebIdentity` が `*` | ✅ 本物(High) | `federatedRoleArn` にスコープ |
| 7 | Amazon Q | Function URL `authType: NONE` (CWE-306) | ⚠️ 誤検知寄り | コード不変。README に設計意図＋DoS対策を注記 |
| 8 | Copilot reviewer | `ts-node` 未同梱でクリーン環境で実行不可 | ✅ 本物(Medium) | 両 `package.json` に追加 |
| 9 | Amazon Q | `app.ts` ハードコードプレースホルダ誤デプロイ (CWE-798) | ✅ 本物(High) | 必須 context 化＋未指定で throw |
| 10 | Amazon Q | StackSet が silent skip | ✅ 本物だが提案は不適 | 警告付き skip（無条件 throw は2段階フローを壊すので不採用） |
| 11 | Copilot reviewer | `AccountPrincipal` が account root で広い信頼 | ✅ 本物(Medium) | `gatewayRoleArn` 任意 context＋`ArnPrincipal`、README 明記 |
| 12 | Copilot CLI | delegated admin (`CallAs`) 非対応なのに README が謳う | ✅ 本物(Medium) | `callAs` を context 切替可能化＋README整合 |
| 13 | Copilot CLI | テスト皆無 | ー | ユーザー判断によりテスト追加なし |
| - | Copilot CLI | `ReadOnlyAccess` 等ハードコード | 軽微 | 既存例と同等・コメント注記済み。対応不要 |

---

## 修正詳細

### A. `examples/cdk-lambda/lib/aws-mcp-gateway-stack.ts`

1. **シークレット参照を String 統一**（指摘 1, 2）
   - `:88-89` の `oidcClientSecret` / `cookieSecret`（`{{resolve:ssm-secure:...}}`）を削除。
   - `OIDC_CLIENT_SECRET` / `COOKIE_SECRET` も `ssm.StringParameter.valueForStringParameter(this, \`/${instanceName}/...\`)` で取得（`:81-85` と同じ方式）。
2. **`FEDERATED_ROLE_ARN` を context 経由・federated 時のみ**（指摘 3）
   - `:90-92` の SSM フォールバック参照を削除。
   - `environment` の `FEDERATED_ROLE_ARN` は `iamMode === 'federated'` のときだけ `federatedRoleArn` を設定（それ以外はキー自体を含めない）。
3. **`iamMode` バリデーション**（指摘 5）
   - props 受領直後に `const VALID = ['shared','federated']; if (!VALID.includes(iamMode)) throw new Error(...)`。
4. **federated の AssumeRoleWithWebIdentity をスコープ**（指摘 6）
   - `:63-69` を `resources: [federatedRoleArn]` に変更。`iamMode==='federated'` かつ `federatedRoleArn` 未指定なら throw（`main.go:606-609` と同じ前提）。
5. **Function URL `NONE` は維持**（指摘 7）— コード変更なし。

### B. `examples/cdk-lambda/bin/app.ts` / `cdk.json`（指摘 4）

- `iamMode` デフォルトを `direct` → **`shared`** に変更（`app.ts:9`, `cdk.json:7`）。

### C. `examples/cdk-lambda/README.md`（指摘 2, 3, 4, 7）

- SSM 作成手順: `EXTERNAL_URL` / `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `COOKIE_SECRET` を全て **`--type String`** に統一（`:70-88`, `:120-124` の overwrite も String）。
- `FEDERATED_ROLE_ARN` の「空文字で作成が必要」手順（`:98-101`）を**削除**。federated 利用時のみ context で渡す旨に書き換え。
- `iamMode` の表記（`:45`, `:57`）を `direct` → `shared` に統一。
- Function URL `NONE` に関する注記を追加: 「OIDC 認証はアプリ層で実施。Function URL は `NONE` 前提（SigV4 認証はブラウザ OIDC フローと非両立）。DoS 対策が必要なら WAF / CloudFront / 予約同時実行数を検討」。
- シークレットを SSM String 保存する点のセキュリティ注記（より高い要件なら Secrets Manager / 本体改修を検討）。

### D. `examples/cdk-assume-role-target/bin/app.ts` / `cdk.json`（指摘 9, 10）

- **プレースホルダ必須化**（指摘 9）: `:9-13` のフォールバックデフォルト（`'111111111111'`, `'my-external-id'`, `['ou-xxxx-yyyy']`）を削除し、`sourceAccountId` / `externalId` / `organizationalUnitIds` が未指定なら明示エラーで throw。`cdk.json` の危険なプレースホルダ値も安全なサンプル/コメントに置換。
- **StackSet 警告付き skip**（指摘 10）: `:27-39` のテンプレート不在時、silent skip ではなく `console.warn('Run "cdk synth AccountTemplateStack" first ...')` を出してから skip（無条件 throw は初回 `cdk synth AccountTemplateStack` を壊すため不採用。2段階フローを維持しつつ診断可能性を確保）。

### E. `examples/cdk-assume-role-target/lib/account-template-stack.ts`（指摘 11）

- 任意 context `gatewayRoleArn` を受け取り、指定時は `iam.ArnPrincipal(gatewayRoleArn).withConditions(...)`、未指定時は従来の `AccountPrincipal` + ExternalId。
- README に「account root principal は source account 内の任意 principal に AssumeRole を許す（ExternalId で緩和）。より厳格にするなら `gatewayRoleArn` を指定」とトレードオフ明記。

### F. `examples/cdk-assume-role-target/lib/stackset-management-stack.ts` / README（指摘 12）

- props/context に `callAs?: 'SELF' | 'DELEGATED_ADMIN'`（デフォルト `'SELF'`）を追加し `CfnStackSet.callAs` に渡す。
- README の「マネジメントアカウント（または委任管理者）」記述（`:40`）を、`callAs` 設定との対応として整合させる。

### G. 両 `package.json`（指摘 8）

- `examples/cdk-lambda/package.json` と `examples/cdk-assume-role-target/package.json` の `devDependencies` に `"ts-node": "^10.9.2"` を追加（`cdk.json` の `npx ts-node ... bin/app.ts` がクリーン環境で動くように）。`package-lock.json` も `npm install` で更新。

---

## 検証

各修正後、両サンプルで `cdk synth` を実行し CloudFormation テンプレート生成を確認する。

```bash
# cdk-lambda
cd examples/cdk-lambda && npm install
npx cdk synth                                   # shared モード
npx cdk synth -c iamMode=federated -c federatedRoleArn=arn:aws:iam::123456789012:role/amg-fed
npx cdk synth -c iamMode=bogus                  # ← throw されること（バリデーション確認）

# 生成テンプレートに ssm-secure が残っていないこと
npx cdk synth | grep -c 'resolve:ssm-secure' || echo "OK: ssm-secure なし"

# cdk-assume-role-target
cd ../cdk-assume-role-target && npm install
npx cdk synth AccountTemplateStack -c sourceAccountId=123456789012 -c externalId=$(uuidgen) -c organizationalUnitIds='["ou-xxxx-yyyy"]'
npx cdk synth StackSetManagementStack -c sourceAccountId=123456789012 -c externalId=$(uuidgen) -c organizationalUnitIds='["ou-xxxx-yyyy"]'
npx cdk synth AccountTemplateStack                # ← 必須 context 未指定で throw されること
```

確認ポイント:
- `cdk-lambda`: 生成テンプレートの Lambda env に `{{resolve:ssm-secure:...}}` が**含まれない**。`OIDC_CLIENT_SECRET` 等が `AWS::SSM::Parameter::Value<String>` パラメータ参照になっている。非 federated 時に `FEDERATED_ROLE_ARN` env が出力されない。federated 時の IAM ポリシー resource が `*` でなく ARN スコープ。
- `cdk-assume-role-target`: 必須 context 未指定で throw。`AccountTemplateStack` synth → `StackSetManagementStack` synth が通る。`gatewayRoleArn` 指定時に trust policy が `ArnPrincipal` になる。

## コミット / PR 反映

- Conventional Commits（日本語）で論理単位ごとに分割コミット（例: `fix: cdk-lambda のシークレット参照を SSM String に統一しデプロイ失敗を解消` 等）。
- `feat-add-cdk-examples` ブランチに push し PR #10 を更新。
- Amazon Q の CWE-306（Function URL NONE）は誤検知である旨を PR コメントで簡潔に説明。
