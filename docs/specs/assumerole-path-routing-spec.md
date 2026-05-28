# AssumeRole Path Routing 機能仕様書

- バージョン: 0.3 (devils-advocate レビュー反映)
- 作成日: 2026-05-28
- 対象 Issue: [#8 feat: マルチAWSアカウント対応の AssumeRole Path Routing を追加](https://github.com/youyo/aws-mcp-gateway/issues/8)

---

## 1. 背景・目的

### 現状の課題

aws-mcp-gateway は現在 2 つの IAM モード（`shared` / `federated`）を持つが、どちらも単一 AWS アカウントに固定されている。

| モード | 認証 | クロスアカウント |
|--------|------|-----------------|
| `shared` | Gateway の実行ロール共有 | `ASSUME_ROLE_ARN` で1アカウントのみ |
| `federated` | OIDC ID Token → `AssumeRoleWithWebIdentity` | `ASSUME_ROLE_ARN` チェーンで1アカウントのみ |

複数 AWS アカウント・複数 IAM ロールに対して同一 Gateway インスタンスからアクセスしたい場合、現在は Gateway を複数デプロイするしか手段がない。

### 目的

**パスベースのルーティング**を追加し、単一 Gateway インスタンスから複数 AWS アカウント・ロールへのアクセスを可能にする。

```
GET  /mcp/assumerole/accounts/{account_id}/rolename/{role_name}  (SSE / Streamable HTTP)
POST /mcp/assumerole/accounts/{account_id}/rolename/{role_name}  (JSON-RPC)
```

Gateway はパスから `account_id` と `role_name` を解析し、STS `AssumeRole` を実行して得た一時クレデンシャルで AWS MCP Server に SigV4 プロキシする。

> **HTTP メソッドについて:** MCP Streamable HTTP は GET（SSE ストリーム確立）と POST（JSON-RPC リクエスト）の両方を使用する。Gateway は両メソッドを透過的にプロキシする。メソッドによってルーティングロジックやバリデーションロジックは変わらない。

---

## 2. 要件

### 2.1 機能要件

| # | 要件 | 説明 |
|---|------|------|
| FR-1 | パスルーティング | `GET` および `POST /mcp/assumerole/accounts/{account_id}/rolename/{role_name}` を新規エンドポイントとして追加。GET は SSE（Streamable HTTP）、POST は JSON-RPC に対応 |
| FR-2 | パラメータ解析 | パスから `account_id`（12桁数字）と `role_name` を抽出する |
| FR-3 | バリデーション | `account_id`: `^[0-9]{12}$`、`role_name`: `^[A-Za-z0-9+=,.@_-]+$` に一致しない場合は 400 を返す |
| FR-4 | Allowlist 認可 | `assumerole.allowed_accounts` と `assumerole.allowed_role_names` の両方に含まれる組み合わせのみ許可（deny by default） |
| FR-5 | STS AssumeRole | 解析したパラメータから ARN `arn:aws:iam::{account_id}:role/{role_name}` を構築し STS `AssumeRole` を実行 |
| FR-6 | SigV4 プロキシ | 取得した一時クレデンシャルを用いて AWS MCP Server へ SigV4 署名付きでプロキシ |
| FR-7 | CloudTrail 監査 | STS セッション名に OIDC `sub` を含める（例: `gw-ar-{sub}`、最大 64 文字）。Gateway アクセスログにも account_id・role_name・user_sub を出力する |
| FR-8 | セッションキャッシュ | キー `(account_id, role_name, subject)` でクレデンシャルをキャッシュ。TTL = STS 有効期限 - 5分 |
| FR-9 | エラー伝播 | STS エラーを適切な HTTP ステータス（400/403/503 等）に変換する |
| FR-10 | 既存モード共存 | `shared` / `federated` モードは変更せず、新規パスのみで assumerole ロジックが動作する |

### 2.2 非機能要件

| # | 要件 |
|---|------|
| NFR-1 | セキュリティ: 明示的 allowlist に含まれないアカウント・ロールへのリクエストは 403 を返す |
| NFR-2 | セキュリティ: account_id / role_name のバリデーション不通過は 400 を返す（ARN インジェクション防止） |
| NFR-3 | 監査: CloudTrail でユーザーごとの AssumeRole を識別可能にする |
| NFR-4 | パフォーマンス: セッションキャッシュにより STS 呼び出しを最小化 |
| NFR-5 | 後方互換: 既存のパス `/mcp` はすべて既存ロジックで処理され、assumerole パスに影響を与えない |

---

## 3. 既存機能との関係

### 3.1 モード比較

| 項目 | shared | federated | assumerole path routing (新規) |
|------|--------|-----------|-------------------------------|
| クレデンシャル取得 | 実行ロール（環境変数/インスタンスプロファイル） | OIDC IDToken → `AssumeRoleWithWebIdentity` | `AssumeRole`（パスパラメータで指定） |
| マルチアカウント | 不可（`ASSUME_ROLE_ARN` で単一のみ） | 不可（`ASSUME_ROLE_ARN` チェーンで単一のみ） | **可能**（パスで account_id / role_name を動的指定） |
| CloudTrail | Gateway ロールのみ | `gw-{sub}` セッション名 | `gw-ar-{sub}` セッション名（64文字制限対応のため短縮プレフィックス） |
| OIDC 認証 | 必要（idproxy middleware） | 必要（idproxy middleware + IDToken） | **必要**（idproxy middleware。IDToken は AssumeRole に不要） |
| STS 操作種別 | -(実行ロール使用) | `AssumeRoleWithWebIdentity` | `AssumeRole` |
| 設定 | `IAM_MODE=shared` | `IAM_MODE=federated` + `FEDERATED_ROLE_ARN` | `ASSUMEROLE_ALLOWED_ACCOUNTS` + `ASSUMEROLE_ALLOWED_ROLE_NAMES` |
| Allowlist | なし | なし | **あり（必須）** |

> **「OIDC IDToken 不要」の意味について**:
> assumerole モードでも OIDC 認証（idproxy middleware）は必須。ユーザーの `sub` は認証セッションから取得する。
> ただし federated モードとは異なり、IDToken 自体を STS に渡す `AssumeRoleWithWebIdentity` は使用しない。
> `StoreIDToken=true` の設定は不要であり、IDToken の保存コストが発生しない。

### 3.2 設計判断: 新規モード vs 既存モードの拡張

assumerole path routing は **既存モードとは独立した新規エンドポイント** として実装する。

**理由:**
- `shared`/`federated` は環境変数で静的に IAM ロールを決定するが、assumerole はリクエストパスで動的に決定する
- `IAM_MODE` 設定との干渉を避け、既存の動作を変更しない
- パスによる明示的なルーティングでセキュリティ境界を明確化する

**実装方針:**
- `http.Handle("/mcp/assumerole/", ...)` で専用ハンドラを登録
- 既存の `/mcp` ハンドラは変更しない

---

## 4. アーキテクチャ

### 4.1 リクエストフロー

```
MCP Client
    │  POST /mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole
    │  Authorization: Bearer <oauth2_token>
    ▼
idproxy (OIDC 認証・認可)
    │  user.Subject, user.Email を context に付与
    ▼
assumeRolePathHandler
    ├─ パス解析: account_id, role_name を抽出
    ├─ バリデーション: 正規表現チェック
    ├─ Allowlist チェック: allowed_accounts ∩ allowed_role_names
    ├─ セッションキャッシュ確認: key=(account_id, role_name, sub)
    │       ├─ Hit: キャッシュ済みクレデンシャルを返す
    │       └─ Miss: STS AssumeRole 実行
    │               RoleArn = arn:aws:iam::{account_id}:role/{role_name}
    │               RoleSessionName = gw-assumerole-{sanitize(sub)}
    ├─ injectMetaAWSRegion (既存関数再利用)
    └─ buildProxy (既存関数再利用)
            │  SigV4 署名（取得した一時クレデンシャル使用）
            ▼
        AWS MCP Server
```

### 4.2 コンポーネント設計

#### 新規コンポーネント

| コンポーネント | 責務 |
|--------------|------|
| `assumeRolePathHandler` | パス解析・バリデーション・allowlist チェック・STS AssumeRole・プロキシ |
| `assumeRoleCredsCache` | `sync.Map` による `(account_id, role_name, sub)` → `*aws.CredentialsCache` マッピング |
| `assumeRoleConfig` | `allowed_accounts`、`allowed_role_names` を保持する設定構造体 |
| `validateAccountID(s)` | `^[0-9]{12}$` バリデーション |
| `validateRoleName(s)` | `^[A-Za-z0-9+=,.@_-]+$` バリデーション |
| `buildAssumeRoleARN(accountID, roleName)` | `arn:aws:iam::{account_id}:role/{role_name}` を構築 |

#### 既存コンポーネント（再利用）

| コンポーネント | 再利用方法 |
|--------------|----------|
| `sigV4RoundTripper` | AssumeRole で取得した一時クレデンシャルを `getCreds` として注入 |
| `buildProxy` | 変更なし。transport のみ差し替え |
| `injectMetaAWSRegion` | 変更なし。リクエストボディへの region 注入 |
| `sanitizeSessionName` | セッション名のサニタイズ |
| `evictFederatedEntry` パターン | キャッシュ eviction ロジックのパターンを踏襲 |

### 4.3 セッションキャッシュ設計

```
key: "{account_id}::{role_name}::{subject}"
value: *aws.CredentialsCache (STS AssumeRole で取得した一時クレデンシャル)
```

- `aws.CredentialsCache` は STS クレデンシャルの有効期限を内部管理し、有効期限切れ前に自動更新する
- **TTL**: `aws.CredentialsCache` の `ExpiryWindow` を 5分（300秒）に設定し、有効期限の5分前にキャッシュを無効化・再取得する（Issue 要件: "TTL = expiration - 5min"）
- Thundering herd 緩和: `sync.Map.LoadOrStore` を使用（`federatedCredsCache` と同じパターン）
- Poisoned entry 防止: STS の permanent エラー（`AccessDenied`）時はキャッシュを削除。Throttling 等の transient エラーはキャッシュを保持（再取得を次回に委ねる）
- メモリリーク防止: 同一 `(account_id, role_name)` で異なる `subject` のエントリは保持を許容（ユーザー数は組織内で有限のため上限を設けない）

---

## 5. 設定スキーマ

### 5.1 環境変数（既存）との関係

assumerole モードは既存の環境変数（`IAM_MODE`, `FEDERATED_ROLE_ARN` 等）とは独立して動作する。新規追加環境変数を用いて設定する。

### 5.2 新規環境変数

| 変数 | 型 | 必須 | 説明 | 例 |
|------|----|------|------|-----|
| `ASSUMEROLE_ALLOWED_ACCOUNTS` | カンマ区切り文字列 | assumerole エンドポイント使用時は必須 | 許可する AWS アカウント ID の一覧 | `123456789012,210987654321` |
| `ASSUMEROLE_ALLOWED_ROLE_NAMES` | カンマ区切り文字列 | assumerole エンドポイント使用時は必須 | 許可するロール名の一覧 | `AwsMcpGatewayRole,ReadOnlyMcpRole` |
| `ASSUMEROLE_MAX_CACHE_TTL` | Duration 文字列 | 任意 | STS クレデンシャルキャッシュの最大 TTL。IdP revocation への対応ウィンドウを短縮できる。デフォルト `55m` | `15m`, `900s` |

**ASSUMEROLE_ALLOWED_ACCOUNTS または ASSUMEROLE_ALLOWED_ROLE_NAMES が未設定の場合:**
- `/mcp/assumerole/` エンドポイントへのリクエストはすべて 403 を返す（deny by default）
- Gateway 起動時に警告ログを出力する（エラーにはしない。既存モードには影響しないため）

**Allowlist の組み合わせセマンティクス:**
現設計では「全許可アカウント × 全許可ロール名」の直積がアクセス可能な組み合わせとなる。
アカウントごとに許可ロールを細かく分けたい場合（例: アカウント A にはロール X のみ許可）は、
本バージョンではサポートしない（非ゴール）。将来的な拡張として検討可能。

**allowlist の動的更新:**
allowlist は起動時に環境変数から読み込まれ、プロセス再起動なしにはホットリロードされない。
allowlist を変更したい場合はプロセスを再起動する必要がある（明示的な非機能仕様）。

### 5.3 設定例（環境変数）

```bash
# assumerole モードの許可設定
export ASSUMEROLE_ALLOWED_ACCOUNTS="123456789012,210987654321"
export ASSUMEROLE_ALLOWED_ROLE_NAMES="AwsMcpGatewayRole,ReadOnlyMcpRole"
```

### 5.4 MCP クライアント設定例

```json
{
  "mcpServers": {
    "aws-mcp-prod": {
      "type": "http",
      "url": "https://aws-mcp.example.com/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole"
    },
    "aws-mcp-staging": {
      "type": "http",
      "url": "https://aws-mcp.example.com/mcp/assumerole/accounts/210987654321/rolename/ReadOnlyMcpRole"
    }
  }
}
```

---

## 6. エラー処理方針

| 状況 | HTTP ステータス | レスポンスボディ | ログ |
|------|---------------|----------------|------|
| account_id が 12桁数字でない | 400 Bad Request | `"invalid account_id"` | Warn |
| role_name が正規表現不一致 | 400 Bad Request | `"invalid role_name"` | Warn |
| account_id が allowlist に含まれない | 403 Forbidden | `"forbidden"` | Warn |
| role_name が allowlist に含まれない | 403 Forbidden | `"forbidden"` | Warn |
| ASSUMEROLE_ALLOWED_* 未設定（deny all） | 403 Forbidden | `"forbidden"` | Warn |
| STS AssumeRole → AccessDenied | 403 Forbidden | `"forbidden"` | Warn |
| STS AssumeRole → Throttling 等の transient エラー | 503 Service Unavailable | `"service unavailable"` | Error |
| リクエストボディ読み取り失敗 | 400 Bad Request | `"bad request"` | Error |
| プロキシエラー（upstream 接続失敗等） | 502 Bad Gateway | `"bad gateway"` | Error (buildProxy.ErrorHandler) |

**セキュリティ原則:**
- エラーレスポンスには内部詳細（ARN、エンドポイント URL、STS エラー文字列）を含めない
- allowlist 非該当時は 403 のみ返し、「どの条件で弾かれたか」をクライアントに知らせない

---

## 7. セキュリティ考慮事項

### 7.1 ARN インジェクション防止

`account_id` と `role_name` をパスから取得するため、ARN 構築前に厳格なバリデーションを実施する。

- `account_id`: `^[0-9]{12}$` — 12桁数字のみ
- `role_name`: `^[A-Za-z0-9+=,.@_-]+$` — STS で許可される文字のみ
- バリデーション不通過は即 400 を返し、STS API を呼ばない

### 7.2 Deny by Default

- `ASSUMEROLE_ALLOWED_ACCOUNTS` と `ASSUMEROLE_ALLOWED_ROLE_NAMES` の両方に含まれる組み合わせのみ許可
- いずれかが未設定の場合はすべての assumerole リクエストを 403
- 明示的な allowlist なしにはアクセス不可（implicit deny）

### 7.3 CloudTrail 監査トレーサビリティ

STS `RoleSessionName` にユーザー識別子を含めることで、CloudTrail 上で誰が AssumeRole したかを追跡可能にする。

```
arn:aws:sts::{account_id}:assumed-role/{role_name}/gw-ar-{sub}
```

- `sub` は OIDC `subject`（ユーザー固有の不変識別子）
- プレフィックス `gw-ar-` （6文字）を採用。`gw-assumerole-` (14文字) は sub が長い場合（EntraID 等: 40〜50文字）に STS 上限の 64 文字を容易に超過するため短縮する
- セッション名は `sanitizeSessionName` でサニタイズ後、最大 64 文字に切り詰める
- `email` よりも `sub` を優先する（`email` は変更可能なため）
- Gateway のアクセスログにも `account_id`・`role_name`・`user_sub` を出力し、CloudTrail との相関検索を可能にする

**監査ログ出力項目（slog）:**

```json
{
  "level": "INFO",
  "msg": "assumerole request",
  "account_id": "123456789012",
  "role_name": "AwsMcpGatewayRole",
  "role_arn": "arn:aws:iam::123456789012:role/AwsMcpGatewayRole",
  "session_name": "gw-ar-abc123",
  "user_sub": "abc123",
  "user_email": "user@example.com"
}
```

### 7.4 OIDC 認証必須

assumerole エンドポイントも idproxy の認証 Middleware を通過する。OIDC 認証が完了していないリクエストは idproxy が 401/302 を返し、gateway のハンドラには到達しない。

### 7.5 最小権限の原則

Gateway の実行ロールには `sts:AssumeRole` 権限を付与するが、AssumeRole 先のロールの trust policy で Gateway ロールのみを信頼する設定を推奨する。

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::{gateway_account_id}:role/{gateway_execution_role}"
  },
  "Action": "sts:AssumeRole"
}
```

### 7.6 セッション名長の上限

STS `RoleSessionName` は最大 64 文字。`sanitizeSessionName` で超過分をトリムする（既存実装と同じ）。

### 7.7 IdP revocation とキャッシュ TTL のトレードオフ

**問題:** assumerole のキャッシュキーは `(account_id, role_name, subject)` のみであり、IdP 側でユーザーアカウントを無効化（revoke）しても、Gateway キャッシュ内の STS 一時クレデンシャルは最大 **55分**（STS デフォルト有効期限 60分 - ExpiryWindow 5分）生存し続ける。

この間、IdP で無効化されたユーザーが AWS リソースへのアクセスを継続できる。

**これは既知のトレードオフ:** OIDC 認証レイヤー（idproxy の Bearer Token）は別途有効期限が適用され、通常 1 時間以内に失効する。したがって実質的なリスクウィンドウは「OIDC トークン有効期限」と「STS クレデンシャル有効期限」の短い方に依存する。

**緩和策（運用者向け）:**

| 緩和策 | 効果 | トレードオフ |
|--------|------|------------|
| `ASSUMEROLE_MAX_CACHE_TTL` 環境変数でキャッシュ上限を短縮（デフォルト: 55分） | revocation ウィンドウを任意の値に短縮 | 値が短いほど STS 呼び出し頻度が増加 |
| `ExpiryWindow` をデフォルト 5分のまま維持 | STS 呼び出し最小化 | revocation ウィンドウ最大 55分（デフォルト） |
| IdP 無効化後に Gateway プロセスを再起動 | キャッシュを即時クリア | 運用コスト高、全ユーザーへの影響あり |
| AWS IAM ロールの trust policy を即時削除 | 緊急無効化 | ロール全体が使用不可になる |

**`ASSUMEROLE_MAX_CACHE_TTL` 仕様:**

| 項目 | 値 |
|------|----|
| 環境変数名 | `ASSUMEROLE_MAX_CACHE_TTL` |
| 型 | Duration 文字列（例: `55m`, `15m`, `900s`） |
| デフォルト | `55m`（STS デフォルト有効期限 60分 - ExpiryWindow 5分） |
| 最小値 | `5m`（ExpiryWindow と同値未満は無効）|
| 動作 | `CredentialsCache` の有効期間上限として適用。この値を超えたキャッシュエントリは次回リクエスト時に強制再取得される |

**本仕様の方針:** デフォルト実装では `ASSUMEROLE_MAX_CACHE_TTL=55m`（最大 55分のウィンドウ）を採用する。セキュリティ要件が高い環境では `ASSUMEROLE_MAX_CACHE_TTL=15m` 等に短縮することで revocation ウィンドウを縮小できる。緊急無効化が必要な場合は IAM trust policy 削除を推奨する。

### 7.8 既存モードへの影響

assumerole パスルーティングは `/mcp/assumerole/` プレフィックスでのみ動作する。既存の `/mcp` パスは変更されない。`IAM_MODE=shared` や `IAM_MODE=federated` の動作に影響しない。

---

## 8. Success Criteria

各項目はテスト可能な条件として定義する。

| # | 条件 | 検証方法 |
|---|------|---------|
| SC-1 | `/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole` へのリクエストが正常に処理され、STS AssumeRole が実行される | ユニットテスト: モック STS で AssumeRole 呼び出しを確認 |
| SC-2 | account_id が 12桁数字でない場合（例: `12345`）は 400 を返す | ユニットテスト: `validateAccountID` |
| SC-3 | role_name に不正文字（例: `../evil`）が含まれる場合は 400 を返す | ユニットテスト: `validateRoleName` |
| SC-4 | allowlist に含まれないアカウント ID は 403 を返す | ユニットテスト: `assumeRolePathHandler` |
| SC-5 | allowlist に含まれないロール名は 403 を返す | ユニットテスト: `assumeRolePathHandler` |
| SC-6 | ASSUMEROLE_ALLOWED_ACCOUNTS が未設定の場合は 403 を返す（deny by default） | ユニットテスト |
| SC-7 | STS セッション名が `gw-ar-{sanitized_sub}` 形式になり、64文字以内に収まる | ユニットテスト: capturedSessionName 確認 |
| SC-8 | 2回目のリクエストで STS AssumeRole が呼ばれない（キャッシュが効く） | ユニットテスト: STS 呼び出し回数のカウント |
| SC-9 | STS AccessDenied エラー時は 403 を返し、キャッシュから削除される | ユニットテスト |
| SC-10 | STS throttling エラー時は 503 を返す | ユニットテスト |
| SC-11 | アップストリームへ転送されるリクエストに SigV4 ヘッダーが付く | E2E テスト: モックサーバーで Authorization ヘッダー確認 |
| SC-12 | 既存の `/mcp` パスへのリクエストは既存ロジックで処理され、影響を受けない | 既存 E2E テスト継続パス |
| SC-13 | リクエストボディに `_meta.AWS_REGION` が注入される | E2E テスト: `injectMetaAWSRegion` 動作確認 |
| SC-14 | Cookie ヘッダーはアップストリームに転送されない | 既存テスト `TestCookieHeaderRemovedFromUpstream` |
| SC-15 | エラーレスポンスに内部詳細（ARN、STS エラー文字列）が含まれない | E2E テスト: レスポンスボディの検査 |

---

## 9. 非ゴール

本仕様の対象外とする機能:

- MCP メッセージレベルのパース・検査
- ツールレベルの IAM ポリシー生成
- 承認ワークフロー（AssumeRole 前の人的承認）
- AWS Organizations の自動アカウント列挙・探索
- アカウント・ロールの動的追加（起動時の設定ファイル読み込みのみ）
- per-tool IAM ポリシーの自動生成
- テナント分離（複数 OIDC テナントへの対応）
- ロールのパーミッション境界の自動設定

---

## 付録: 実装上の注意事項

### A. `net/http` のパスマッチング

`go.mod` で確認: `go 1.26.1`。Go 1.22 以降の `net/http` は `{wildcard}` パターンをサポートするため、以下のように実装する。

```go
// GET（SSE）と POST（JSON-RPC）の両メソッドを受け付けるため、メソッドプレフィックスなしで登録する
http.Handle("/mcp/assumerole/",
    auth.Wrap(assumeRolePathHandler))
```

パスパラメータは `r.PathValue("account_id")` / `r.PathValue("role_name")` で取得する。

> **メソッドプレフィックスを付けない理由:** Go 1.22 の `net/http` でメソッドプレフィックス（`POST /...`）を使うと GET が 405 で弾かれる。MCP Streamable HTTP は GET（SSE）と POST（JSON-RPC）の両方を使うため、メソッドを限定しないパターンで登録し、ハンドラ内では両メソッドを透過的に扱う。

### B. STS クレデンシャルキャッシュの TTL

`aws.CredentialsCache` を以下のように `ExpiryWindow = 5分` で初期化する。

```go
aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) {
    o.ExpiryWindow = 5 * time.Minute
})
```

これにより、STS クレデンシャルの有効期限の5分前に次回の `Retrieve` で自動更新される（Issue 要件の「TTL = expiration - 5min」に対応）。

### C. 既存 `federatedCredsCache` との分離

assumerole モード専用のキャッシュ（`assumeRoleCredsCache`）を別の `sync.Map` として宣言する。federated モードのキャッシュとキー空間が衝突しないようにする。

### D. URL エンコーディング

`r.PathValue()` はパーセントデコード済みの値を返すため、`role_name` 内の URL エンコード文字は自動でデコードされる。ただし `role_name` バリデーション（`^[A-Za-z0-9+=,.@_-]+$`）はデコード後の文字列に対して適用し、エンコードされた不正文字が通り抜けないようにする。

### E. STS AssumeRole のリトライ

`aws-sdk-go-v2` の `aws.CredentialsCache` は transient エラー（Throttling 等）に対してデフォルトのリトライポリシーを適用する（指数バックオフ）。追加のリトライ設定は不要。
