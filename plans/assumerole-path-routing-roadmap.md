# AssumeRole Path Routing Roadmap

- バージョン: 0.3 (spec v0.3 反映・形式統一)
- 作成日: 2026-05-28
- 対象 spec: [docs/specs/assumerole-path-routing-spec.md](../docs/specs/assumerole-path-routing-spec.md)
- 対象 Issue: [#8](https://github.com/youyo/aws-mcp-gateway/issues/8)

---

## 概要

spec v0.3 の Success Criteria (SC-1〜SC-15) を TDD（Red → Green → Refactor）で実装するマイルストーン計画。
既存コード（`sanitizeSessionName`、`classifyFederatedError`、`buildProxy`、`injectMetaAWSRegion` 等）を最大限再利用し、変更範囲を最小化する。

### 並列実行マップ

```
M01 バリデータ ──┐
M02 Allowlist設定 ┼── M04 SessionCache+STS ── M05 ハンドラ本体 ── M06 ルータ統合 ── M07 監査ログ
M03 Allowlist認可 ┘                                                               └── M08 非回帰・ドキュメント
```

- M01〜M03: 相互に独立（並列可）
- M04: M01〜M03 完了後
- M05: M04 完了後
- M06: M05 完了後
- M07, M08: M06 完了後（相互に並列可）

---

## マイルストーン一覧

### M01: バリデータ実装

- 概要: `account_id` / `role_name` のバリデーション関数を TDD で実装する。ARN インジェクション防止の最初の防衛線。
- 実装内容:
  - `validateAccountID(s string) bool` — 正規表現 `^[0-9]{12}$`
  - `validateRoleName(s string) bool` — 正規表現 `^[A-Za-z0-9+=,.@_-]+$`
  - 両正規表現をパッケージ変数 `regexp.MustCompile` でコンパイル済みとして宣言
- テスト先行（Red）:
  - `validateAccountID` 正常系: `"123456789012"` → true
  - `validateAccountID` 異常系: `"12345"`, `"abc"`, `""`, `"1234567890123"` → false
  - `validateRoleName` 正常系: `"AwsMcpGatewayRole"`, `"role+=,.@_-"` → true
  - `validateRoleName` 異常系: `"../evil"`, `"role;drop"`, `""`, `"\x00"`, `"ロール名"` → false
  - Unicode・制御文字の境界値（Go の regexp は ASCII のみマッチするため全角・制御文字は拒否される）
- 完了条件:
  - 上記テストが全件 green
  - `go vet ./...` が警告なし
- blockedBy: なし

---

### M02: Allowlist 設定読み込み

- 概要: `ASSUMEROLE_ALLOWED_ACCOUNTS` / `ASSUMEROLE_ALLOWED_ROLE_NAMES` / `ASSUMEROLE_MAX_CACHE_TTL` を環境変数から読み込み、設定構造体を構築する。
- 実装内容:
  - `assumeRoleConfig` 構造体を定義

    ```go
    type assumeRoleConfig struct {
        allowedAccounts  []string
        allowedRoleNames []string
        maxCacheTTL      time.Duration // ASSUMEROLE_MAX_CACHE_TTL, デフォルト 55分
    }
    ```

  - `loadAssumeRoleConfig()` を実装（既存 `splitCSV` を再利用）
  - `ASSUMEROLE_MAX_CACHE_TTL` のパース（`time.ParseDuration`、デフォルト `55m`、最小値 `5m`）
  - allowlist 未設定時に起動ログ Warn を出力（エラーにはしない。未設定でも M03/M05 側で deny by default として 403 を返す設計）
- テスト先行（Red）:
  - 環境変数未設定 → `allowedAccounts == nil`, `maxCacheTTL == 55 * time.Minute`
  - `ASSUMEROLE_ALLOWED_ACCOUNTS="123456789012,210987654321"` → 2要素スライス
  - `ASSUMEROLE_MAX_CACHE_TTL="15m"` → `15 * time.Minute`
  - `ASSUMEROLE_MAX_CACHE_TTL="3m"` → エラー or 最小値 `5m` にクランプ
  - 不正な Duration 文字列 → エラーログ + デフォルト値にフォールバック
- 完了条件:
  - 上記テストが全件 green
  - allowlist 未設定時の Warn ログが確認できる
- blockedBy: なし

---

### M03: Allowlist 認可チェック

- 概要: `account_id` と `role_name` が allowlist に含まれるかチェックする関数を実装する。
- 実装内容:
  - `isAllowedAccount(cfg assumeRoleConfig, accountID string) bool`
  - `isAllowedRoleName(cfg assumeRoleConfig, roleName string) bool`
  - 認可セマンティクス: `allowed_accounts × allowed_role_names` の直積（アカウントごとのロール細分化は非ゴール）
- テスト先行（Red）:
  - 両方が allowlist に含まれる → true
  - account_id が allowlist 外 → false
  - role_name が allowlist 外 → false
  - allowlist が空（未設定）→ false（deny by default）
- 完了条件:
  - 上記テストが全件 green
- blockedBy: なし

---

### M04: SessionCache + STS クレデンシャル取得

- 概要: `(account_id, role_name, subject)` をキーに `*aws.CredentialsCache` をキャッシュし、STS `AssumeRole` を実行する関数を実装する。
- 実装内容:
  - `assumeRoleCredsCache sync.Map` をパッケージ変数として宣言（`federatedCredsCache` とは別）
  - `buildAssumeRoleARN(accountID, roleName string) string` — `arn:aws:iam::{accountID}:role/{roleName}` を構築
  - `getAssumeRoleCredentials(ctx, stsClient, accountID, roleName, sub string, maxTTL time.Duration) (*aws.CredentialsCache, error)` を実装
    - キー: `"{account_id}::{role_name}::{subject}"`
    - `stscreds.NewAssumeRoleProvider` を使用
    - `RoleArn = buildAssumeRoleARN(accountID, roleName)`
    - `RoleSessionName = sanitizeSessionName("gw-ar-" + sub)`（既存関数再利用）
    - `ExpiryWindow = 5 * time.Minute`
    - `maxTTL` 経過後は強制再取得（`ASSUMEROLE_MAX_CACHE_TTL` 対応）
    - `sync.Map.LoadOrStore` で thundering herd を緩和
  - `classifyFederatedError` を再利用した STS エラー分類（重複実装なし）
  - AccessDenied 時にキャッシュを削除（poisoned entry 防止）
- テスト先行（Red）:
  - 初回呼び出しで STS AssumeRole が1回呼ばれる（モック `CredentialsProviderFunc` でカウント）
  - 2回目呼び出しで STS AssumeRole が呼ばれない（キャッシュヒット）
  - `AccessDenied` → エラー返却 + キャッシュから削除
  - `Throttling` → エラー返却 + キャッシュは保持
  - セッション名が `gw-ar-{sub}` 形式で 64 文字以内に収まる
- テストモック戦略:

  ```go
  type credentialsProviderFunc func(ctx context.Context) (aws.Credentials, error)
  func (f credentialsProviderFunc) Retrieve(ctx context.Context) (aws.Credentials, error) {
      return f(ctx)
  }
  ```

- 完了条件:
  - 上記テストが全件 green
  - `ExpiryWindow = 5 * time.Minute` がコードで確認できる
- blockedBy: M01, M02, M03

---

### M05: assumeRolePathHandler 本体

- 概要: パス解析・バリデーション・認可・STS・プロキシを繋ぎ合わせたハンドラを実装する。
- 実装内容:
  - `handleAssumeRoleRequest(w http.ResponseWriter, r *http.Request, user *idproxy.User, cfg assumeRoleConfig, ...)` を実装

    ```
    1. r.PathValue("account_id"), r.PathValue("role_name") でパラメータ抽出
    2. validateAccountID / validateRoleName → 失敗時 400
    3. isAllowedAccount / isAllowedRoleName → 失敗時 403
    4. user == nil || user.Subject == "" → 500（fail-closed）
    5. getAssumeRoleCredentials でクレデンシャル取得
    6. STS エラー分類 → 403(AccessDenied) / 503(transient)
    7. slog.Info("assumerole request", ...) で監査ログ出力（最低限）
    8. injectMetaAWSRegion でリクエストボディ加工（既存関数再利用）
    9. buildProxy(target, transport).ServeHTTP(w, r)（既存関数再利用）
    ```

  - GET（SSE）と POST（JSON-RPC）の両メソッドを透過的に処理（メソッドで分岐しない）
  - エラーレスポンスには内部詳細（ARN、STS エラー文字列）を含めない
- テスト先行（Red）:
  - 正常リクエスト（POST）→ 200、モックサーバーに SigV4 ヘッダーが付く
  - 正常リクエスト（GET）→ 200、モックサーバーに SigV4 ヘッダーが付く（SSE 模擬: `text/event-stream` レスポンス確認）
  - account_id 不正 → 400、ボディが `"invalid account_id\n"` のみ
  - role_name 不正 → 400、ボディが `"invalid role_name\n"` のみ
  - allowlist 外 account_id → 403、ボディが `"forbidden\n"` のみ
  - allowlist 外 role_name → 403、ボディが `"forbidden\n"` のみ
  - `user == nil` → 500
  - STS AccessDenied → 403、ボディが `"forbidden\n"` のみ（ARN 非露出）
  - STS Throttling → 503
  - エラーレスポンスに `"arn:"` や `"AccessDenied"` が含まれない
- 完了条件:
  - 上記テストが全件 green
  - GET リクエスト（SSE 模擬）も正常にプロキシされる
- blockedBy: M01, M02, M03, M04

---

### M06: ルータ統合・既存機能との接続

- 概要: `main()` に assumerole エンドポイントを追加し、既存の `/mcp` への影響がないことを確認する。
- 実装内容:
  - `main()` に以下を追加:

    ```go
    assumeRoleCfg := loadAssumeRoleConfig()
    // GET(SSE) と POST(JSON-RPC) の両方を受け付けるためメソッド指定なし
    http.Handle("/mcp/assumerole/",
        auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := idproxy.UserFromContext(r.Context())
            slog.Info("request", "method", r.Method, "path", r.URL.Path,
                "user_email", func() string { if user != nil { return user.Email }; return "" }(),
                "user_sub", func() string { if user != nil { return user.Subject }; return "" }(),
                "remote_addr", r.RemoteAddr)
            handleAssumeRoleRequest(w, r, user, assumeRoleCfg, /* ... */)
        })))
    ```

  - 既存の `http.Handle("/", auth.Wrap(loggingProxy))` は変更しない
  - `/mcp/assumerole/` は `/mcp` より具体的なため Go の `net/http` で自動的に優先される
- テスト先行（Red）:
  - **既存 E2E テスト全件 green** を `go test ./...` で確認
  - Cookie が assumerole エンドポイントでもアップストリームに転送されない
  - **新規 E2E テスト**: `/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole` への POST がモックサーバーに届く
  - **新規 E2E テスト**: `/mcp` へのリクエストが assumerole ハンドラで処理されない（既存動作を維持）
- 完了条件:
  - `go test ./...` が全件 green
  - 既存の `shared`/`federated` モードの動作が変わらない
- blockedBy: M05

---

### M07: 監査ログ強化

- 概要: assumerole リクエストの監査ログを spec v0.3 記載のフォーマットで出力する。
- 実装内容:
  - `handleAssumeRoleRequest` 内の `slog.Info` を spec 記載フィールドに拡充:

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

  - エラー時（403・503）にも account_id・role_name を含む Warn/Error ログを出力
  - PII（user_email）は既存の `loggingProxy` と同じ方針で出力（マスキングなし）
- テスト先行（Red）:
  - 正常リクエスト時に `account_id`・`role_name`・`role_arn`・`session_name`・`user_sub`・`user_email` が全フィールド出力される
  - 403 エラー時にも `account_id`・`role_name` が Warn レベルで出力される
- 完了条件:
  - 上記テストが全件 green
- blockedBy: M06

---

### M08: 非回帰確認・ドキュメント更新

- 概要: 全テスト green を確認し、README に assumerole モードの使い方を追記する。
- 実装内容:
  - `go test ./...` で全件 green 確認
  - `go vet ./...` で警告なし確認
  - README.md に assumerole path routing セクションを追加:
    - 環境変数一覧（`ASSUMEROLE_ALLOWED_ACCOUNTS`, `ASSUMEROLE_ALLOWED_ROLE_NAMES`, `ASSUMEROLE_MAX_CACHE_TTL`）
    - MCP クライアント設定例（GET/POST 両対応のエンドポイント）
    - IAM 要件（実行ロールへの `sts:AssumeRole` 付与）
    - Trust policy 設定例
    - IdP revocation と最大 55分の revocation ウィンドウの注記
  - README.ja.md にも同等の日本語セクションを追加
- 完了条件:
  - `go test ./...` が全件 green
  - `go vet ./...` が警告なし
  - README に assumerole エンドポイントの使い方が記載されている
- blockedBy: M06

---

## Success Criteria 対応表

| SC | 内容 | 対応マイルストーン |
|----|------|-----------------|
| SC-1 | 正常 AssumeRole フロー | M05 |
| SC-2 | account_id 不正 → 400 | M01, M05 |
| SC-3 | role_name 不正 → 400 | M01, M05 |
| SC-4 | allowlist 外 account → 403 | M03, M05 |
| SC-5 | allowlist 外 role → 403 | M03, M05 |
| SC-6 | allowlist 未設定 → 403 | M02, M03, M05 |
| SC-7 | セッション名 `gw-ar-{sub}` 形式・64文字以内 | M04, M05 |
| SC-8 | 2回目で STS 非呼び出し（キャッシュ） | M04 |
| SC-9 | AccessDenied → 403 + キャッシュ削除 | M04 |
| SC-10 | Throttling → 503 | M04 |
| SC-11 | SigV4 ヘッダー付きプロキシ | M05, M06 |
| SC-12 | 既存 `/mcp` への影響なし | M06, M08 |
| SC-13 | `_meta.AWS_REGION` 注入（既存関数再利用） | M05 |
| SC-14 | Cookie 非転送（`buildProxy` 再利用） | M06 |
| SC-15 | エラー時に内部詳細非露出 | M05 |

---

## リスクと対策

| リスク | 影響 | 対策 |
|--------|------|------|
| STS モックの複雑さ | M04 テスト工数増大 | `credentialsProviderFunc` パターンで抽象化 |
| セッション名 64文字超過 | CloudTrail に誤ったセッション名が記録される | `sanitizeSessionName` 最大長テストを M04 に含める |
| `classifyFederatedError` の重複 | コード重複・メンテコスト増大 | 既存関数を再利用（重複実装しない） |
| Unicode・制御文字によるバリデーション迂回 | ARN インジェクション | M01 に Unicode・制御文字の境界値テストを追加 |
| GET メソッドが 405 になる | SSE が使えない | `http.Handle("/mcp/assumerole/", ...)` でメソッド指定なしで登録 |
| IdP revocation 後のキャッシュ生存 | 最大 55分の revocation ウィンドウ | `ASSUMEROLE_MAX_CACHE_TTL` 環境変数で短縮可能（M02 実装）|
| 既存テストの非回帰 | 既存モードへの意図しない副作用 | M06・M08 で `go test ./...` を必ず確認 |

---

## 非ゴール（本ロードマップに含めない）

- 複数インスタンス間での分散キャッシュ共有
- allowlist のホットリロード（プロセス再起動が必要）
- アカウントごとのロール細分化（`allowed_accounts × allowed_role_names` の直積のみ）
- MCP メッセージレベルのパース・検査
- ツールレベルの IAM ポリシー生成
- 承認ワークフロー（AssumeRole 前の人的承認）
