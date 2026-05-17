**日本語** | [English](README.md)

# aws-mcp-gateway

OIDC 認証付き AWS MCP Server リバースプロキシ。

[idproxy](https://github.com/youyo/idproxy)（OIDC 認証 + OAuth 2.1 AS）と SigV4 署名 `httputil.ReverseProxy` を組み合わせ、AWS MCP Server をセキュアなリモート MCP エンドポイントとして公開します。`mcp-go` やメッセージレベルの解析は不要です。

## アーキテクチャ

```
MCP クライアント（Claude Code、Cursor 等）
    ↓  OAuth 2.1（Bearer Token）
aws-mcp-gateway
  ├── idproxy          — OIDC ブラウザ認証（Entra ID、Google、Cognito 等）
  │                      OAuth 2.1 Authorization Server（Dynamic Client Registration）
  └── ReverseProxy     — SigV4 署名 Streamable HTTP プロキシ
    ↓  HTTPS + SigV4
AWS MCP Server（マネージド、us-east-1 / eu-central-1）
    ↓  call_aws
任意の AWS リソース（任意のリージョン）
```

AWS 認証情報は環境から自動解決されます（Lambda 実行ロール、ECS タスクロール、EC2 インスタンスプロファイル等）。アプリケーションレベルの認証情報設定は不要です。

## 特徴

- **OIDC ブラウザ認証** — Google、Microsoft Entra ID 等の任意の OIDC プロバイダーに対応
- **OAuth 2.1 Authorization Server** — PKCE 必須、Bearer Token 発行、Dynamic Client Registration（RFC 7591）
- **SigV4 署名** — Lambda/ECS/EC2 の IAM ロールから自動解決
- **Streamable HTTP 透過プロキシ** — MCP メッセージをそのまま通過
- **per-user IAM 分離** — OIDC ユーザーごとの一時認証情報（federated モード）
- **CloudTrail 監査トレーサビリティ**
- **JSON 構造化ログ** — `log/slog` 経由

## 環境変数

### 必須

| 変数 | 説明 | 例 |
|------|------|------|
| `EXTERNAL_URL` | ゲートウェイの公開 URL | `https://aws-mcp.example.com` |
| `OIDC_ISSUER` | OIDC Issuer URL | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| `OIDC_CLIENT_ID` | OAuth クライアント ID | `your-client-id` |
| `OIDC_CLIENT_SECRET` | OAuth クライアントシークレット | `your-client-secret` |

### オプション

| 変数 | 説明 | デフォルト |
|------|------|----------|
| `ALLOWED_DOMAINS` | 許可するメールドメイン（カンマ区切り、例: `example.com,corp.example.com`）。未設定の場合は OIDC テナント内の全ユーザーが認証可能 — ログに警告が出るがゲートウェイは起動する。大文字小文字を区別しない。注意: 許可リストはログイン時のみチェックされる。許可リストを変更しても既発行のトークンは有効期限まで有効。 | none |
| `ALLOWED_EMAILS` | 許可するメールアドレス（カンマ区切り）。`ALLOWED_DOMAINS` と OR 条件。大文字小文字を区別しない。 | none |
| `COOKIE_SECRET` | Cookie 暗号化キー（hex エンコード、32 バイト以上） | ランダム生成（再起動でセッション消失） |
| `AWS_MCP_ENDPOINT` | AWS MCP Server エンドポイント URL（`AWS_MCP_REGION` より優先） | `AWS_MCP_REGION` から導出 |
| `AWS_MCP_REGION` | AWS MCP Server エンドポイントのリージョン | `us-east-1` |
| `TARGET_AWS_REGION` | AWS API 操作のデフォルトリージョン | `ap-northeast-1` |
| `ASSUME_ROLE_ARN` | MCP リクエスト署名前に assume する IAM ロール ARN。`shared` モードでは全ユーザーがセッション名 `aws-mcp-gateway` を共有。`federated` モードでは `AssumeRoleWithWebIdentity` の後にチェーンされ、セッション名は `gw-<sub>-chain`（per-user CloudTrail 追跡）。ランタイムロール（または federated ロール）に `sts:AssumeRole` 権限とターゲットロールの trust policy が必要。 | none |
| `IAM_MODE` | `shared`（デフォルト）: 全ユーザーがランタイム IAM ロールを共有。`federated`: OIDC 認証ユーザーごとに `AssumeRoleWithWebIdentity` で一時認証情報を取得。`FEDERATED_ROLE_ARN` と OIDC 認証設定（`OIDC_ISSUER`、`OIDC_CLIENT_ID`、`OIDC_CLIENT_SECRET`）が必要。 | `shared` |
| `FEDERATED_ROLE_ARN` | federated モードで `AssumeRoleWithWebIdentity` する IAM ロール ARN。OIDC ID Token が STS に渡される。ターゲットロールの trust policy で OIDC issuer を信頼する必要がある。セッション名はユーザーの OIDC `sub` から `gw-<sub>` 形式で生成（per-user CloudTrail 追跡用）。 | none（`IAM_MODE=federated` 時は必須） |
| `STORE_BACKEND` | セッションストアバックエンド: `memory` または `dynamodb` | `memory` |
| `DYNAMODB_TABLE` | DynamoDB テーブル名（`STORE_BACKEND=dynamodb` 時は必須） | none |
| `DYNAMODB_REGION` | DynamoDB テーブルのリージョン（`STORE_BACKEND=dynamodb` 時は必須） | `ap-northeast-1` |
| `PORT` | Listen ポート | `8080` |

> **注:** `AWS_MCP_REGION` は接続する MCP Server エンドポイントのリージョン（`us-east-1` または `eu-central-1`）を制御します。新リージョンが追加されたらこの変数を変更するだけで対応できます。`TARGET_AWS_REGION` は AWS 操作のデフォルトリージョンで、MCP Server のリージョンとは異なっていても構いません。

## プロバイダー設定

| プロバイダー | `OIDC_ISSUER` |
|------------|--------------|
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| Google | `https://accounts.google.com` |
| Amazon Cognito | `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}` |

ゲートウェイを OIDC クライアントとして登録し、リダイレクト URI を以下に設定してください:

```
{EXTERNAL_URL}/auth/callback
```

Microsoft Entra ID の詳細設定手順は [Lambda デプロイ例](examples/lambda/README.md#microsoft-entra-id-setup) を参照してください。

## IAM パーミッション

ランタイム（Lambda、ECS、EC2）にアタッチされた IAM ロールが、MCP エージェントが実行できる AWS オペレーションを制御します。ユースケースに合ったパターンを選択してください。

### IAM 条件キー

AWS MCP Server はすべてのダウンストリーム AWS API コールに 2 つの条件キーを付与します:

| キー | 説明 | 値の例 |
|------|------|--------|
| `aws:CalledViaAWSMCP` | 呼び出し元の MCP Server サービスプリンシパル | `aws-mcp.amazonaws.com` |
| `aws:ViaAWSMCPService` | マネージド MCP Server 経由リクエストかどうか（Boolean） | `"true"` |

`aws:CalledViaAWSMCP` を使うと特定の MCP Server にのみ権限を限定できます。`aws:ViaAWSMCPService` を使うとすべてのマネージド MCP Server をまとめて許可/拒否できます。

> **参考:** [Understanding IAM for managed AWS MCP servers](https://aws.amazon.com/blogs/security/understanding-iam-for-managed-aws-mcp-servers/)

---

### パターン 1: 読み取り専用

AWS マネージドポリシー `ReadOnlyAccess` をアタッチします。全 AWS サービスをカバーし、新サービス追加時も自動的に更新されます。

> **注意:** AWS マネージドポリシーには IAM 条件を付与できないため、`aws:CalledViaAWSMCP` が適用できません。このロールを持つ任意のプロセスが MCP 経由でなくても直接 AWS リソースを読み取れます。`ReadOnlyAccess` はログ、パラメータ、シークレットメタデータ、IAM 設定等への広範な読み取りアクセスを含みます。環境上許容できるかを評価してください。本番環境で厳格な制御が必要な場合は、代わりに最小権限のカスタムマネージドポリシーを使用してください。

```bash
# ロールの作成（例: ECS タスク用）
aws iam create-role \
  --role-name aws-mcp-gateway-readonly \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name aws-mcp-gateway-readonly \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

---

### パターン 2: フルアクセス

MCP 経由で全 AWS サービスにフルアクセス。サンドボックスや個人用アカウントでのみ使用してください。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FullAccessViaMCP",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:CalledViaAWSMCP": "aws-mcp.amazonaws.com"
        }
      }
    }
  ]
}
```

```bash
aws iam create-role \
  --role-name aws-mcp-gateway-full \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name aws-mcp-gateway-full \
  --policy-name mcp-full \
  --policy-document file://policy-full.json
```

---

### パターン 3: 削除禁止

> ⚠️ **重要:** 拒否リストによるアプローチはすべての破壊的な操作を確実には防げません。`iam:PassRole`、`iam:PutRolePolicy`、`lambda:UpdateFunctionCode`、`s3:PutBucketPolicy` 等は明示的な削除権限がなくても重大な影響を引き起こす可能性があります。本番環境で強力な防御が必要な場合は、代わりに AWS Organizations レベルの **SCP（Service Control Policy）** を使用してください。
>
> このパターンは非クリティカルな環境での補完的な制御としてのみ使用してください。

一般的な削除アクションを明示的に拒否した MCP フルアクセスポリシー。Deny には MCP 条件がないため、呼び出し元に関わらず削除をブロックします。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAllViaMCP",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:CalledViaAWSMCP": "aws-mcp.amazonaws.com"
        }
      }
    },
    {
      "Sid": "DenyCommonDeleteActions",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteObjects",
        "ec2:TerminateInstances", "ec2:DeleteVpc", "ec2:DeleteSubnet",
        "ec2:DeleteSecurityGroup", "ec2:DeleteInternetGateway",
        "rds:DeleteDBInstance", "rds:DeleteDBCluster", "rds:DeleteDBSnapshot",
        "dynamodb:DeleteTable",
        "lambda:DeleteFunction",
        "ecs:DeleteCluster", "ecs:DeleteService",
        "eks:DeleteCluster", "eks:DeleteNodegroup",
        "iam:DeleteRole", "iam:DeletePolicy", "iam:DeleteUser",
        "cloudformation:DeleteStack",
        "secretsmanager:DeleteSecret",
        "logs:DeleteLogGroup",
        "ecr:DeleteRepository",
        "sqs:DeleteQueue",
        "sns:DeleteTopic",
        "route53:DeleteHostedZone",
        "events:DeleteRule",
        "elasticloadbalancing:DeleteLoadBalancer",
        "cloudfront:DeleteDistribution"
      ],
      "Resource": "*"
    }
  ]
}
```

```bash
aws iam create-role \
  --role-name aws-mcp-gateway-nodelete \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name aws-mcp-gateway-nodelete \
  --policy-name mcp-nodelete \
  --policy-document file://policy-nodelete.json
```

---

### パターン 4: 運用調査用

`ReadOnlyAccess` にインシデント調査に必要な実行権限を追加したインラインポリシーを組み合わせます。

> ⚠️ **重要: `ReadOnlyAccess` は MCP パスに限定されません。** AWS マネージドポリシーには IAM 条件を付与できないため、`ReadOnlyAccess` の読み取り権限は MCP 経由かどうかに関わらず適用されます。**インラインの実行権限のみ** `aws:CalledViaAWSMCP` でゲートされます。
>
> 実質的にこのロールは: **常時広範な読み取り**（`ReadOnlyAccess` 経由） + **MCP 限定の実行**（インラインポリシー経由）となります。
>
> ⚠️ **インラインポリシーはリモート実行権限を付与します:**
> - `ssm:SendCommand` / `ecs:ExecuteCommand` — リモートシェルアクセスと同等。シークレット、認証情報、ファイルシステムデータが漏洩する可能性があります。
> - `lambda:InvokeFunction` — 副作用を伴うビジネスロジックを実行します。
>
> **例の `Resource: "*"` は簡略化されています。** 本番環境では特定の ARN、タグ、または SSM ドキュメントにスコープを絞ってください。
>
> **必須の監査ログ設定**（CloudTrail だけでは不十分）:
> - SSM Session Manager: S3/CloudWatch Logs へのセッションログを有効化
> - ECS Exec: タスク定義で `execute-command` ログを有効化
> - Lambda: 関数レベルの CloudWatch Logs を有効化

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OperationalAccessViaMCP",
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ecs:ExecuteCommand",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:GetQueryResults",
        "xray:GetTraceSummaries",
        "xray:BatchGetTraces",
        "xray:GetInsightSummaries",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:CalledViaAWSMCP": "aws-mcp.amazonaws.com"
        }
      }
    }
  ]
}
```

```bash
aws iam create-role \
  --role-name aws-mcp-gateway-debug \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# ReadOnlyAccess は全読み取り操作をカバー（MCP 条件なし — マネージドポリシーには条件付与不可）
aws iam attach-role-policy \
  --role-name aws-mcp-gateway-debug \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# インラインポリシーで実行権限を追加（MCP 条件付き）
aws iam put-role-policy \
  --role-name aws-mcp-gateway-debug \
  --policy-name mcp-debug-exec \
  --policy-document file://policy-debug-exec.json
```

---

### MCP アクセス全拒否（SCP / 緊急ロックアウト）

アカウント内で MCP 経由のすべてのアクションを完全にブロックする Service Control Policy（SCP）として使用します。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllViaMCP",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:ViaAWSMCPService": "true"
        }
      }
    }
  ]
}
```

## セキュリティ考慮事項

### Shared IAM ロール

OIDC で認証した全ユーザーが、ゲートウェイランタイムにアタッチされた同一 IAM ロールを共有します。ゲートウェイは per-user の IAM 認可を行いません — OIDC 認証は *誰がゲートウェイにアクセスできるか* を制御し、IAM は *ゲートウェイが何を実行できるか* を制御します。

つまり:
- 認証された全ユーザーがゲートウェイ IAM ロールの全権限を継承します
- per-user の権限境界が必要な場合は、別々のロールを持つ別々のゲートウェイインスタンスをデプロイするか、OIDC の許可リスト（`ALLOWED_EMAILS`、`ALLOWED_DOMAINS`）で認証可能なユーザーを制限してください

### Federated IAM モード（`IAM_MODE=federated`）

federated モードでは、認証済みユーザーごとに **個別の一時的 AWS 認証情報** が `AssumeRoleWithWebIdentity` で発行されます。ユーザーの OIDC ID Token が STS に渡され、`FEDERATED_ROLE_ARN` に対してセッション固有の認証情報が発行されます。

**メリット:**
- per-user の CloudTrail 追跡: 各ユーザーの API コールが独自セッション（`gw-<oidc_sub>`）で記録される
- ユーザー間での認証情報共有なし
- OIDC ID Token の有効期限（約 1 時間）に連動した自動失効

**セットアップ要件:**
1. IAM Identity Provider に OIDC プロバイダー（Entra ID 等）を登録
2. `FEDERATED_ROLE_ARN` に `sts:AssumeRoleWithWebIdentity` を許可する trust policy を設定
3. `IAM_MODE=federated` と `FEDERATED_ROLE_ARN` を設定

詳細手順: [Lambda デプロイ例 - Federated IAM Mode Setup](examples/lambda/README.md#federated-iam-mode-setup)

### Federated + クロスアカウントアクセス（`IAM_MODE=federated` + `ASSUME_ROLE_ARN`）

federated モードと `ASSUME_ROLE_ARN` を組み合わせるとロールチェーンが構成されます:

```
OIDC ユーザー → FEDERATED_ROLE_ARN（アカウント A、per-user 追跡）→ ASSUME_ROLE_ARN（アカウント B）
```

per-user の CloudTrail 追跡を維持しながら、別の AWS アカウントのリソースにアクセスできます。

**認証情報チェーン:**
| ステップ | 操作 | 結果 |
|---------|------|------|
| 1 | OIDC ID Token → `AssumeRoleWithWebIdentity` | Federated 認証情報（セッション: `gw-<sub>`） |
| 2 | Federated 認証情報 → `AssumeRole` | ターゲットロール認証情報（セッション: `gw-<sub>-chain`） |

> ⚠️ **AWS ロールチェーン制限**: 各ロールの `MaxSessionDuration` に関わらず、最大セッション時間は **1 時間** に制限されます。

### IAM モード比較

| モード | 認証情報 | CloudTrail 帰属 | クロスアカウント |
|--------|---------|-----------------|---------------|
| `shared`（デフォルト）| Lambda 実行ロール共有 | ゲートウェイロールのみ | `ASSUME_ROLE_ARN` で可（全ユーザー共有） |
| `federated` | OIDC トークンで per-user | Per-user（`gw-<sub>`） | 不可 |
| `federated` + `ASSUME_ROLE_ARN` | Per-user チェーン | Per-user（`gw-<sub>`） | 可 |

### 監査トレーサビリティ

CloudTrail はダウンストリームの AWS API コールを **ゲートウェイの IAM ロール** のもとに記録します。CloudTrail だけでは特定の AWS API コールがどのユーザーによるものかを区別できません。

標準的な戦略は、**ゲートウェイアクセスログ**（誰がゲートウェイを呼び出したか、OIDC アイデンティティ付き）と **CloudTrail / 実行ログ**（どの AWS アクションが発生したか）をタイムスタンプで相関させることです。

**`IAM_MODE=federated` の場合**、CloudTrail は各ユーザーのコールを直接その assumed-role セッションのもとに記録します:

```
arn:aws:sts::<ACCOUNT_ID>:assumed-role/<FEDERATED_ROLE>/gw-<oidc_sub>
```

タイムスタンプの相関が不要になります — セッション名（`gw-<oidc_sub>`）で CloudTrail をフィルタリングするだけで、どのユーザーがどの AWS アクションを実行したかを正確に追跡できます。

---

#### 1. CloudTrail の有効化（未設定の場合）

```bash
# CloudTrail ログ用 S3 バケットの作成
aws s3 mb s3://my-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --region ap-northeast-1

# 全リージョンで CloudTrail を有効化
aws cloudtrail create-trail \
  --name aws-mcp-gateway-trail \
  --s3-bucket-name my-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --is-multi-region-trail \
  --include-global-service-events

aws cloudtrail start-logging --name aws-mcp-gateway-trail
```

---

#### 2. ゲートウェイアクセスログ（リクエストごとの OIDC アイデンティティ）

`aws-mcp-gateway` はすべてのリクエストで認証済みユーザーのメールアドレスと OIDC `sub` を JSON 形式（`log/slog` 経由）でログに記録します。追加設定は不要です — stdout をログアグリゲータ（CloudWatch Logs エージェント、Fluent Bit 等）にルーティングするだけです。

ログ行の例:
```json
{"time":"2026-01-01T10:00:00Z","level":"INFO","msg":"request","method":"POST","path":"/mcp","user_email":"user@example.com","user_sub":"abc123","remote_addr":"10.0.0.1:12345"}
```

CloudWatch Logs からゲートウェイログを照会する（stdout を CloudWatch Logs に転送している場合）:

```bash
# 特定ユーザーの直近 1 時間のリクエストを検索
START=$(date -u -d '1 hour ago' +%s 2>/dev/null || date -u -v-1H +%s)  # Linux / macOS
END=$(date -u +%s)

QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ecs/aws-mcp-gateway \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, user_email, method, path | filter user_email = "user@example.com" | sort @timestamp desc' \
  --query 'queryId' --output text)

# 完了まで待機
while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

---

#### 3. SSM Run Command — 出力ログの有効化（パターン 4）

> **注意:** `ssm:SendCommand`（Run Command）と `ssm:StartSession`（Session Manager）は別機能で、ログの出力先も異なります。

`ssm:SendCommand` の場合、実行ごとに CloudWatch Logs に出力します:

```bash
aws logs create-log-group --log-group-name /aws/ssm/run-command

# コマンド実行時にログ設定を渡す
aws ssm send-command \
  --instance-ids i-xxxxxxxxxxxxxxxxx \
  --document-name "AWS-RunShellScript" \
  --parameters '{"commands":["your-command"]}' \
  --cloud-watch-output-config '{"CloudWatchOutputEnabled":true,"CloudWatchLogGroupName":"/aws/ssm/run-command"}'
```

---

#### 4. ECS Exec — ログの有効化（パターン 4）

ECS Exec の監査ログはタスク定義ではなく **クラスター** レベルで `executeCommandConfiguration` の設定が必要です:

```bash
aws logs create-log-group --log-group-name /aws/ecs/exec-logs

# クラスターレベルで ECS Exec ログを設定
aws ecs update-cluster \
  --cluster my-cluster \
  --configuration "executeCommandConfiguration={logging=OVERRIDE,logConfiguration={cloudWatchLogGroupName=/aws/ecs/exec-logs,cloudWatchEncryptionEnabled=false}}"

# サービスで execute-command を有効化
aws ecs update-service \
  --cluster my-cluster \
  --service my-service \
  --enable-execute-command
```

---

#### 5. ログ照会 — サンプルコマンド

**ゲートウェイアクセスログからユーザーのアクティビティを検索:**

```bash
START=$(date -u -d '1 hour ago' +%s 2>/dev/null || date -u -v-1H +%s)
END=$(date -u +%s)

QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ecs/aws-mcp-gateway \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, user_email, user_sub, method | sort @timestamp desc | limit 100' \
  --query 'queryId' --output text)

while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

**CloudTrail からゲートウェイロールの AWS API コールを検索:**

> **注意:** ECS/Lambda の assumed-role コールは IAM ロール名ではなく `i-xxxxxxxx` やタスク ID のようなセッション名で記録されます。信頼性の高いフィルタリングには `userIdentity.sessionContext.sessionIssuer.arn` のロール ARN でフィルタしてください。

```bash
# 信頼性の高い方法: CloudTrail の raw JSON からロール ARN でフィルタ
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=ec2.amazonaws.com \
  --start-time 2026-01-01T10:00:00Z \
  --end-time 2026-01-01T10:05:00Z \
  --output json | jq '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.sessionContext.sessionIssuer.arn | contains("aws-mcp-gateway")) |
    {time: .eventTime, action: .eventName, resource: .resources}'
```

**SSM Run Command の出力ログを照会:**

```bash
START=$(date -u -d '1 hour ago' +%s 2>/dev/null || date -u -v-1H +%s)
END=$(date -u +%s)

QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ssm/run-command \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, @logStream, @message | sort @timestamp desc | limit 50' \
  --query 'queryId' --output text)

while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

**ECS Exec ログを照会:**

```bash
QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ecs/exec-logs \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, @logStream, @message | sort @timestamp desc | limit 50' \
  --query 'queryId' --output text)

while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

**ゲートウェイのユーザー ID と CloudTrail を相関:**

```bash
# Step 1: ゲートウェイログから対象ユーザーの時間帯を特定（user_email → タイムスタンプ）
# Step 2: その時間帯の CloudTrail をゲートウェイロール ARN でフィルタ
aws cloudtrail lookup-events \
  --start-time 2026-01-01T10:00:00Z \
  --end-time 2026-01-01T10:05:00Z \
  --output json | jq '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.sessionContext.sessionIssuer.arn | contains("aws-mcp-gateway")) |
    {time: .eventTime, action: .eventName, ip: .sourceIPAddress}'
```

## クイックスタート

```bash
export EXTERNAL_URL=http://localhost:8080
export OIDC_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
export OIDC_CLIENT_ID=your-client-id
export OIDC_CLIENT_SECRET=your-client-secret
export COOKIE_SECRET=$(openssl rand -hex 32)

aws-mcp-gateway
```

### MCP クライアント設定（Claude Code）

```json
{
  "mcpServers": {
    "aws-mcp": {
      "type": "http",
      "url": "https://aws-mcp.example.com/mcp"
    }
  }
}
```

## アカウント分離

AWS アカウントごとに 1 インスタンスをデプロイし、それぞれ専用の IAM ロールを割り当てます:

```
aws-mcp-gateway-prod    → 本番アカウント用 IAM ロール
aws-mcp-gateway-staging → ステージングアカウント用 IAM ロール
aws-mcp-gateway-sandbox → サンドボックスアカウント用 IAM ロール
```

## ライセンス

MIT
