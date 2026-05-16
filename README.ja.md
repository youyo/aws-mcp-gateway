# aws-mcp-gateway

[English](README.md) | **日本語**

[AWS MCP Server](https://docs.aws.amazon.com/aws-mcp/latest/userguide/getting-started-aws-mcp-server.html) に OIDC 認証を付与するリバースプロキシ。

[idproxy](https://github.com/youyo/idproxy)（OIDC 認証 + OAuth 2.1 AS）と SigV4 署名付きの `httputil.ReverseProxy` を組み合わせ、AWS MCP Server を保護された Remote MCP エンドポイントとして公開します。`mcp-go` やメッセージレベルの解析は不要です。

## アーキテクチャ

```
MCP クライアント（Claude Code、Cursor 等）
    ↓  OAuth 2.1（Bearer Token）
aws-mcp-gateway
  ├── idproxy          — OIDC ブラウザ認証（EntraID、Google、Cognito 等）
  │                      OAuth 2.1 Authorization Server（Dynamic Client Registration）
  └── ReverseProxy     — SigV4 署名付き Streamable HTTP プロキシ
    ↓  HTTPS + SigV4
AWS MCP Server（マネージド、us-east-1 / eu-central-1）
    ↓  call_aws
任意の AWS リソース（任意のリージョン）
```

AWS 認証情報は環境から自動解決されます（Lambda 実行ロール、ECS タスクロール、EC2 インスタンスプロファイル等）。アプリケーションレベルでの認証情報設定は不要です。

## 機能

- **OIDC 認証** — 任意の OIDC プロバイダー対応（Microsoft Entra ID、Google、Amazon Cognito 等）
- **OAuth 2.1 Authorization Server** — Dynamic Client Registration（RFC 7591）対応
- **SigV4 署名** — IAM ロールからの認証情報を自動解決
- **Streamable HTTP 透過プロキシ** — MCP メッセージをそのまま素通り
- **AWSアカウントごとの分離** — アカウントごとに独立したインスタンスを IAM ロール付きでデプロイ
- **JSON 構造化ログ** — `log/slog` を使用

## 環境変数

### 必須

| 変数 | 説明 | 例 |
|------|------|----|
| `EXTERNAL_URL` | このゲートウェイの公開 URL | `https://aws-mcp.example.com` |
| `OIDC_ISSUER` | OIDC Issuer URL | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| `OIDC_CLIENT_ID` | OAuth クライアント ID | `your-client-id` |

### 任意

| 変数 | 説明 | デフォルト |
|------|------|-----------|
| `OIDC_CLIENT_SECRET` | OAuth クライアントシークレット | **必須** |
| `ALLOWED_DOMAINS` | 許可するメールドメインのカンマ区切りリスト（例: `example.com,corp.example.com`）。`ALLOWED_DOMAINS` と `ALLOWED_EMAILS` が両方未設定の場合、**OIDC テナントの任意ユーザーが認証可能**（警告ログを出力） | なし |
| `ALLOWED_EMAILS` | 許可するメールアドレスのカンマ区切りリスト。`ALLOWED_DOMAINS` と OR 条件で評価 | なし |
| `COOKIE_SECRET` | Cookie 暗号化キー（hex 形式、32バイト以上） | ランダム生成（再起動でセッション消失） |
| `AWS_MCP_ENDPOINT` | AWS MCP Server エンドポイント URL（`AWS_MCP_REGION` より優先） | `AWS_MCP_REGION` から自動生成 |
| `AWS_MCP_REGION` | AWS MCP Server エンドポイントのリージョン | `us-east-1` |
| `TARGET_AWS_REGION` | AWS API 操作のデフォルトリージョン | `ap-northeast-1` |
| `ASSUME_ROLE_ARN` | MCP リクエスト署名前に Assume Role する IAM ロール ARN。ランタイムロールに `sts:AssumeRole` 権限、ターゲットロールに trust policy が必要。CloudTrail では全ユーザーが `aws-mcp-gateway` のセッション名を共有。 | なし（ランタイムロールを使用） |
| `STORE_BACKEND` | セッションストアのバックエンド: `memory` または `dynamodb` | `memory` |
| `DYNAMODB_TABLE` | DynamoDB テーブル名（`STORE_BACKEND=dynamodb` 時必須） | なし |
| `DYNAMODB_REGION` | DynamoDB テーブルのリージョン（`STORE_BACKEND=dynamodb` 時必須） | `ap-northeast-1` |
| `PORT` | リスンポート | `8080` |

> **Note:** `AWS_MCP_REGION` は接続先 MCP サーバーエンドポイントのリージョンです。新リージョンが追加された場合はこの変数を変更するだけで対応できます。`TARGET_AWS_REGION` は AWS の操作対象リージョンで、両者は異なっていて構いません。

## OIDC プロバイダー設定

| プロバイダー | `OIDC_ISSUER` |
|------------|--------------|
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| Google | `https://accounts.google.com` |
| Amazon Cognito | `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}` |

OIDC プロバイダーにこのゲートウェイをクライアントとして登録し、リダイレクト URI を以下に設定してください：

```
{EXTERNAL_URL}/auth/callback
```

## IAM 権限

ランタイム環境（Lambda、ECS、EC2）に付与する IAM ロールが、MCP エージェントが実行できる AWS 操作を制御します。

### IAM 条件キー

AWS MCP Server はすべてのダウンストリーム AWS API コールに以下の条件キーを自動付与します：

| キー | 説明 | 値の例 |
|-----|------|--------|
| `aws:CalledViaAWSMCP` | 呼び出し元 MCP サーバーのサービスプリンシパル | `aws-mcp.amazonaws.com` |
| `aws:ViaAWSMCPService` | 管理 MCP サーバー経由の場合に `"true"` | `"true"` |

`aws:CalledViaAWSMCP` で特定の MCP サーバーに絞り込み、`aws:ViaAWSMCPService` で全管理 MCP サーバーをまとめて制御します。

> **参考:** [Understanding IAM for managed AWS MCP servers](https://aws.amazon.com/blogs/security/understanding-iam-for-managed-aws-mcp-servers/)

---

### パターン 1: 読み取り専用（ReadOnlyAccess）

AWS 管理ポリシー `ReadOnlyAccess` をアタッチします。全 AWS サービスをカバーし、新サービスが追加されても自動的に対応されます。

> **注意:** AWS 管理ポリシーには IAM 条件を付けられないため、`aws:CalledViaAWSMCP` は適用できません。このロールで動作するプロセスは MCP 経由以外でも AWS リソースを直接読み取れます。`ReadOnlyAccess` はログ・パラメータ・シークレットメタデータ・IAM 設定など広範な読み取りを含むため、環境によっては情報流出リスクがあります。本番で厳格な制御が必要な場合は customer-managed の最小権限読み取りポリシーを推奨します。

```bash
# ロールを作成（ECS タスク用の例）
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

### パターン 2: 全権限（Full Access）

MCP 経由で全 AWS サービスへ完全アクセス。サンドボックスや個人アカウントのみで使用してください。

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

### パターン 3: 削除禁止（No Delete）

> ⚠️ **注意:** Deny-list による削除禁止は完全なガードレールではありません。`iam:PassRole`、`iam:PutRolePolicy`、`lambda:UpdateFunctionCode`、`s3:PutBucketPolicy` 等は削除操作でなくても大きな影響を与えられます。本番環境での強力な制御には、AWS Organizations の **SCP（Service Control Policy）** を使用してください。
>
> このパターンは非クリティカルな環境での補助的な制御としてのみ使用してください。

MCP 経由の全操作を許可しつつ、一般的な削除系操作を明示的に拒否します。Deny には MCP 条件を付けず、どの経路からも削除できない制約にします。

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

### パターン 4: 障害調査（Operational Investigation）

`ReadOnlyAccess` に加えて、障害調査に必要な実行系権限をインラインポリシーで追加します。

> ⚠️ **重要: `ReadOnlyAccess` は MCP 経由に限定されません。** AWS 管理ポリシーには IAM 条件を付けられないため、`ReadOnlyAccess` の読み取り権限は MCP 経由・直接呼び出し問わず常に有効です。MCP 条件（`aws:CalledViaAWSMCP`）が効くのは**インラインで追加した実行系権限のみ**です。
>
> このロールの実態: **常時有効な広範 read**（`ReadOnlyAccess` 由来）+ **MCP 経由限定の実行系**（インラインポリシー由来）。
>
> ⚠️ **インラインポリシーはリモート実行権限を含みます:**
> - `ssm:SendCommand` / `ecs:ExecuteCommand` — インスタンス・コンテナへのリモートシェルアクセスと同等。秘密情報・認証情報・ファイルシステムへのアクセスが可能。
> - `lambda:InvokeFunction` — ビジネスロジックを実行し、副作用が発生しうる。
>
> **例では `Resource: "*"` を使用していますが、本番では ARN・タグ・SSM ドキュメント等で必ず絞ってください。**
>
> **必須の監査ログ設定**（CloudTrail のみでは不十分）:
> - SSM Session Manager: セッションログを S3/CloudWatch Logs に出力
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

# 読み取り操作は ReadOnlyAccess でカバー
aws iam attach-role-policy \
  --role-name aws-mcp-gateway-debug \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# 実行系権限は MCP 条件付きのインラインポリシーで追加
aws iam put-role-policy \
  --role-name aws-mcp-gateway-debug \
  --policy-name mcp-debug-exec \
  --policy-document file://policy-debug-exec.json
```

---

### 全 MCP アクセスを禁止（SCP / 緊急ロックアウト）

SCP（Service Control Policy）としてアカウント全体の MCP 経由操作を完全ブロックする際に使用します。

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

## セキュリティの考慮事項

### IAM ロールの共有

OIDC で認証した全ユーザーは、ゲートウェイランタイムに付与された同一の IAM ロールを共有します。ゲートウェイはユーザーごとの IAM 認可を行わず、OIDC 認証は「誰がゲートウェイにアクセスできるか」を制御し、IAM は「ゲートウェイが代わりに何をできるか」を制御します。

つまり：
- 認証済みの全ユーザーはゲートウェイの IAM ロール権限をそのまま継承します
- ユーザーごとの権限境界が必要な場合は、別々のロールを持つ独立したゲートウェイインスタンスをデプロイするか、idproxy の `ALLOWED_EMAILS`/`ALLOWED_DOMAINS` でアクセス可能なユーザーを絞ってください

### 監査追跡性

CloudTrail はダウンストリームの AWS API コールを**個人ユーザーではなくゲートウェイの IAM ロール**として記録します。CloudTrail だけでは「誰が」特定の AWS API を呼び出したかを特定できません。

基本戦略は**ゲートウェイアクセスログ**（誰がいつ呼んだか、OIDC ID 付き）と **CloudTrail / 実行ログ**（どの AWS 操作が発生したか）をタイムスタンプで突き合わせることです。

---

#### 1. CloudTrail の有効化（未設定の場合）

```bash
# CloudTrail ログ保存用の S3 バケットを作成
aws s3 mb s3://my-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --region ap-northeast-1

# マルチリージョン証跡を作成・有効化
aws cloudtrail create-trail \
  --name aws-mcp-gateway-trail \
  --s3-bucket-name my-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --is-multi-region-trail \
  --include-global-service-events

aws cloudtrail start-logging --name aws-mcp-gateway-trail
```

---

#### 2. ゲートウェイのアクセスログ（OIDC Identity）

`aws-mcp-gateway` はリクエストごとに認証済みユーザーの email と OIDC `sub` を JSON 形式でログします。追加設定不要 — stdout をログアグリゲーター（CloudWatch Logs エージェント、Fluent Bit 等）に流すだけです。

ログ出力例:
```json
{"time":"2026-01-01T10:00:00Z","level":"INFO","msg":"request","method":"POST","path":"/mcp","user_email":"user@example.com","user_sub":"abc123","remote_addr":"10.0.0.1:12345"}
```

ゲートウェイログをクエリ（stdout → CloudWatch Logs を想定）:

```bash
START=$(date -u -d '1 hour ago' +%s 2>/dev/null || date -u -v-1H +%s)  # Linux / macOS 両対応
END=$(date -u +%s)

QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ecs/aws-mcp-gateway \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, user_email, method, path | filter user_email = "user@example.com" | sort @timestamp desc' \
  --query 'queryId' --output text)

# 完了を待機してから結果を取得
while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

---

#### 3. SSM Run Command — 出力ログの有効化（パターン 4 使用時）

> **注意:** `ssm:SendCommand`（Run Command）と `ssm:StartSession`（Session Manager）は別機能で、ログの設定先も異なります。

`ssm:SendCommand` の出力は、コマンド実行時に CloudWatch Logs へ直接送信します。

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

#### 4. ECS Exec — ログの有効化（パターン 4 使用時）

ECS Exec の監査ログは**クラスターレベル**の `executeCommandConfiguration` で設定します（タスク定義ではありません）。

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

#### 5. ログ取得サンプル

```bash
# 日時変数（Linux/macOS 両対応）
START=$(date -u -d '1 hour ago' +%s 2>/dev/null || date -u -v-1H +%s)
END=$(date -u +%s)
```

**CloudTrail でゲートウェイロールの AWS API コールを確認:**

> **注意:** ECS/Lambda の assumed-role コールは IAM ロール名ではなくセッション名（タスク ID 等）で記録されます。`userIdentity.sessionContext.sessionIssuer.arn` でロール ARN フィルターするのが確実です。

```bash
aws cloudtrail lookup-events \
  --start-time 2026-01-01T10:00:00Z \
  --end-time 2026-01-01T10:05:00Z \
  --output json | jq '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.sessionContext.sessionIssuer.arn | contains("aws-mcp-gateway")) |
    {time: .eventTime, action: .eventName, ip: .sourceIPAddress}'
```

**SSM Run Command 出力ログをクエリ:**

```bash
QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ssm/run-command \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, @logStream, @message | sort @timestamp desc | limit 50' \
  --query 'queryId' --output text)

while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

**ECS Exec ログをクエリ:**

```bash
QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ecs/exec-logs \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, @logStream, @message | sort @timestamp desc | limit 50' \
  --query 'queryId' --output text)

while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

**ゲートウェイログと CloudTrail の時刻相関:**

```bash
# Step 1: ゲートウェイログで不審ユーザー・時刻を特定（user_email → @timestamp）
# Step 2: その時刻でゲートウェイロール ARN で CloudTrail を検索
aws cloudtrail lookup-events \
  --start-time 2026-01-01T10:00:00Z \
  --end-time 2026-01-01T10:05:00Z \
  --output json | jq '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.sessionContext.sessionIssuer.arn | contains("aws-mcp-gateway")) |
    {time: .eventTime, action: .eventName, resource: .resources}'
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

## AWSアカウントごとの分離

アカウントごとに独立したインスタンスをデプロイし、それぞれに専用の IAM ロールを割り当てます：

```
aws-mcp-gateway-prod    → 本番アカウントの IAM ロール
aws-mcp-gateway-staging → ステージングアカウントの IAM ロール
aws-mcp-gateway-sandbox → サンドボックスアカウントの IAM ロール
```

## ライセンス

MIT
