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
| `OIDC_CLIENT_SECRET` | OAuth クライアントシークレット | なし |
| `COOKIE_SECRET` | Cookie 暗号化キー（hex 形式、32バイト以上） | ランダム生成（再起動でセッション消失） |
| `AWS_MCP_ENDPOINT` | AWS MCP Server エンドポイント URL（`AWS_MCP_REGION` より優先） | `AWS_MCP_REGION` から自動生成 |
| `AWS_MCP_REGION` | AWS MCP Server エンドポイントのリージョン | `us-east-1` |
| `TARGET_AWS_REGION` | AWS API 操作のデフォルトリージョン | `ap-northeast-1` |
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

> **注意:** AWS 管理ポリシーには IAM 条件を付けられないため、`aws:CalledViaAWSMCP` は適用できません。このロールはゲートウェイ専用なのでリスクは限定的ですが、このロールで動作するプロセスは MCP 経由以外でも AWS リソースを読み取れることに注意してください。

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

> ⚠️ **インラインポリシーはリモート実行権限を含みます（Read-Only ではありません）。**
> - `ssm:SendCommand` / `ecs:ExecuteCommand` — インスタンス・コンテナへのリモートシェルアクセスと同等。秘密情報・認証情報・ファイルシステムへのアクセスが可能。
> - `lambda:InvokeFunction` — ビジネスロジックを実行し、副作用が発生しうる。
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

CloudTrail はダウンストリームの AWS API コールを**個人ユーザーではなくゲートウェイの IAM ロール**として記録します。CloudTrail だけでは「どのユーザーが」特定の AWS API を呼び出したかを特定できません。

ユーザー ID と AWS 操作を紐づけるには：
- ゲートウェイのアクセスログにリクエストごとの OIDC `sub` / email を記録する
- タイムスタンプとソース IP でゲートウェイログと CloudTrail を突き合わせる
- パターン 4（障害調査）では加えて SSM セッションログ・ECS Exec ログを有効にする

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
