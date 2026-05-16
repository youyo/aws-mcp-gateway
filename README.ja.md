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

### パターン 1: 読み取り専用（Read-Only）

主要サービスへの読み取り専用アクセス。安全な調査・閲覧に適しています。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyViaMCP",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*", "ec2:Get*",
        "s3:Get*", "s3:List*",
        "rds:Describe*",
        "ecs:Describe*", "ecs:List*",
        "eks:Describe*", "eks:List*",
        "lambda:Get*", "lambda:List*",
        "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
        "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
        "iam:Get*", "iam:List*",
        "ssm:Describe*", "ssm:Get*", "ssm:List*"
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

aws iam put-role-policy \
  --role-name aws-mcp-gateway-readonly \
  --policy-name mcp-readonly \
  --policy-document file://policy-readonly.json
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

> ⚠️ **このパターンは実行系権限を含みます。** `ssm:SendCommand`、`ecs:ExecuteCommand`、`lambda:InvokeFunction` は実行中のシステムに影響を与えられます。障害調査に必要な権限ですが、CloudTrail による監査ログを有効にした上で、信頼できるオンコールエンジニア・SRE のみに使用してください。

読み取りアクセスに加えて、ログクエリ・分散トレース・Lambda invoke・リモートシェルアクセスなど、障害調査・オンコール対応に必要な操作を許可します。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyPlusDebugViaMCP",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*", "ec2:Get*",
        "s3:Get*", "s3:List*",
        "rds:Describe*",
        "ecs:Describe*", "ecs:List*",
        "eks:Describe*", "eks:List*",
        "lambda:Get*", "lambda:List*",
        "lambda:InvokeFunction",
        "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
        "logs:Describe*", "logs:Get*", "logs:FilterLogEvents",
        "logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults",
        "cloudtrail:LookupEvents",
        "xray:GetTraceSummaries", "xray:BatchGetTraces", "xray:GetInsightSummaries",
        "ssm:StartSession", "ssm:SendCommand", "ssm:GetCommandInvocation",
        "ecs:ExecuteCommand"
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

aws iam put-role-policy \
  --role-name aws-mcp-gateway-debug \
  --policy-name mcp-debug \
  --policy-document file://policy-debug.json
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
