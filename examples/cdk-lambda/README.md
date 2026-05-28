# CDK Lambda Example

aws-mcp-gateway を AWS Lambda + Function URL で動かすための CDK (TypeScript) サンプル。

## 作成されるリソース

| リソース | 概要 |
|---|---|
| `AWS::DynamoDB::Table` | セッションストア (PAY_PER_REQUEST, TTL 有効) |
| `AWS::IAM::Role` (`${instanceName}-lambda-role`) | Lambda 実行ロール |
| `AWS::Lambda::Function` | aws-mcp-gateway 本体 (arm64 / provided.al2023) |
| `AWS::Lambda::Url` | Function URL (NONE auth, RESPONSE_STREAM) |

## 前提

- AWS CDK v2 および Node.js 20+ がインストール済み
- CDK bootstrap 済み (`cdk bootstrap`)
- デプロイ先 AWS アカウントに必要な権限あり

---

## セットアップ

### 1. バイナリの配置

`asset/` ディレクトリに `bootstrap` バイナリを配置してください。

```bash
VERSION=0.7.1  # 最新リリースに合わせてください
curl -fsSL -o aws-mcp-gateway.tar.gz \
  "https://github.com/youyo/aws-mcp-gateway/releases/download/v${VERSION}/aws-mcp-gateway_${VERSION}_Linux_arm64.tar.gz"
tar xzf aws-mcp-gateway.tar.gz aws-mcp-gateway
mv aws-mcp-gateway asset/bootstrap
rm aws-mcp-gateway.tar.gz
```

### 2. cdk.json の設定

```json
{
  "context": {
    "instanceName": "amg",
    "awsMcpRegion": "us-east-1",
    "targetAwsRegion": "ap-northeast-1",
    "iamMode": "direct",
    "assumeRoleArn": "",
    "federatedRoleArn": ""
  }
}
```

| キー | 説明 | デフォルト |
|---|---|---|
| `instanceName` | 全リソース名のプレフィックス | `amg` |
| `awsMcpRegion` | AWS MCP Server リージョン | `us-east-1` |
| `targetAwsRegion` | AWS API コール先リージョン | `ap-northeast-1` |
| `iamMode` | `direct` または `federated` | `direct` |
| `assumeRoleArn` | AssumeRole 先 ARN (省略可) | `""` |
| `federatedRoleArn` | federated モード用 ARN (省略可) | `""` |

### 3. SSM Parameter Store の設定

デプロイ前に以下のパラメータを作成してください。

```bash
INSTANCE_NAME=amg
REGION=ap-northeast-1

# 初回は placeholder を設定 (Function URL 確定後に更新)
aws ssm put-parameter --region $REGION --type SecureString \
  --name /${INSTANCE_NAME}/EXTERNAL_URL \
  --value "https://placeholder.invalid"

aws ssm put-parameter --region $REGION --type SecureString \
  --name /${INSTANCE_NAME}/OIDC_ISSUER \
  --value "https://login.microsoftonline.com/<tenant-id>/v2.0"

aws ssm put-parameter --region $REGION --type SecureString \
  --name /${INSTANCE_NAME}/OIDC_CLIENT_ID \
  --value "<your-client-id>"

aws ssm put-parameter --region $REGION --type SecureString \
  --name /${INSTANCE_NAME}/OIDC_CLIENT_SECRET \
  --value "<your-client-secret>"

aws ssm put-parameter --region $REGION --type SecureString \
  --name /${INSTANCE_NAME}/COOKIE_SECRET \
  --value "$(openssl rand -hex 32)"

aws ssm put-parameter --region $REGION --type String \
  --name /${INSTANCE_NAME}/DYNAMODB_TABLE \
  --value "${INSTANCE_NAME}"

aws ssm put-parameter --region $REGION --type String \
  --name /${INSTANCE_NAME}/DYNAMODB_REGION \
  --value "ap-northeast-1"

# federated モードを使わない場合も空文字で作成が必要
aws ssm put-parameter --region $REGION --type String \
  --name /${INSTANCE_NAME}/FEDERATED_ROLE_ARN \
  --value ""
```

---

## デプロイ

### 初回デプロイ

```bash
npm install
cdk deploy
```

デプロイ完了後、出力の `FunctionUrl` をコピーして SSM を更新します。

```bash
FUNCTION_URL="https://<id>.lambda-url.ap-northeast-1.on.aws"

aws ssm put-parameter \
  --region ap-northeast-1 \
  --name /${INSTANCE_NAME}/EXTERNAL_URL \
  --value "${FUNCTION_URL%/}" \
  --type SecureString --overwrite
```

### 2回目以降 — EXTERNAL_URL を反映して再デプロイ

```bash
cdk deploy
```

### コンテキスト値のオーバーライド (コマンドライン)

```bash
cdk deploy \
  -c instanceName=amg-prod \
  -c iamMode=federated \
  -c federatedRoleArn=arn:aws:iam::123456789012:role/amg-federated
```

---

## AssumeRole (クロスアカウント) を使う場合

ターゲットアカウントに AssumeRole 先の Role を作成する必要があります。
`examples/cdk-assume-role-target/` の CDK サンプルを使用してください。

```bash
# assumeRoleArn を指定して deploy
cdk deploy -c assumeRoleArn=arn:aws:iam::<TARGET_ACCOUNT_ID>:role/aws-mcp-gateway-target
```

---

## クリーンアップ

```bash
cdk destroy
```

> DynamoDB テーブルは `RETAIN` ポリシーのため自動削除されません。別途手動で削除してください。
