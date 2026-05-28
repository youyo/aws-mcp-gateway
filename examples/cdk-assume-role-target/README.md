# CDK AssumeRole Target Example

aws-mcp-gateway の AssumeRole 先 IAM Role を AWS Organizations 配下の複数アカウントへ
CloudFormation StackSets で配布するための CDK (TypeScript) サンプル。

## アーキテクチャ

```
GitHub
  ↓ (CloudFormation Git sync — オプション)
StackSetManagementStack  ← デプロイ対象はこのスタックのみ
  ↓ (StackSets / SERVICE_MANAGED)
各 AWS アカウント
  └── aws-mcp-gateway-target (IAM Role)
       └── Principal: arn:aws:iam::<sourceAccountId>:root
           Condition: sts:ExternalId = <externalId>
```

## スタック構成

| スタック | 用途 |
|---|---|
| `AccountTemplateStack` | 各アカウントへ配布する IAM Role のテンプレート生成用 (AWS にはデプロイしない) |
| `StackSetManagementStack` | AccountTemplateStack の CloudFormation テンプレートを StackSet に埋め込んで配布 |

### デプロイフロー

```
1. cdk synth AccountTemplateStack
       ↓ cdk.out/AccountTemplateStack.template.json が生成される
2. cdk deploy StackSetManagementStack
       ↓ template.json を読み込んで StackSet に埋め込む
       ↓ StackSets が各 AWS アカウントに IAM Role を作成
```

## 前提

- AWS CDK v2 および Node.js 20+ がインストール済み
- CDK bootstrap 済み (`cdk bootstrap`)
- マネジメントアカウント (または委任管理者) からデプロイすること
- AWS Organizations の信頼されたアクセスが有効

```bash
aws organizations enable-aws-service-access \
  --service-principal cloudformation.stacksets.amazonaws.com
```

---

## セットアップ

### cdk.json の設定

```json
{
  "context": {
    "sourceAccountId": "123456789012",
    "externalId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "roleName": "aws-mcp-gateway-target",
    "organizationalUnitIds": ["ou-xxxx-yyyy"],
    "regions": ["ap-northeast-1"]
  }
}
```

| キー | 説明 |
|---|---|
| `sourceAccountId` | aws-mcp-gateway がデプロイされている AWS アカウント ID |
| `externalId` | AssumeRole 条件の ExternalId — **UUID 等の推測困難な値**を設定してください |
| `roleName` | 各アカウントに作成する Role 名 |
| `organizationalUnitIds` | 配布先 OU ID の配列 |
| `regions` | 配布先リージョンの配列 |

> **セキュリティ注意**: `externalId` は推測困難な値 (例: UUID) を設定してください。
> ExternalId は Confused Deputy 攻撃を防ぐための条件です。

### sourceAccountId の確認

aws-mcp-gateway をデプロイしているアカウントで実行します。

```bash
aws sts get-caller-identity --query Account --output text
```

---

## デプロイ

```bash
npm install

# Step 1: AccountTemplateStack を synth して IAM Role テンプレートを生成
npx cdk synth AccountTemplateStack

# Step 2: 生成されたテンプレートを StackSet に埋め込んでデプロイ
npx cdk deploy StackSetManagementStack
```

> `AccountTemplateStack` は AWS にデプロイしません。`cdk.out/AccountTemplateStack.template.json`
> を生成することが目的です。`StackSetManagementStack` がこのファイルを読み込んで
> StackSet の `templateBody` に埋め込みます。

### コンテキスト値のオーバーライド (コマンドライン)

```bash
npx cdk synth AccountTemplateStack \
  -c sourceAccountId=123456789012 \
  -c externalId=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

npx cdk deploy StackSetManagementStack \
  -c organizationalUnitIds='["ou-xxxx-yyyy","ou-aaaa-bbbb"]' \
  -c regions='["ap-northeast-1","us-east-1"]'
```

---

## aws-mcp-gateway 側の設定

StackSets で Role が配布されたら、aws-mcp-gateway 側の設定を行います。

### 1. Lambda 実行ロールに AssumeRole 許可を追加

```bash
INSTANCE_NAME=amg
TARGET_ACCOUNT_ID=987654321098
ROLE_NAME=aws-mcp-gateway-target

aws iam put-role-policy \
  --role-name ${INSTANCE_NAME}-lambda-role \
  --policy-name assume-mcp-target \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Action\": \"sts:AssumeRole\",
      \"Resource\": \"arn:aws:iam::${TARGET_ACCOUNT_ID}:role/${ROLE_NAME}\"
    }]
  }"
```

> `examples/cdk-lambda` を使っている場合は `cdk.json` の `assumeRoleArn` に ARN を設定して
> `cdk deploy` するだけで同様の設定ができます。

### 2. ASSUME_ROLE_ARN を SSM に設定

```bash
aws ssm put-parameter \
  --region ap-northeast-1 \
  --name /${INSTANCE_NAME}/ASSUME_ROLE_ARN \
  --value "arn:aws:iam::${TARGET_ACCOUNT_ID}:role/${ROLE_NAME}" \
  --type String --overwrite
```

---

## Git sync による管理 (オプション)

CloudFormation Git sync を使うと、Git へのプッシュをトリガーに自動デプロイできます。

1. `cdk synth AccountTemplateStack && cdk synth StackSetManagementStack` を実行
2. `cdk.out/StackSetManagementStack.template.json` を Git リポジトリで管理
3. CloudFormation コンソールで Git sync を設定
4. プッシュ → 自動デプロイ → 全 OU 配下アカウントに Role が反映

詳細は [CloudFormation Git sync ドキュメント](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/git-sync.html) を参照してください。

---

## クリーンアップ

```bash
npx cdk destroy StackSetManagementStack
```

StackSet を削除するとスタックインスタンスも削除され、各アカウントの Role も削除されます。
