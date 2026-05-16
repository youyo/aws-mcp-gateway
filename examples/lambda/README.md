# Lambda Deployment Example

Deploy `aws-mcp-gateway` on AWS Lambda with Function URL using [lambroll](https://github.com/fujiwara/lambroll) and [Lambda Web Adapter](https://github.com/awslabs/aws-lambda-web-adapter).

## Architecture

```
MCP Client
    ↓ HTTPS
Lambda Function URL (NONE auth)
    ↓
aws-mcp-gateway (Lambda Web Adapter)
    ├── idproxy  — OIDC auth + OAuth 2.1 AS (session store: DynamoDB)
    └── SigV4 proxy → AWS MCP Server
```

## Prerequisites

- [lambroll](https://github.com/fujiwara/lambroll) installed
- AWS credentials configured
- IAM roles created (see below)
- SSM Parameter Store values set (see below)
- DynamoDB table created (see below)

## IAM Roles

Two IAM roles are required.

---

### 1. Lambda Execution Role

The role Lambda assumes at runtime.

```bash
# Create the role
aws iam create-role \
  --role-name aws-mcp-gateway-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# 1a. Basic Lambda permissions (CloudWatch Logs)
aws iam attach-role-policy \
  --role-name aws-mcp-gateway-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# 1b. AWS MCP access — choose a pattern from the main README
# Example: ReadOnlyAccess
aws iam attach-role-policy \
  --role-name aws-mcp-gateway-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# 1c. DynamoDB session store
aws iam put-role-policy \
  --role-name aws-mcp-gateway-lambda-role \
  --policy-name dynamodb-session-store \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"],
      "Resource": "arn:aws:dynamodb:ap-northeast-1:*:table/aws-mcp-gateway"
    }]
  }'
```

> **Note:** No SSM permission is needed on the Lambda execution role.
> `function.json` uses lambroll template syntax (`{{ ssm ... }}`), which is resolved
> **at deploy time** by the deployer's credentials — not at Lambda runtime.

---

### 2. Deploy Role (GitHub Actions / CI)

The role used by lambroll at deploy time to read SSM parameters and update the Lambda function.

```bash
aws iam create-role \
  --role-name aws-mcp-gateway-deploy-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:<owner>/<repo>:*"
        }
      }
    }]
  }'

# SSM read (to resolve function.json templates at deploy time)
aws iam put-role-policy \
  --role-name aws-mcp-gateway-deploy-role \
  --policy-name ssm-read \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": "arn:aws:ssm:ap-northeast-1:*:parameter/aws-mcp-gateway/*"
    }]
  }'

# Lambda deploy permissions (lambroll requires these)
aws iam put-role-policy \
  --role-name aws-mcp-gateway-deploy-role \
  --policy-name lambda-deploy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "lambda:CreateFunction", "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration", "lambda:GetFunction",
          "lambda:GetFunctionConfiguration", "lambda:PublishVersion",
          "lambda:CreateAlias", "lambda:UpdateAlias", "lambda:GetAlias",
          "lambda:ListFunctions",
          "lambda:AddPermission", "lambda:RemovePermission", "lambda:GetPolicy",
          "lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig",
          "lambda:GetFunctionUrlConfig"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "arn:aws:iam::*:role/aws-mcp-gateway-lambda-role"
      }
    ]
  }'
```

## AssumeRole Setup (optional — for cross-account access)

When `ASSUME_ROLE_ARN` is set, the Lambda execution role assumes the specified target role before signing MCP requests.

> ⚠️ **CloudTrail audit note:** All users share the session name `aws-mcp-gateway` in CloudTrail. You cannot isolate per-user actions in the target account from CloudTrail alone — correlate with gateway access logs by timestamp instead.

### 1. Grant `sts:AssumeRole` on the Lambda execution role

```bash
aws iam put-role-policy \
  --role-name aws-mcp-gateway-lambda-role \
  --policy-name assume-mcp-target \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/<TARGET_ROLE_NAME>"
    }]
  }'
```

### 2. Add a trust policy to the target role

In the **target AWS account**, allow the Lambda execution role to assume the target role:

```bash
aws iam update-assume-role-policy \
  --role-name <TARGET_ROLE_NAME> \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<LAMBDA_ACCOUNT_ID>:role/aws-mcp-gateway-lambda-role"
      },
      "Action": "sts:AssumeRole"
    }]
  }'
```

### 3. Set the SSM parameter

```bash
aws ssm put-parameter --region $REGION --type String \
  --name /aws-mcp-gateway/ASSUME_ROLE_ARN \
  --value "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/<TARGET_ROLE_NAME>" \
  --overwrite
```

## DynamoDB Setup (required for Lambda)

Lambda cold starts reset in-memory state. DynamoDB provides persistent sessions across invocations.

```bash
REGION=ap-northeast-1

# Create table
aws dynamodb create-table \
  --region $REGION \
  --table-name aws-mcp-gateway \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Enable TTL for automatic session expiry
aws dynamodb update-time-to-live \
  --region $REGION \
  --table-name aws-mcp-gateway \
  --time-to-live-specification "Enabled=true,AttributeName=ttl"
```

## SSM Parameter Store Setup

```bash
REGION=ap-northeast-1

# Required
aws ssm put-parameter --region $REGION --type SecureString --name /aws-mcp-gateway/EXTERNAL_URL \
  --value "https://<function-url-id>.lambda-url.ap-northeast-1.on.aws"

aws ssm put-parameter --region $REGION --type SecureString --name /aws-mcp-gateway/OIDC_ISSUER \
  --value "https://login.microsoftonline.com/<tenant-id>/v2.0"

aws ssm put-parameter --region $REGION --type SecureString --name /aws-mcp-gateway/OIDC_CLIENT_ID \
  --value "<your-client-id>"

aws ssm put-parameter --region $REGION --type SecureString --name /aws-mcp-gateway/OIDC_CLIENT_SECRET \
  --value "<your-client-secret>"

aws ssm put-parameter --region $REGION --type SecureString --name /aws-mcp-gateway/COOKIE_SECRET \
  --value "$(openssl rand -hex 32)"

# DynamoDB session store
aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/DYNAMODB_TABLE \
  --value "aws-mcp-gateway"

aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/DYNAMODB_REGION \
  --value "ap-northeast-1"

# Optional (defaults shown)
aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/AWS_MCP_REGION \
  --value "us-east-1"

aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/TARGET_AWS_REGION \
  --value "ap-northeast-1"

# ASSUME_ROLE_ARN (optional — set to empty string if not using AssumeRole)
# lambroll does not support optional SSM parameters; the parameter must always exist.
# Set to the target role ARN when using cross-account access, or empty string otherwise.
aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/ASSUME_ROLE_ARN \
  --value ""
```

## Deploy

> **First-time deployment requires 2 steps** because the Function URL (needed for `EXTERNAL_URL`) is only known after the first deploy.

### Step 1 — Initial deploy (without Function URL)

```bash
VERSION=0.3.0  # update to latest release
curl -fsSL -o aws-mcp-gateway.tar.gz \
  "https://github.com/youyo/aws-mcp-gateway/releases/download/v${VERSION}/aws-mcp-gateway_${VERSION}_Linux_arm64.tar.gz"
tar xzf aws-mcp-gateway.tar.gz aws-mcp-gateway
mv aws-mcp-gateway bootstrap
zip -j function.zip bootstrap

# Deploy function only (no Function URL yet)
ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/aws-mcp-gateway-lambda-role \
AWS_REGION=ap-northeast-1 \
lambroll deploy \
  --function examples/lambda/function.json \
  --src function.zip
```

### Step 2 — Set EXTERNAL_URL and create Function URL

```bash
# Get the Function URL
FUNCTION_URL=$(aws lambda get-function-url-config \
  --function-name aws-mcp-gateway \
  --query 'FunctionUrl' --output text 2>/dev/null || echo "")

if [ -z "$FUNCTION_URL" ]; then
  # Create Function URL on first run
  aws lambda create-function-url-config \
    --function-name aws-mcp-gateway \
    --auth-type NONE \
    --invoke-mode RESPONSE_STREAM
  FUNCTION_URL=$(aws lambda get-function-url-config \
    --function-name aws-mcp-gateway \
    --query 'FunctionUrl' --output text)
fi

echo "Function URL: $FUNCTION_URL"

# Update EXTERNAL_URL in SSM (strip trailing slash)
aws ssm put-parameter \
  --name /aws-mcp-gateway/EXTERNAL_URL \
  --value "${FUNCTION_URL%/}" \
  --type SecureString --overwrite

# Re-deploy with Function URL and updated EXTERNAL_URL
ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/aws-mcp-gateway-lambda-role \
AWS_REGION=ap-northeast-1 \
lambroll deploy \
  --function examples/lambda/function.json \
  --function-url examples/lambda/function_url.json \
  --src function.zip
```

### Subsequent deploys (GitHub Actions)

After the initial setup, push a tag to trigger automated deployment:

```bash
git tag v0.3.0 && git push origin v0.3.0
```

### GitHub Actions (after initial setup)

Copy `.github/workflows/deploy.yml` to your repository and set:

| Variable | Value |
|---|---|
| `vars.AWS_DEPLOY_ROLE_ARN` | Deploy role ARN (`aws-mcp-gateway-deploy-role`) |
| `vars.LAMBDA_ROLE_ARN` | Lambda execution role ARN (`aws-mcp-gateway-lambda-role`) |

## MCP Client Configuration

### Single account

```bash
# Get Function URL
aws lambda get-function-url-config --function-name aws-mcp-gateway \
  --query 'FunctionUrl' --output text
```

```json
{
  "mcpServers": {
    "aws-mcp": {
      "type": "http",
      "url": "https://<function-url-id>.lambda-url.ap-northeast-1.on.aws/mcp"
    }
  }
}
```

### Multiple accounts

Deploy one Lambda per AWS account. Use `{nickname}-{account-id}` as the MCP server name so Claude Code can distinguish them:

```json
{
  "mcpServers": {
    "aws-prod-123456789012": {
      "type": "http",
      "url": "https://<prod-url>.lambda-url.ap-northeast-1.on.aws/mcp"
    },
    "aws-staging-987654321098": {
      "type": "http",
      "url": "https://<stg-url>.lambda-url.ap-northeast-1.on.aws/mcp"
    },
    "aws-sandbox-327269898957": {
      "type": "http",
      "url": "https://<sbx-url>.lambda-url.ap-northeast-1.on.aws/mcp"
    }
  }
}
```

Claude Code will expose tools as `aws-prod-123456789012___call_aws`, `aws-staging-987654321098___call_aws`, etc., making the target account unambiguous.
