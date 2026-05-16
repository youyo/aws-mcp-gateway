# Lambda Deployment Example

Deploy `aws-mcp-gateway` on AWS Lambda with Function URL using [lambroll](https://github.com/fujiwara/lambroll) and [Lambda Web Adapter](https://github.com/awslabs/aws-lambda-web-adapter).

## Architecture

```
MCP Client
    ↓ HTTPS
Lambda Function URL (NONE auth)
    ↓
aws-mcp-gateway (Lambda Web Adapter)
    ├── idproxy  — OIDC auth + OAuth 2.1 AS
    └── SigV4 proxy → AWS MCP Server
```

> **Note:** The session store uses in-memory by default. Sessions are lost on Lambda cold starts. For production, configure a persistent store (DynamoDB) in `main.go`.

## Prerequisites

- [lambroll](https://github.com/fujiwara/lambroll) installed
- AWS credentials configured
- IAM role for Lambda (see below)
- SSM Parameter Store values set (see below)

## IAM Role

The Lambda execution role needs:

1. **Basic Lambda permissions** — attach `arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole`

2. **AWS MCP permissions** — choose a pattern from the [main README](../../README.md#iam-permissions):

```bash
# Example: ReadOnlyAccess
aws iam attach-role-policy \
  --role-name aws-mcp-gateway-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

3. **SSM read permission** (to read parameters at deploy time):

```bash
aws iam put-role-policy \
  --role-name aws-mcp-gateway-lambda-role \
  --policy-name ssm-read \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["ssm:GetParameter"],
      "Resource": "arn:aws:ssm:ap-northeast-1:*:parameter/aws-mcp-gateway/*"
    }]
  }'
```

Create the role:

```bash
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
```

## DynamoDB Setup (required for Lambda)

Lambda restarts on cold starts, so the default in-memory session store loses all sessions. Use DynamoDB for persistent sessions.

```bash
REGION=ap-northeast-1

# Create DynamoDB table
aws dynamodb create-table \
  --region $REGION \
  --table-name aws-mcp-gateway \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Enable TTL (required for automatic session expiry)
aws dynamodb update-time-to-live \
  --region $REGION \
  --table-name aws-mcp-gateway \
  --time-to-live-specification "Enabled=true,AttributeName=ttl"
```

Add DynamoDB permissions to the Lambda execution role:

```bash
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

# Optional (defaults shown)
aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/AWS_MCP_REGION \
  --value "us-east-1"

aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/TARGET_AWS_REGION \
  --value "ap-northeast-1"

# DynamoDB session store (required for Lambda)
aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/DYNAMODB_TABLE \
  --value "aws-mcp-gateway"

aws ssm put-parameter --region $REGION --type String --name /aws-mcp-gateway/DYNAMODB_REGION \
  --value "ap-northeast-1"
```

## Deploy

### Manual deploy

```bash
# 1. Download binary for arm64 Linux
VERSION=0.2.0
curl -fsSL -o aws-mcp-gateway.tar.gz \
  "https://github.com/youyo/aws-mcp-gateway/releases/download/v${VERSION}/aws-mcp-gateway_${VERSION}_Linux_arm64.tar.gz"
tar xzf aws-mcp-gateway.tar.gz aws-mcp-gateway
mv aws-mcp-gateway bootstrap
zip -j function.zip bootstrap

# 2. Deploy with lambroll
ROLE_ARN=arn:aws:iam::123456789012:role/aws-mcp-gateway-lambda-role \
AWS_REGION=ap-northeast-1 \
lambroll deploy --function function.json --function-url function_url.json
```

### GitHub Actions

Copy `.github/workflows/deploy.yml` to your repository and set:

| Secret / Variable | Value |
|---|---|
| `vars.AWS_DEPLOY_ROLE_ARN` | IAM role ARN for GitHub Actions OIDC |
| `vars.LAMBDA_ROLE_ARN` | Lambda execution role ARN |

Push a tag to trigger deployment:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

## MCP Client Configuration

After deployment, get the Function URL:

```bash
aws lambda get-function-url-config --function-name aws-mcp-gateway \
  --query 'FunctionUrl' --output text
```

Configure Claude Code:

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
