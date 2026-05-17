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

## Known Limitations

### `call_aws` and API-execution tools

AWS MCP Server's `call_aws`, `run_script`, and `get_presigned_url` tools require **IAM Identity Center (SSO)-backed sessions**. Lambda execution roles and custom IAM roles — including those assumed via `AssumeRoleWithWebIdentity` — are rejected with `error -32600: Failed to serve request`.

**Knowledge tools work fully through the gateway:**

| Tool | Works via gateway |
|---|---|
| `list_regions` | ✅ |
| `search_documentation` | ✅ |
| `read_documentation` | ✅ |
| `recommend` | ✅ |
| `get_regional_availability` | ✅ |
| `call_aws` | ❌ Requires SSO session |
| `run_script` | ❌ Requires SSO session |
| `get_presigned_url` | ❌ Requires SSO session |

For `call_aws` and other API-execution tools, use [mcp-proxy-for-aws](https://github.com/aws/mcp-proxy-for-aws) locally with your SSO credentials alongside this gateway:

```json
{
  "mcpServers": {
    "aws-mcp-knowledge": {
      "type": "http",
      "url": "https://<gateway-url>/mcp"
    },
    "aws-mcp-api": {
      "command": "uvx",
      "args": ["mcp-proxy-for-aws@latest", "https://aws-mcp.us-east-1.api.aws/mcp",
               "--metadata", "AWS_REGION=ap-northeast-1"],
      "env": {"AWS_PROFILE": "your-sso-profile"}
    }
  }
}
```

---

## Instance Naming (`INSTANCE_NAME`)

Every resource (Lambda function, DynamoDB table, SSM parameters, IAM roles) is namespaced by `INSTANCE_NAME`. This allows multiple independent deployments within the same AWS account without conflicts.

| Example `INSTANCE_NAME` | Use case |
|---|---|
| `amg` | Single deployment (default) |
| `amg-prod` | Production account gateway |
| `amg-sandbox` | Sandbox account gateway |

> ⚠️ **SSM restriction**: `INSTANCE_NAME` must **not** start with `aws`. AWS SSM Parameter Store reserves the `/aws` namespace and will return `AccessDeniedException` for any parameter path beginning with `/aws`.

`INSTANCE_NAME` must be set as a **GitHub Actions Variable** (`vars.INSTANCE_NAME`) for CI deployment, or as an environment variable for manual deployment.

## Prerequisites

- [lambroll](https://github.com/fujiwara/lambroll) installed
- AWS credentials configured
- `INSTANCE_NAME` decided (see above)
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
  --role-name ${INSTANCE_NAME}-lambda-role \
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
  --role-name ${INSTANCE_NAME}-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# 1b. AWS MCP access — choose a pattern from the main README
# Example: ReadOnlyAccess
aws iam attach-role-policy \
  --role-name ${INSTANCE_NAME}-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# 1c. DynamoDB session store
aws iam put-role-policy \
  --role-name ${INSTANCE_NAME}-lambda-role \
  --policy-name dynamodb-session-store \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"],
      "Resource": "arn:aws:dynamodb:ap-northeast-1:*:table/${INSTANCE_NAME}"
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
  --role-name ${INSTANCE_NAME}-deploy-role \
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
  --role-name ${INSTANCE_NAME}-deploy-role \
  --policy-name ssm-read \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": "arn:aws:ssm:ap-northeast-1:*:parameter/${INSTANCE_NAME}/*"
    }]
  }'

# Lambda deploy permissions (lambroll requires these)
aws iam put-role-policy \
  --role-name ${INSTANCE_NAME}-deploy-role \
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
        "Resource": "arn:aws:iam::*:role/${INSTANCE_NAME}-lambda-role"
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
  --role-name ${INSTANCE_NAME}-lambda-role \
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
        "AWS": "arn:aws:iam::<LAMBDA_ACCOUNT_ID>:role/${INSTANCE_NAME}-lambda-role"
      },
      "Action": "sts:AssumeRole"
    }]
  }'
```

### 3. Set the SSM parameter

```bash
aws ssm put-parameter --region $REGION --type String \
  --name /${INSTANCE_NAME}/ASSUME_ROLE_ARN \
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
  --table-name ${INSTANCE_NAME} \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Enable TTL for automatic session expiry
aws dynamodb update-time-to-live \
  --region $REGION \
  --table-name ${INSTANCE_NAME} \
  --time-to-live-specification "Enabled=true,AttributeName=ttl"
```

## Microsoft Entra ID Setup

### 1. Register an application

1. [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** → **App registrations** → **New registration**
2. Fill in:
   - **Name**: `aws-mcp-gateway` (or any name)
   - **Supported account types**: *Accounts in this organizational directory only*
   - **Redirect URI**: leave blank for now — set after Function URL is known (Step 6)
3. Click **Register**

### 2. Collect required values

From the app's **Overview** page:

| SSM parameter | Azure Portal label | Location |
|---|---|---|
| `OIDC_CLIENT_ID` | **Application (client) ID** | Overview |
| `<tenant-id>` in `OIDC_ISSUER` | **Directory (tenant) ID** | Overview |

`OIDC_ISSUER` value:
```
https://login.microsoftonline.com/<tenant-id>/v2.0
```

### 3. Create a client secret

1. Left menu → **Certificates & secrets** → **Client secrets** → **New client secret**
2. Enter a description and choose an expiry
3. Click **Add** → copy the **Value** immediately (it disappears on navigation)

This is `OIDC_CLIENT_SECRET`.

### 4. Add API permissions

1. Left menu → **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**
2. Add: `openid`, `email`, `profile`
3. Click **Grant admin consent for \<your org\>** → **Yes**

All three permissions should show a green checkmark.

### 5. Add optional claims to the ID token

1. Left menu → **Token configuration** → **Add optional claim**
2. **Token type**: `ID`
3. Check **`email`** → **Add**

> **Note:** `name` (display name) is included automatically when the `profile` scope is granted. `family_name` and `given_name` are not required by aws-mcp-gateway.

### 6. Set redirect URI (after Function URL is known)

After the initial Lambda deploy (Step 6 in Deploy), add the redirect URI:

1. Left menu → **Authentication** → **Add a platform** → **Web**
2. **Redirect URI**: `https://<function-url-id>.lambda-url.ap-northeast-1.on.aws/callback`
3. Click **Configure**

---

## SSM Parameter Store Setup

```bash
REGION=ap-northeast-1

# Required
aws ssm put-parameter --region $REGION --type SecureString --name /${INSTANCE_NAME}/EXTERNAL_URL \
  --value "https://<function-url-id>.lambda-url.ap-northeast-1.on.aws"

aws ssm put-parameter --region $REGION --type SecureString --name /${INSTANCE_NAME}/OIDC_ISSUER \
  --value "https://login.microsoftonline.com/<tenant-id>/v2.0"

aws ssm put-parameter --region $REGION --type SecureString --name /${INSTANCE_NAME}/OIDC_CLIENT_ID \
  --value "<your-client-id>"

aws ssm put-parameter --region $REGION --type SecureString --name /${INSTANCE_NAME}/OIDC_CLIENT_SECRET \
  --value "<your-client-secret>"

aws ssm put-parameter --region $REGION --type SecureString --name /${INSTANCE_NAME}/COOKIE_SECRET \
  --value "$(openssl rand -hex 32)"

# DynamoDB session store
aws ssm put-parameter --region $REGION --type String --name /${INSTANCE_NAME}/DYNAMODB_TABLE \
  --value "${INSTANCE_NAME}"

aws ssm put-parameter --region $REGION --type String --name /${INSTANCE_NAME}/DYNAMODB_REGION \
  --value "ap-northeast-1"

# Optional (defaults shown)
aws ssm put-parameter --region $REGION --type String --name /${INSTANCE_NAME}/AWS_MCP_REGION \
  --value "us-east-1"

aws ssm put-parameter --region $REGION --type String --name /${INSTANCE_NAME}/TARGET_AWS_REGION \
  --value "ap-northeast-1"

# ASSUME_ROLE_ARN (optional — set to empty string if not using AssumeRole)
# lambroll does not support optional SSM parameters; the parameter must always exist.
# Set to the target role ARN when using cross-account access, or empty string otherwise.
aws ssm put-parameter --region $REGION --type String --name /${INSTANCE_NAME}/ASSUME_ROLE_ARN \
  --value ""
```

## Deploy

> **First-time deployment requires 2 steps** because the Function URL (needed for `EXTERNAL_URL`) is only known after the first deploy.

### Step 1 — Initial deploy (without Function URL)

```bash
# Set INSTANCE_NAME first — used throughout all subsequent commands
export INSTANCE_NAME=amg          # default; use amg-prod / amg-sandbox etc. for multiple deployments
export AWS_REGION=ap-northeast-1

VERSION=0.5.2  # update to latest release
curl -fsSL -o aws-mcp-gateway.tar.gz \
  "https://github.com/youyo/aws-mcp-gateway/releases/download/v${VERSION}/aws-mcp-gateway_${VERSION}_Linux_arm64.tar.gz"
tar xzf aws-mcp-gateway.tar.gz aws-mcp-gateway
mv aws-mcp-gateway bootstrap
zip -j function.zip bootstrap

# Seed EXTERNAL_URL with a placeholder (required before first deploy)
# lambroll resolves all SSM values at deploy time — the parameter must exist.
# Update to the real Function URL in Step 2.
aws ssm put-parameter \
  --region $AWS_REGION \
  --name /${INSTANCE_NAME}/EXTERNAL_URL \
  --value "https://placeholder.invalid" \
  --type SecureString

# Deploy function only (no Function URL yet)
ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/${INSTANCE_NAME}-lambda-role \
lambroll deploy \
  --function examples/lambda/function.json \
  --src function.zip
```

### Step 2 — Set EXTERNAL_URL and create Function URL

```bash
# INSTANCE_NAME and AWS_REGION must be set (from Step 1, or re-export here)
export INSTANCE_NAME=amg
export AWS_REGION=ap-northeast-1

# Get the Function URL
FUNCTION_URL=$(aws lambda get-function-url-config \
  --function-name "${INSTANCE_NAME}" \
  --query 'FunctionUrl' --output text 2>/dev/null || echo "")

if [ -z "$FUNCTION_URL" ]; then
  # Create Function URL on first run
  aws lambda create-function-url-config \
    --function-name "${INSTANCE_NAME}" \
    --auth-type NONE \
    --invoke-mode RESPONSE_STREAM
  FUNCTION_URL=$(aws lambda get-function-url-config \
    --function-name "${INSTANCE_NAME}" \
    --query 'FunctionUrl' --output text)
fi

echo "Function URL: $FUNCTION_URL"

# Update EXTERNAL_URL in SSM (strip trailing slash)
aws ssm put-parameter \
  --name /${INSTANCE_NAME}/EXTERNAL_URL \
  --value "${FUNCTION_URL%/}" \
  --type SecureString --overwrite

# Re-deploy with Function URL and updated EXTERNAL_URL
ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/${INSTANCE_NAME}-lambda-role \
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
| `vars.INSTANCE_NAME` | Instance name e.g. `amg-prod` |
| `vars.AWS_DEPLOY_ROLE_ARN` | Deploy role ARN (`${INSTANCE_NAME}-deploy-role`) |
| `vars.LAMBDA_ROLE_ARN` | Lambda execution role ARN (`${INSTANCE_NAME}-lambda-role`) |

## MCP Client Configuration

### Single account

```bash
# Get Function URL (replace amg with your INSTANCE_NAME)
aws lambda get-function-url-config --function-name amg \
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
