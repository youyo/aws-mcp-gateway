# aws-mcp-gateway

**English** | [日本語](README.ja.md)

OIDC-authenticated reverse proxy for [AWS MCP Server](https://docs.aws.amazon.com/aws-mcp/latest/userguide/getting-started-aws-mcp-server.html).

Combines [idproxy](https://github.com/youyo/idproxy) (OIDC auth + OAuth 2.1 AS) with a SigV4-signed `httputil.ReverseProxy` to expose AWS MCP Server as a protected remote MCP endpoint — no `mcp-go` or message-level parsing required.

## Architecture

```
MCP Client (Claude Code, Cursor, etc.)
    ↓  OAuth 2.1 (Bearer Token)
aws-mcp-gateway
  ├── idproxy          — OIDC browser auth (EntraID, Google, Cognito, …)
  │                      OAuth 2.1 Authorization Server (Dynamic Client Registration)
  └── ReverseProxy     — SigV4-signed Streamable HTTP proxy
    ↓  HTTPS + SigV4
AWS MCP Server (managed, us-east-1 / eu-central-1)
    ↓  call_aws
Any AWS resource (any region)
```

AWS credentials are resolved automatically from the environment (Lambda execution role, ECS task role, EC2 instance profile, etc.). No credential configuration needed at the application level.

## Features

- **OIDC authentication** via any OIDC provider (Microsoft Entra ID, Google, Amazon Cognito, …)
- **OAuth 2.1 Authorization Server** with Dynamic Client Registration (RFC 7591)
- **SigV4 signing** — automatic credential resolution from IAM roles
- **Streamable HTTP transparent proxy** — MCP messages pass through unchanged
- **Per-AWS-account isolation** — deploy one instance per account with its own IAM role
- **JSON structured logging** via `log/slog`

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `EXTERNAL_URL` | Public URL of this gateway | `https://aws-mcp.example.com` |
| `OIDC_ISSUER` | OIDC Issuer URL | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| `OIDC_CLIENT_ID` | OAuth Client ID | `your-client-id` |
| `OIDC_CLIENT_SECRET` | OAuth Client Secret | `your-client-secret` |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOWED_DOMAINS` | Comma-separated allowed email domains (e.g. `example.com,corp.example.com`). If both are unset, **any user in the OIDC tenant can authenticate** — a warning is logged but the gateway still starts. Case-insensitive. Note: the allowlist is only checked at login time; issued tokens remain valid until expiry even if the allowlist is tightened. | none |
| `ALLOWED_EMAILS` | Comma-separated allowed email addresses. Combined with `ALLOWED_DOMAINS` (OR logic). Case-insensitive. | none |
| `COOKIE_SECRET` | Cookie encryption key (hex-encoded, 32+ bytes) | Random (sessions lost on restart) |
| `AWS_MCP_ENDPOINT` | AWS MCP Server endpoint URL (overrides `AWS_MCP_REGION`) | derived from `AWS_MCP_REGION` |
| `AWS_MCP_REGION` | Region of the AWS MCP Server endpoint | `us-east-1` |
| `TARGET_AWS_REGION` | Default AWS region for API operations | `ap-northeast-1` |
| `ASSUME_ROLE_ARN` | IAM role ARN to assume before signing MCP requests. Requires `sts:AssumeRole` on the runtime role and a trust policy on the target role. All users share session name `aws-mcp-gateway` in CloudTrail. | none (use runtime role) |
| `IAM_MODE` | `shared` (default): all users share the runtime IAM role. `federated`: each OIDC-authenticated user gets per-user temporary credentials via `AssumeRoleWithWebIdentity` using their ID Token. Requires `AUTH_MODE=oidc` and `FEDERATED_ROLE_ARN`. | `shared` |
| `FEDERATED_ROLE_ARN` | IAM role ARN to assume via `AssumeRoleWithWebIdentity` in federated mode. The OIDC ID Token is passed to STS; the target role must trust the OIDC issuer. The session name is derived from the user's OIDC `sub` for per-user CloudTrail auditability. | none (required when `IAM_MODE=federated`) |
| `STORE_BACKEND` | Session store backend: `memory` or `dynamodb` | `memory` |
| `DYNAMODB_TABLE` | DynamoDB table name (required when `STORE_BACKEND=dynamodb`) | none |
| `DYNAMODB_REGION` | DynamoDB table region (required when `STORE_BACKEND=dynamodb`) | `ap-northeast-1` |
| `PORT` | Listen port | `8080` |

> **Note:** `AWS_MCP_REGION` controls which MCP server endpoint to connect to (`us-east-1` or `eu-central-1`). When a new region becomes available, just change this variable. `TARGET_AWS_REGION` sets the default region for AWS operations — these can be different.

## Provider Setup

| Provider | `OIDC_ISSUER` |
|----------|--------------|
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| Google | `https://accounts.google.com` |
| Amazon Cognito | `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}` |

Register the gateway as an OIDC client and set the redirect URI to:

```
{EXTERNAL_URL}/auth/callback
```

## IAM Permissions

The IAM role attached to the runtime (Lambda, ECS, EC2) controls what AWS operations the MCP agent can perform. Choose a pattern that fits your use case.

### IAM Condition Keys

AWS MCP Server injects two condition keys into every downstream AWS API call:

| Key | Description | Example value |
|-----|-------------|---------------|
| `aws:CalledViaAWSMCP` | Service principal of the MCP server making the call | `aws-mcp.amazonaws.com` |
| `aws:ViaAWSMCPService` | Boolean — `"true"` when called via any managed MCP server | `"true"` |

Use `aws:CalledViaAWSMCP` to restrict permissions to a specific MCP server. Use `aws:ViaAWSMCPService` to allow/deny all managed MCP servers at once.

> **Reference:** [Understanding IAM for managed AWS MCP servers](https://aws.amazon.com/blogs/security/understanding-iam-for-managed-aws-mcp-servers/)

---

### Pattern 1: Read-Only

Attach the AWS-managed `ReadOnlyAccess` policy. Covers all AWS services and is automatically updated as new services are added.

> **Note:** AWS managed policies cannot carry IAM conditions, so `aws:CalledViaAWSMCP` cannot be applied. Any process running with this role can read AWS resources directly, not only via MCP. `ReadOnlyAccess` includes broad read access (logs, parameters, secrets metadata, IAM configurations) — evaluate whether this is acceptable for your environment. For production with strict controls, use a customer-managed least-privilege read policy instead.

```bash
# Create role (example: for ECS task)
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

### Pattern 2: Full Access

Full access to all AWS services via MCP. Use only in sandbox or personal accounts.

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

### Pattern 3: No Delete

> ⚠️ **Important:** A deny-list approach cannot reliably prevent all destructive actions. Actions like `iam:PassRole`, `iam:PutRolePolicy`, `lambda:UpdateFunctionCode`, and `s3:PutBucketPolicy` can cause significant impact even without explicit delete permissions. For strong prevention in production, use an **SCP (Service Control Policy)** at the AWS Organizations level instead.
>
> Use this pattern only as a supplementary control in non-critical environments.

Full MCP access with common delete actions explicitly denied. The Deny has no MCP condition — it blocks deletion regardless of call origin.

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

### Pattern 4: Operational Investigation

`ReadOnlyAccess` plus an inline policy that grants execution permissions needed for incident investigation.

> ⚠️ **Important: `ReadOnlyAccess` is NOT restricted to MCP paths.** Because AWS managed policies cannot carry IAM conditions, the read permissions from `ReadOnlyAccess` apply regardless of whether the call comes through MCP or directly. Only the **inline execution permissions** are gated by `aws:CalledViaAWSMCP`.
>
> In practice this role has: **always-on broad read** (via `ReadOnlyAccess`) + **MCP-only execution** (via inline policy).
>
> ⚠️ **The inline policy grants remote execution permissions:**
> - `ssm:SendCommand` / `ecs:ExecuteCommand` — equivalent to remote shell access. Can expose secrets, credentials, and filesystem data.
> - `lambda:InvokeFunction` — executes business logic with potential side effects.
>
> **`Resource: "*"` in the example is simplified.** In production, scope to specific ARNs, tags, or SSM documents.
>
> **Required audit logging** (CloudTrail alone is insufficient):
> - SSM Session Manager: enable session logging to S3/CloudWatch Logs
> - ECS Exec: enable `execute-command` logging in task definition
> - Lambda: enable function-level CloudWatch Logs

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

# ReadOnlyAccess covers all read operations (no MCP condition — managed policies cannot carry conditions)
aws iam attach-role-policy \
  --role-name aws-mcp-gateway-debug \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Inline policy adds execution permissions (with MCP condition)
aws iam put-role-policy \
  --role-name aws-mcp-gateway-debug \
  --policy-name mcp-debug-exec \
  --policy-document file://policy-debug-exec.json
```

---

### Deny All MCP Access (SCP / Emergency Lockout)

Use this as a Service Control Policy (SCP) to completely block all MCP-originated actions across an account.

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

## Security Considerations

### Shared IAM Role

All users who authenticate via OIDC share the same IAM role attached to the gateway runtime. The gateway does not perform per-user IAM authorization — OIDC authentication determines *who can access the gateway*, but IAM controls *what the gateway can do on their behalf*.

This means:
- Every authenticated user inherits the full permissions of the gateway's IAM role
- If you need per-user permission boundaries, deploy separate gateway instances with separate roles, or restrict who can authenticate via OIDC (`ALLOWED_EMAILS`, `ALLOWED_DOMAINS` in idproxy)

### Audit Traceability

CloudTrail records downstream AWS API calls under the **gateway's IAM role**, not the individual user. You cannot distinguish *which user* triggered a specific AWS API call from CloudTrail alone.

The strategy is to correlate **gateway access logs** (who called the gateway, with OIDC identity) against **CloudTrail / execution logs** (what AWS actions happened) by timestamp.

---

#### 1. Enable CloudTrail (if not already active)

```bash
# Create an S3 bucket for CloudTrail logs
aws s3 mb s3://my-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --region ap-northeast-1

# Enable CloudTrail in all regions
aws cloudtrail create-trail \
  --name aws-mcp-gateway-trail \
  --s3-bucket-name my-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --is-multi-region-trail \
  --include-global-service-events

aws cloudtrail start-logging --name aws-mcp-gateway-trail
```

---

#### 2. Gateway Access Logging (OIDC Identity per Request)

`aws-mcp-gateway` logs the authenticated user's email and OIDC `sub` on every request in JSON format (via `log/slog`). No additional setup is required — just route stdout to your log aggregator (CloudWatch Logs agent, Fluent Bit, etc.).

Example log line:
```json
{"time":"2026-01-01T10:00:00Z","level":"INFO","msg":"request","method":"POST","path":"/mcp","user_email":"user@example.com","user_sub":"abc123","remote_addr":"10.0.0.1:12345"}
```

To query gateway logs from CloudWatch Logs (assuming stdout → CloudWatch Logs):

```bash
# Find all requests from a specific user in the last hour
START=$(date -u -d '1 hour ago' +%s 2>/dev/null || date -u -v-1H +%s)  # Linux / macOS
END=$(date -u +%s)

QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ecs/aws-mcp-gateway \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, user_email, method, path | filter user_email = "user@example.com" | sort @timestamp desc' \
  --query 'queryId' --output text)

# Poll until complete
while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

---

#### 3. SSM Run Command — Enable Output Logging (Pattern 4)

> **Note:** `ssm:SendCommand` (Run Command) and `ssm:StartSession` (Session Manager) are different features with separate log destinations.

For `ssm:SendCommand`, direct output to CloudWatch Logs per invocation:

```bash
aws logs create-log-group --log-group-name /aws/ssm/run-command

# Pass log configuration when running a command
aws ssm send-command \
  --instance-ids i-xxxxxxxxxxxxxxxxx \
  --document-name "AWS-RunShellScript" \
  --parameters '{"commands":["your-command"]}' \
  --cloud-watch-output-config '{"CloudWatchOutputEnabled":true,"CloudWatchLogGroupName":"/aws/ssm/run-command"}'
```

---

#### 4. ECS Exec — Enable Logging (Pattern 4)

ECS Exec audit logs require `executeCommandConfiguration` at the **cluster** level, not the task definition:

```bash
aws logs create-log-group --log-group-name /aws/ecs/exec-logs

# Configure ECS Exec logging at cluster level
aws ecs update-cluster \
  --cluster my-cluster \
  --configuration "executeCommandConfiguration={logging=OVERRIDE,logConfiguration={cloudWatchLogGroupName=/aws/ecs/exec-logs,cloudWatchEncryptionEnabled=false}}"

# Enable execute-command on the service
aws ecs update-service \
  --cluster my-cluster \
  --service my-service \
  --enable-execute-command
```

---

#### 5. Query Logs — Sample Commands

**Query gateway access logs to find a user's activity:**

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

**Find AWS API calls from the gateway role in CloudTrail:**

> **Note:** ECS/Lambda assumed-role calls are recorded with a session name like `i-xxxxxxxx` or a task ID, not the IAM role name. Filter by the role ARN in `userIdentity.sessionContext.sessionIssuer.arn` for reliable results.

```bash
# Reliable: filter by role ARN from raw CloudTrail JSON
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=ec2.amazonaws.com \
  --start-time 2026-01-01T10:00:00Z \
  --end-time 2026-01-01T10:05:00Z \
  --output json | jq '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.sessionContext.sessionIssuer.arn | contains("aws-mcp-gateway")) |
    {time: .eventTime, action: .eventName, resource: .resources}'
```

**Query SSM Run Command output logs:**

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

**Query ECS Exec logs:**

```bash
QUERY_ID=$(aws logs start-query \
  --log-group-name /aws/ecs/exec-logs \
  --start-time $START --end-time $END \
  --query-string 'fields @timestamp, @logStream, @message | sort @timestamp desc | limit 50' \
  --query 'queryId' --output text)

while [ "$(aws logs get-query-results --query-id $QUERY_ID --query 'status' --output text)" = "Running" ]; do sleep 2; done
aws logs get-query-results --query-id $QUERY_ID --output json
```

**Correlate gateway user identity with CloudTrail:**

```bash
# Step 1: Find the time window from gateway logs (user_email → timestamp)
# Step 2: Query CloudTrail for that window filtered by gateway role ARN
aws cloudtrail lookup-events \
  --start-time 2026-01-01T10:00:00Z \
  --end-time 2026-01-01T10:05:00Z \
  --output json | jq '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.sessionContext.sessionIssuer.arn | contains("aws-mcp-gateway")) |
    {time: .eventTime, action: .eventName, ip: .sourceIPAddress}'
```

## Quick Start

```bash
export EXTERNAL_URL=http://localhost:8080
export OIDC_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
export OIDC_CLIENT_ID=your-client-id
export OIDC_CLIENT_SECRET=your-client-secret
export COOKIE_SECRET=$(openssl rand -hex 32)

aws-mcp-gateway
```

### MCP Client Configuration (Claude Code)

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

## Per-Account Isolation

Deploy one instance per AWS account, each with its own IAM role:

```
aws-mcp-gateway-prod    → IAM role for production account
aws-mcp-gateway-staging → IAM role for staging account
aws-mcp-gateway-sandbox → IAM role for sandbox account
```

## License

MIT
