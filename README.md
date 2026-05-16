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

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `OIDC_CLIENT_SECRET` | OAuth Client Secret | none |
| `COOKIE_SECRET` | Cookie encryption key (hex-encoded, 32+ bytes) | Random (sessions lost on restart) |
| `AWS_MCP_ENDPOINT` | AWS MCP Server endpoint URL (overrides `AWS_MCP_REGION`) | derived from `AWS_MCP_REGION` |
| `AWS_MCP_REGION` | Region of the AWS MCP Server endpoint | `us-east-1` |
| `TARGET_AWS_REGION` | Default AWS region for API operations | `ap-northeast-1` |
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

#### 2. SSM Session Manager — Enable Logging (Pattern 4)

Store all session input/output to CloudWatch Logs for later forensics.

```bash
# Create CloudWatch Log Group for SSM sessions
aws logs create-log-group --log-group-name /aws/ssm/sessions

# Apply Session Manager preferences (account-wide)
aws ssm update-service-setting \
  --setting-id arn:aws:ssm:ap-northeast-1:$(aws sts get-caller-identity --query Account --output text):servicesetting/ssm/session-manager/cloudwatch-log-group-name \
  --setting-value /aws/ssm/sessions

aws ssm update-service-setting \
  --setting-id arn:aws:ssm:ap-northeast-1:$(aws sts get-caller-identity --query Account --output text):servicesetting/ssm/session-manager/cloudwatch-log-upload-enabled \
  --setting-value true
```

---

#### 3. ECS Exec — Enable Logging (Pattern 4)

Add `logConfiguration` to your task definition's `linuxParameters.initProcessEnabled` section:

```json
{
  "taskDefinition": {
    "containerDefinitions": [{
      "name": "your-container",
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/exec-logs",
          "awslogs-region": "ap-northeast-1",
          "awslogs-stream-prefix": "exec"
        }
      }
    }],
    "enableExecuteCommand": true
  }
}
```

```bash
# Create the log group
aws logs create-log-group --log-group-name /ecs/exec-logs

# Update your ECS service to enable execute-command
aws ecs update-service \
  --cluster my-cluster \
  --service my-service \
  --enable-execute-command
```

---

#### 4. Query Logs — Sample Commands

**Find all AWS API calls made via this gateway (CloudTrail):**

```bash
# Look up events by the gateway's IAM role in the last hour
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=aws-mcp-gateway-readonly \
  --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].{Time:EventTime,Event:EventName,Source:EventSource}' \
  --output table
```

**Find CloudWatch Logs Insights query — correlate by time window:**

```bash
# Query SSM session logs for commands run in a time window
aws logs start-query \
  --log-group-name /aws/ssm/sessions \
  --start-time $(date -u -v-1H +%s) \
  --end-time $(date -u +%s) \
  --query-string 'fields @timestamp, sessionId, target, @message | sort @timestamp desc | limit 50'

# Get results (replace QUERY_ID with the id returned above)
aws logs get-query-results --query-id QUERY_ID \
  --query 'results[*][?field==`@message`].value' --output text
```

**CloudWatch Logs Insights — ECS Exec logs:**

```bash
aws logs start-query \
  --log-group-name /ecs/exec-logs \
  --start-time $(date -u -v-1H +%s) \
  --end-time $(date -u +%s) \
  --query-string 'fields @timestamp, container, @message | sort @timestamp desc | limit 50'
```

**CloudWatch Logs Insights — Lambda invocation logs (Pattern 4):**

```bash
aws logs start-query \
  --log-group-name /aws/lambda/your-function-name \
  --start-time $(date -u -v-1H +%s) \
  --end-time $(date -u +%s) \
  --query-string 'fields @timestamp, @requestId, @message | filter @message like /START|END|REPORT/ | sort @timestamp desc'
```

**Correlate gateway user identity with CloudTrail (cross-reference by time):**

```bash
# 1. Find gateway access logs around the suspicious time (adjust log source as needed)
#    Gateway logs contain OIDC email/sub per request

# 2. Query CloudTrail for the same time window with the gateway role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=aws-mcp-gateway-debug \
  --start-time 2026-01-01T10:00:00Z \
  --end-time 2026-01-01T10:05:00Z \
  --output json | jq '.Events[] | {time: .EventTime, action: .EventName, resource: .Resources}'
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
