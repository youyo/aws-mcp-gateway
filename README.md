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

Read-only access to common services. Suitable for safe exploration and auditing.

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

aws iam put-role-policy \
  --role-name aws-mcp-gateway-readonly \
  --policy-name mcp-readonly \
  --policy-document file://policy-readonly.json
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

> ⚠️ **This pattern grants execution-level permissions**, not read-only. `ssm:SendCommand`, `ecs:ExecuteCommand`, and `lambda:InvokeFunction` can affect running systems. These are essential for incident investigation — use only for trusted on-call engineers and SRE workflows with CloudTrail audit logging enabled.

Read access plus log querying, distributed tracing, Lambda invocation, and remote shell access for incident investigation.

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
