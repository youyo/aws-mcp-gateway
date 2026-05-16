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

### Pattern 1: Read-Only

Safe for read-only exploration — describe, list, and get operations only.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "aws-marketplace:View*",
        "*:Describe*",
        "*:Get*",
        "*:List*",
        "*:View*",
        "*:Search*",
        "*:Lookup*",
        "*:BatchGet*"
      ],
      "Resource": "*"
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

Full access to all AWS services. Use only in sandbox or personal accounts.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

```bash
aws iam attach-role-policy \
  --role-name aws-mcp-gateway-full \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

---

### Pattern 3: No Delete (Deny Destructive Actions)

Full access except for delete, terminate, and remove operations. Suitable for staging environments where provisioning is allowed but accidental deletion must be prevented.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "*:Delete*",
        "*:Terminate*",
        "*:Remove*",
        "*:Deregister*",
        "*:Detach*",
        "*:Destroy*",
        "*:Purge*",
        "s3:DeleteObject*",
        "s3:DeleteBucket*",
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
        "rds:DeleteDBCluster",
        "dynamodb:DeleteTable",
        "lambda:DeleteFunction"
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

### Pattern 4: Read-Only + Debug

Read-only access plus the ability to query logs, traces, and invoke Lambda for investigation. Useful for on-call engineers and SRE workflows.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "*:Describe*",
        "*:Get*",
        "*:List*",
        "*:View*",
        "*:Search*",
        "*:Lookup*",
        "*:BatchGet*",
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:GetQueryResults",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "cloudtrail:LookupEvents",
        "xray:GetTraceSummaries",
        "xray:BatchGetTraces",
        "xray:GetInsightSummaries",
        "lambda:InvokeFunction",
        "ssm:StartSession",
        "ssm:SendCommand",
        "ecs:ExecuteCommand"
      ],
      "Resource": "*"
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

Refer to [Understanding IAM for managed AWS MCP servers](https://aws.amazon.com/blogs/security/understanding-iam-for-managed-aws-mcp-servers/) for further details on IAM condition keys.

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
