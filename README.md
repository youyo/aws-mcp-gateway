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
| `AWS_MCP_ENDPOINT` | AWS MCP Server endpoint URL | `https://aws-mcp.us-east-1.api.aws/mcp` |
| `AWS_MCP_REGION` | Region of the AWS MCP Server endpoint | `us-east-1` |
| `TARGET_AWS_REGION` | Default AWS region for API operations | `ap-northeast-1` |
| `PORT` | Listen port | `8080` |

> **Note:** `AWS_MCP_REGION` is the region where the MCP server endpoint is hosted (`us-east-1` or `eu-central-1`). `TARGET_AWS_REGION` is the region where AWS operations are performed — these can be different.

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

The IAM role attached to the runtime (Lambda, ECS, EC2) must allow the `aws-mcp` service:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:CalledViaFirst": "mcp.amazonaws.com"
        }
      }
    }
  ]
}
```

Refer to [Understanding IAM for managed AWS MCP servers](https://aws.amazon.com/blogs/security/understanding-iam-for-managed-aws-mcp-servers/) for fine-grained control.

## Quick Start

```bash
export EXTERNAL_URL=http://localhost:8080
export OIDC_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
export OIDC_CLIENT_ID=your-client-id
export OIDC_CLIENT_SECRET=your-client-secret
export COOKIE_SECRET=$(openssl rand -hex 32)

go run .
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
