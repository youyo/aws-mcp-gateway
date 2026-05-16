// aws-mcp-gateway: OIDC-authenticated reverse proxy for AWS MCP Server.
//
// Architecture:
//   MCP Client (Claude Code etc.)
//     ↓ OAuth 2.1 (Bearer Token)
//   idproxy (EntraID OIDC auth)
//     ↓ upstream HTTP
//   httputil.ReverseProxy + SigV4 RoundTripper
//     ↓ Streamable HTTP + SigV4
//   AWS MCP Server (managed)
//
// AWS credentials are resolved automatically from the environment
// (Lambda execution role, ECS task role, EC2 instance profile, etc.)
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	idproxy "github.com/youyo/idproxy"
	"github.com/youyo/idproxy/store"
)

const (
	defaultAWSMCPEndpoint  = "https://aws-mcp.us-east-1.api.aws/mcp"
	awsMCPService          = "aws-mcp"
	defaultListenPort      = "8080"
	defaultTargetAWSRegion = "ap-northeast-1"
	defaultMCPRegion       = "us-east-1"
)

// sigV4RoundTripper signs outbound HTTP requests with AWS SigV4.
type sigV4RoundTripper struct {
	base     http.RoundTripper
	signer   *v4.Signer
	region   string
	service  string
	getCreds func(ctx context.Context) (aws.Credentials, error)
}

func newSigV4RoundTripper(ctx context.Context, region, service string) (*sigV4RoundTripper, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// If ASSUME_ROLE_ARN is set, assume the specified role before signing requests.
	// Useful when the runtime role (Lambda execution role, etc.) needs to access
	// a different AWS account or a role with narrower permissions.
	if assumeRoleARN := os.Getenv("ASSUME_ROLE_ARN"); assumeRoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, assumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "aws-mcp-gateway"
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
		slog.Info("using assumed role", "role_arn", assumeRoleARN)
	}

	return &sigV4RoundTripper{
		base:    http.DefaultTransport,
		signer:  v4.NewSigner(),
		region:  region,
		service: service,
		getCreds: func(ctx context.Context) (aws.Credentials, error) {
			return cfg.Credentials.Retrieve(ctx)
		},
	}, nil
}

func (t *sigV4RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	hash := sha256.Sum256(bodyBytes)
	payloadHash := fmt.Sprintf("%x", hash)

	creds, err := t.getCreds(req.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	if err := t.signer.SignHTTP(req.Context(), creds, req, payloadHash, t.service, t.region, time.Now()); err != nil {
		return nil, fmt.Errorf("SigV4 signing failed: %w", err)
	}

	return t.base.RoundTrip(req)
}

// newStore initializes the session store based on the STORE_BACKEND environment variable.
// Supported backends: "memory" (default), "dynamodb".
func newStore(ctx context.Context) (idproxy.Store, error) {
	backend := getEnvOrDefault("STORE_BACKEND", "memory")
	switch backend {
	case "dynamodb":
		table := mustEnv("DYNAMODB_TABLE")
		region := getEnvOrDefault("DYNAMODB_REGION", "ap-northeast-1")
		slog.Info("using DynamoDB session store", "table", table, "region", region)
		return store.NewDynamoDBStore(table, region)
	default:
		slog.Warn("using in-memory session store — sessions will be lost on restart (not suitable for Lambda)")
		return store.NewMemoryStore(), nil
	}
}

func buildProxy(target *url.URL, transport http.RoundTripper, targetAWSRegion string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1, // flush immediately for SSE / Streamable HTTP
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			r.Out.URL.Path = target.Path
			r.Out.Header.Set("x-amz-mcp-metadata-aws_region", targetAWSRegion)
			// Remove session cookies — they must not be forwarded to the upstream AWS MCP Server.
			r.Out.Header.Del("Cookie")
		},
		ModifyResponse: func(resp *http.Response) error {
			slog.Info("upstream response",
				"method", resp.Request.Method,
				"path", resp.Request.URL.Path,
				"status", resp.StatusCode,
			)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy error", "error", err.Error())
			// Return a generic message to avoid leaking upstream details (endpoint URLs, AWS error structures, etc.)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required environment variable not set", "key", key)
		os.Exit(1)
	}
	return v
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	// JSON structured logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx := context.Background()

	// Configuration
	mcpRegion := getEnvOrDefault("AWS_MCP_REGION", defaultMCPRegion)
	// AWS_MCP_ENDPOINT takes precedence; otherwise derive from AWS_MCP_REGION.
	// This allows future regions (e.g. ap-northeast-1) to work by just changing AWS_MCP_REGION.
	mcpEndpoint := os.Getenv("AWS_MCP_ENDPOINT")
	if mcpEndpoint == "" {
		mcpEndpoint = fmt.Sprintf("https://aws-mcp.%s.api.aws/mcp", mcpRegion)
	}
	targetAWSRegion := getEnvOrDefault("TARGET_AWS_REGION", defaultTargetAWSRegion)
	port := getEnvOrDefault("PORT", defaultListenPort)
	externalURL := mustEnv("EXTERNAL_URL")
	oidcIssuer := mustEnv("OIDC_ISSUER")
	oidcClientID := mustEnv("OIDC_CLIENT_ID")
	oidcClientSecret := mustEnv("OIDC_CLIENT_SECRET")
	allowedDomains := os.Getenv("ALLOWED_DOMAINS")
	allowedEmails := os.Getenv("ALLOWED_EMAILS")
	// Check the parsed result (not the raw strings) to catch whitespace-only values.
	parsedDomains := splitCSV(allowedDomains)
	parsedEmails := splitCSV(allowedEmails)
	if len(parsedDomains) == 0 && len(parsedEmails) == 0 {
		slog.Warn("ALLOWED_DOMAINS and ALLOWED_EMAILS are both empty — ANY authenticated user in the OIDC tenant can access the gateway. Set at least one to restrict access.")
	}

	cookieSecretHex := os.Getenv("COOKIE_SECRET")
	var cookieSecret []byte
	if cookieSecretHex != "" {
		var err error
		cookieSecret, err = hex.DecodeString(cookieSecretHex)
		if err != nil {
			slog.Error("invalid COOKIE_SECRET: must be hex-encoded", "error", err.Error())
			os.Exit(1)
		}
	} else {
		cookieSecret = make([]byte, 32)
		if _, err := rand.Read(cookieSecret); err != nil {
			slog.Error("failed to generate cookie secret", "error", err.Error())
			os.Exit(1)
		}
		slog.Warn("COOKIE_SECRET not set, using random secret (sessions will be lost on restart)")
	}

	// SigV4 transport
	transport, err := newSigV4RoundTripper(ctx, mcpRegion, awsMCPService)
	if err != nil {
		slog.Error("failed to create SigV4 round tripper", "error", err.Error())
		os.Exit(1)
	}

	// Reverse proxy to AWS MCP Server
	target, err := url.Parse(mcpEndpoint)
	if err != nil {
		slog.Error("invalid AWS MCP endpoint", "endpoint", mcpEndpoint, "error", err.Error())
		os.Exit(1)
	}
	proxy := buildProxy(target, transport, targetAWSRegion)

	// ECDSA signing key for OAuth 2.1 JWT (ephemeral; use a persisted key in production)
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("failed to generate ECDSA signing key", "error", err.Error())
		os.Exit(1)
	}

	// idproxy: OIDC auth + OAuth 2.1 Authorization Server
	provider := idproxy.OIDCProvider{
		Issuer:   oidcIssuer,
		ClientID: oidcClientID,
	}
	provider.ClientSecret = oidcClientSecret

	// Select session store backend via STORE_BACKEND env var.
	// "dynamodb" requires DYNAMODB_TABLE and DYNAMODB_REGION.
	// Default: "memory" (sessions lost on process restart — not suitable for Lambda).
	sessionStore, err := newStore(ctx)
	if err != nil {
		slog.Error("failed to initialize session store", "error", err.Error())
		os.Exit(1)
	}

	authCfg := idproxy.Config{
		Providers:      []idproxy.OIDCProvider{provider},
		ExternalURL:    externalURL,
		CookieSecret:   cookieSecret,
		Store:          sessionStore,
		AllowedDomains: parsedDomains,
		AllowedEmails:  parsedEmails,
		OAuth: &idproxy.OAuthConfig{
			SigningKey: signingKey,
		},
	}
	authCfg.UseStrictPostLoginRedirectValidator()

	auth, err := idproxy.New(ctx, authCfg)
	if err != nil {
		slog.Error("failed to initialize idproxy", "error", err.Error())
		os.Exit(1)
	}

	// Log OIDC user identity on every authenticated request for audit traceability.
	// This enables correlating gateway access logs (who) with CloudTrail (what AWS actions).
	loggingProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		if user != nil {
			slog.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"user_email", user.Email,
				"user_sub", user.Subject,
				"remote_addr", r.RemoteAddr,
			)
		}
		proxy.ServeHTTP(w, r)
	})

	http.Handle("/", auth.Wrap(loggingProxy))

	slog.Info("aws-mcp-gateway started",
		"addr", ":"+port,
		"endpoint", mcpEndpoint,
		"mcp_region", mcpRegion,
		"target_aws_region", targetAWSRegion,
		"external_url", externalURL,
		"oidc_issuer", oidcIssuer,
	)

	srv := &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// WriteTimeout is intentionally not set to support long-running SSE / Streamable HTTP responses.
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err.Error())
		os.Exit(1)
	}
}

// splitCSV splits a comma-separated string into a trimmed slice, returning nil for empty input.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			result = append(result, v)
		}
	}
	return result
}
