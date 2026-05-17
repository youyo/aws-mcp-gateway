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
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
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

// ctxKey はコンテキストキーの型。
type ctxKey int

const (
	ctxKeyRPCID ctxKey = iota // JSON-RPC id をコンテキストに格納するキー
)

// pendingRequest は 202 待ちの JSON-RPC リクエスト。
type pendingRequest struct {
	respCh chan string
}

// upstreamSession はセッションごとの GET SSE 接続状態を管理する。
type upstreamSession struct {
	pending sync.Map        // JSON-RPC id(string) -> *pendingRequest
	ready   chan struct{}    // GET SSE 接続が確立したら close される
	cancel  context.CancelFunc
}

// activeSessions はアクティブな upstream セッションを管理する。
// キー: mcp-session-id (string) -> *upstreamSession
var activeSessions sync.Map

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
	if assumeRoleARN := strings.TrimSpace(os.Getenv("ASSUME_ROLE_ARN")); assumeRoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, assumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "aws-mcp-gateway"
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
		slog.Info("using assumed role", "role_arn", assumeRoleARN)
	}

	return &sigV4RoundTripper{
		base:    sigV4HTTPTransport,
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

// sigV4HTTPTransport は SigV4 署名リクエスト用の共有 HTTP Transport。
// mcp-proxy-for-aws に合わせて HTTP/1.1 固定にする（HTTP/2 は無効化）。
// AWS MCP Server の Streamable HTTP / SSE は HTTP/1.1 を前提としており、
// HTTP/2 で接続すると call_aws 等の API ツールが -32600 を返す場合がある。
var sigV4HTTPTransport = func() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	tr.MaxIdleConns = 100
	tr.MaxIdleConnsPerHost = 20
	tr.IdleConnTimeout = 90 * time.Second
	tr.TLSHandshakeTimeout = 10 * time.Second
	tr.ResponseHeaderTimeout = 30 * time.Second
	// HTTP/1.1 固定: mcp-proxy-for-aws と同じ transport 設定
	tr.ForceAttemptHTTP2 = false
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	return tr
}()

// federatedCredsCache はユーザーごとの CredentialsCache をキャッシュする。
// キー: "sub::tokenFingerprint"（8桁の sha256 hex）
// 同一トークンに対してリクエストごとに STS を呼ぶことを防ぐ。
var federatedCredsCache sync.Map

// tokenFingerprint は ID Token の sha256 上位 4 バイトを hex 文字列で返す。
// キャッシュキーのトークン同一性チェックに使用する（全文保持を避ける）。
func tokenFingerprint(idToken string) string {
	h := sha256.Sum256([]byte(idToken))
	return hex.EncodeToString(h[:4])
}

// getFederatedRoundTripper は (sub, idToken) をキーに CredentialsCache をキャッシュし、
// per-user SigV4 RoundTripper を返す。同一トークンでの二回目以降は STS 呼び出しなし。
func getFederatedRoundTripper(ctx context.Context, region, service, roleARN, idToken, sub string) (*sigV4RoundTripper, error) {
	cacheKey := sub + "::" + tokenFingerprint(idToken)

	if cached, ok := federatedCredsCache.Load(cacheKey); ok {
		creds := cached.(*aws.CredentialsCache)
		return makeFederatedRoundTripper(creds, cacheKey, region, service), nil
	}

	// cache miss: 同一 sub の古いトークン fingerprint エントリを削除（メモリリーク防止）
	oldPrefix := sub + "::"
	federatedCredsCache.Range(func(k, _ interface{}) bool {
		if ks, ok := k.(string); ok && strings.HasPrefix(ks, oldPrefix) && ks != cacheKey {
			federatedCredsCache.Delete(ks)
		}
		return true
	})

	baseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for federated role: %w", err)
	}

	sessionName := sanitizeSessionName("gw-" + sub)
	stsClient := sts.NewFromConfig(baseCfg)
	provider := stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, staticTokenRetriever(idToken),
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = sessionName
		},
	)
	newCreds := aws.NewCredentialsCache(provider)
	// LoadOrStore で thundering herd を緩和: 並列リクエストが同時に到達した場合、
	// 先にストアされたエントリを使い、重複ストアを防ぐ。
	actual, _ := federatedCredsCache.LoadOrStore(cacheKey, newCreds)
	creds := actual.(*aws.CredentialsCache)

	return makeFederatedRoundTripper(creds, cacheKey, region, service), nil
}

// makeFederatedRoundTripper は CredentialsCache から per-user SigV4 RoundTripper を生成する。
// STS 呼び出しが失敗した場合（poisoned entry 防止）、キャッシュエントリを削除して次回再試行を可能にする。
func makeFederatedRoundTripper(creds *aws.CredentialsCache, cacheKey, region, service string) *sigV4RoundTripper {
	return &sigV4RoundTripper{
		base:    sigV4HTTPTransport,
		signer:  v4.NewSigner(),
		region:  region,
		service: service,
		getCreds: func(ctx context.Context) (aws.Credentials, error) {
			c, err := creds.Retrieve(ctx)
			if err != nil {
				// permanent error のみ cache を削除（transient エラーでのキャッシュ thrash 防止）
				if classifyFederatedError(err) != federatedErrTransient {
					federatedCredsCache.Delete(cacheKey)
				}
				return aws.Credentials{}, err
			}
			return c, nil
		},
	}
}

// federatedErrorClass は STS エラーの種別。
type federatedErrorClass int

const (
	federatedErrTransient    federatedErrorClass = iota // throttling 等、キャッシュ保持
	federatedErrInvalidToken                            // IDToken 期限切れ・無効、認証要求
	federatedErrForbidden                               // AccessDenied、ロール設定の問題
)

// classifyFederatedError は STS エラーを HTTP 応答用に分類する。
func classifyFederatedError(err error) federatedErrorClass {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "InvalidIdentityToken", "ExpiredTokenException", "ExpiredToken":
			return federatedErrInvalidToken
		case "AccessDenied":
			return federatedErrForbidden
		}
	}
	return federatedErrTransient
}

// staticTokenRetriever implements stscreds.IdentityTokenRetriever for an in-memory token.
type staticTokenRetriever string

func (t staticTokenRetriever) GetIdentityToken() ([]byte, error) {
	return []byte(t), nil
}

// sanitizeSessionName removes characters not allowed in STS RoleSessionName and truncates to 64 chars.
// STS allows [\w+=,.@-]+ which includes '+'.
func sanitizeSessionName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '=' || r == ',' || r == '.' || r == '@' || r == '-' || r == '_' || r == '+' {
			b.WriteRune(r)
		}
	}
	name := b.String()
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// injectMetaAWSRegion は JSON-RPC リクエストボディの params._meta.AWS_REGION に region を注入する。
// AWS MCP Server の call_aws 等 API ツールは _meta.AWS_REGION が必須。
// mcp-proxy-for-aws の sigv4_helper.py の _inject_metadata_hook と同じ動作。
// また、JSON-RPC id をコンテキストに格納して ModifyResponse で参照できるようにする。
func injectMetaAWSRegion(r *http.Request, region string) *http.Request {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return r
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return r
	}

	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(body, &rpc); err != nil || rpc["jsonrpc"] == nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return r
	}

	var params map[string]json.RawMessage
	if raw, ok := rpc["params"]; ok {
		_ = json.Unmarshal(raw, &params)
	}
	if params == nil {
		params = make(map[string]json.RawMessage)
	}

	var meta map[string]json.RawMessage
	if raw, ok := params["_meta"]; ok {
		_ = json.Unmarshal(raw, &meta)
	}
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}

	// クライアントが明示した値を優先し、未設定時のみ注入する
	if _, ok := meta["AWS_REGION"]; !ok {
		meta["AWS_REGION"], _ = json.Marshal(region)
	}

	params["_meta"], _ = json.Marshal(meta)
	rpc["params"], _ = json.Marshal(params)
	newBody, err := json.Marshal(rpc)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return r
	}

	// JSON-RPC id をコンテキストに格納（ModifyResponse で参照するため）
	ctx := r.Context()
	if idRaw, ok := rpc["id"]; ok {
		ctx = context.WithValue(ctx, ctxKeyRPCID, string(idRaw))
	}

	r2 := r.Clone(ctx)
	r2.Body = io.NopCloser(bytes.NewReader(newBody))
	r2.ContentLength = int64(len(newBody))
	return r2
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
	mcpEndpoint := target.String()
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1, // flush immediately for SSE / Streamable HTTP
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			r.Out.URL.Path = target.Path
			r.Out.Header.Set("x-amz-mcp-metadata-aws_region", targetAWSRegion)
			// mcp-proxy-for-aws と同じ Accept ヘッダーを設定する。
			// call_aws 等の API ツールは SSE ストリームで応答する可能性があり、
			// text/event-stream を含まないと -32600 を返す場合がある。
			r.Out.Header.Set("Accept", "application/json, text/event-stream")
			// Remove session cookies — they must not be forwarded to the upstream AWS MCP Server.
			r.Out.Header.Del("Cookie")
		},
		ModifyResponse: func(resp *http.Response) error {
			slog.Info("upstream response",
				"method", resp.Request.Method,
				"path", resp.Request.URL.Path,
				"status", resp.StatusCode,
			)

			sessionID := resp.Header.Get("mcp-session-id")

			// 200 + mcp-session-id: GET SSE チャネルを開始（先にセッションを登録してから goroutine 起動）
			if resp.StatusCode == http.StatusOK && sessionID != "" {
				newSess := &upstreamSession{ready: make(chan struct{})}
				if actual, loaded := activeSessions.LoadOrStore(sessionID, newSess); !loaded {
					go startUpstreamSSE(sessionID, newSess, mcpEndpoint, transport, targetAWSRegion)
				} else {
					// 既存セッションが ready 済みでなければ何もしない（goroutine が既に動いている）
					_ = actual
				}
			}

			// 202: SSE からレスポンスを待って同期的に返す
			if resp.StatusCode == http.StatusAccepted && sessionID != "" {
				rpcIDVal := resp.Request.Context().Value(ctxKeyRPCID)
				if rpcIDVal != nil {
					rpcID := rpcIDVal.(string)
					// upstreamSession を取得（まだなければ作成）
					sessVal, _ := activeSessions.LoadOrStore(sessionID, &upstreamSession{
						ready: make(chan struct{}),
					})
					sess := sessVal.(*upstreamSession)

					pr := &pendingRequest{
						respCh: make(chan string, 1),
					}
					sess.pending.Store(rpcID, pr)
					defer sess.pending.Delete(rpcID)

					// GET SSE が開くのを待つ
					select {
					case <-sess.ready:
					case <-time.After(10 * time.Second):
						slog.Warn("GET SSE チャネルが開かれなかった（タイムアウト）", "session_id", sessionID)
						return nil
					}

					// SSE からレスポンスを待つ
					select {
					case data := <-pr.respCh:
						// レスポンスを 200 に書き換える
						resp.StatusCode = http.StatusOK
						resp.Status = "200 OK"
						resp.Body = io.NopCloser(strings.NewReader(data))
						resp.ContentLength = int64(len(data))
						resp.Header.Set("Content-Type", "application/json")
					case <-time.After(30 * time.Second):
						slog.Warn("SSE レスポンスのタイムアウト", "session_id", sessionID, "rpc_id", rpcID)
					}
				}
			}

			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy error", "error", err.Error())
			// Return a generic message to avoid leaking upstream details (endpoint URLs, AWS error structures, etc.)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

// startUpstreamSSE は指定セッションの GET SSE チャネルを upstream に開き、
// SSE イベントを受信して pending request に届ける。
// sess は呼び出し元が activeSessions.LoadOrStore で登録済みのセッション。
func startUpstreamSSE(sessionID string, sess *upstreamSession, endpoint string, transport http.RoundTripper, region string) {
	ctx, cancel := context.WithCancel(context.Background())
	sess.cancel = cancel
	defer activeSessions.Delete(sessionID)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		slog.Error("GET SSE リクエスト作成失敗", "error", err.Error())
		return
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("mcp-session-id", sessionID)
	// mcp-proxy-for-aws が送るプロトコルバージョンヘッダー（サーバーが 2025-06-18 にネゴシエートする）
	req.Header.Set("mcp-protocol-version", "2025-06-18")
	req.Header.Set("x-amz-mcp-metadata-aws_region", region)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		slog.Error("GET SSE 接続失敗", "error", err.Error(), "session_id", sessionID)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("GET SSE 非 200 レスポンス", "status", resp.StatusCode, "session_id", sessionID)
		return
	}

	slog.Info("GET SSE チャネル確立", "session_id", sessionID)
	// ready を通知（待機中の pending request に接続確立を知らせる）
	close(sess.ready)

	// SSE イベントを読んで pending request に届ける
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1<<20), 8<<20) // 最大 8MB のイベントに対応
	var dataLines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		} else if line == "" && len(dataLines) > 0 {
			data := strings.Join(dataLines, "\n")
			dataLines = nil
			var msg map[string]json.RawMessage
			if json.Unmarshal([]byte(data), &msg) == nil {
				if idRaw, ok := msg["id"]; ok {
					idStr := string(idRaw)
					if v, ok := sess.pending.Load(idStr); ok {
						if pr, ok := v.(*pendingRequest); ok {
							select {
							case pr.respCh <- data:
							default:
							}
						}
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("GET SSE スキャンエラー", "error", err.Error(), "session_id", sessionID)
	}
	slog.Info("GET SSE チャネル終了", "session_id", sessionID)
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

	// IAM_MODE determines how AWS credentials are resolved per request.
	// "shared" (default): use the runtime role (Lambda/ECS/EC2) or ASSUME_ROLE_ARN.
	// "federated": use the OIDC ID Token to AssumeRoleWithWebIdentity per authenticated user.
	iamMode := getEnvOrDefault("IAM_MODE", "shared")
	federatedRoleARN := os.Getenv("FEDERATED_ROLE_ARN")
	if iamMode == "federated" && federatedRoleARN == "" {
		slog.Error("FEDERATED_ROLE_ARN is required when IAM_MODE=federated")
		os.Exit(1)
	}

	// StoreIDToken is required in federated mode to obtain the OIDC ID Token per request.
	storeIDToken := iamMode == "federated"

	authCfg := idproxy.Config{
		Providers:      []idproxy.OIDCProvider{provider},
		ExternalURL:    externalURL,
		CookieSecret:   cookieSecret,
		Store:          sessionStore,
		AllowedDomains: parsedDomains,
		AllowedEmails:  parsedEmails,
		StoreIDToken:   storeIDToken,
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
				"iam_mode", iamMode,
			)
		}

		// federated モードでは IDToken が必須。空の場合は shared role へのフォールバックを防ぐ。
		// IDToken は StoreIDToken=true + authorization_code フローで取得される。
		// 欠落時は 500 を返す（fail-closed）。
		if iamMode == "federated" {
			userSub := ""
			if user != nil {
				userSub = user.Subject
			}
			if user == nil || user.IDToken == "" {
				slog.Error("federated mode requires IDToken but none available",
					"user_sub", userSub,
					"hint", "ensure StoreIDToken=true and user authenticated via OIDC browser flow",
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			federatedTransport, ferr := getFederatedRoundTripper(r.Context(), mcpRegion, awsMCPService, federatedRoleARN, user.IDToken, user.Subject)
			if ferr != nil {
				slog.Error("failed to get federated round tripper", "error", ferr.Error(), "user_sub", user.Subject)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			// 事前 credentials 取得で STS エラーを HTTP ステータスへ変換する。
			// CredentialsCache が結果をキャッシュするため、proxy 内の再呼び出しは追加 STS コールにならない。
			if _, cerr := federatedTransport.getCreds(r.Context()); cerr != nil {
				switch classifyFederatedError(cerr) {
				case federatedErrInvalidToken:
					slog.Warn("federated STS rejected ID Token, client should re-authenticate",
						"error", cerr.Error(), "user_sub", user.Subject)
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="OIDC ID Token expired or invalid"`)
					http.Error(w, "invalid_token", http.StatusUnauthorized)
				case federatedErrForbidden:
					slog.Warn("federated STS denied access (role trust policy?)",
						"error", cerr.Error(), "user_sub", user.Subject)
					http.Error(w, "forbidden", http.StatusForbidden)
				default:
					slog.Error("federated STS transient error",
						"error", cerr.Error(), "user_sub", user.Subject)
					http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				}
				return
			}

			federatedProxy := buildProxy(target, federatedTransport, targetAWSRegion)
			federatedProxy.ServeHTTP(w, injectMetaAWSRegion(r, targetAWSRegion))
			return
		}

		proxy.ServeHTTP(w, injectMetaAWSRegion(r, targetAWSRegion))
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
