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
	"regexp"
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
// http.DefaultTransport を clone して HTTP_PROXY/HTTPS_PROXY 環境変数や
// TLS 設定を保持しつつ、本番運用向けにタイムアウトと接続プールを設定する。
// HTTP/1.1 固定: mcp-proxy-for-aws と挙動を揃える（HTTP/2 ネゴシエーション不要）。
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
	tr.ResponseHeaderTimeout = 60 * time.Second
	tr.ForceAttemptHTTP2 = false
	// Clone the TLS config to avoid mutating DefaultTransport's shared instance.
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	return tr
}()

// federatedCredsCache はユーザーごとの CredentialsCache をキャッシュする。
// キー: "sub::tokenFingerprint"（8桁の sha256 hex）
// 同一トークンに対してリクエストごとに STS を呼ぶことを防ぐ。
var federatedCredsCache sync.Map

// evictFederatedEntry は cacheKey に紐づく credentials のキャッシュを削除する。
// permanent な STS エラー時や、同一 sub の古い fingerprint をパージする際に使用する。
func evictFederatedEntry(cacheKey string) {
	federatedCredsCache.Delete(cacheKey)
}

// tokenFingerprint は ID Token の sha256 上位 4 バイトを hex 文字列で返す。
// キャッシュキーのトークン同一性チェックに使用する（全文保持を避ける）。
func tokenFingerprint(idToken string) string {
	h := sha256.Sum256([]byte(idToken))
	return hex.EncodeToString(h[:4])
}

// getFederatedRoundTripper は (sub, idToken, assumeRoleARN) をキーに CredentialsCache をキャッシュし、
// per-user SigV4 RoundTripper を返す。同一トークンでの二回目以降は STS 呼び出しなし。
//
// assumeRoleARN が空でない場合はロールチェーンを構成する:
//   OIDC IDToken → roleARN (AssumeRoleWithWebIdentity) → assumeRoleARN (AssumeRole)
// ユーザー別の CloudTrail 追跡（RoleSessionName = gw-{sub}）は roleARN の
// セッション名で引き続き機能する。
func getFederatedRoundTripper(ctx context.Context, region, service, roleARN, idToken, sub, assumeRoleARN string) (*sigV4RoundTripper, error) {
	cacheKey := sub + "::" + tokenFingerprint(idToken)
	if assumeRoleARN != "" {
		cacheKey = cacheKey + "::" + assumeRoleARN
	}

	if cached, ok := federatedCredsCache.Load(cacheKey); ok {
		creds := cached.(*aws.CredentialsCache)
		return makeFederatedRoundTripper(creds, cacheKey, region, service), nil
	}

	// cache miss: 同一 sub で異なるトークン fingerprint のエントリを削除（メモリリーク防止）。
	// 同一 fp + 異なる assumeRoleARN のエントリはそのまま保持する。
	sameFPPrefix := sub + "::" + tokenFingerprint(idToken)
	subPrefix := sub + "::"
	federatedCredsCache.Range(func(k, _ interface{}) bool {
		if ks, ok := k.(string); ok && strings.HasPrefix(ks, subPrefix) && !strings.HasPrefix(ks, sameFPPrefix) {
			evictFederatedEntry(ks)
		}
		return true
	})

	baseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for federated role: %w", err)
	}

	// cache miss パスのみで sessionName を計算する（キャッシュヒット時は不要な処理をスキップ）
	sessionName := sanitizeSessionName("gw-" + sub)

	stsClient := sts.NewFromConfig(baseCfg)
	provider := stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, staticTokenRetriever(idToken),
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = sessionName
		},
	)
	var credsProvider aws.CredentialsProvider = aws.NewCredentialsCache(provider)

	// assumeRoleARN がある場合、キャッシュミス時のみチェーンを構築する。
	// チェーン込みの CredentialsCache をキャッシュするため、キャッシュヒット後は
	// 追加の STS:AssumeRole 呼び出しが発生しない。
	if assumeRoleARN != "" {
		// baseCfg を値コピーし Credentials のみ差し替える。
		// これにより FIPS・DualStack・VPC エンドポイント・Retryer 等の設定が継承される。
		chainCfg := baseCfg
		chainCfg.Credentials = credsProvider
		chainSTS := sts.NewFromConfig(chainCfg)
		chainProvider := stscreds.NewAssumeRoleProvider(chainSTS, assumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sanitizeSessionName("gw-" + sub + "-chain")
		})
		credsProvider = chainProvider
	}

	newCreds := aws.NewCredentialsCache(credsProvider)
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
					evictFederatedEntry(cacheKey)
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
//
// ok=false のとき呼び出し元は 400 Bad Request を返すべき（io.ReadAll 失敗時）。
// 不正な形状（params が object でない、_meta が object でない等）の場合は
// 原文ボディを破壊せずそのまま返す（fail-safe、ok=true）。
func injectMetaAWSRegion(r *http.Request, region string) (*http.Request, bool) {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return r, true
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return r, false
	}

	// 原文ボディを保持して返す共通関数（不正形状時の fail-safe パス）。
	returnOriginal := func() (*http.Request, bool) {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return r, true
	}

	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(body, &rpc); err != nil || rpc["jsonrpc"] == nil {
		return returnOriginal()
	}

	// params が存在する場合のみ object として解釈を試みる。
	// params が object でない（string, number, array 等）の場合は原文を返す。
	// params が null の場合も原文を返す（null は object として解釈できない）。
	var params map[string]json.RawMessage
	if raw, ok := rpc["params"]; ok {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return returnOriginal()
		}
		if err := json.Unmarshal(raw, &params); err != nil {
			return returnOriginal()
		}
	}
	if params == nil {
		params = make(map[string]json.RawMessage)
	}

	// _meta が存在する場合のみ object として解釈を試みる。
	// _meta が object でない（number 等）の場合は原文を返す。
	// _meta が null の場合は空 map として注入する。
	var meta map[string]json.RawMessage
	if raw, ok := params["_meta"]; ok {
		if !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			if err := json.Unmarshal(raw, &meta); err != nil {
				return returnOriginal()
			}
		}
	}
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}

	// クライアントが明示した値を優先し、未設定時のみ注入する
	if _, ok := meta["AWS_REGION"]; !ok {
		regionJSON, err := json.Marshal(region)
		if err != nil {
			return returnOriginal()
		}
		meta["AWS_REGION"] = regionJSON
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return returnOriginal()
	}
	params["_meta"] = metaJSON

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return returnOriginal()
	}
	rpc["params"] = paramsJSON

	newBody, err := json.Marshal(rpc)
	if err != nil {
		return returnOriginal()
	}

	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(newBody))
	r2.ContentLength = int64(len(newBody))
	return r2, true
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

func buildProxy(target *url.URL, transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1, // flush immediately for SSE / Streamable HTTP
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			r.Out.URL.Path = target.Path
			// Streamable HTTP に必要な Accept ヘッダーを設定する。
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
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy error", "error", err.Error())
			// Return a generic message to avoid leaking upstream details (endpoint URLs, AWS error structures, etc.)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

// federatedConfig は federated モード固有の設定値をまとめる。
// 関数引数の数を抑えるためのバンドル。
type federatedConfig struct {
	mcpRegion        string
	awsMCPService    string
	federatedRoleARN string
	assumeRoleARN    string
	targetAWSRegion  string
	target           *url.URL
}

// handleFederatedRequest は IAM_MODE=federated の場合のリクエストを処理する。
//   - IDToken が未取得（user==nil or IDToken=""）の場合は 500 を返す（shared への fallback を防ぐ）。
//   - per-user の SigV4 transport を取得し、STS エラーを HTTP ステータスへ変換する。
//   - ReverseProxy はリクエストごとに buildProxy で生成する（orphan proxy race 解消）。
func handleFederatedRequest(w http.ResponseWriter, r *http.Request, user *idproxy.User, cfg federatedConfig) {
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

	federatedTransport, ferr := getFederatedRoundTripper(r.Context(), cfg.mcpRegion, cfg.awsMCPService, cfg.federatedRoleARN, user.IDToken, user.Subject, cfg.assumeRoleARN)
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

	r, ok := injectMetaAWSRegion(r, cfg.targetAWSRegion)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	buildProxy(cfg.target, federatedTransport).ServeHTTP(w, r)
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

	transport, err := newSigV4RoundTripper(ctx, mcpRegion, awsMCPService)
	if err != nil {
		slog.Error("failed to create SigV4 round tripper", "error", err.Error())
		os.Exit(1)
	}

	target, err := url.Parse(mcpEndpoint)
	if err != nil {
		slog.Error("invalid AWS MCP endpoint", "endpoint", mcpEndpoint, "error", err.Error())
		os.Exit(1)
	}
	proxy := buildProxy(target, transport)

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

	authCfg := idproxy.Config{
		Providers:      []idproxy.OIDCProvider{provider},
		ExternalURL:    externalURL,
		CookieSecret:   cookieSecret,
		Store:          sessionStore,
		AllowedDomains: parsedDomains,
		AllowedEmails:  parsedEmails,
		// StoreIDToken is required in federated mode to obtain the OIDC ID Token per request.
		StoreIDToken: iamMode == "federated",
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

	fedCfg := federatedConfig{
		mcpRegion:        mcpRegion,
		awsMCPService:    awsMCPService,
		federatedRoleARN: federatedRoleARN,
		assumeRoleARN:    strings.TrimSpace(os.Getenv("ASSUME_ROLE_ARN")),
		targetAWSRegion:  targetAWSRegion,
		target:           target,
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
			handleFederatedRequest(w, r, user, fedCfg)
			return
		}

		r, ok := injectMetaAWSRegion(r, targetAWSRegion)
		if !ok {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
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

// M1: validateAccountID / validateRoleName

var (
	reAccountID = regexp.MustCompile(`^[0-9]{12}$`)
	reRoleName  = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]+$`)
)

func validateAccountID(s string) bool { return reAccountID.MatchString(s) }
func validateRoleName(s string) bool  { return reRoleName.MatchString(s) }

// M2: assumeRoleConfig / loadAssumeRoleConfig

type assumeRoleConfig struct {
	allowedAccounts  []string
	allowedRoleNames []string
}

func loadAssumeRoleConfig() assumeRoleConfig {
	cfg := assumeRoleConfig{
		allowedAccounts:  splitCSV(os.Getenv("ASSUMEROLE_ALLOWED_ACCOUNTS")),
		allowedRoleNames: splitCSV(os.Getenv("ASSUMEROLE_ALLOWED_ROLE_NAMES")),
	}
	if len(cfg.allowedAccounts) == 0 || len(cfg.allowedRoleNames) == 0 {
		slog.Warn("ASSUMEROLE_ALLOWED_ACCOUNTS or ASSUMEROLE_ALLOWED_ROLE_NAMES is not set; all /mcp/assumerole/ requests will be denied")
	}
	return cfg
}

// M3: isAllowedAssumeRole

func isAllowedAssumeRole(cfg assumeRoleConfig, accountID, roleName string) bool {
	if len(cfg.allowedAccounts) == 0 || len(cfg.allowedRoleNames) == 0 {
		return false
	}
	accountOK := false
	for _, a := range cfg.allowedAccounts {
		if a == accountID {
			accountOK = true
			break
		}
	}
	if !accountOK {
		return false
	}
	for _, r := range cfg.allowedRoleNames {
		if r == roleName {
			return true
		}
	}
	return false
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
