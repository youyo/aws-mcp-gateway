// aws-mcp-gateway: OIDC-authenticated reverse proxy for AWS MCP Server.
//
// Architecture:
//
//	MCP Client (Claude Code etc.)
//	  ↓ OAuth 2.1 (Bearer Token)
//	idproxy (EntraID OIDC auth)
//	  ↓ upstream HTTP
//	httputil.ReverseProxy + SigV4 RoundTripper
//	  ↓ Streamable HTTP + SigV4
//	AWS MCP Server (managed)
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
	"crypto/x509"
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

	// maxRequestBodyBytes は受け入れるリクエストボディの最大サイズ。
	// Lambda Function URL のペイロード上限（6 MiB）に合わせて設定し、
	// ECS/EC2 等の長時間稼働環境でのメモリ DoS を防ぐ多層防御。
	maxRequestBodyBytes = 6 * 1024 * 1024 // 6 MiB
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
		// Second line of defence (the handler layer applies MaxBytesReader):
		// read up to limit+1 to detect oversized bodies and reject them explicitly.
		// Silent truncation is not acceptable — the proxy would SigV4-sign and
		// forward a payload different from what the caller sent.
		bodyBytes, err = io.ReadAll(io.LimitReader(req.Body, maxRequestBodyBytes+1))
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		if len(bodyBytes) > maxRequestBodyBytes {
			return nil, fmt.Errorf("request body exceeds %d bytes limit", maxRequestBodyBytes)
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

// federatedCacheEntry は federatedCredsCache のエントリ。
// 定期 sweep で経過時間を判定するため createdAt を保持する。
type federatedCacheEntry struct {
	creds     *aws.CredentialsCache
	createdAt time.Time
}

// federatedCredsCache はユーザーごとの *federatedCacheEntry をキャッシュする。
// キー: "sub::tokenFingerprint"（16桁の sha256 hex）
// 同一トークンに対してリクエストごとに STS を呼ぶことを防ぐ。
var federatedCredsCache sync.Map

// evictFederatedEntry は cacheKey に紐づく credentials のキャッシュを削除する。
// permanent な STS エラー時や、同一 sub の古い fingerprint をパージする際に使用する。
func evictFederatedEntry(cacheKey string) {
	federatedCredsCache.Delete(cacheKey)
}

// tokenFingerprint は ID Token の sha256 上位 8 バイトを hex 文字列で返す。
// キャッシュキーのトークン同一性チェックに使用する（全文保持を避ける）。
// 8 バイト（16 hex 文字）で衝突空間 2^64 を確保する。
func tokenFingerprint(idToken string) string {
	h := sha256.Sum256([]byte(idToken))
	return hex.EncodeToString(h[:8])
}

// newWebIdentitySTSClient は WebIdentityRoleProvider に渡す STS クライアントを生成する。
// テストでオーバーライド可能な関数変数として公開することで、federated モードの
// WebIdentity STS 呼び出しをモック可能にする（本番コードは変更せず、テスト時のみ差し替える）。
var newWebIdentitySTSClient = func(ctx context.Context, region string) (stscreds.AssumeRoleWithWebIdentityAPIClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for WebIdentity STS client: %w", err)
	}
	return sts.NewFromConfig(cfg), nil
}

// newChainedSTSClient は WebIdentity CredentialsProvider をラップした baseCfg から
// AssumeRole 用 STS クライアントを生成する。
// テストでオーバーライド可能な関数変数として公開することで、federated assumerole
// パスのモックを可能にする（本番コードは変更せず、テスト時のみ差し替える）。
var newChainedSTSClient = func(ctx context.Context, region string, creds aws.CredentialsProvider) (stscreds.AssumeRoleAPIClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for chained STS client: %w", err)
	}
	cfg.Credentials = creds
	return sts.NewFromConfig(cfg), nil
}

// getFederatedCreds は (sub, idToken, assumeRoleARN) をキーに CredentialsCache をキャッシュし、
// per-user の CredentialsCache と cacheKey を返す。
// getFederatedRoundTripper および handleAssumeRoleRequest から共通で利用する。
//
// email が非空の場合は RoleSessionName に email を使用する（CloudTrail の可読性向上）。
// cacheKey は引き続き sub ベースで変更しない（email は変わりうるため）。
//
// assumeRoleARN が空でない場合はロールチェーンを構成する:
//
//	OIDC IDToken → roleARN (AssumeRoleWithWebIdentity) → assumeRoleARN (AssumeRole)
func getFederatedCreds(ctx context.Context, region, roleARN, idToken, sub, email, assumeRoleARN string) (*aws.CredentialsCache, string, error) {
	cacheKey := sub + "::" + tokenFingerprint(idToken)
	if assumeRoleARN != "" {
		cacheKey = cacheKey + "::" + assumeRoleARN
	}

	if cached, ok := federatedCredsCache.Load(cacheKey); ok {
		entry := cached.(*federatedCacheEntry)
		return entry.creds, cacheKey, nil
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

	// cache miss パスのみで sessionName を計算する（キャッシュヒット時は不要な処理をスキップ）
	// email が非空なら email を使用して CloudTrail の可読性を向上させる。cacheKey は sub ベースのまま。
	// buildSessionName でプレフィックス分を除いた残り文字数で識別子を切り詰める。
	sessionName := buildSessionName("gw-", sessionIdentifier(email, sub), "")

	webIdSTS, err := newWebIdentitySTSClient(ctx, region)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create WebIdentity STS client: %w", err)
	}
	provider := stscreds.NewWebIdentityRoleProvider(webIdSTS, roleARN, staticTokenRetriever(idToken),
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = sessionName
		},
	)
	var credsProvider aws.CredentialsProvider = aws.NewCredentialsCache(provider)

	// assumeRoleARN がある場合、キャッシュミス時のみチェーンを構築する。
	// チェーン込みの CredentialsCache をキャッシュするため、キャッシュヒット後は
	// 追加の STS:AssumeRole 呼び出しが発生しない。
	if assumeRoleARN != "" {
		// newChainedSTSClient で baseCfg を値コピーし Credentials のみ差し替える。
		// これにより FIPS・DualStack・VPC エンドポイント・Retryer 等の設定が継承される。
		chainSTS, cerr := newChainedSTSClient(ctx, region, credsProvider)
		if cerr != nil {
			return nil, "", cerr
		}
		chainProvider := stscreds.NewAssumeRoleProvider(chainSTS, assumeRoleARN, func(o *stscreds.AssumeRoleOptions) {
			// buildSessionName で "-chain" サフィックスを末尾に確保する。
			// 識別子が長い場合でも "-chain" が消失しない。
			o.RoleSessionName = buildSessionName("gw-", sessionIdentifier(email, sub), "-chain")
		})
		credsProvider = chainProvider
	}

	newCreds := aws.NewCredentialsCache(credsProvider)
	// LoadOrStore で thundering herd を緩和: 並列リクエストが同時に到達した場合、
	// 先にストアされたエントリを使い、重複ストアを防ぐ。
	actual, _ := federatedCredsCache.LoadOrStore(cacheKey, &federatedCacheEntry{
		creds:     newCreds,
		createdAt: time.Now(),
	})
	creds := actual.(*federatedCacheEntry).creds

	return creds, cacheKey, nil
}

// getFederatedRoundTripper は getFederatedCreds を呼び出し、
// per-user SigV4 RoundTripper を返す。後方互換を維持するためのラッパー。
//
// email が非空の場合は RoleSessionName に email を使用する（CloudTrail の可読性向上）。
// cacheKey は sub ベースのまま変更しない。
func getFederatedRoundTripper(ctx context.Context, region, service, roleARN, idToken, sub, email, assumeRoleARN string) (*sigV4RoundTripper, error) {
	creds, cacheKey, err := getFederatedCreds(ctx, region, roleARN, idToken, sub, email, assumeRoleARN)
	if err != nil {
		return nil, err
	}
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

// sessionIdentifier は STS RoleSessionName に使う識別子を返す。
// email が非空なら email を、空なら sub を返す。
// cacheKey には使わず、session name の計算のみに使用する。
func sessionIdentifier(email, sub string) string {
	if email != "" {
		return email
	}
	return sub
}

// sanitizeSessionName removes characters not allowed in STS RoleSessionName.
// STS allows [\w+=,.@-]+ which includes '+'.
// Length truncation is the caller's responsibility (buildSessionName handles it).
func sanitizeSessionName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '=' || r == ',' || r == '.' || r == '@' || r == '-' || r == '_' || r == '+' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// buildSessionName は prefix + sanitize(id) + suffix を組み立て、合計 64 文字以内に収める。
// suffix（"-chain" 等）を末尾に確保してからその分を identifier から切り詰めることで、
// suffix が長い identifier によって消失しないことを保証する。
// STS RoleSessionName は [\w+=,.@-]+ のみ許可するため sanitize を経由する。
func buildSessionName(prefix, id, suffix string) string {
	// prefix と suffix は STS 許可文字のみを含む前提（呼び出し側が責任を持つ）
	maxIDLen := 64 - len(prefix) - len(suffix)
	if maxIDLen < 0 {
		maxIDLen = 0
	}
	sanitized := sanitizeSessionName(id)
	if len(sanitized) > maxIDLen {
		sanitized = sanitized[:maxIDLen]
	}
	return prefix + sanitized + suffix
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
		table, err := requireEnv("DYNAMODB_TABLE")
		if err != nil {
			return nil, err
		}
		region := getEnvOrDefault("DYNAMODB_REGION", "ap-northeast-1")
		slog.Info("using DynamoDB session store", "table", table, "region", region)
		return store.NewDynamoDBStore(table, region)
	default:
		slog.Warn("using in-memory session store — sessions will be lost on restart (not suitable for Lambda)")
		return store.NewMemoryStore(), nil
	}
}

// sseWriteIdleTimeout は SSE / Streamable HTTP レスポンスのアイドル書き込み期限。
// クライアントが読み取りを停止すると、この時間で書き込みが失敗し goroutine リークを防ぐ。
// 書き込みごとに期限をリセットする（ロールング）ため、正常な長時間ストリームは切断されない。
const sseWriteIdleTimeout = 120 * time.Second

// writeDeadlineResponseWriter は各書き込みでロールング書き込み期限を設定する ResponseWriter ラッパー。
// サーバーレベル WriteTimeout は SSE 全体を一律に切断するため使えない。代わりに
// 接続単位で「アイドル」期限を設け、クライアントが idleTimeout の間読み取らなければ
// 次の書き込みが期限切れで失敗し、プロキシの goroutine がアンワインドされる。
type writeDeadlineResponseWriter struct {
	http.ResponseWriter
	rc          *http.ResponseController
	idleTimeout time.Duration
}

func newWriteDeadlineResponseWriter(w http.ResponseWriter, idleTimeout time.Duration) *writeDeadlineResponseWriter {
	return &writeDeadlineResponseWriter{
		ResponseWriter: w,
		rc:             http.NewResponseController(w),
		idleTimeout:    idleTimeout,
	}
}

// bump はアイドル書き込み期限を now+idleTimeout に更新する。
// SetWriteDeadline 非対応の ResponseWriter（テストの ResponseRecorder 等）では
// エラーが返るが無視する（その場合は期限制御が効かないだけで動作は継続する）。
func (w *writeDeadlineResponseWriter) bump() {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idleTimeout))
}

func (w *writeDeadlineResponseWriter) Write(p []byte) (int, error) {
	w.bump()
	return w.ResponseWriter.Write(p)
}

func (w *writeDeadlineResponseWriter) WriteHeader(statusCode int) {
	w.bump()
	w.ResponseWriter.WriteHeader(statusCode)
}

// Flush は ReverseProxy の FlushInterval=-1（SSE 即時フラッシュ）に対応する。
func (w *writeDeadlineResponseWriter) Flush() {
	_ = w.rc.Flush()
}

// Unwrap は http.NewResponseController が下層の ResponseWriter に到達できるようにする。
// これが無いと SetWriteDeadline / Flush が "not supported" になる。
func (w *writeDeadlineResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func buildProxy(target *url.URL, transport http.RoundTripper) http.Handler {
	rp := &httputil.ReverseProxy{
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(newWriteDeadlineResponseWriter(w, sseWriteIdleTimeout), r)
	})
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

	federatedTransport, ferr := getFederatedRoundTripper(r.Context(), cfg.mcpRegion, cfg.awsMCPService, cfg.federatedRoleARN, user.IDToken, user.Subject, user.Email, cfg.assumeRoleARN)
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

// loadSigningKey は SIGNING_KEY_HEX 環境変数から ECDSA P-256 秘密鍵をロードする。
// COOKIE_SECRET と同じパターン: 設定済みなら使用し、未設定なら ephemeral 鍵を生成して警告を出す。
//
// マルチインスタンス（Lambda 並行実行・ECS 複数タスク）では全インスタンスで同一の鍵を
// 共有する必要がある。idproxy はトークン検証にローカル署名検証を使用するため、
// インスタンス A が発行した JWT をインスタンス B が検証できなくなる。
//
// SIGNING_KEY_HEX の生成手順（Go の x509.MarshalPKCS8PrivateKey が出力する PKCS8 DER を推奨）:
//
//	go run -e 'package main; import ("crypto/ecdsa";"crypto/elliptic";"crypto/rand";"crypto/x509";"encoding/hex";"fmt"); func main() {k,_:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);d,_:=x509.MarshalPKCS8PrivateKey(k);fmt.Print(hex.EncodeToString(d))}'
//
// PKCS8 DER と SEC1 DER の両フォーマットを受け付ける。
// macOS 標準の LibreSSL は openssl genpkey でも SEC1 を出力する場合があるため。
func loadSigningKey() (*ecdsa.PrivateKey, error) {
	keyHex := strings.TrimSpace(os.Getenv("SIGNING_KEY_HEX"))
	if keyHex != "" {
		keyDER, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid SIGNING_KEY_HEX: must be hex-encoded DER: %w", err)
		}
		// PKCS8 DER を優先して試みる
		parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			// macOS LibreSSL は openssl genpkey でも SEC1 形式を出力する場合があるため
			// SEC1 (traditional EC private key format) もフォールバックとして受け付ける
			ecKey, sec1Err := x509.ParseECPrivateKey(keyDER)
			if sec1Err != nil {
				return nil, fmt.Errorf("invalid SIGNING_KEY_HEX: failed to parse as PKCS8 or SEC1 DER: %w", err)
			}
			if ecKey.Curve != elliptic.P256() {
				return nil, fmt.Errorf("invalid SIGNING_KEY_HEX: key must be ECDSA P-256 (got %s)", ecKey.Curve.Params().Name)
			}
			slog.Info("using ECDSA signing key from SIGNING_KEY_HEX (SEC1 format)")
			return ecKey, nil
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid SIGNING_KEY_HEX: key type %T is not ECDSA", parsed)
		}
		if ecKey.Curve != elliptic.P256() {
			return nil, fmt.Errorf("invalid SIGNING_KEY_HEX: key must be ECDSA P-256 (got %s), required for ES256 JWT signing", ecKey.Curve.Params().Name)
		}
		slog.Info("using ECDSA signing key from SIGNING_KEY_HEX")
		return ecKey, nil
	}
	slog.Warn("SIGNING_KEY_HEX not set, using ephemeral signing key — tokens will be invalid across restarts and multiple instances")
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// requireEnv は必須の環境変数を取得する。未設定なら error を返す。
// os.Exit せずエラーを返すことで、呼び出し元（main / newStore）でハンドリングでき、
// 統合テストでテストプロセスごと終了する問題を避ける。
func requireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("required environment variable not set: %s", key)
	}
	return v, nil
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
	// 必須環境変数をまとめて取得し、未設定があれば全てを報告して終了する。
	var missingEnv []string
	getRequired := func(key string) string {
		v, err := requireEnv(key)
		if err != nil {
			missingEnv = append(missingEnv, key)
		}
		return v
	}
	externalURL := getRequired("EXTERNAL_URL")
	oidcIssuer := getRequired("OIDC_ISSUER")
	oidcClientID := getRequired("OIDC_CLIENT_ID")
	oidcClientSecret := getRequired("OIDC_CLIENT_SECRET")
	if len(missingEnv) > 0 {
		slog.Error("required environment variables not set", "keys", missingEnv)
		os.Exit(1)
	}
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

	// ECDSA signing key for OAuth 2.1 JWT.
	// Set SIGNING_KEY_HEX (hex-encoded PKCS8 DER) for stable multi-instance deployments.
	// Without it, an ephemeral key is generated per process restart, which invalidates
	// tokens across Lambda concurrent executions and restarts.
	signingKey, err := loadSigningKey()
	if err != nil {
		slog.Error("failed to load ECDSA signing key", "error", err.Error())
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
	iamMode := strings.ToLower(strings.TrimSpace(getEnvOrDefault("IAM_MODE", "shared")))
	federatedRoleARN := os.Getenv("FEDERATED_ROLE_ARN")
	if iamMode != "shared" && iamMode != "federated" {
		slog.Error("invalid IAM_MODE: must be 'shared' or 'federated'", "value", iamMode)
		os.Exit(1)
	}
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

	// STS クライアントを assumerole エンドポイント用に生成する。
	// 設計上の決定:
	//   - IAM_MODE (shared/federated) に関わらず、ランタイムロール（実行環境の credentials）から
	//     直接 AssumeRole する。federated モードの per-user OIDC 認証情報は使わない。
	//   - ASSUME_ROLE_ARN も使わない。assumerole エンドポイントはパスで指定した
	//     account_id/role_name への AssumeRole が目的であり、中継ロールは不要。
	//   - OIDC 認証（auth.Wrap）は必須。ゲートウェイへのアクセス制御は idproxy が担保する。
	//     AWS 権限分離はランタイムロールの sts:AssumeRole 権限と allowlist で行う。
	assumeRoleCfg := loadAssumeRoleConfig()
	stsBaseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(mcpRegion))
	if err != nil {
		slog.Error("failed to load AWS config for STS client", "error", err.Error())
		os.Exit(1)
	}
	stsClient := sts.NewFromConfig(stsBaseCfg)

	// /mcp/assumerole/accounts/{account_id}/rolename/{role_name} は /mcp より具体的なため
	// Go 1.22+ の net/http パターンマッチングで自動的に優先される。
	http.Handle("/mcp/assumerole/accounts/{account_id}/rolename/{role_name}", auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		handleAssumeRoleRequest(w, r, user, assumeRoleCfg, target, stsClient, mcpRegion, targetAWSRegion, iamMode, federatedRoleARN)
	})))

	// Log OIDC user identity on every authenticated request for audit traceability.
	// This enables correlating gateway access logs (who) with CloudTrail (what AWS actions).
	loggingProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
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

	startCredsCacheSweeper(ctx, credsCacheSweepInterval, federatedCredsCacheTTL, assumeRoleCfg.maxCacheTTL)
	slog.Info("credentials cache sweeper started",
		"interval", credsCacheSweepInterval,
		"federated_ttl", federatedCredsCacheTTL,
		"assume_role_ttl", assumeRoleCfg.maxCacheTTL,
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

// assumeRoleCacheEntry はキャッシュエントリの作成時刻付きラッパー。
// maxCacheTTL 経過後は強制的に再作成してメモリリークを防ぐ。
// sessionName には STS に渡した実際の RoleSessionName を保存する。
// キャッシュヒット時でもログに正確な値を出力できる。
type assumeRoleCacheEntry struct {
	creds       *aws.CredentialsCache
	createdAt   time.Time
	sessionName string
}

// assumeRoleCredsCache はユーザー×ロールごとの *assumeRoleCacheEntry をキャッシュする。
// キー: "{account_id}::{role_name}::{subject}"
var assumeRoleCredsCache sync.Map

// sweepExpiredCredsCaches は createdAt が TTL を超えたキャッシュエントリを削除する。
// 定期実行され、別ユーザー・別ロールの古いエントリ（Range パージが届かないもの）を回収する。
// comma-ok アサーションで未知の値型（テストが格納するダミー文字列等）を安全にスキップする。
func sweepExpiredCredsCaches(now time.Time, federatedTTL, assumeRoleTTL time.Duration) {
	federatedCredsCache.Range(func(k, v any) bool {
		if e, ok := v.(*federatedCacheEntry); ok && now.Sub(e.createdAt) > federatedTTL {
			federatedCredsCache.Delete(k)
		}
		return true
	})
	assumeRoleCredsCache.Range(func(k, v any) bool {
		if e, ok := v.(*assumeRoleCacheEntry); ok && now.Sub(e.createdAt) > assumeRoleTTL {
			assumeRoleCredsCache.Delete(k)
		}
		return true
	})
}

// startCredsCacheSweeper は定期的に sweepExpiredCredsCaches を呼ぶ goroutine を起動する。
func startCredsCacheSweeper(ctx context.Context, interval, federatedTTL, assumeRoleTTL time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepExpiredCredsCaches(time.Now(), federatedTTL, assumeRoleTTL)
			}
		}
	}()
}

// buildAssumeRoleARN は accountID と roleName から IAM ロール ARN を生成する。
func buildAssumeRoleARN(accountID, roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
}

// getAssumeRoleCredentials は (accountID, roleName, sub[, tokenFP]) をキーに CredentialsCache をキャッシュし、
// AssumeRole による per-user クレデンシャルと実際に STS に渡した RoleSessionName を返す。
// maxCacheTTL 経過後はエントリを削除して再作成する（メモリリーク防止）。
// AccessDenied 時はキャッシュエントリを削除してエラーを返す。
// Throttling 等の transient エラー時はキャッシュを保持してエラーを返す。
//
// email が非空の場合は RoleSessionName に email を使用する（CloudTrail の可読性向上）。
// cacheKey は sub ベースのまま変更しない（email は変わりうるため）。
// キャッシュヒット時は作成時の sessionName を返すため、ログと CloudTrail が一致する。
//
// tokenFP が非空の場合（federated モード）はキャッシュキーに追加する。
// IDToken 更新時に古いキャッシュが再利用されることを防ぐ。
// shared モードでは空文字を渡して後方互換を維持する。
func getAssumeRoleCredentials(ctx context.Context, stsClient stscreds.AssumeRoleAPIClient, accountID, roleName, sub, email, externalID string, maxTTL time.Duration, tokenFP string) (*aws.CredentialsCache, string, error) {
	cacheKey := accountID + "::" + roleName + "::" + sub
	if tokenFP != "" {
		cacheKey = cacheKey + "::" + tokenFP
	}

	if cached, ok := assumeRoleCredsCache.Load(cacheKey); ok {
		entry := cached.(*assumeRoleCacheEntry)
		if time.Since(entry.createdAt) < maxTTL {
			return entry.creds, entry.sessionName, nil
		}
		// CompareAndDelete で TOCTOU を防ぐ: 自分が読んだエントリと同一の場合のみ削除。
		assumeRoleCredsCache.CompareAndDelete(cacheKey, cached)
	}

	// cache miss: federated モード（tokenFP != ""）で同一 accountID+roleName+sub の
	// 古い tokenFP エントリを削除する（メモリリーク防止）。
	// IDToken ローテーション時に tokenFP が変わり古いエントリが二度と参照されなくなるため。
	// federatedCredsCache の同様のロジック（Range による古い fingerprint のパージ）と対称的な実装。
	if tokenFP != "" {
		baseKey := accountID + "::" + roleName + "::" + sub + "::"
		assumeRoleCredsCache.Range(func(k, _ interface{}) bool {
			if ks, ok := k.(string); ok && strings.HasPrefix(ks, baseKey) && ks != cacheKey {
				assumeRoleCredsCache.Delete(ks)
			}
			return true
		})
	}

	roleARN := buildAssumeRoleARN(accountID, roleName)
	// email が非空なら email を使用して CloudTrail の可読性を向上させる。cacheKey は sub ベースのまま。
	// buildSessionName でプレフィックス分を除いた残り文字数で識別子を切り詰めるため、
	// サフィックスが長い識別子によって消失しない。
	sessionName := buildSessionName("gw-ar-", sessionIdentifier(email, sub), "")

	// STS セッション期間はデフォルト（1 時間）を使用する。
	// maxTTL はローカルキャッシュの退避 TTL であり STS セッション期間とは独立。
	// o.Duration を maxTTL に設定すると STS 最小 Duration（900 秒）を下回る可能性がある。
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		// ExternalId は配布先 target role の信頼ポリシー条件（Confused Deputy 攻撃対策）。
		// 空の場合は設定しない（ExternalId 条件を持たない既存ロールとの後方互換のため）。
		if externalID != "" {
			o.ExternalID = aws.String(externalID)
		}
	})

	// エビクションロジックを組み込んだ provider でラップした CredentialsCache をキャッシュする。
	evictingProvider := credentialsProviderFunc(func(innerCtx context.Context) (aws.Credentials, error) {
		c, err := provider.Retrieve(innerCtx)
		if err != nil {
			if classifyFederatedError(err) != federatedErrTransient {
				assumeRoleCredsCache.Delete(cacheKey)
			}
			return aws.Credentials{}, err
		}
		return c, nil
	})

	newEntry := &assumeRoleCacheEntry{
		// ExpiryWindow: STS トークン有効期限の 5 分前に自動更新を試みる。
		creds: aws.NewCredentialsCache(evictingProvider, func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = 5 * time.Minute
		}),
		createdAt:   time.Now(),
		sessionName: sessionName,
	}
	actual, _ := assumeRoleCredsCache.LoadOrStore(cacheKey, newEntry)
	actualEntry := actual.(*assumeRoleCacheEntry)
	return actualEntry.creds, actualEntry.sessionName, nil
}

// credentialsProviderFunc は関数を aws.CredentialsProvider として使えるようにするアダプタ。
type credentialsProviderFunc func(ctx context.Context) (aws.Credentials, error)

func (f credentialsProviderFunc) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return f(ctx)
}

var (
	reAccountID = regexp.MustCompile(`^[0-9]{12}$`)
	reRoleName  = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]+$`)
)

func validateAccountID(s string) bool { return reAccountID.MatchString(s) }
func validateRoleName(s string) bool {
	// IAM ロール名の最大長は 64 文字。
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	return reRoleName.MatchString(s)
}

type assumeRoleConfig struct {
	allowedAccounts  []string
	allowedRoleNames []string
	// externalID は配布先 target role の信頼ポリシーに設定された sts:ExternalId 条件値。
	// Confused Deputy 攻撃対策。空の場合は AssumeRole 時に ExternalId を付与しない。
	externalID  string
	maxCacheTTL time.Duration
}

const (
	defaultAssumeRoleMaxCacheTTL = 55 * time.Minute
	minAssumeRoleMaxCacheTTL     = 5 * time.Minute

	// credsCacheSweepInterval は credentials キャッシュの定期 sweep 間隔。
	credsCacheSweepInterval = 10 * time.Minute
	// federatedCredsCacheTTL は federatedCredsCache エントリの最大保持時間。
	// 離脱ユーザーのエントリ回収用。アクティブユーザーは WebIdentity で再認証され、
	// 約 1 時間に 1 回 STS 呼び出しが増える程度（assumeRole の maxCacheTTL 退避と同等の方針）。
	federatedCredsCacheTTL = 1 * time.Hour
)

func loadAssumeRoleConfig() assumeRoleConfig {
	cfg := assumeRoleConfig{
		allowedAccounts:  splitCSV(os.Getenv("ASSUMEROLE_ALLOWED_ACCOUNTS")),
		allowedRoleNames: splitCSV(os.Getenv("ASSUMEROLE_ALLOWED_ROLE_NAMES")),
		externalID:       strings.TrimSpace(os.Getenv("ASSUMEROLE_EXTERNAL_ID")),
		maxCacheTTL:      defaultAssumeRoleMaxCacheTTL,
	}
	if raw := os.Getenv("ASSUMEROLE_MAX_CACHE_TTL"); raw != "" {
		if d, err := time.ParseDuration(raw); err != nil {
			slog.Error("invalid ASSUMEROLE_MAX_CACHE_TTL, using default", "value", raw, "err", err, "default", defaultAssumeRoleMaxCacheTTL)
		} else if d < minAssumeRoleMaxCacheTTL {
			slog.Warn("ASSUMEROLE_MAX_CACHE_TTL too short, using minimum", "value", d, "min", minAssumeRoleMaxCacheTTL)
			cfg.maxCacheTTL = minAssumeRoleMaxCacheTTL
		} else {
			cfg.maxCacheTTL = d
		}
	}
	// role 名 allowlist が主制御。空なら全 assumerole リクエストが拒否される。
	if len(cfg.allowedRoleNames) == 0 {
		slog.Warn("ASSUMEROLE_ALLOWED_ROLE_NAMES is not set; all /mcp/assumerole/ requests will be denied")
	} else if cfg.externalID == "" {
		// assumerole が有効（role allowlist 設定済み）なのに ExternalId 未設定の場合、
		// 配布先 target role が ExternalId 条件を持つと全 AssumeRole が AccessDenied になる。
		// 逆に条件を持たない場合は Confused Deputy 対策が効いていないため、運用ミス検知として警告する。
		slog.Warn("ASSUMEROLE_EXTERNAL_ID is not set; AssumeRole requests will proceed without an ExternalId (Confused Deputy protection may be absent)")
	}
	// account allowlist 未設定 = 任意アカウント許可。開放姿勢を起動時に可視化する。
	if len(cfg.allowedRoleNames) > 0 && len(cfg.allowedAccounts) == 0 {
		slog.Warn("ASSUMEROLE_ALLOWED_ACCOUNTS is not set; AssumeRole permitted for any account with an allowed role name")
	}
	return cfg
}

func isAllowedAssumeRole(cfg assumeRoleConfig, accountID, roleName string) bool {
	// role 名 allowlist は必須の主制御。空なら全拒否（fail-closed）。
	if len(cfg.allowedRoleNames) == 0 {
		return false
	}
	// account allowlist は任意。空の場合は任意アカウントを許可する
	// （対象アカウントが多数の場合にリスト維持を不要にするため）。
	// 設定されている場合のみアカウントを制限する。
	// この場合の認可境界は role 名 allowlist + ExternalId + target role の信頼ポリシー。
	if len(cfg.allowedAccounts) > 0 {
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
	}
	for _, r := range cfg.allowedRoleNames {
		if r == roleName {
			return true
		}
	}
	return false
}

// handleAssumeRoleRequest は /mcp/assumerole/accounts/{account_id}/rolename/{role_name} へのリクエストを処理する。
// バリデーション → allowlist 認可 → STS AssumeRole → SigV4 署名プロキシ の順で処理する。
// エラーレスポンスには内部詳細（ARN、STS エラー文字列）を含めない（fail-closed）。
//
// iamMode が "federated" の場合、stsClient 引数（shared モード用）は無視し、
// user.IDToken を使って per-user CredentialsCache を生成した上で AssumeRole する。
// これにより CloudTrail の callerArn に assumed-role/{federatedRole}/gw-{sub} が記録される。
// shared モードは後方互換を完全維持する。
func handleAssumeRoleRequest(
	w http.ResponseWriter,
	r *http.Request,
	user *idproxy.User,
	cfg assumeRoleConfig,
	target *url.URL,
	stsClient stscreds.AssumeRoleAPIClient,
	mcpRegion string,
	targetAWSRegion string,
	iamMode string,
	federatedRoleARN string,
) {
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	}
	accountID := r.PathValue("account_id")
	roleName := r.PathValue("role_name")

	if !validateAccountID(accountID) {
		slog.Warn("assumerole invalid account_id", "account_id", accountID)
		http.Error(w, "invalid account_id", http.StatusBadRequest)
		return
	}
	if !validateRoleName(roleName) {
		slog.Warn("assumerole invalid role_name", "role_name", roleName)
		http.Error(w, "invalid role_name", http.StatusBadRequest)
		return
	}

	if user == nil || user.Subject == "" {
		slog.Error("assumerole missing user subject",
			"account_id", accountID,
			"role_name", roleName,
		)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if !isAllowedAssumeRole(cfg, accountID, roleName) {
		slog.Warn("assumerole forbidden: not in allowlist",
			"account_id", accountID,
			"role_name", roleName,
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// federated モード: IDToken から per-user STS クライアントを生成し AssumeRole する。
	// これにより CloudTrail の callerArn に assumed-role/{federatedRole}/gw-{sub} が記録される。
	// shared モード: 起動時生成のランタイムロール stsClient（引数）をそのまま使う（後方互換）。
	var tokenFP string
	if iamMode == "federated" {
		if user.IDToken == "" {
			slog.Error("assumerole federated mode requires IDToken but none available",
				"user_sub", user.Subject,
				"hint", "ensure StoreIDToken=true and user authenticated via OIDC browser flow",
			)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// getFederatedCreds で WebIdentity 認証済み CredentialsCache を取得する。
		// assumeRoleARN="" を渡して WebIdentity のみのチェーンにする（assumerole 自身が AssumeRole する）。
		federatedCreds, federatedCacheKey, ferr := getFederatedCreds(r.Context(), mcpRegion, federatedRoleARN, user.IDToken, user.Subject, user.Email, "")
		if ferr != nil {
			slog.Error("assumerole: failed to get federated credentials",
				"error", ferr.Error(),
				"user_sub", user.Subject,
			)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// getFederatedCreds が返す CredentialsCache の Retrieve() を呼び IDToken の有効性を確認する。
		// WebIdentity エラー（InvalidIdentityToken 等）をこの時点で HTTP ステータスへ変換する。
		// 注意: InvalidIdentityToken が smithy.APIError として伝播するかは SDK の実装依存。
		if _, ferr = federatedCreds.Retrieve(r.Context()); ferr != nil {
			switch classifyFederatedError(ferr) {
			case federatedErrInvalidToken:
				slog.Warn("assumerole federated STS rejected ID Token, client should re-authenticate",
					"error", ferr.Error(), "account_id", accountID, "role_name", roleName)
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="OIDC ID Token expired or invalid"`)
				http.Error(w, "invalid_token", http.StatusUnauthorized)
			case federatedErrForbidden:
				evictFederatedEntry(federatedCacheKey)
				slog.Warn("assumerole federated STS denied access",
					"error", ferr.Error(), "account_id", accountID, "role_name", roleName)
				http.Error(w, "forbidden", http.StatusForbidden)
			default:
				slog.Error("assumerole federated STS transient error",
					"error", ferr.Error(), "account_id", accountID, "role_name", roleName)
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			}
			return
		}

		// federated CredentialsCache から AssumeRole 用の STS クライアントを生成する。
		// baseCfg を値コピーし Credentials のみ差し替えるため FIPS・Retryer 等の設定が継承される。
		// TODO(quality): getAssumeRoleCredentials のキャッシュにヒットした場合、
		// この newChainedSTSClient 呼び出しは不要になる。
		// getAssumeRoleCredentials に lazy factory パターン（stsClient を func で受け取る）を
		// 適用すればキャッシュヒット時スキップが可能だが、e2e_test.go 内の直接呼び出し箇所
		// （8 箇所）のシグネチャ変更が必要となり影響範囲が大きいため現時点では見送る。
		chainSTS, cerr := newChainedSTSClient(r.Context(), mcpRegion, federatedCreds)
		if cerr != nil {
			slog.Error("assumerole: failed to create chained STS client",
				"error", cerr.Error(), "user_sub", user.Subject)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		stsClient = chainSTS
		// federated モードではキャッシュキーに tokenFingerprint を追加して IDToken 更新時に再生成する。
		tokenFP = tokenFingerprint(user.IDToken)
	}

	creds, sessionName, err := getAssumeRoleCredentials(r.Context(), stsClient, accountID, roleName, user.Subject, user.Email, cfg.externalID, cfg.maxCacheTTL, tokenFP)
	if err != nil {
		slog.Error("getAssumeRoleCredentials failed",
			"error", err.Error(),
			"account_id", accountID,
			"role_name", roleName,
		)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	// STS は Retrieve() 時に実際に呼ばれる。事前取得でエラーを HTTP ステータスへ変換する。
	// CredentialsCache が結果をキャッシュするため、proxy 内の再呼び出しは追加 STS コールにならない。
	if _, rerr := creds.Retrieve(r.Context()); rerr != nil {
		switch classifyFederatedError(rerr) {
		case federatedErrForbidden:
			slog.Warn("assumerole sts forbidden",
				"error", rerr.Error(),
				"account_id", accountID,
				"role_name", roleName,
			)
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			slog.Warn("assumerole sts error",
				"error", rerr.Error(),
				"account_id", accountID,
				"role_name", roleName,
			)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		}
		return
	}

	roleARN := buildAssumeRoleARN(accountID, roleName)
	// sessionName は getAssumeRoleCredentials が返した実際の値を使用する。
	// キャッシュヒット時でも作成時の sessionName を返すため、ログと CloudTrail が一致する。
	slog.Info("assumerole request",
		"account_id", accountID,
		"role_name", roleName,
		"role_arn", roleARN,
		"session_name", sessionName,
		"user_sub", user.Subject,
		"user_email", user.Email,
		"iam_mode", iamMode,
	)

	r, ok := injectMetaAWSRegion(r, targetAWSRegion)
	if !ok {
		slog.Warn("assumerole injectMetaAWSRegion failed",
			"account_id", accountID,
			"role_name", roleName,
		)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// makeFederatedRoundTripper と同パターンで STS クレデンシャルを注入した SigV4 Transport を組み立てる。
	transport := &sigV4RoundTripper{
		base:    sigV4HTTPTransport,
		signer:  v4.NewSigner(),
		region:  mcpRegion,
		service: awsMCPService,
		getCreds: func(ctx context.Context) (aws.Credentials, error) {
			return creds.Retrieve(ctx)
		},
	}
	buildProxy(target, transport).ServeHTTP(w, r)
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
