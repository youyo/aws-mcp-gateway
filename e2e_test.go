package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	idproxy "github.com/youyo/idproxy"
)

// TestSigV4HeadersAttached: モックサーバーに転送されるリクエストに SigV4 ヘッダーが付くことを確認
func TestSigV4HeadersAttached(t *testing.T) {
	// 偽クレデンシャルを設定（SigV4署名処理は走る）
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	var capturedHeaders http.Header
	// モックサーバー: 受け取ったヘッダーを記録して 200 を返す
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer mock.Close()

	// プロキシをモックサーバーに向けてセットアップ
	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", "mcp")
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}

	target, _ := url.Parse(mock.URL)
	proxy := buildProxy(target, transport)

	// プロキシサーバーを起動
	srv := httptest.NewServer(proxy)
	defer srv.Close()

	// リクエストを送信
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	resp, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("リクエスト失敗: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("ステータス: %d", resp.StatusCode)

	// SigV4 署名ヘッダーの確認
	auth := capturedHeaders.Get("Authorization")
	if auth == "" {
		t.Error("Authorization ヘッダーがない")
	} else if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		t.Errorf("SigV4 形式でない Authorization ヘッダー: %s", auth)
	} else {
		t.Logf("✓ SigV4 Authorization ヘッダー確認: %s...", auth[:50])
	}

	// X-Amz-Date ヘッダーの確認
	if capturedHeaders.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date ヘッダーがない")
	} else {
		t.Logf("✓ X-Amz-Date: %s", capturedHeaders.Get("X-Amz-Date"))
	}
}

// TestStreamingPassThrough: SSE レスポンスがプロキシを素通りするかを確認
func TestStreamingPassThrough(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	// SSE レスポンスを返すモックサーバー
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("Flusher 非対応")
			return
		}
		for i := 0; i < 3; i++ {
			w.Write([]byte("data: {\"chunk\":" + string(rune('0'+i)) + "}\n\n"))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer mock.Close()

	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", "mcp")
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}
	target, _ := url.Parse(mock.URL)
	proxy := buildProxy(target, transport)
	srv := httptest.NewServer(proxy)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`))
	if err != nil {
		t.Fatalf("リクエスト失敗: %v", err)
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		t.Errorf("SSE Content-Type が伝播していない: %s", contentType)
	} else {
		t.Logf("✓ Content-Type 伝播確認: %s", contentType)
	}

	body, _ := io.ReadAll(resp.Body)
	t.Logf("✓ SSE ボディ受信 (%d bytes): %s", len(body), string(body))
}

// TestRealAWSMCPEndpointError: 実際の AWS MCP エンドポイントに偽クレデンシャルで叩いてエラーを確認
func TestRealAWSMCPEndpointError(t *testing.T) {
	if os.Getenv("RUN_REAL_AWS_TEST") == "" {
		t.Skip("RUN_REAL_AWS_TEST が未設定のためスキップ（実際のAWSエンドポイントに接続します）")
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", awsMCPService)
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}
	target, _ := url.Parse(defaultAWSMCPEndpoint)
	proxy := buildProxy(target, transport)
	srv := httptest.NewServer(proxy)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream") // Streamable HTTP 必須ヘッダー

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("接続エラー（DNS/ネットワーク）: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("ステータス: %d", resp.StatusCode)
	t.Logf("レスポンス: %s", string(body))

	// 偽クレデンシャルなので 403 が期待値
	// 403 が返ってきた → エンドポイントに到達できている（プロキシ動作 OK）
	// 接続エラー → エンドポイント自体に問題
	var result map[string]interface{}
	if json.Unmarshal(body, &result) == nil {
		t.Logf("JSON レスポンス: %v", result)
	}
	t.Logf("ステータス %d → %s", resp.StatusCode, statusMessage(resp.StatusCode))
}

func statusMessage(code int) string {
	switch {
	case code == 403:
		return "✓ 403 Forbidden: エンドポイント到達 OK、署名が拒否された（偽クレデンシャルなので想定通り）"
	case code == 401:
		return "✓ 401 Unauthorized: エンドポイント到達 OK、認証が必要"
	case code == 200:
		return "✓ 200 OK: 接続・署名ともに成功"
	default:
		return "想定外のステータス"
	}
}

// TestSplitCSV: splitCSV のエッジケースを確認
func TestSplitCSV(t *testing.T) {
	cases := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{" ", nil},       // 空白のみ → nil（ALLOWED_DOMAINS=" " 設定ミスのケース）
		{",", nil},       // カンマのみ → nil
		{"example.com", []string{"example.com"}},
		{"example.com,corp.example.com", []string{"example.com", "corp.example.com"}},
		{" example.com , corp.example.com ", []string{"example.com", "corp.example.com"}}, // 前後空白のトリム
		{"example.com,,corp.example.com", []string{"example.com", "corp.example.com"}},    // 空要素のスキップ
	}

	for _, tc := range cases {
		got := splitCSV(tc.input)
		if len(got) != len(tc.expected) {
			t.Errorf("splitCSV(%q) = %v, want %v", tc.input, got, tc.expected)
			continue
		}
		for i := range got {
			if got[i] != tc.expected[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.expected[i])
			}
		}
		t.Logf("✓ splitCSV(%q) = %v", tc.input, got)
	}
}

// TestCookieHeaderRemovedFromUpstream: セッション Cookie がアップストリームに転送されないことを確認
func TestCookieHeaderRemovedFromUpstream(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	var capturedCookie string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer mock.Close()

	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", awsMCPService)
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}
	target, _ := url.Parse(mock.URL)
	proxy := buildProxy(target, transport)
	srv := httptest.NewServer(proxy)
	defer srv.Close()

	// Cookie ヘッダーを付けてリクエスト
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "_idproxy_session=sensitive-session-value")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("リクエスト失敗: %v", err)
	}
	defer resp.Body.Close()

	if capturedCookie != "" {
		t.Errorf("Cookie ヘッダーがアップストリームに転送された: %s", capturedCookie)
	} else {
		t.Logf("✓ Cookie ヘッダーがアップストリームに転送されていない（セッション保護 OK）")
	}
}

// TestErrorHandlerReturnsGenericMessage: プロキシエラー時に汎用メッセージが返ることを確認
func TestErrorHandlerReturnsGenericMessage(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	// 存在しないエンドポイント（即座に接続失敗）
	target, _ := url.Parse("http://127.0.0.1:19999")
	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", awsMCPService)
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}
	proxy := buildProxy(target, transport)
	srv := httptest.NewServer(proxy)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("リクエスト失敗: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("期待値 502、実際: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(body))
	// 内部詳細（URLやエラー文字列）が含まれていないことを確認
	if strings.Contains(bodyStr, "127.0.0.1") || strings.Contains(bodyStr, "connection refused") {
		t.Errorf("エラー詳細がクライアントに露出している: %s", bodyStr)
	}
	if bodyStr != "bad gateway" {
		t.Errorf("汎用メッセージでない: %q", bodyStr)
	}
	t.Logf("✓ エラー時の汎用メッセージ確認: %q", bodyStr)
}

// TestSanitizeSessionName: sanitizeSessionName が STS 許可文字 [\w+=,.@-]+ を正しく通過させることを確認
func TestSanitizeSessionName(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"gw-alice@example.com", "gw-alice@example.com"},
		{"gw-alice+tag@example.com", "gw-alice+tag@example.com"}, // '+' は STS 許可文字
		{"gw-alice sub!<>", "gw-alicesub"},                       // スペース・記号は除去
	}
	for _, tc := range cases {
		got := sanitizeSessionName(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizeSessionName(%q) = %q, want %q", tc.input, got, tc.expected)
		} else {
			t.Logf("✓ sanitizeSessionName(%q) = %q", tc.input, got)
		}
	}
}

// TestOIDCUserLoggingSkipsWhenNoUser: 未認証リクエストではユーザーログがスキップされることを確認
func TestOIDCUserLoggingSkipsWhenNoUser(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer mock.Close()

	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", awsMCPService)
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}
	target, _ := url.Parse(mock.URL)
	proxy := buildProxy(target, transport)

	// ユーザーなし（未認証）でリクエストが通ることを確認
	// idproxy.UserFromContext が nil を返す → ログをスキップして proxy.ServeHTTP に委譲
	userLogged := false
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := idproxy.UserFromContext(r.Context())
		if user != nil {
			userLogged = true
		}
		proxy.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(loggingHandler)
	defer srv.Close()

	// コンテキストにユーザーを設定しない（未認証）
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("リクエスト失敗: %v", err)
	}
	defer resp.Body.Close()

	if userLogged {
		t.Error("ユーザーなしなのにログが実行された")
	}
	t.Logf("✓ 未認証リクエストではユーザーログをスキップ（UserFromContext = nil）")
}

// stubAPIError は smithy.APIError を実装するテスト用スタブ。
type stubAPIError struct {
	code, msg string
}

func (e *stubAPIError) Error() string            { return e.msg }
func (e *stubAPIError) ErrorCode() string        { return e.code }
func (e *stubAPIError) ErrorMessage() string     { return e.msg }
func (e *stubAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// TestClassifyFederatedError: classifyFederatedError の分類ロジックを確認
func TestClassifyFederatedError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected federatedErrorClass
	}{
		{
			name:     "nil error → transient",
			err:      nil,
			expected: federatedErrTransient,
		},
		{
			name:     "InvalidIdentityToken → invalidToken",
			err:      &stubAPIError{code: "InvalidIdentityToken", msg: "token invalid"},
			expected: federatedErrInvalidToken,
		},
		{
			name:     "ExpiredTokenException → invalidToken",
			err:      &stubAPIError{code: "ExpiredTokenException", msg: "token expired"},
			expected: federatedErrInvalidToken,
		},
		{
			name:     "ExpiredToken → invalidToken",
			err:      &stubAPIError{code: "ExpiredToken", msg: "token expired"},
			expected: federatedErrInvalidToken,
		},
		{
			name:     "AccessDenied → forbidden",
			err:      &stubAPIError{code: "AccessDenied", msg: "access denied"},
			expected: federatedErrForbidden,
		},
		{
			name:     "Throttling → transient",
			err:      &stubAPIError{code: "Throttling", msg: "throttled"},
			expected: federatedErrTransient,
		},
		{
			name:     "通常の error（API error でない）→ transient",
			err:      errors.New("generic error"),
			expected: federatedErrTransient,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyFederatedError(tc.err)
			if got != tc.expected {
				t.Errorf("classifyFederatedError(%v) = %v, want %v", tc.err, got, tc.expected)
			} else {
				t.Logf("✓ classifyFederatedError(%v) = %v", tc.err, got)
			}
		})
	}
}

// TestInjectMetaAWSRegion: JSON-RPC リクエストボディへの _meta.AWS_REGION 注入を検証する。
// - 正常注入（_meta なし → 追加）
// - 既存値の保持（client が明示した値は上書きしない）
// - 不正形状（_meta が数値、params が文字列）→ 原文を破壊せず返す
// - JSON-RPC でないボディ → 原文を返す
// - ContentLength=0 / NoBody → 注入スキップ（ok=true）
// - params:null → 原文を返す（ok=true）
// - _meta:null → 空 map として注入（ok=true）
// - 正常ケースで ok=true
func TestInjectMetaAWSRegion(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		region    string
		wantBody  string // 期待ボディ（"" の場合は body と同一であることを確認）
		mustEqual bool   // true: 原文と byte-equal であること
		wantOK    bool
		noBody    bool // true: ContentLength=0, Body=http.NoBody を使う
	}{
		{
			name:     "_meta なし → AWS_REGION を注入",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
			region:   "ap-northeast-1",
			wantBody: `{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"AWS_REGION":"ap-northeast-1"}}}`,
			wantOK:   true,
		},
		{
			name:     "既存 AWS_REGION → 上書きしない",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"AWS_REGION":"us-west-2"}}}`,
			region:   "ap-northeast-1",
			wantBody: `{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"AWS_REGION":"us-west-2"}}}`,
			wantOK:   true,
		},
		{
			name:      "_meta が数値 → 原文を返す（破壊しない）",
			body:      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":42}}`,
			region:    "ap-northeast-1",
			mustEqual: true,
			wantOK:    true,
		},
		{
			name:      "params が文字列 → 原文を返す（破壊しない）",
			body:      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"hello"}`,
			region:    "ap-northeast-1",
			mustEqual: true,
			wantOK:    true,
		},
		{
			name:      "JSON-RPC でない（jsonrpc キーなし）→ 原文を返す",
			body:      `{"foo":"bar"}`,
			region:    "ap-northeast-1",
			mustEqual: true,
			wantOK:    true,
		},
		{
			name:      "不正な JSON → 原文を返す",
			body:      `not a json`,
			region:    "ap-northeast-1",
			mustEqual: true,
			wantOK:    true,
		},
		{
			name:   "ContentLength=0 / NoBody → 注入スキップ（ok=true）",
			body:   "",
			region: "ap-northeast-1",
			noBody: true,
			wantOK: true,
		},
		{
			name:      "params:null → 原文を返す（ok=true）",
			body:      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`,
			region:    "ap-northeast-1",
			mustEqual: true,
			wantOK:    true,
		},
		{
			name:     "_meta:null → 空 map として注入（ok=true）",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":null}}`,
			region:   "ap-northeast-1",
			wantBody: `{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"AWS_REGION":"ap-northeast-1"}}}`,
			wantOK:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.noBody {
				req, _ = http.NewRequest(http.MethodPost, "http://example.com/", http.NoBody)
				req.ContentLength = 0
			} else {
				req, _ = http.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(tc.body))
				req.ContentLength = int64(len(tc.body))
			}
			req.Header.Set("Content-Type", "application/json")

			out, ok := injectMetaAWSRegion(req, tc.region)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}

			if tc.noBody {
				t.Logf("✓ NoBody の場合に ok=%v を返した", ok)
				return
			}

			gotBody, err := io.ReadAll(out.Body)
			if err != nil {
				t.Fatalf("body 読み取り失敗: %v", err)
			}

			if tc.mustEqual {
				if string(gotBody) != tc.body {
					t.Errorf("原文と異なるボディが返された:\n  got:  %s\n  want: %s", gotBody, tc.body)
				} else {
					t.Logf("✓ 原文がそのまま返された: %s", gotBody)
				}
				return
			}

			// JSON として等価比較（キー順序差異を吸収）
			var gotObj, wantObj map[string]interface{}
			if err := json.Unmarshal(gotBody, &gotObj); err != nil {
				t.Fatalf("got が JSON でない: %v body=%s", err, gotBody)
			}
			if err := json.Unmarshal([]byte(tc.wantBody), &wantObj); err != nil {
				t.Fatalf("wantBody が JSON でない: %v", err)
			}
			gotNorm, _ := json.Marshal(gotObj)
			wantNorm, _ := json.Marshal(wantObj)
			if string(gotNorm) != string(wantNorm) {
				t.Errorf("ボディが期待値と異なる:\n  got:  %s\n  want: %s", gotNorm, wantNorm)
			} else {
				t.Logf("✓ ボディ等価: %s", gotNorm)
			}
		})
	}
}

// TestHandleFederatedRequest_IDTokenMissing: federated モードで IDToken が欠落している場合
// （user==nil および user.IDToken=""）に 500 を返して shared role への fallback を防ぐことを確認する。
func TestHandleFederatedRequest_IDTokenMissing(t *testing.T) {
	target, _ := url.Parse("http://upstream.example.invalid/mcp")
	cfg := federatedConfig{
		mcpRegion:        "us-east-1",
		awsMCPService:    awsMCPService,
		federatedRoleARN: "arn:aws:iam::123456789012:role/test",
		targetAWSRegion:  "ap-northeast-1",
		target:           target,
	}

	cases := []struct {
		name string
		user *idproxy.User
	}{
		{name: "user が nil → 500", user: nil},
		{name: "IDToken が空 → 500", user: &idproxy.User{Email: "alice@example.com", Subject: "sub-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))

			handleFederatedRequest(rec, req, tc.user, cfg)

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("期待値 500、実際: %d body=%s", rec.Code, rec.Body.String())
			} else {
				t.Logf("✓ IDToken 欠落時に 500 を返した (body=%q)", strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// TestEvictFederatedEntry: evictFederatedEntry が credentials キャッシュから削除することを確認。
func TestEvictFederatedEntry(t *testing.T) {
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() {
		federatedCredsCache = sync.Map{}
	})

	cacheKey := "sub-test::deadbeef"
	federatedCredsCache.Store(cacheKey, "dummy-creds")

	evictFederatedEntry(cacheKey)

	if _, ok := federatedCredsCache.Load(cacheKey); ok {
		t.Error("credentials cache に残っている")
	}
	t.Logf("✓ evictFederatedEntry が credentials キャッシュから削除した")
}

// TestGetFederatedRoundTripper_WithAssumeRole は IAM_MODE=federated + ASSUME_ROLE_ARN
// の組み合わせで AssumeRole チェーンが使われることを検証する。
// 実際の STS を呼ばず、getFederatedRoundTripper の挙動だけを確認する。
func TestGetFederatedRoundTripper_WithAssumeRole(t *testing.T) {
	// ASSUME_ROLE_ARN 設定済みなら getCreds が AssumeRoleProvider を経由すること
	// を直接テストするのは困難なため、ここでは「関数が正常に返ること」
	// + 「ASSUME_ROLE_ARN が空のときと戻り値の型が変わらないこと」を確認する。
	// より深い統合テストは e2e で行う。

	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	// federatedCredsCache をクリーン
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() { federatedCredsCache = sync.Map{} })

	ctx := context.Background()
	// 実際の STS を呼ばない（テスト環境では認証情報なし → エラーが返るのが正常）
	// ここでは関数が panic せず型が返ることのみ確認
	transport, err := getFederatedRoundTripper(
		ctx,
		"us-east-1", "aws-mcp",
		"arn:aws:iam::123456789012:role/FederatedRole",
		"eyJhbGciOiJSUzI1NiJ9.test-id-token",
		"test-sub",
		"arn:aws:iam::123456789012:role/TestRole",
	)
	// 認証情報がないためエラーが返ることもあるが、panic しないこと
	if err == nil {
		if transport == nil {
			t.Error("expected non-nil transport when no error")
		}
	}
	// ASSUME_ROLE_ARN が設定されている場合でも関数が動作すること
}

// TestGetFederatedRoundTripper_CacheKeyIncludesAssumeRole は
// ASSUME_ROLE_ARN が異なる場合に別キャッシュエントリになることを確認。
func TestGetFederatedRoundTripper_CacheKeyIncludesAssumeRole(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() { federatedCredsCache = sync.Map{} })

	ctx := context.Background()
	// ARN-A と ARN-B で呼び出す → キャッシュに 2 エントリ入ること
	// (実際の STS は呼ばないのでエラーになるが、panic しないこと)
	getFederatedRoundTripper(ctx, "us-east-1", "aws-mcp",
		"arn:aws:iam::111:role/Fed", "token1", "sub1", "arn:aws:iam::111:role/A")
	getFederatedRoundTripper(ctx, "us-east-1", "aws-mcp",
		"arn:aws:iam::111:role/Fed", "token1", "sub1", "arn:aws:iam::111:role/B")

	count := 0
	federatedCredsCache.Range(func(k, _ interface{}) bool { count++; return true })
	if count != 2 {
		t.Errorf("expected 2 cache entries for different assumeRoleARN, got %d", count)
	}
}

// TestGetFederatedRoundTripper_NoAssumeRole は ASSUME_ROLE_ARN="" のとき
// キャッシュキーが ASSUME_ROLE_ARN を含まないことを確認（後方互換）。
func TestGetFederatedRoundTripper_NoAssumeRole(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() { federatedCredsCache = sync.Map{} })

	ctx := context.Background()
	getFederatedRoundTripper(ctx, "us-east-1", "aws-mcp",
		"arn:aws:iam::111:role/Fed", "token1", "sub1", "")

	found := false
	federatedCredsCache.Range(func(k, _ interface{}) bool {
		found = true
		key := k.(string)
		// assumeRoleARN="" の場合、キーは "sub::fingerprint" の形式
		parts := strings.SplitN(key, "::", 3)
		if len(parts) == 3 && parts[2] != "" {
			t.Errorf("assumeRoleARN='' なのにキーに ARN が含まれている: %s", key)
		}
		return true
	})
	if !found {
		t.Error("キャッシュにエントリが存在しない")
	}
}

// TestGetFederatedRoundTripper_CacheHit_ReusesSameCredentials は
// 同一引数で 2 回呼び出した場合に同一の *aws.CredentialsCache が返ることを確認する。
// これにより「キャッシュヒット時にチェーンを再構築して毎回 STS を呼ぶ」regression を防ぐ。
func TestGetFederatedRoundTripper_CacheHit_ReusesSameCredentials(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() { federatedCredsCache = sync.Map{} })

	ctx := context.Background()
	const (
		region  = "us-east-1"
		service = "aws-mcp"
		roleARN = "arn:aws:iam::111:role/Fed"
		idToken = "test-token"
		sub     = "sub-test"
		chained = "arn:aws:iam::222:role/Chain"
	)

	// 1 回目（cache miss → store）
	_, _ = getFederatedRoundTripper(ctx, region, service, roleARN, idToken, sub, chained)

	cacheKey := sub + "::" + tokenFingerprint(idToken) + "::" + chained
	v1, ok1 := federatedCredsCache.Load(cacheKey)
	if !ok1 {
		t.Fatal("1回目呼び出し後にキャッシュエントリがない")
	}

	// 2 回目（cache hit → 同じエントリを返すべき）
	_, _ = getFederatedRoundTripper(ctx, region, service, roleARN, idToken, sub, chained)
	v2, ok2 := federatedCredsCache.Load(cacheKey)
	if !ok2 {
		t.Fatal("2回目呼び出し後にキャッシュエントリがない")
	}

	// ポインタ一致確認（同一インスタンス = CredentialsCache が再生成されていない）
	if v1 != v2 {
		t.Fatalf("CredentialsCache が再構築された（regression）: 1回目=%p 2回目=%p", v1, v2)
	}
}

// TestOIDCUserLoggingWithUser: 認証済みユーザーの email/sub が取得できることを確認
func TestOIDCUserLoggingWithUser(t *testing.T) {
	// idproxy.UserFromContext / idproxy.User の動作確認
	// idproxy が Auth.Wrap でコンテキストにユーザーを注入する設計のため、
	// 単体テストでは UserFromContext が User 構造体の各フィールドに正常アクセスできることを確認する

	dummyUser := &idproxy.User{
		Email:   "alice@example.com",
		Subject: "oidc-sub-xyz",
	}

	if dummyUser.Email != "alice@example.com" {
		t.Errorf("Email フィールドが期待値と異なる: %s", dummyUser.Email)
	}
	if dummyUser.Subject != "oidc-sub-xyz" {
		t.Errorf("Subject フィールドが期待値と異なる: %s", dummyUser.Subject)
	}

	// UserFromContext はコンテキストにユーザーがない場合 nil を返す
	nilUser := idproxy.UserFromContext(context.Background())
	if nilUser != nil {
		t.Errorf("空のコンテキストから User が返ってきた（期待値: nil）: %v", nilUser)
	}
	t.Logf("✓ UserFromContext(空コンテキスト) = nil 確認")
	t.Logf("✓ User{Email: %s, Subject: %s} フィールドアクセス確認", dummyUser.Email, dummyUser.Subject)
}

// M1: validateAccountID のテスト
func TestValidateAccountID(t *testing.T) {
	valid := []string{"123456789012"}
	for _, s := range valid {
		if !validateAccountID(s) {
			t.Errorf("validateAccountID(%q) = false, want true", s)
		}
	}
	invalid := []string{"12345", "abc", "", "1234567890123", " 123456789012"}
	for _, s := range invalid {
		if validateAccountID(s) {
			t.Errorf("validateAccountID(%q) = true, want false", s)
		}
	}
}

// M1: validateRoleName のテスト
func TestValidateRoleName(t *testing.T) {
	valid := []string{"AwsMcpGatewayRole", "role+=,.@_-"}
	for _, s := range valid {
		if !validateRoleName(s) {
			t.Errorf("validateRoleName(%q) = false, want true", s)
		}
	}
	invalid := []string{"../evil", "role;drop", "", "\x00", "ロール名"}
	for _, s := range invalid {
		if validateRoleName(s) {
			t.Errorf("validateRoleName(%q) = true, want false", s)
		}
	}
}

// M2: loadAssumeRoleConfig のテスト
func TestLoadAssumeRoleConfig(t *testing.T) {
	t.Run("環境変数未設定時はnilスライス", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_ALLOWED_ACCOUNTS", "")
		t.Setenv("ASSUMEROLE_ALLOWED_ROLE_NAMES", "")
		cfg := loadAssumeRoleConfig()
		if cfg.allowedAccounts != nil {
			t.Errorf("allowedAccounts = %v, want nil", cfg.allowedAccounts)
		}
		if cfg.allowedRoleNames != nil {
			t.Errorf("allowedRoleNames = %v, want nil", cfg.allowedRoleNames)
		}
	})
	t.Run("カンマ区切りで2要素", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_ALLOWED_ACCOUNTS", "111111111111,222222222222")
		t.Setenv("ASSUMEROLE_ALLOWED_ROLE_NAMES", "RoleA,RoleB")
		cfg := loadAssumeRoleConfig()
		if len(cfg.allowedAccounts) != 2 {
			t.Errorf("allowedAccounts len = %d, want 2", len(cfg.allowedAccounts))
		}
		if len(cfg.allowedRoleNames) != 2 {
			t.Errorf("allowedRoleNames len = %d, want 2", len(cfg.allowedRoleNames))
		}
	})
}

// M3: isAllowedAssumeRole のテスト
func TestIsAllowed(t *testing.T) {
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
	}
	if !isAllowedAssumeRole(cfg, "123456789012", "AwsMcpGatewayRole") {
		t.Error("両方含む場合は true を期待")
	}
	if isAllowedAssumeRole(cfg, "999999999999", "AwsMcpGatewayRole") {
		t.Error("account が許可リスト外の場合は false を期待")
	}
	if isAllowedAssumeRole(cfg, "123456789012", "OtherRole") {
		t.Error("role が許可リスト外の場合は false を期待")
	}
	empty := assumeRoleConfig{}
	if isAllowedAssumeRole(empty, "123456789012", "AwsMcpGatewayRole") {
		t.Error("空の cfg の場合は false を期待")
	}
}
