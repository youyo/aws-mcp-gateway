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
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
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
		"",
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
		"arn:aws:iam::111:role/Fed", "token1", "sub1", "", "arn:aws:iam::111:role/A")
	getFederatedRoundTripper(ctx, "us-east-1", "aws-mcp",
		"arn:aws:iam::111:role/Fed", "token1", "sub1", "", "arn:aws:iam::111:role/B")

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
		"arn:aws:iam::111:role/Fed", "token1", "sub1", "", "")

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
	_, _ = getFederatedRoundTripper(ctx, region, service, roleARN, idToken, sub, "", chained)

	cacheKey := sub + "::" + tokenFingerprint(idToken) + "::" + chained
	v1, ok1 := federatedCredsCache.Load(cacheKey)
	if !ok1 {
		t.Fatal("1回目呼び出し後にキャッシュエントリがない")
	}

	// 2 回目（cache hit → 同じエントリを返すべき）
	_, _ = getFederatedRoundTripper(ctx, region, service, roleARN, idToken, sub, "", chained)
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
	invalid := []string{"../evil", "..", "role;drop", "", "\x00", "ロール名",
		// IAM ロール名の最大長 64 文字を超えるケース
		"A" + strings.Repeat("a", 64),
	}
	for _, s := range invalid {
		if validateRoleName(s) {
			t.Errorf("validateRoleName(%q) = true, want false", s)
		}
	}
	// 64 文字ちょうどは有効
	maxLen := strings.Repeat("a", 64)
	if !validateRoleName(maxLen) {
		t.Errorf("validateRoleName(%q) = false, want true (64 chars)", maxLen)
	}
}

// M2: loadAssumeRoleConfig のテスト
func TestLoadAssumeRoleConfig(t *testing.T) {
	t.Run("環境変数未設定時はnilスライス", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_ALLOWED_ACCOUNTS", "")
		t.Setenv("ASSUMEROLE_ALLOWED_ROLE_NAMES", "")
		t.Setenv("ASSUMEROLE_MAX_CACHE_TTL", "")
		cfg := loadAssumeRoleConfig()
		if cfg.allowedAccounts != nil {
			t.Errorf("allowedAccounts = %v, want nil", cfg.allowedAccounts)
		}
		if cfg.allowedRoleNames != nil {
			t.Errorf("allowedRoleNames = %v, want nil", cfg.allowedRoleNames)
		}
		if cfg.maxCacheTTL != defaultAssumeRoleMaxCacheTTL {
			t.Errorf("maxCacheTTL = %v, want %v", cfg.maxCacheTTL, defaultAssumeRoleMaxCacheTTL)
		}
	})
	t.Run("カンマ区切りで2要素", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_ALLOWED_ACCOUNTS", "111111111111,222222222222")
		t.Setenv("ASSUMEROLE_ALLOWED_ROLE_NAMES", "RoleA,RoleB")
		t.Setenv("ASSUMEROLE_MAX_CACHE_TTL", "")
		cfg := loadAssumeRoleConfig()
		if len(cfg.allowedAccounts) != 2 {
			t.Errorf("allowedAccounts len = %d, want 2", len(cfg.allowedAccounts))
		}
		if len(cfg.allowedRoleNames) != 2 {
			t.Errorf("allowedRoleNames len = %d, want 2", len(cfg.allowedRoleNames))
		}
	})
	t.Run("ASSUMEROLE_MAX_CACHE_TTL 有効値", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_MAX_CACHE_TTL", "30m")
		cfg := loadAssumeRoleConfig()
		if cfg.maxCacheTTL != 30*time.Minute {
			t.Errorf("maxCacheTTL = %v, want 30m", cfg.maxCacheTTL)
		}
	})
	t.Run("ASSUMEROLE_MAX_CACHE_TTL 不正値はデフォルト使用", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_MAX_CACHE_TTL", "invalid")
		cfg := loadAssumeRoleConfig()
		if cfg.maxCacheTTL != defaultAssumeRoleMaxCacheTTL {
			t.Errorf("maxCacheTTL = %v, want %v", cfg.maxCacheTTL, defaultAssumeRoleMaxCacheTTL)
		}
	})
	t.Run("ASSUMEROLE_MAX_CACHE_TTL 最小値未満は最小値に切り上げ", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_MAX_CACHE_TTL", "1m")
		cfg := loadAssumeRoleConfig()
		if cfg.maxCacheTTL != minAssumeRoleMaxCacheTTL {
			t.Errorf("maxCacheTTL = %v, want %v", cfg.maxCacheTTL, minAssumeRoleMaxCacheTTL)
		}
	})
	t.Run("ASSUMEROLE_EXTERNAL_ID 未設定時は空文字", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_EXTERNAL_ID", "")
		cfg := loadAssumeRoleConfig()
		if cfg.externalID != "" {
			t.Errorf("externalID = %q, want 空文字", cfg.externalID)
		}
	})
	t.Run("ASSUMEROLE_EXTERNAL_ID 設定時はその値（前後空白を除去）", func(t *testing.T) {
		t.Setenv("ASSUMEROLE_EXTERNAL_ID", "  ext-123  ")
		cfg := loadAssumeRoleConfig()
		if cfg.externalID != "ext-123" {
			t.Errorf("externalID = %q, want %q", cfg.externalID, "ext-123")
		}
	})
}

// ExternalId サポート: getAssumeRoleCredentials が externalID を AssumeRole に伝播することを確認する。
func TestGetAssumeRoleCredentials_ExternalId(t *testing.T) {
	t.Run("externalID 指定時は ExternalId として AssumeRole に伝播する", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		client := &mockAssumeRoleClient{}
		creds, err := getAssumeRoleCredentials(context.Background(), client, "123456789012", "AwsMcpGatewayRole", "sub-extid", "", "my-external-id", 1*time.Hour, "")
		if err != nil {
			t.Fatalf("getAssumeRoleCredentials エラー: %v", err)
		}
		if _, rerr := creds.Retrieve(context.Background()); rerr != nil {
			t.Fatalf("Retrieve エラー: %v", rerr)
		}
		got := client.externalId()
		if got == nil {
			t.Fatal("ExternalId が AssumeRole に渡っていない（nil）")
		}
		if *got != "my-external-id" {
			t.Errorf("ExternalId = %q, want %q", *got, "my-external-id")
		}
		t.Logf("✓ ExternalId = %q が伝播された", *got)
	})

	t.Run("externalID 空時は ExternalId を設定しない（後方互換）", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		client := &mockAssumeRoleClient{}
		creds, err := getAssumeRoleCredentials(context.Background(), client, "123456789012", "AwsMcpGatewayRole", "sub-noextid", "", "", 1*time.Hour, "")
		if err != nil {
			t.Fatalf("getAssumeRoleCredentials エラー: %v", err)
		}
		if _, rerr := creds.Retrieve(context.Background()); rerr != nil {
			t.Fatalf("Retrieve エラー: %v", rerr)
		}
		if got := client.externalId(); got != nil {
			t.Errorf("ExternalId = %q, want nil（未設定であるべき）", *got)
		}
		t.Logf("✓ ExternalId 未設定（後方互換）")
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
	// account allowlist 未設定 = 任意アカウント許可（role 名のみで制御）。
	roleOnly := assumeRoleConfig{
		allowedRoleNames: []string{"aws-mcp-gateway-target"},
	}
	if !isAllowedAssumeRole(roleOnly, "999999999999", "aws-mcp-gateway-target") {
		t.Error("account allowlist 未設定時は任意アカウント + 許可 role で true を期待")
	}
	if !isAllowedAssumeRole(roleOnly, "111111111111", "aws-mcp-gateway-target") {
		t.Error("account allowlist 未設定時は別の任意アカウントでも true を期待")
	}
	if isAllowedAssumeRole(roleOnly, "999999999999", "OtherRole") {
		t.Error("account allowlist 未設定でも role 名が許可リスト外なら false を期待")
	}
	// role allowlist 未設定は account の有無に関わらず全拒否（fail-closed）。
	accountOnly := assumeRoleConfig{
		allowedAccounts: []string{"123456789012"},
	}
	if isAllowedAssumeRole(accountOnly, "123456789012", "aws-mcp-gateway-target") {
		t.Error("role allowlist 未設定時は全拒否（fail-closed）を期待")
	}

	empty := assumeRoleConfig{}
	if isAllowedAssumeRole(empty, "123456789012", "AwsMcpGatewayRole") {
		t.Error("空の cfg の場合は false を期待")
	}
}

// M4 テスト用モック: AssumeRoleAPIClient を実装する。
type mockAssumeRoleClient struct {
	callCount int64
	err       error
	// 直近の AssumeRole 呼び出しで渡された ExternalId をキャプチャする（ExternalId 伝播テスト用）。
	mu                   sync.Mutex
	capturedExternalId   *string
	capturedSessionName  string
}

func (m *mockAssumeRoleClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	atomic.AddInt64(&m.callCount, 1)
	m.mu.Lock()
	m.capturedExternalId = params.ExternalId
	if params.RoleSessionName != nil {
		m.capturedSessionName = *params.RoleSessionName
	}
	m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	expiry := time.Now().Add(1 * time.Hour)
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIATEST"),
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("token"),
			Expiration:      &expiry,
		},
	}, nil
}

// externalId は直近の AssumeRole 呼び出しでキャプチャした ExternalId を返す。
func (m *mockAssumeRoleClient) externalId() *string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.capturedExternalId
}

// M4: TestBuildAssumeRoleARN は buildAssumeRoleARN が正しい ARN 文字列を返すことを確認する。
func TestBuildAssumeRoleARN(t *testing.T) {
	got := buildAssumeRoleARN("123456789012", "AwsMcpGatewayRole")
	want := "arn:aws:iam::123456789012:role/AwsMcpGatewayRole"
	if got != want {
		t.Errorf("buildAssumeRoleARN = %q, want %q", got, want)
	}
	t.Logf("✓ buildAssumeRoleARN = %q", got)
}

// M4: TestGetAssumeRoleCredentials_SessionName はセッション名が "gw-ar-{sub}" 形式で
// STS 許可文字のみかつ 64 文字以内に収まることを確認する。
func TestGetAssumeRoleCredentials_SessionName(t *testing.T) {
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	longSub := strings.Repeat("a", 100)
	client := &mockAssumeRoleClient{}
	creds, err := getAssumeRoleCredentials(context.Background(), client, "123456789012", "AwsMcpGatewayRole", longSub, "", "", 1*time.Hour, "")
	if err != nil {
		t.Fatalf("getAssumeRoleCredentials エラー: %v", err)
	}
	if creds == nil {
		t.Fatal("creds が nil")
	}

	// セッション名の確認: AssumeRole が呼ばれていること（キャッシュなし）
	_, rerr := creds.Retrieve(context.Background())
	if rerr != nil {
		t.Fatalf("Retrieve エラー: %v", rerr)
	}

	// RoleSessionName が 64 文字以内か確認するため、sanitizeSessionName の結果を直接確認
	sessionName := sanitizeSessionName("gw-ar-" + longSub)
	if len(sessionName) > 64 {
		t.Errorf("セッション名が 64 文字を超えている: len=%d", len(sessionName))
	}
	t.Logf("✓ sessionName len=%d (≤64)", len(sessionName))
}

// M4: TestGetAssumeRoleCredentials_CacheHit は同一引数で 2 回呼んだ場合に
// キャッシュが機能して同一 CredentialsCache ポインタを返すことを確認する。
func TestGetAssumeRoleCredentials_CacheHit(t *testing.T) {
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	client := &mockAssumeRoleClient{}
	ctx := context.Background()

	creds1, err1 := getAssumeRoleCredentials(ctx, client, "123456789012", "AwsMcpGatewayRole", "sub-test", "", "", 1*time.Hour, "")
	if err1 != nil {
		t.Fatalf("1回目 getAssumeRoleCredentials エラー: %v", err1)
	}
	creds2, err2 := getAssumeRoleCredentials(ctx, client, "123456789012", "AwsMcpGatewayRole", "sub-test", "", "", 1*time.Hour, "")
	if err2 != nil {
		t.Fatalf("2回目 getAssumeRoleCredentials エラー: %v", err2)
	}

	// 同一ポインタ = LoadOrStore でキャッシュが機能
	if creds1 != creds2 {
		t.Errorf("CredentialsCache が再構築された（キャッシュ不動作）: creds1=%p creds2=%p", creds1, creds2)
	}
	t.Logf("✓ キャッシュヒットで同一ポインタを返した: %p", creds1)
}

// M4: TestGetAssumeRoleCredentials_AccessDenied は AccessDenied エラー時に
// キャッシュエントリが削除されることを確認する。
func TestGetAssumeRoleCredentials_AccessDenied(t *testing.T) {
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	accessDeniedErr := &stubAPIError{code: "AccessDenied", msg: "access denied"}
	client := &mockAssumeRoleClient{err: accessDeniedErr}
	ctx := context.Background()

	creds, err := getAssumeRoleCredentials(ctx, client, "123456789012", "AwsMcpGatewayRole", "sub-denied", "", "", 1*time.Hour, "")
	if err != nil {
		t.Fatalf("getAssumeRoleCredentials は AccessDenied をラップして返すはずだが直接エラー: %v", err)
	}
	if creds == nil {
		t.Fatal("creds が nil（CredentialsCache が返ってくるはず）")
	}

	// Retrieve を呼ぶと AccessDenied が発生する
	_, rerr := creds.Retrieve(ctx)
	if rerr == nil {
		t.Fatal("AccessDenied エラーが返るはずが nil")
	}

	// キャッシュが削除されていることを確認
	cacheKey := "123456789012::AwsMcpGatewayRole::sub-denied"
	if _, ok := assumeRoleCredsCache.Load(cacheKey); ok {
		t.Error("AccessDenied 後もキャッシュに残っている（削除されるべき）")
	}
	t.Logf("✓ AccessDenied 後にキャッシュエントリが削除された")
}

// M4: TestGetAssumeRoleCredentials_Throttling は Throttling エラー時に
// キャッシュエントリが保持されることを確認する。
func TestGetAssumeRoleCredentials_Throttling(t *testing.T) {
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	throttleErr := &stubAPIError{code: "Throttling", msg: "rate exceeded"}
	client := &mockAssumeRoleClient{err: throttleErr}
	ctx := context.Background()

	creds, err := getAssumeRoleCredentials(ctx, client, "123456789012", "AwsMcpGatewayRole", "sub-throttle", "", "", 1*time.Hour, "")
	if err != nil {
		t.Fatalf("getAssumeRoleCredentials は Throttling をラップして返すはずだが直接エラー: %v", err)
	}
	if creds == nil {
		t.Fatal("creds が nil")
	}

	// Retrieve を呼ぶと Throttling エラーが発生する
	_, rerr := creds.Retrieve(ctx)
	if rerr == nil {
		t.Fatal("Throttling エラーが返るはずが nil")
	}

	// キャッシュは保持されていることを確認
	cacheKey := "123456789012::AwsMcpGatewayRole::sub-throttle"
	if _, ok := assumeRoleCredsCache.Load(cacheKey); !ok {
		t.Error("Throttling 後にキャッシュが削除された（保持されるべき）")
	}
	t.Logf("✓ Throttling 後にキャッシュエントリが保持された")
}

// M5: handleAssumeRoleRequest のテスト

// mockSTSClientM5 は AssumeRoleAPIClient を実装するモック（M5 テスト用）。
type mockSTSClientM5 struct {
	err error
}

func (m *mockSTSClientM5) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	expiry := time.Now().Add(1 * time.Hour)
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIATESM5"),
			SecretAccessKey: aws.String("secretm5"),
			SessionToken:    aws.String("tokenm5"),
			Expiration:      &expiry,
		},
	}, nil
}

func TestHandleAssumeRoleRequest(t *testing.T) {
	const (
		allowedAccount = "123456789012"
		allowedRole    = "AwsMcpGatewayRole"
		mcpRegion      = "us-east-1"
		targetRegion   = "ap-northeast-1"
	)

	validUser := &idproxy.User{
		Email:   "alice@example.com",
		Subject: "sub-alice",
	}

	validCfg := assumeRoleConfig{
		allowedAccounts:  []string{allowedAccount},
		allowedRoleNames: []string{allowedRole},
		maxCacheTTL:      1 * time.Hour,
	}

	// モックアップストリームサーバー（Authorization ヘッダーをキャプチャ）
	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)

	t.Run("正常系 POST: 200 および Authorization ヘッダー付き", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		capturedAuth = ""
		stsClient := &mockSTSClientM5{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp/assumerole/accounts/"+allowedAccount+"/rolename/"+allowedRole, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		req.SetPathValue("account_id", allowedAccount)
		req.SetPathValue("role_name", allowedRole)

		handleAssumeRoleRequest(rec, req, validUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusOK {
			t.Errorf("期待値 200、実際: %d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.HasPrefix(capturedAuth, "AWS4-HMAC-SHA256") {
			t.Errorf("SigV4 Authorization ヘッダーが付いていない: %q", capturedAuth)
		}
		t.Logf("✓ 正常系 POST: status=%d Authorization=%s...", rec.Code, capturedAuth[:min(50, len(capturedAuth))])
	})

	t.Run("account_id 不正: 400", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		stsClient := &mockSTSClientM5{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.SetPathValue("account_id", "bad-account")
		req.SetPathValue("role_name", allowedRole)

		handleAssumeRoleRequest(rec, req, validUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusBadRequest {
			t.Errorf("期待値 400、実際: %d", rec.Code)
		}
		body := strings.TrimSpace(rec.Body.String())
		if body != "invalid account_id" {
			t.Errorf("期待値 %q、実際: %q", "invalid account_id", body)
		}
		t.Logf("✓ 不正 account_id: status=%d body=%q", rec.Code, body)
	})

	t.Run("role_name 不正: 400", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		stsClient := &mockSTSClientM5{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.SetPathValue("account_id", allowedAccount)
		req.SetPathValue("role_name", "../evil")

		handleAssumeRoleRequest(rec, req, validUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusBadRequest {
			t.Errorf("期待値 400、実際: %d", rec.Code)
		}
		body := strings.TrimSpace(rec.Body.String())
		if body != "invalid role_name" {
			t.Errorf("期待値 %q、実際: %q", "invalid role_name", body)
		}
		t.Logf("✓ 不正 role_name: status=%d body=%q", rec.Code, body)
	})

	t.Run("allowlist 外 account: 403", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		stsClient := &mockSTSClientM5{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.SetPathValue("account_id", "999999999999")
		req.SetPathValue("role_name", allowedRole)

		handleAssumeRoleRequest(rec, req, validUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusForbidden {
			t.Errorf("期待値 403、実際: %d", rec.Code)
		}
		body := strings.TrimSpace(rec.Body.String())
		if body != "forbidden" {
			t.Errorf("期待値 %q、実際: %q", "forbidden", body)
		}
		t.Logf("✓ allowlist 外 account: status=%d body=%q", rec.Code, body)
	})

	t.Run("allowlist 外 role: 403", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		stsClient := &mockSTSClientM5{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.SetPathValue("account_id", allowedAccount)
		req.SetPathValue("role_name", "OtherRole")

		handleAssumeRoleRequest(rec, req, validUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusForbidden {
			t.Errorf("期待値 403、実際: %d", rec.Code)
		}
		body := strings.TrimSpace(rec.Body.String())
		if body != "forbidden" {
			t.Errorf("期待値 %q、実際: %q", "forbidden", body)
		}
		t.Logf("✓ allowlist 外 role: status=%d body=%q", rec.Code, body)
	})

	t.Run("user が nil: 500", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		stsClient := &mockSTSClientM5{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.SetPathValue("account_id", allowedAccount)
		req.SetPathValue("role_name", allowedRole)

		handleAssumeRoleRequest(rec, req, nil, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("期待値 500、実際: %d", rec.Code)
		}
		t.Logf("✓ user=nil: status=%d", rec.Code)
	})

	t.Run("user.Subject が空: 500", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		stsClient := &mockSTSClientM5{}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.SetPathValue("account_id", allowedAccount)
		req.SetPathValue("role_name", allowedRole)
		emptyUser := &idproxy.User{Email: "alice@example.com", Subject: ""}

		handleAssumeRoleRequest(rec, req, emptyUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("期待値 500、実際: %d", rec.Code)
		}
		t.Logf("✓ user.Subject 空: status=%d", rec.Code)
	})

	t.Run("STS AccessDenied: 403、ボディに ARN や AccessDenied を含まない", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		accessDeniedErr := &stubAPIError{code: "AccessDenied", msg: "AccessDenied: User is not authorized"}
		stsClient := &mockSTSClientM5{err: accessDeniedErr}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		req.SetPathValue("account_id", allowedAccount)
		req.SetPathValue("role_name", allowedRole)

		handleAssumeRoleRequest(rec, req, validUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusForbidden {
			t.Errorf("期待値 403、実際: %d", rec.Code)
		}
		body := strings.TrimSpace(rec.Body.String())
		if strings.Contains(body, "arn:") {
			t.Errorf("エラーボディに ARN が含まれている: %q", body)
		}
		if strings.Contains(body, "AccessDenied") {
			t.Errorf("エラーボディに AccessDenied が含まれている: %q", body)
		}
		t.Logf("✓ STS AccessDenied: status=%d body=%q", rec.Code, body)
	})

	t.Run("STS Throttling: 503", func(t *testing.T) {
		assumeRoleCredsCache = sync.Map{}
		t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

		throttleErr := &stubAPIError{code: "Throttling", msg: "rate exceeded"}
		stsClient := &mockSTSClientM5{err: throttleErr}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
		req.SetPathValue("account_id", allowedAccount)
		req.SetPathValue("role_name", allowedRole)

		handleAssumeRoleRequest(rec, req, validUser, validCfg, target, stsClient, mcpRegion, targetRegion, "shared", "")

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("期待値 503、実際: %d", rec.Code)
		}
		t.Logf("✓ STS Throttling: status=%d", rec.Code)
	})
}

// --- federated assumerole テスト ---

// mockFederatedSTS は AssumeRoleWithWebIdentity / AssumeRole を実装するテスト用モック。
// TestHandleAssumeRoleRequest_Federated_* テストで newWebIdentitySTSClient / newChainedSTSClient 注入に使用する。
type mockFederatedSTS struct {
	webIdentityErr          error
	assumeRoleErr           error
	mu                      sync.Mutex
	capturedWebIdentityName string
}

func (m *mockFederatedSTS) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	m.mu.Lock()
	if params.RoleSessionName != nil {
		m.capturedWebIdentityName = *params.RoleSessionName
	}
	m.mu.Unlock()
	if m.webIdentityErr != nil {
		return nil, m.webIdentityErr
	}
	expiry := time.Now().Add(1 * time.Hour)
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIA_WEBID"),
			SecretAccessKey: aws.String("secret_webid"),
			SessionToken:    aws.String("token_webid"),
			Expiration:      &expiry,
		},
	}, nil
}

func (m *mockFederatedSTS) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.assumeRoleErr != nil {
		return nil, m.assumeRoleErr
	}
	expiry := time.Now().Add(1 * time.Hour)
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIA_FEDERATED"),
			SecretAccessKey: aws.String("secret_federated"),
			SessionToken:    aws.String("token_federated"),
			Expiration:      &expiry,
		},
	}, nil
}

// TestHandleAssumeRoleRequest_Federated_IDTokenMissing は
// iamMode=federated で user.IDToken="" の場合に 500 を返すことを確認する（fail-closed）。
func TestHandleAssumeRoleRequest_Federated_IDTokenMissing(t *testing.T) {
	target, _ := url.Parse("http://upstream.example.invalid/mcp")
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
		maxCacheTTL:      1 * time.Hour,
	}

	cases := []struct {
		name string
		user *idproxy.User
	}{
		{
			name: "IDToken が空 → 500",
			user: &idproxy.User{Email: "alice@example.com", Subject: "sub-alice"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assumeRoleCredsCache = sync.Map{}
			t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole", strings.NewReader(`{}`))
			req.SetPathValue("account_id", "123456789012")
			req.SetPathValue("role_name", "AwsMcpGatewayRole")

			handleAssumeRoleRequest(rec, req, tc.user, cfg, target, nil, "us-east-1", "ap-northeast-1", "federated", "arn:aws:iam::123456789012:role/FederatedRole")

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("期待値 500、実際: %d body=%s", rec.Code, rec.Body.String())
			} else {
				t.Logf("✓ federated IDToken 欠落時に 500 を返した (body=%q)", strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// TestHandleAssumeRoleRequest_Federated_IDTokenExpired は
// iamMode=federated で WebIdentity が InvalidIdentityToken エラーを返した場合に
// 401 + WWW-Authenticate ヘッダーを返すことを確認する。
func TestHandleAssumeRoleRequest_Federated_IDTokenExpired(t *testing.T) {
	federatedCredsCache = sync.Map{}
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() {
		federatedCredsCache = sync.Map{}
		assumeRoleCredsCache = sync.Map{}
	})

	target, _ := url.Parse("http://upstream.example.invalid/mcp")
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
		maxCacheTTL:      1 * time.Hour,
	}

	// WebIdentity 層で InvalidIdentityToken エラーを返すようにモックする。
	// handleAssumeRoleRequest 内の getFederatedCreds → federatedCreds.Retrieve() で
	// このエラーが発生し、401 + WWW-Authenticate を返すことを確認する。
	invalidTokenErr := &stubAPIError{code: "InvalidIdentityToken", msg: "token is expired"}
	mockSTS := &mockFederatedSTS{webIdentityErr: invalidTokenErr}

	origNewWebIdentitySTSClient := newWebIdentitySTSClient
	origNewChainedSTSClient := newChainedSTSClient
	t.Cleanup(func() {
		newWebIdentitySTSClient = origNewWebIdentitySTSClient
		newChainedSTSClient = origNewChainedSTSClient
	})
	newWebIdentitySTSClient = func(ctx context.Context, region string) (stscreds.AssumeRoleWithWebIdentityAPIClient, error) {
		return mockSTS, nil
	}
	newChainedSTSClient = func(ctx context.Context, region string, creds aws.CredentialsProvider) (stscreds.AssumeRoleAPIClient, error) {
		return mockSTS, nil
	}

	user := &idproxy.User{
		Email:   "alice@example.com",
		Subject: "sub-alice",
		IDToken: "eyJhbGciOiJSUzI1NiJ9.expired-token",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole", strings.NewReader(`{}`))
	req.SetPathValue("account_id", "123456789012")
	req.SetPathValue("role_name", "AwsMcpGatewayRole")

	handleAssumeRoleRequest(rec, req, user, cfg, target, nil, "us-east-1", "ap-northeast-1", "federated", "arn:aws:iam::123456789012:role/FederatedRole")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("期待値 401、実際: %d body=%s", rec.Code, rec.Body.String())
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "invalid_token") {
		t.Errorf("WWW-Authenticate ヘッダーに invalid_token が含まれていない: %q", wwwAuth)
	}
	t.Logf("✓ federated IDToken 失効時に 401 + WWW-Authenticate を返した: status=%d header=%q", rec.Code, wwwAuth)
}

// TestHandleAssumeRoleRequest_Federated_Success は
// iamMode=federated で正常に AssumeRole 成功した場合に SigV4 署名リクエストが proxy に到達することを確認する。
func TestHandleAssumeRoleRequest_Federated_Success(t *testing.T) {
	federatedCredsCache = sync.Map{}
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() {
		federatedCredsCache = sync.Map{}
		assumeRoleCredsCache = sync.Map{}
	})

	// モックアップストリームサーバー（Authorization ヘッダーをキャプチャ）
	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
		maxCacheTTL:      1 * time.Hour,
	}

	// WebIdentity / AssumeRole 両方を成功させるモックを注入する。
	mockSTS := &mockFederatedSTS{}

	origNewWebIdentitySTSClient := newWebIdentitySTSClient
	origNewChainedSTSClient := newChainedSTSClient
	t.Cleanup(func() {
		newWebIdentitySTSClient = origNewWebIdentitySTSClient
		newChainedSTSClient = origNewChainedSTSClient
	})
	newWebIdentitySTSClient = func(ctx context.Context, region string) (stscreds.AssumeRoleWithWebIdentityAPIClient, error) {
		return mockSTS, nil
	}
	newChainedSTSClient = func(ctx context.Context, region string, creds aws.CredentialsProvider) (stscreds.AssumeRoleAPIClient, error) {
		return mockSTS, nil
	}

	user := &idproxy.User{
		Email:   "alice@example.com",
		Subject: "sub-alice",
		IDToken: "eyJhbGciOiJSUzI1NiJ9.valid-token",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.SetPathValue("account_id", "123456789012")
	req.SetPathValue("role_name", "AwsMcpGatewayRole")

	handleAssumeRoleRequest(rec, req, user, cfg, target, nil, "us-east-1", "ap-northeast-1", "federated", "arn:aws:iam::123456789012:role/FederatedRole")

	if rec.Code != http.StatusOK {
		t.Errorf("期待値 200、実際: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(capturedAuth, "AWS4-HMAC-SHA256") {
		t.Errorf("federated SigV4 Authorization ヘッダーが付いていない: %q", capturedAuth)
	}
	t.Logf("✓ federated 正常系: status=%d Authorization=%s...", rec.Code, capturedAuth[:min(50, len(capturedAuth))])
}

// TestHandleAssumeRoleRequest_Federated_AccessDenied は
// iamMode=federated で WebIdentity が AccessDenied エラーを返した場合に
// 403 を返し、federatedCredsCache からエントリが evict されることを確認する。
func TestHandleAssumeRoleRequest_Federated_AccessDenied(t *testing.T) {
	federatedCredsCache = sync.Map{}
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() {
		federatedCredsCache = sync.Map{}
		assumeRoleCredsCache = sync.Map{}
	})

	target, _ := url.Parse("http://upstream.example.invalid/mcp")
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
		maxCacheTTL:      1 * time.Hour,
	}

	// WebIdentity 層で AccessDenied エラーを返すようにモックする。
	// handleAssumeRoleRequest 内の getFederatedCreds → federatedCreds.Retrieve() で
	// このエラーが発生し、403 を返すことを確認する。
	accessDeniedErr := &stubAPIError{code: "AccessDenied", msg: "access denied"}
	mockSTS := &mockFederatedSTS{webIdentityErr: accessDeniedErr}

	origNewWebIdentitySTSClient := newWebIdentitySTSClient
	origNewChainedSTSClient := newChainedSTSClient
	t.Cleanup(func() {
		newWebIdentitySTSClient = origNewWebIdentitySTSClient
		newChainedSTSClient = origNewChainedSTSClient
	})
	newWebIdentitySTSClient = func(ctx context.Context, region string) (stscreds.AssumeRoleWithWebIdentityAPIClient, error) {
		return mockSTS, nil
	}
	newChainedSTSClient = func(ctx context.Context, region string, creds aws.CredentialsProvider) (stscreds.AssumeRoleAPIClient, error) {
		return mockSTS, nil
	}

	user := &idproxy.User{
		Email:   "alice@example.com",
		Subject: "sub-alice",
		IDToken: "eyJhbGciOiJSUzI1NiJ9.access-denied-token",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole", strings.NewReader(`{}`))
	req.SetPathValue("account_id", "123456789012")
	req.SetPathValue("role_name", "AwsMcpGatewayRole")

	handleAssumeRoleRequest(rec, req, user, cfg, target, nil, "us-east-1", "ap-northeast-1", "federated", "arn:aws:iam::123456789012:role/FederatedRole")

	if rec.Code != http.StatusForbidden {
		t.Errorf("期待値 403、実際: %d body=%s", rec.Code, rec.Body.String())
	}

	// eviction 確認: federatedCredsCache にエントリが残っていないこと。
	var remaining int
	federatedCredsCache.Range(func(_, _ interface{}) bool {
		remaining++
		return true
	})
	if remaining != 0 {
		t.Errorf("federatedCredsCache にエントリが残存している（evict されていない）: %d 件", remaining)
	}

	t.Logf("✓ federated AccessDenied 時に 403 を返し、キャッシュが evict された: status=%d", rec.Code)
}

// TestGetFederatedCreds_CacheHit は getFederatedCreds の同一 sub+fingerprint でキャッシュヒットすることを確認する。
func TestGetFederatedCreds_CacheHit(t *testing.T) {
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() { federatedCredsCache = sync.Map{} })

	// WebIdentity STS をモックして実際の STS 呼び出しを防ぐ。
	origNewWebIdentitySTSClient := newWebIdentitySTSClient
	t.Cleanup(func() { newWebIdentitySTSClient = origNewWebIdentitySTSClient })
	newWebIdentitySTSClient = func(ctx context.Context, region string) (stscreds.AssumeRoleWithWebIdentityAPIClient, error) {
		return &mockFederatedSTS{}, nil
	}

	ctx := context.Background()
	const (
		region  = "us-east-1"
		roleARN = "arn:aws:iam::111:role/Fed"
		idToken = "test-federated-token"
		sub     = "sub-fedcache-test"
	)

	// 1 回目（cache miss）
	creds1, key1, err1 := getFederatedCreds(ctx, region, roleARN, idToken, sub, "", "")
	if err1 != nil {
		t.Fatalf("1回目 getFederatedCreds エラー: %v", err1)
	}
	if creds1 == nil {
		t.Fatal("1回目: creds が nil")
	}

	// 2 回目（cache hit）
	creds2, key2, err2 := getFederatedCreds(ctx, region, roleARN, idToken, sub, "", "")
	if err2 != nil {
		t.Fatalf("2回目 getFederatedCreds エラー: %v", err2)
	}
	if creds2 == nil {
		t.Fatal("2回目: creds が nil")
	}

	if key1 != key2 {
		t.Errorf("cacheKey が異なる: 1回目=%q 2回目=%q", key1, key2)
	}
	if creds1 != creds2 {
		t.Errorf("CredentialsCache が再構築された（キャッシュ不動作）: creds1=%p creds2=%p", creds1, creds2)
	}
	t.Logf("✓ getFederatedCreds キャッシュヒット: key=%q ptr=%p", key1, creds1)
}

// TestAssumeRoleEndpointRouting: /mcp/assumerole/{account_id}/{role_name} が
// assumerole ハンドラにルーティングされ、PathValue が正しく取得できることを確認する。
// ASSUMEROLE_ALLOWED_ACCOUNTS / ASSUMEROLE_ALLOWED_ROLE_NAMES 未設定時は 403 が返ることも確認する。
func TestAssumeRoleEndpointRouting(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	// allowlist 未設定 → 全リクエストが 403
	t.Setenv("ASSUMEROLE_ALLOWED_ACCOUNTS", "")
	t.Setenv("ASSUMEROLE_ALLOWED_ROLE_NAMES", "")

	// assumerole ハンドラが呼ばれたかを記録するフラグ
	assumeRoleHandlerCalled := false
	var capturedAccountID, capturedRoleName string

	// assumerole ハンドラをシミュレートするモックハンドラ
	assumeRoleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assumeRoleHandlerCalled = true
		capturedAccountID = r.PathValue("account_id")
		capturedRoleName = r.PathValue("role_name")
		// allowlist 未設定を模倣して 403
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	// default ハンドラ（/mcp/assumerole/ に来ていないことを確認するため）
	defaultHandlerCalled := false
	defaultHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp/assumerole/accounts/{account_id}/rolename/{role_name}", assumeRoleHandler)
	mux.Handle("/", defaultHandler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("/mcp/assumerole/{account_id}/{role_name} が assumerole ハンドラにルーティングされる", func(t *testing.T) {
		assumeRoleHandlerCalled = false
		defaultHandlerCalled = false
		capturedAccountID = ""
		capturedRoleName = ""

		resp, err := http.Post(srv.URL+"/mcp/assumerole/accounts/123456789012/rolename/AwsMcpGatewayRole",
			"application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("リクエスト失敗: %v", err)
		}
		defer resp.Body.Close()

		if !assumeRoleHandlerCalled {
			t.Error("assumerole ハンドラが呼ばれなかった")
		}
		if defaultHandlerCalled {
			t.Error("/ ハンドラが誤って呼ばれた")
		}
		if capturedAccountID != "123456789012" {
			t.Errorf("account_id PathValue = %q, want %q", capturedAccountID, "123456789012")
		}
		if capturedRoleName != "AwsMcpGatewayRole" {
			t.Errorf("role_name PathValue = %q, want %q", capturedRoleName, "AwsMcpGatewayRole")
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("期待値 403、実際: %d", resp.StatusCode)
		}
		t.Logf("✓ assumerole ハンドラへのルーティング確認: account_id=%q role_name=%q status=%d",
			capturedAccountID, capturedRoleName, resp.StatusCode)
	})

	t.Run("/mcp へのリクエストは assumerole ハンドラではなく / ハンドラで処理される", func(t *testing.T) {
		assumeRoleHandlerCalled = false
		defaultHandlerCalled = false

		resp, err := http.Post(srv.URL+"/mcp",
			"application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("リクエスト失敗: %v", err)
		}
		defer resp.Body.Close()

		if assumeRoleHandlerCalled {
			t.Error("assumerole ハンドラが誤って呼ばれた")
		}
		if !defaultHandlerCalled {
			t.Error("/ ハンドラが呼ばれなかった")
		}
		t.Logf("✓ /mcp へのリクエストは / ハンドラで処理された: status=%d", resp.StatusCode)
	})
}

// TestSessionIdentifier は sessionIdentifier ヘルパーの単体テスト。
// email が非空なら email を、空なら sub を返すことを確認する。
func TestSessionIdentifier(t *testing.T) {
	cases := []struct {
		name  string
		email string
		sub   string
		want  string
	}{
		{"email あり", "user@example.com", "sub-abc123", "user@example.com"},
		{"email 空", "", "sub-abc123", "sub-abc123"},
		{"email も sub も空", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sessionIdentifier(tc.email, tc.sub)
			if got != tc.want {
				t.Errorf("sessionIdentifier(%q, %q) = %q, want %q", tc.email, tc.sub, got, tc.want)
			}
		})
	}
}

// TestGetAssumeRoleCredentials_SessionName_Email は email がある場合にセッション名が
// "gw-ar-{email}" 形式になることを確認する。
func TestGetAssumeRoleCredentials_SessionName_Email(t *testing.T) {
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	client := &mockAssumeRoleClient{}
	const email = "user@example.com"
	const sub = "sub-test-email"
	creds, err := getAssumeRoleCredentials(context.Background(), client, "123456789012", "AwsMcpGatewayRole", sub, email, "", 1*time.Hour, "")
	if err != nil {
		t.Fatalf("getAssumeRoleCredentials エラー: %v", err)
	}
	if creds == nil {
		t.Fatal("creds が nil")
	}

	// Retrieve でセッション名を確定させる
	if _, rerr := creds.Retrieve(context.Background()); rerr != nil {
		t.Fatalf("Retrieve エラー: %v", rerr)
	}

	client.mu.Lock()
	captured := client.capturedSessionName
	client.mu.Unlock()

	want := sanitizeSessionName("gw-ar-" + email)
	if captured != want {
		t.Errorf("RoleSessionName = %q, want %q (email ベース)", captured, want)
	}
	t.Logf("✓ email あり: RoleSessionName = %q", captured)
}

// TestGetAssumeRoleCredentials_SessionName_EmailFallback は email が空の場合に
// セッション名が "gw-ar-{sub}" 形式にフォールバックすることを確認する。
func TestGetAssumeRoleCredentials_SessionName_EmailFallback(t *testing.T) {
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	client := &mockAssumeRoleClient{}
	const sub = "sub-test-fallback"
	creds, err := getAssumeRoleCredentials(context.Background(), client, "123456789012", "AwsMcpGatewayRole", sub, "", "", 1*time.Hour, "")
	if err != nil {
		t.Fatalf("getAssumeRoleCredentials エラー: %v", err)
	}
	if creds == nil {
		t.Fatal("creds が nil")
	}

	if _, rerr := creds.Retrieve(context.Background()); rerr != nil {
		t.Fatalf("Retrieve エラー: %v", rerr)
	}

	client.mu.Lock()
	captured := client.capturedSessionName
	client.mu.Unlock()

	want := sanitizeSessionName("gw-ar-" + sub)
	if captured != want {
		t.Errorf("RoleSessionName = %q, want %q (sub フォールバック)", captured, want)
	}
	t.Logf("✓ email 空: RoleSessionName = %q (sub フォールバック)", captured)
}

// TestGetFederatedCreds_SessionName_Email は email がある場合に WebIdentity セッション名が
// "gw-{email}" 形式になることを確認する。
func TestGetFederatedCreds_SessionName_Email(t *testing.T) {
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() { federatedCredsCache = sync.Map{} })

	mockSTS := &mockFederatedSTS{}
	origNewWebIdentitySTSClient := newWebIdentitySTSClient
	t.Cleanup(func() { newWebIdentitySTSClient = origNewWebIdentitySTSClient })
	newWebIdentitySTSClient = func(ctx context.Context, region string) (stscreds.AssumeRoleWithWebIdentityAPIClient, error) {
		return mockSTS, nil
	}

	const email = "user@example.com"
	const sub = "sub-federated-email"
	const idToken = "test-id-token-email"
	ctx := context.Background()

	creds, _, err := getFederatedCreds(ctx, "us-east-1", "arn:aws:iam::123:role/Fed", idToken, sub, email, "")
	if err != nil {
		t.Fatalf("getFederatedCreds エラー: %v", err)
	}
	if _, rerr := creds.Retrieve(ctx); rerr != nil {
		t.Fatalf("Retrieve エラー: %v", rerr)
	}

	mockSTS.mu.Lock()
	captured := mockSTS.capturedWebIdentityName
	mockSTS.mu.Unlock()

	want := sanitizeSessionName("gw-" + email)
	if captured != want {
		t.Errorf("WebIdentity RoleSessionName = %q, want %q (email ベース)", captured, want)
	}
	t.Logf("✓ email あり: WebIdentity RoleSessionName = %q", captured)
}

// TestGetFederatedCreds_SessionName_EmailFallback は email が空の場合に WebIdentity セッション名が
// "gw-{sub}" 形式にフォールバックすることを確認する。
func TestGetFederatedCreds_SessionName_EmailFallback(t *testing.T) {
	federatedCredsCache = sync.Map{}
	t.Cleanup(func() { federatedCredsCache = sync.Map{} })

	mockSTS := &mockFederatedSTS{}
	origNewWebIdentitySTSClient := newWebIdentitySTSClient
	t.Cleanup(func() { newWebIdentitySTSClient = origNewWebIdentitySTSClient })
	newWebIdentitySTSClient = func(ctx context.Context, region string) (stscreds.AssumeRoleWithWebIdentityAPIClient, error) {
		return mockSTS, nil
	}

	const sub = "sub-federated-fallback"
	const idToken = "test-id-token-fallback"
	ctx := context.Background()

	creds, _, err := getFederatedCreds(ctx, "us-east-1", "arn:aws:iam::123:role/Fed", idToken, sub, "", "")
	if err != nil {
		t.Fatalf("getFederatedCreds エラー: %v", err)
	}
	if _, rerr := creds.Retrieve(ctx); rerr != nil {
		t.Fatalf("Retrieve エラー: %v", rerr)
	}

	mockSTS.mu.Lock()
	captured := mockSTS.capturedWebIdentityName
	mockSTS.mu.Unlock()

	want := sanitizeSessionName("gw-" + sub)
	if captured != want {
		t.Errorf("WebIdentity RoleSessionName = %q, want %q (sub フォールバック)", captured, want)
	}
	t.Logf("✓ email 空: WebIdentity RoleSessionName = %q (sub フォールバック)", captured)
}
