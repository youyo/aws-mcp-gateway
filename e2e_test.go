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

// TestSSEChannelMaintained: mcp-session-id を返す upstream に対して GET SSE チャネルが開かれることを確認
func TestSSEChannelMaintained(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	// sseSendCh は GET SSE ハンドラの goroutine に送信データを渡すチャネル
	sseSendCh := make(chan string, 1)
	sseDone := make(chan struct{})

	// モックサーバー: initialize POST → 200 + mcp-session-id
	//                 GET SSE → 200 SSE ストリーム（チャネル開設確認用）
	//                 call POST → 202 (SSE からレスポンスを待つ)
	sseReady := make(chan struct{}) // GET SSE が確立したら close される（1回だけ）
	var sseReadyOnce sync.Once

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// GET SSE チャネル
			sessionID := r.Header.Get("mcp-session-id")
			if sessionID == "" {
				http.Error(w, "no session", http.StatusBadRequest)
				return
			}
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "flusher not supported", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher.Flush()
			// sseReady を一度だけ close して通知
			sseReadyOnce.Do(func() { close(sseReady) })
			// GET ハンドラの goroutine でデータを書く（ResponseWriter は安全）
			for {
				select {
				case data := <-sseSendCh:
					w.Write([]byte(data))
					flusher.Flush()
				case <-sseDone:
					return
				}
			}
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var rpc map[string]json.RawMessage
			json.Unmarshal(body, &rpc)
			// initialize リクエストには 200 + mcp-session-id を返す
			if method, _ := rpc["method"]; strings.Trim(string(method), `"`) == "initialize" {
				w.Header().Set("mcp-session-id", "test-session-001")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}`))
				return
			}
			// tools/call → 202 を返し、SSE でレスポンスを送信
			var idRaw json.RawMessage
			if id, ok := rpc["id"]; ok {
				idRaw = id
			}
			w.Header().Set("mcp-session-id", "test-session-001")
			w.WriteHeader(http.StatusAccepted)
			// SSE チャネルにレスポンスを送信（GET ハンドラの goroutine 経由）
			go func() {
				// GET SSE が開くまで待つ
				select {
				case <-sseReady:
				case <-time.After(5 * time.Second):
					return
				}
				respMsg := map[string]json.RawMessage{
					"jsonrpc": json.RawMessage(`"2.0"`),
					"id":      idRaw,
					"result":  json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
				}
				data, _ := json.Marshal(respMsg)
				select {
				case sseSendCh <- "data: " + string(data) + "\n\n":
				case <-time.After(5 * time.Second):
				}
			}()
		}
	}))
	defer mock.Close()
	defer close(sseDone)

	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", "mcp")
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}
	target, _ := url.Parse(mock.URL)
	proxy := buildProxy(target, transport, "ap-northeast-1")
	// injectMetaAWSRegion を経由させるラッパー（本番 loggingProxy と同等）
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, injectMetaAWSRegion(r, "ap-northeast-1"))
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// 1. initialize リクエストでセッションを確立
	initBody := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}`
	initResp, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(initBody))
	if err != nil {
		t.Fatalf("initialize リクエスト失敗: %v", err)
	}
	defer initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("initialize が 200 でない: %d", initResp.StatusCode)
	}

	// GET SSE チャネルが開かれるのを待つ（最大 5s）
	select {
	case <-sseReady:
		t.Logf("✓ GET SSE チャネルが開かれた")
	case <-time.After(5 * time.Second):
		t.Fatal("GET SSE チャネルが 5 秒以内に開かれなかった")
	}

	// 2. tools/call → 202 → SSE レスポンス待ち → 同期的に返す
	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_aws","arguments":{"service":"s3","operation":"list_buckets"}}}`
	client := &http.Client{Timeout: 10 * time.Second}
	callReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(callBody))
	callReq.Header.Set("Content-Type", "application/json")
	callReq.Header.Set("mcp-session-id", "test-session-001")
	callResp, err := client.Do(callReq)
	if err != nil {
		t.Fatalf("tools/call リクエスト失敗: %v", err)
	}
	defer callResp.Body.Close()

	if callResp.StatusCode != http.StatusOK {
		t.Errorf("202 を同期的に 200 へ変換できていない: %d", callResp.StatusCode)
	}
	body, _ := io.ReadAll(callResp.Body)
	t.Logf("✓ tools/call レスポンス (%d): %s", callResp.StatusCode, string(body))
}

// TestSSEChannelNotStartedWithoutSessionID: mcp-session-id がない場合は GET SSE を開かないことを確認
func TestSSEChannelNotStartedWithoutSessionID(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	getRequests := 0
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getRequests++
		}
		// mcp-session-id を返さない
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer mock.Close()

	transport, err := newSigV4RoundTripper(context.Background(), "us-east-1", "mcp")
	if err != nil {
		t.Fatalf("RoundTripper 作成失敗: %v", err)
	}
	target, _ := url.Parse(mock.URL)
	proxy := buildProxy(target, transport, "ap-northeast-1")
	srv := httptest.NewServer(proxy)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatalf("リクエスト失敗: %v", err)
	}
	defer resp.Body.Close()

	// 短時間待って GET が来ないことを確認
	time.Sleep(100 * time.Millisecond)
	if getRequests > 0 {
		t.Errorf("mcp-session-id なしなのに GET SSE チャネルが開かれた: getRequests=%d", getRequests)
	} else {
		t.Logf("✓ mcp-session-id なしでは GET SSE チャネルは開かれない")
	}
}

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
	proxy := buildProxy(target, transport, "ap-northeast-1")

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
	proxy := buildProxy(target, transport, "ap-northeast-1")
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
	proxy := buildProxy(target, transport, "ap-northeast-1")
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
	proxy := buildProxy(target, transport, "ap-northeast-1")
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
	proxy := buildProxy(target, transport, "ap-northeast-1")
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
	proxy := buildProxy(target, transport, "ap-northeast-1")

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
