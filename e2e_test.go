package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
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
