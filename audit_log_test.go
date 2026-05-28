package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	idproxy "github.com/youyo/idproxy"
)

// captureHandler はテスト用のログキャプチャ slog ハンドラ。
type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

type capturedRecord struct {
	level   slog.Level
	msg     string
	attrs   map[string]string
}

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{
		level: r.Level,
		msg:   r.Message,
		attrs: make(map[string]string),
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler         { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler              { return h }

func (h *captureHandler) findRecord(msg string) (capturedRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.msg == msg {
			return r, true
		}
	}
	return capturedRecord{}, false
}

func (h *captureHandler) findRecordContaining(msgPart string) (capturedRecord, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if strings.Contains(r.msg, msgPart) {
			return r, true
		}
	}
	return capturedRecord{}, false
}

// installCaptureLogger は captureHandler をデフォルト slog にセットし、
// テスト終了時に元のハンドラを復元する。
func installCaptureLogger(t *testing.T) *captureHandler {
	t.Helper()
	original := slog.Default()
	h := &captureHandler{}
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() {
		slog.SetDefault(original)
	})
	return h
}

// mockSTSClientM7 は AssumeRoleAPIClient のテスト用モック（M7 専用）。
type mockSTSClientM7 struct {
	err error
}

func (m *mockSTSClientM7) AssumeRole(_ context.Context, _ *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	expiry := time.Now().Add(1 * time.Hour)
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIATEST7"),
			SecretAccessKey: aws.String("secret7"),
			SessionToken:    aws.String("token7"),
			Expiration:      &expiry,
		},
	}, nil
}

func TestAuditLog_SuccessRequest(t *testing.T) {
	h := installCaptureLogger(t)
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	user := &idproxy.User{Email: "user@example.com", Subject: "abc123"}
	stsClient := &mockSTSClientM7{}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/mcp/assumerole/123456789012/AwsMcpGatewayRole", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.SetPathValue("account_id", "123456789012")
	req.SetPathValue("role_name", "AwsMcpGatewayRole")

	handleAssumeRoleRequest(rec, req, user, cfg, target, stsClient, "us-east-1", "ap-northeast-1")

	if rec.Code != 200 {
		t.Fatalf("期待値 200、実際: %d body=%s", rec.Code, rec.Body.String())
	}

	r, ok := h.findRecord("assumerole request")
	if !ok {
		t.Fatal("'assumerole request' ログが見つからない")
	}
	assertAttr(t, r, "account_id", "123456789012")
	assertAttr(t, r, "role_name", "AwsMcpGatewayRole")
	assertAttr(t, r, "role_arn", "arn:aws:iam::123456789012:role/AwsMcpGatewayRole")
	assertAttr(t, r, "user_sub", "abc123")
	assertAttr(t, r, "user_email", "user@example.com")

	sessionName := r.attrs["session_name"]
	if !strings.HasPrefix(sessionName, "gw-ar-") {
		t.Errorf("session_name = %q、'gw-ar-' で始まることを期待", sessionName)
	}
	if r.level != slog.LevelInfo {
		t.Errorf("ログレベル = %v、INFO を期待", r.level)
	}
	t.Logf("✓ 正常系ログ: account_id=%q role_name=%q role_arn=%q session_name=%q user_sub=%q user_email=%q",
		r.attrs["account_id"], r.attrs["role_name"], r.attrs["role_arn"],
		r.attrs["session_name"], r.attrs["user_sub"], r.attrs["user_email"])
}

func TestAuditLog_ForbiddenByAllowlist(t *testing.T) {
	h := installCaptureLogger(t)
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	target, _ := url.Parse("http://upstream.invalid/mcp")
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
		maxCacheTTL:      1 * time.Hour,
	}
	user := &idproxy.User{Email: "user@example.com", Subject: "abc123"}
	stsClient := &mockSTSClientM7{}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/mcp/assumerole/999999999999/AwsMcpGatewayRole", strings.NewReader(`{}`))
	req.SetPathValue("account_id", "999999999999")
	req.SetPathValue("role_name", "AwsMcpGatewayRole")

	handleAssumeRoleRequest(rec, req, user, cfg, target, stsClient, "us-east-1", "ap-northeast-1")

	if rec.Code != 403 {
		t.Fatalf("期待値 403、実際: %d", rec.Code)
	}

	r, ok := h.findRecordContaining("forbidden")
	if !ok {
		t.Fatal("allowlist 拒否時の Warn/Error ログが見つからない")
	}
	assertAttr(t, r, "account_id", "999999999999")
	assertAttr(t, r, "role_name", "AwsMcpGatewayRole")
	if r.level < slog.LevelWarn {
		t.Errorf("ログレベル = %v、Warn 以上を期待", r.level)
	}
	t.Logf("✓ allowlist 拒否時ログ: level=%v msg=%q account_id=%q role_name=%q",
		r.level, r.msg, r.attrs["account_id"], r.attrs["role_name"])
}

func TestAuditLog_STSAccessDenied(t *testing.T) {
	h := installCaptureLogger(t)
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	target, _ := url.Parse("http://upstream.invalid/mcp")
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
		maxCacheTTL:      1 * time.Hour,
	}
	user := &idproxy.User{Email: "user@example.com", Subject: "abc123"}
	accessDeniedErr := &stubAPIError{code: "AccessDenied", msg: "AccessDenied: not authorized"}
	stsClient := &mockSTSClientM7{err: accessDeniedErr}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/mcp/assumerole/123456789012/AwsMcpGatewayRole", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.SetPathValue("account_id", "123456789012")
	req.SetPathValue("role_name", "AwsMcpGatewayRole")

	handleAssumeRoleRequest(rec, req, user, cfg, target, stsClient, "us-east-1", "ap-northeast-1")

	if rec.Code != 403 {
		t.Fatalf("期待値 403、実際: %d", rec.Code)
	}

	r, ok := h.findRecordContaining("forbidden")
	if !ok {
		t.Fatal("STS AccessDenied 時の Warn/Error ログが見つからない")
	}
	assertAttr(t, r, "account_id", "123456789012")
	assertAttr(t, r, "role_name", "AwsMcpGatewayRole")
	if r.level < slog.LevelWarn {
		t.Errorf("ログレベル = %v、Warn 以上を期待", r.level)
	}
	t.Logf("✓ STS AccessDenied 時ログ: level=%v msg=%q account_id=%q role_name=%q",
		r.level, r.msg, r.attrs["account_id"], r.attrs["role_name"])
}

func TestAuditLog_STSThrottling(t *testing.T) {
	h := installCaptureLogger(t)
	assumeRoleCredsCache = sync.Map{}
	t.Cleanup(func() { assumeRoleCredsCache = sync.Map{} })

	target, _ := url.Parse("http://upstream.invalid/mcp")
	cfg := assumeRoleConfig{
		allowedAccounts:  []string{"123456789012"},
		allowedRoleNames: []string{"AwsMcpGatewayRole"},
		maxCacheTTL:      1 * time.Hour,
	}
	user := &idproxy.User{Email: "user@example.com", Subject: "abc123"}
	throttleErr := &stubAPIError{code: "Throttling", msg: "rate exceeded"}
	stsClient := &mockSTSClientM7{err: throttleErr}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/mcp/assumerole/123456789012/AwsMcpGatewayRole", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.SetPathValue("account_id", "123456789012")
	req.SetPathValue("role_name", "AwsMcpGatewayRole")

	handleAssumeRoleRequest(rec, req, user, cfg, target, stsClient, "us-east-1", "ap-northeast-1")

	if rec.Code != 503 {
		t.Fatalf("期待値 503、実際: %d", rec.Code)
	}

	r, ok := h.findRecordContaining("sts")
	if !ok {
		r, ok = h.findRecordContaining("unavailable")
	}
	if !ok {
		t.Fatal("STS Throttling 時の Warn/Error ログが見つからない")
	}
	assertAttr(t, r, "account_id", "123456789012")
	assertAttr(t, r, "role_name", "AwsMcpGatewayRole")
	if r.level < slog.LevelWarn {
		t.Errorf("ログレベル = %v、Warn 以上を期待", r.level)
	}
	t.Logf("✓ STS Throttling 時ログ: level=%v msg=%q account_id=%q role_name=%q",
		r.level, r.msg, r.attrs["account_id"], r.attrs["role_name"])
}

func assertAttr(t *testing.T, r capturedRecord, key, want string) {
	t.Helper()
	got, ok := r.attrs[key]
	if !ok {
		t.Errorf("ログに %q フィールドがない（msg=%q）", key, r.msg)
		return
	}
	if got != want {
		t.Errorf("ログ %q = %q、期待値 %q（msg=%q）", key, got, want, r.msg)
	}
}

