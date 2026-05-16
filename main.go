// Spike: AWS MCP Server への SigV4 署名リバースプロキシ
// 検証内容: httputil.ReverseProxy + SigV4 RoundTripper で
// Streamable HTTP MCP プロトコルが素通りするかを確認する
//
// 使い方:
//   AWS_REGION=us-east-1 go run main.go
//
// 別ターミナルで確認:
//   curl -X POST http://localhost:8080/mcp \
//     -H "Content-Type: application/json" \
//     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

const (
	awsMCPEndpoint = "https://aws-mcp.us-east-1.api.aws/mcp"
	awsService     = "aws-mcp"
	listenAddr     = ":8080"
)

// sigV4RoundTripper は http.RoundTripper に SigV4 署名を付与する
type sigV4RoundTripper struct {
	base    http.RoundTripper
	signer  *v4.Signer
	region  string
	service string
	getCreds func(ctx context.Context) (string, string, string, error)
}

func newSigV4RoundTripper(ctx context.Context, region, service string) (*sigV4RoundTripper, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("AWS 設定の読み込み失敗: %w", err)
	}

	getCreds := func(ctx context.Context) (string, string, string, error) {
		creds, err := cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return "", "", "", err
		}
		return creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, nil
	}

	return &sigV4RoundTripper{
		base:     http.DefaultTransport,
		signer:   v4.NewSigner(),
		region:   region,
		service:  service,
		getCreds: getCreds,
	}, nil
}

func (t *sigV4RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// ボディを読み取ってハッシュを計算（SigV4 に必要）
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("リクエストボディの読み取り失敗: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	hash := sha256.Sum256(bodyBytes)
	payloadHash := fmt.Sprintf("%x", hash)

	// クレデンシャルを取得
	accessKey, secretKey, sessionToken, err := t.getCreds(req.Context())
	if err != nil {
		return nil, fmt.Errorf("AWS クレデンシャルの取得失敗: %w", err)
	}

	// SigV4 署名
	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
	}
	err = t.signer.SignHTTP(req.Context(), creds, req, payloadHash, t.service, t.region, time.Now())
	if err != nil {
		return nil, fmt.Errorf("SigV4 署名失敗: %w", err)
	}

	return t.base.RoundTrip(req)
}

func buildProxy(target *url.URL, transport http.RoundTripper, metadataRegion string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			r.Out.URL.Path = target.Path // パスを固定（二重にならないよう）
			r.Out.Header.Set("x-amz-mcp-metadata-aws_region", metadataRegion)
		},
		ModifyResponse: func(resp *http.Response) error {
			log.Printf("← %s %s %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("プロキシエラー: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}
}

func main() {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	metadataRegion := os.Getenv("TARGET_AWS_REGION")
	if metadataRegion == "" {
		metadataRegion = "ap-northeast-1"
	}

	ctx := context.Background()

	// SigV4 RoundTripper を作成
	transport, err := newSigV4RoundTripper(ctx, region, awsService)
	if err != nil {
		log.Fatalf("RoundTripper の作成失敗: %v", err)
	}

	// AWS MCP Server のエンドポイントをパース
	target, err := url.Parse(awsMCPEndpoint)
	if err != nil {
		log.Fatalf("エンドポイントのパース失敗: %v", err)
	}

	proxy := buildProxy(target, transport, metadataRegion)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("→ %s %s", r.Method, r.URL.Path)
		proxy.ServeHTTP(w, r)
	})

	log.Printf("起動: %s → %s (target region: %s)", listenAddr, awsMCPEndpoint, metadataRegion)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
