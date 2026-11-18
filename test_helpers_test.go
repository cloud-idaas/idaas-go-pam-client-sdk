package pam_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

type fakeHTTP struct {
	handle func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error)
	calls  int64
	closed int64
}

func (f *fakeHTTP) ExecuteContext(ctx context.Context, request *domain.HttpRequest) (*domain.HttpResponse, error) {
	atomic.AddInt64(&f.calls, 1)
	return f.handle(ctx, request)
}
func (*fakeHTTP) Execute(*domain.HttpRequest) (*domain.HttpResponse, error) {
	panic("ExecuteContext must be used")
}
func (*fakeHTTP) Get(string, map[string]string) (*domain.HttpResponse, error) {
	panic("ExecuteContext must be used")
}
func (*fakeHTTP) Post(string, map[string]string, interface{}) (*domain.HttpResponse, error) {
	panic("ExecuteContext must be used")
}
func (f *fakeHTTP) CloseIdleConnections() { atomic.AddInt64(&f.closed, 1) }

type fakeProvider struct {
	get   func(context.Context) (credential.IDaaSCredential, error)
	calls int64
}

func (f *fakeProvider) GetCredential() (credential.IDaaSCredential, error) {
	panic("GetCredentialWithContext must be used")
}
func (f *fakeProvider) GetCredentialWithContext(ctx context.Context) (credential.IDaaSCredential, error) {
	atomic.AddInt64(&f.calls, 1)
	if f.get != nil {
		return f.get(ctx)
	}
	return &credential.IDaaSTokenResponse{AccessToken: "test-bearer", TokenType: "Bearer", ExpiresIn: 3600}, nil
}

type fakeLogger struct {
	info  int64
	panic bool
}

func (*fakeLogger) Debug(context.Context, string, ...interface{}) {}
func (*fakeLogger) Warn(context.Context, string, ...interface{})  {}
func (*fakeLogger) Error(context.Context, string, ...interface{}) {}
func (f *fakeLogger) Info(_ context.Context, message string, kv ...interface{}) {
	atomic.AddInt64(&f.info, 1)
	if f.panic {
		panic("host logger failure")
	}
	if strings.Contains(message, "test-key") || strings.Contains(message, "test-bearer") {
		panic("unexpected credential in log")
	}
}

func response(body string) *domain.HttpResponse {
	return &domain.HttpResponse{StatusCode: 200, Body: []byte(body), Headers: map[string][]string{"X-Request-ID": {"test-request"}}}
}

func newClient(t *testing.T, provider *fakeProvider, http *fakeHTTP) *pam.Client {
	t.Helper()
	client, err := pam.NewClient(pam.Config{
		DeveloperAPIEndpoint: "https://pam.example.test/base/",
		IDaaSInstanceID:      "instance:+ /角色",
		CredentialProvider:   provider,
		HTTPClient:           http,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func pointer[T any](value T) *T { return &value }

type contextKey struct{}
