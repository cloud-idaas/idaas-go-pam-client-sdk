package pam_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func receiveError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("operation failed to finish")
		return nil
	}
}

func TestCloseWhileWaitingForProvider(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p := &fakeProvider{get: func(context.Context) (credential.IDaaSCredential, error) {
		close(entered)
		<-release
		return &credential.IDaaSTokenResponse{AccessToken: "test-bearer"}, nil
	}}
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return response(`{}`), nil }}
	client := newClient(t, p, h)
	result := make(chan error, 1)
	go func() { _, err := client.GetAPIKey(context.Background(), "key"); result <- err }()
	<-entered
	closeResult := make(chan error, 1)
	go func() { closeResult <- client.Close() }()
	err := receiveError(t, closeResult)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiveError(t, result); !errors.Is(err, pam.ErrClosed) {
		t.Fatal("provider waiter did not observe close")
	}
	if atomic.LoadInt64(&h.calls) != 0 {
		t.Fatal("HTTP started after provider wait was closed")
	}
}

func TestCloseDoesNotWaitForHTTP(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
		close(entered)
		<-release
		return response(`{"credentialContent":{"apiKeyContent":{"apiKey":"test-key"}}}`), nil
	}}
	client := newClient(t, &fakeProvider{}, h)
	result := make(chan error, 1)
	go func() { _, err := client.GetAPIKey(context.Background(), "key"); result <- err }()
	<-entered
	closeResult := make(chan error, 1)
	go func() { closeResult <- client.Close() }()
	err := receiveError(t, closeResult)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiveError(t, result); err != nil {
		t.Fatal("committed HTTP call did not finish")
	}
	if h.closed != 0 {
		t.Fatal("injected resource was closed")
	}
}

func allCalls(ctx context.Context, client *pam.Client) []func() error {
	return []func() error{
		func() error { _, e := client.GetAPIKey(ctx, ""); return e },
		func() error {
			_, e := client.GenerateJWTAuthenticationToken(ctx, pam.GenerateJWTAuthenticationTokenRequest{})
			return e
		},
		func() error { _, e := client.ObtainJWTAuthenticationToken(ctx, "", ""); return e },
		func() error { _, e := client.ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, ""); return e },
		func() error {
			_, e := client.ListAuthenticationTokens(ctx, pam.ListAuthenticationTokensRequest{})
			return e
		},
		func() error { _, e := client.ValidateAuthenticationToken(ctx, "", nil); return e },
		func() error { return client.RevokeAuthenticationToken(ctx, "", nil) },
		func() error { return client.ReinstateAuthenticationToken(ctx, "", nil) },
		func() error { return client.RevokeAuthenticationTokenByConsumer(ctx, "", "") },
		func() error { return client.ReinstateAuthenticationTokenByConsumer(ctx, "", "") },
		func() error { _, e := client.ObtainAccessCredential(ctx, ""); return e },
	}
}

func TestClosedAndCanceledCalls(t *testing.T) {
	p, h := &fakeProvider{}, &fakeHTTP{}
	client := newClient(t, p, h)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range allCalls(ctx, client) {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation not preserved")
		}
	}
	for _, call := range allCalls(nil, client) { //nolint:staticcheck // Verify the public API rejects a nil context before using dependencies.
		if err := call(); err == nil {
			t.Fatal("nil context accepted")
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, call := range allCalls(context.Background(), client) {
		if err := call(); !errors.Is(err, pam.ErrClosed) {
			t.Fatal("closed call not rejected")
		}
	}
	if p.calls != 0 || h.calls != 0 {
		t.Fatal("rejected calls used dependencies")
	}
}

func TestConcurrentCallsAndClose(t *testing.T) {
	p := &fakeProvider{}
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
		return response(`{"active":false}`), nil
	}}
	client := newClient(t, p, h)
	var workers sync.WaitGroup
	for i := 0; i < 100; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := client.ValidateAuthenticationToken(context.Background(), "token", nil)
			if err != nil && !errors.Is(err, pam.ErrClosed) {
				t.Error(err)
			}
		}()
	}
	for i := 0; i < 10; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	if p.calls != 0 || h.closed != 0 {
		t.Fatal("unexpected resource use")
	}
}

func TestContextPropagatesIntoHTTP(t *testing.T) {
	h := &fakeHTTP{handle: func(ctx context.Context, _ *domain.HttpRequest) (*domain.HttpResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	client := newClient(t, &fakeProvider{}, h)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	h.handle = func(ctx context.Context, _ *domain.HttpRequest) (*domain.HttpResponse, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := make(chan error, 1)
	go func() { _, err := client.ValidateAuthenticationToken(ctx, "token", nil); result <- err }()
	<-started
	cancel()
	if err := receiveError(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal("HTTP cancellation lost")
	}
}
