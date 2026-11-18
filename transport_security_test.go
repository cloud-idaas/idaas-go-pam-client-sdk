//go:build pam_transport_security
// +build pam_transport_security

package pam_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

const transportShortToken = "synthetic-transport-short-token"
const transportJWTResponse = `{"jwtContent":{"jwtValue":"synthetic-transport-jwt"}}`

func defaultTransportClient(t *testing.T, endpoint string) (*pam.Client, *fakeProvider) {
	t.Helper()
	provider := &fakeProvider{}
	client, err := pam.NewClient(pam.Config{
		DeveloperAPIEndpoint: endpoint,
		IDaaSInstanceID:      "transport-instance",
		CredentialProvider:   provider,
	})
	if err != nil {
		t.Fatal("default transport client construction failed")
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error("default transport client cleanup failed")
		}
	})
	return client, provider
}

func observeShortTokenRequest(t *testing.T, r *http.Request) bool {
	t.Helper()
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
		t.Error("short-token request method or authentication changed")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		t.Error("short-token request body could not be read")
	}
	return strings.Contains(string(body), transportShortToken)
}

func TestDefaultTransportSameOriginRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				if !observeShortTokenRequest(t, r) {
					t.Error("same-origin redirect lost the short-token body")
				}
				switch r.URL.Path {
				case "/v2/transport-instance/authenticationTokens/_/actions/obtainJwtByDerivedShortToken":
					http.Redirect(w, r, "/complete", status)
				case "/complete":
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, transportJWTResponse)
				default:
					t.Error("unexpected same-origin redirect path")
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			client, provider := defaultTransportClient(t, server.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := client.ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, transportShortToken)
			if err != nil || result == nil || result.JWTValue != "synthetic-transport-jwt" || atomic.LoadInt32(&calls) != 2 {
				t.Fatal("same-origin redirect control did not complete")
			}
			if atomic.LoadInt64(&provider.calls) != 0 {
				t.Fatal("short-token exchange requested a Bearer credential")
			}
		})
	}
}

func TestDefaultTransportCrossOriginRedirectsNeverReplayShortToken(t *testing.T) {
	for _, first := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, second := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			t.Run(fmt.Sprintf("%d-%d", first, second), func(t *testing.T) {
				var sourceCalls, targetCalls, leaked int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&targetCalls, 1)
					if observeShortTokenRequest(t, r) {
						atomic.StoreInt32(&leaked, 1)
					}
					switch r.URL.Path {
					case "/hop":
						http.Redirect(w, r, "/complete", second)
					case "/complete":
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, transportJWTResponse)
					default:
						t.Error("unexpected cross-origin redirect path")
						http.NotFound(w, r)
					}
				}))
				t.Cleanup(target.Close)
				source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&sourceCalls, 1)
					if r.URL.Path != "/v2/transport-instance/authenticationTokens/_/actions/obtainJwtByDerivedShortToken" || !observeShortTokenRequest(t, r) {
						t.Error("original short-token request did not reach its configured endpoint")
					}
					http.Redirect(w, r, target.URL+"/hop", first)
				}))
				t.Cleanup(source.Close)
				client, provider := defaultTransportClient(t, source.URL)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := client.ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, transportShortToken)
				if atomic.LoadInt32(&leaked) != 0 {
					t.Error("cross-origin redirect replayed a confidential short token")
				}
				if err == nil || result != nil || atomic.LoadInt32(&targetCalls) != 0 {
					t.Error("cross-origin request was not rejected before reaching the target")
				}
				if atomic.LoadInt32(&sourceCalls) != 1 || atomic.LoadInt64(&provider.calls) != 0 {
					t.Error("original request or credential-provider behavior changed")
				}
				var sdkError coreerrors.IDaaSError
				if !errors.As(err, &sdkError) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					t.Error("redirect rejection was not a classified SDK failure")
				}
			})
		}
	}
}

func TestDefaultTransportRejectsCrossOriginBeforeSending(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, authenticated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-bearer-%t", status, authenticated), func(t *testing.T) {
				var calls int32
				target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					atomic.AddInt32(&calls, 1)
				}))
				defer target.Close()
				source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if authenticated && r.Header.Get("Authorization") != "Bearer test-bearer" {
						t.Error("original request lost its Bearer credential")
					}
					http.Redirect(w, r, target.URL, status)
				}))
				defer source.Close()
				client, provider := defaultTransportClient(t, source.URL)
				var err error
				if authenticated {
					err = client.RevokeAuthenticationToken(context.Background(), transportShortToken, nil)
				} else {
					_, err = client.ObtainJWTAuthenticationTokenByDerivedShortToken(context.Background(), transportShortToken)
				}
				var sdk *coreerrors.HttpError
				if !errors.As(err, &sdk) || atomic.LoadInt32(&calls) != 0 || strings.Contains(err.Error(), transportShortToken) {
					t.Fatal("redirect was not safely rejected")
				}
				want := int64(0)
				if authenticated {
					want = 1
				}
				if atomic.LoadInt64(&provider.calls) != want {
					t.Fatal("credential lookup behavior changed")
				}
			})
		}
	}
}

func TestDefaultTransportRejectsTLSDowngrade(t *testing.T) {
	var calls int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { atomic.AddInt32(&calls, 1) }))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	client, err := pam.NewClient(pam.Config{DeveloperAPIEndpoint: source.URL, IDaaSInstanceID: "tls-instance",
		CredentialProvider: &fakeProvider{}, HTTPConfiguration: &coreconfig.HttpConfiguration{UnsafeIgnoreSSLCert: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	_, err = client.ObtainJWTAuthenticationTokenByDerivedShortToken(context.Background(), transportShortToken)
	var sdk *coreerrors.HttpError
	if !errors.As(err, &sdk) || atomic.LoadInt32(&calls) != 0 {
		t.Fatal("TLS downgrade was followed")
	}
}

func TestDefaultTransportCancellationAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			entered := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				<-r.Context().Done()
			}))
			defer server.Close()
			options := &coreconfig.HttpConfiguration{}
			if timeout {
				options.ReadTimeout = 100
			}
			client, err := pam.NewClient(pam.Config{DeveloperAPIEndpoint: server.URL, IDaaSInstanceID: "context-instance",
				CredentialProvider: &fakeProvider{}, HTTPConfiguration: options})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := client.ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, transportShortToken)
				done <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("request never reached server")
			}
			if !timeout {
				cancel()
			}
			err = receiveError(t, done)
			if timeout {
				var network interface{ Timeout() bool }
				if !errors.As(err, &network) || !network.Timeout() {
					t.Fatal("HTTP timeout classification lost")
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatal("context cancellation lost")
			}
		})
	}
}
