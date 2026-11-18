package pam_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func TestConfigValidation(t *testing.T) {
	factory.Reset()
	t.Cleanup(factory.Reset)
	var nilProvider *fakeProvider
	var nilHTTP *fakeHTTP
	var nilLogger *fakeLogger
	tests := []struct {
		name   string
		change func(*pam.Config)
	}{
		{"missing endpoint", func(c *pam.Config) { c.DeveloperAPIEndpoint = "" }},
		{"missing instance", func(c *pam.Config) { c.IDaaSInstanceID = "" }},
		{"missing provider", func(c *pam.Config) { c.CredentialProvider = nil }},
		{"blank endpoint", func(c *pam.Config) { c.DeveloperAPIEndpoint = " " }},
		{"blank instance", func(c *pam.Config) { c.IDaaSInstanceID = "\t" }},
		{"typed nil provider", func(c *pam.Config) { c.CredentialProvider = nilProvider }},
		{"typed nil HTTP", func(c *pam.Config) { c.HTTPClient = nilHTTP }},
		{"typed nil logger", func(c *pam.Config) { c.Logger = nilLogger }},
		{"bad scheme", func(c *pam.Config) { c.DeveloperAPIEndpoint = "ftp://pam.test" }},
		{"bad host", func(c *pam.Config) { c.DeveloperAPIEndpoint = "https://" }},
		{"bad port", func(c *pam.Config) { c.DeveloperAPIEndpoint = "https://pam.test:bad" }},
		{"userinfo", func(c *pam.Config) { c.DeveloperAPIEndpoint = "https://user:private@pam.test" }},
		{"query", func(c *pam.Config) { c.DeveloperAPIEndpoint = "https://pam.test?q=private" }},
		{"empty query", func(c *pam.Config) { c.DeveloperAPIEndpoint = "https://pam.test?" }},
		{"fragment", func(c *pam.Config) { c.DeveloperAPIEndpoint = "https://pam.test#private" }},
		{"negative timeout", func(c *pam.Config) { c.HTTPConfiguration = &coreconfig.HttpConfiguration{ConnectTimeout: -1} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := pam.Config{DeveloperAPIEndpoint: "pam.example.test", IDaaSInstanceID: "instance", CredentialProvider: &fakeProvider{}, HTTPClient: &fakeHTTP{}}
			test.change(&cfg)
			client, err := pam.NewClient(cfg)
			var configError *coreerrors.ConfigError
			if client != nil || !errors.As(err, &configError) {
				t.Fatal("expected configuration error")
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("configuration value leaked")
			}
		})
	}
	if client, err := pam.NewDefaultClient(); client != nil || err == nil {
		t.Fatal("uninitialized defaults accepted")
	}
}

func TestBuilderAndOwnedResources(t *testing.T) {
	factory.Reset()
	t.Cleanup(factory.Reset)
	p := &fakeProvider{}
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
		return response(`{"credentialContent":{"apiKeyContent":{"apiKey":"test-key"}}}`), nil
	}}
	options := &coreconfig.HttpConfiguration{}
	b := pam.NewBuilder().DeveloperAPIEndpoint("pam.example.test").IDaaSInstanceID(".").CredentialProvider(p).HTTPClient(h).HTTPConfiguration(options).Logger(&fakeLogger{})
	client, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	b.DeveloperAPIEndpoint("changed.test").IDaaSInstanceID("changed")
	options.ConnectTimeout = -1
	h.handle = func(_ context.Context, r *domain.HttpRequest) (*domain.HttpResponse, error) {
		if r.URL != "https://pam.example.test/v2/%2E/credentials/_/actions/obtain" {
			t.Fatal("builder mutated existing client")
		}
		return response(`{"credentialContent":{"apiKeyContent":{"apiKey":"test-key"}}}`), nil
	}
	if _, err := client.GetAPIKey(context.Background(), "key"); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if h.closed != 0 {
		t.Fatal("caller-owned resource closed")
	}
	owned, err := pam.NewClient(pam.Config{DeveloperAPIEndpoint: "http://127.0.0.1", IDaaSInstanceID: "..", CredentialProvider: p, HTTPConfiguration: &coreconfig.HttpConfiguration{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 {
		t.Fatal("constructors fetched credentials")
	}
}

func TestFactoryConfigurationCombinations(t *testing.T) {
	factory.Reset()
	t.Cleanup(factory.Reset)
	t.Setenv("PAM_UNIT_CLIENT_SECRET", "fixed-unit-secret")
	var tokenRequests int64
	coreHTTP := &fakeHTTP{handle: func(_ context.Context, r *domain.HttpRequest) (*domain.HttpResponse, error) {
		atomic.AddInt64(&tokenRequests, 1)
		if r.URL != "https://auth.example.test/token" {
			return nil, fmt.Errorf("unexpected token URL")
		}
		return response(`{"access_token":"factory-bearer","token_type":"Bearer","expires_in":3600}`), nil
	}}
	f := factory.GetInstance().WithHttpClient(coreHTTP) //nolint:staticcheck // Core's test HTTP injection is available only through the instance API.
	if err := f.Initialize(&coreconfig.IDaaSClientConfig{
		ClientId: "unit-client", InstanceId: "factory-instance", DeveloperApiEndpoint: "https://factory.example.test", IssuerEndpoint: "https://auth.example.test", TokenEndpoint: "https://auth.example.test/token", Scope: "urn:unit|read",
		HttpConfiguration:  &coreconfig.HttpConfiguration{ConnectTimeout: 5000, ReadTimeout: 10000},
		AuthnConfiguration: &coreconfig.IdentityAuthenticationConfiguration{AuthnMethod: enums.TokenAuthnMethodClientSecretPost, IdentityType: enums.AuthenticationIdentityClient, ClientSecretEnvVarName: "PAM_UNIT_CLIENT_SECRET"},
	}); err != nil {
		t.Fatal(err)
	}
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("explicit-%03b", mask), func(t *testing.T) {
			explicit := &fakeProvider{}
			wantEndpoint, wantInstance, wantToken := "https://factory.example.test", "factory-instance", "factory-bearer"
			cfg := pam.Config{}
			if mask&1 != 0 {
				cfg.DeveloperAPIEndpoint = "https://explicit.example.test"
				wantEndpoint = cfg.DeveloperAPIEndpoint
			}
			if mask&2 != 0 {
				cfg.IDaaSInstanceID = "explicit-instance"
				wantInstance = cfg.IDaaSInstanceID
			}
			if mask&4 != 0 {
				cfg.CredentialProvider = explicit
				wantToken = "test-bearer"
			}
			h := &fakeHTTP{handle: func(_ context.Context, r *domain.HttpRequest) (*domain.HttpResponse, error) {
				if r.URL != wantEndpoint+"/v2/"+wantInstance+"/credentials/_/actions/obtain" || r.Headers["Authorization"] != "Bearer "+wantToken {
					t.Fatal("incorrect resolved configuration")
				}
				return response(`{"credentialContent":{"apiKeyContent":{"apiKey":"test-key"}}}`), nil
			}}
			cfg.HTTPClient = h
			client, err := pam.NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if explicit.calls != 0 {
				t.Fatal("constructor fetched credential")
			}
			if _, err := client.GetAPIKey(context.Background(), "key"); err != nil {
				t.Fatal(err)
			}
			wantCalls := int64(0)
			if mask&4 != 0 {
				wantCalls = 1
			}
			if explicit.calls != wantCalls {
				t.Fatal("explicit provider precedence lost")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	defaultClient, err := pam.NewDefaultClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultClient.Close(); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&tokenRequests) == 0 {
		t.Fatal("factory path did not obtain a token")
	}
}
