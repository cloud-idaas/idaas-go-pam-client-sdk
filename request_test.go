package pam_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func validGeneration() pam.GenerateJWTAuthenticationTokenRequest {
	return pam.GenerateJWTAuthenticationTokenRequest{CredentialProviderIdentifier: "provider", Subject: "subject", Audiences: []string{"aud"}}
}

func TestGenerationInputValidationBeforeCredentials(t *testing.T) {
	tests := []struct {
		name   string
		change func(*pam.GenerateJWTAuthenticationTokenRequest)
	}{
		{"provider", func(r *pam.GenerateJWTAuthenticationTokenRequest) { r.CredentialProviderIdentifier = " " }},
		{"subject", func(r *pam.GenerateJWTAuthenticationTokenRequest) { r.Subject = "" }},
		{"audiences", func(r *pam.GenerateJWTAuthenticationTokenRequest) { r.Audiences = nil }},
		{"audience element", func(r *pam.GenerateJWTAuthenticationTokenRequest) { r.Audiences = []string{" "} }},
		{"issuer", func(r *pam.GenerateJWTAuthenticationTokenRequest) { r.Issuer = pointer(" ") }},
		{"zero expiration", func(r *pam.GenerateJWTAuthenticationTokenRequest) { r.Expiration = pointer(int64(0)) }},
		{"large expiration", func(r *pam.GenerateJWTAuthenticationTokenRequest) { r.Expiration = pointer(int64(315360001)) }},
		{"unencodable claims", func(r *pam.GenerateJWTAuthenticationTokenRequest) {
			r.CustomClaims = map[string]interface{}{"bad": make(chan int)}
		}},
		{"large claims", func(r *pam.GenerateJWTAuthenticationTokenRequest) {
			r.CustomClaims = map[string]interface{}{"x": strings.Repeat("x", 16377)}
		}},
		{"large UTF8 claims", func(r *pam.GenerateJWTAuthenticationTokenRequest) {
			r.CustomClaims = map[string]interface{}{"x": strings.Repeat("界", 5460)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, h := &fakeProvider{}, &fakeHTTP{}
			client := newClient(t, p, h)
			input := validGeneration()
			test.change(&input)
			_, err := client.GenerateJWTAuthenticationToken(context.Background(), input)
			var configError *coreerrors.ConfigError
			if !errors.As(err, &configError) || p.calls != 0 || h.calls != 0 {
				t.Fatal("invalid request reached dependencies")
			}
		})
	}
}

type changingClaim struct{ calls int }

func (c *changingClaim) MarshalJSON() ([]byte, error) {
	c.calls++
	return []byte(fmt.Sprintf(`{"version":%d}`, c.calls)), nil
}

func TestClaimsSnapshotAndBounds(t *testing.T) {
	claim := &changingClaim{}
	h := &fakeHTTP{handle: func(_ context.Context, r *domain.HttpRequest) (*domain.HttpResponse, error) {
		for i := 0; i < 2; i++ {
			encoded, err := json.Marshal(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &body); err != nil {
				t.Fatal(err)
			}
			if string(body["customClaims"]) != `{"claim":{"version":1}}` {
				t.Fatal("claim snapshot changed")
			}
		}
		return response(`{"authenticationTokenId":"id","jwtContent":{"jwtValue":"jwt"}}`), nil
	}}
	client := newClient(t, &fakeProvider{}, h)
	input := validGeneration()
	input.CustomClaims = map[string]interface{}{"claim": claim}
	if _, err := client.GenerateJWTAuthenticationToken(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if claim.calls != 1 {
		t.Fatal("custom serializer invoked multiple times")
	}
	for _, duration := range []int64{1, 315360000} {
		h.handle = func(_ context.Context, r *domain.HttpRequest) (*domain.HttpResponse, error) {
			encoded, err := json.Marshal(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &body); err != nil {
				t.Fatal(err)
			}
			if _, exists := body["issuer"]; exists {
				t.Fatal("nil issuer emitted")
			}
			if _, exists := body["includeDerivedShortToken"]; exists {
				t.Fatal("nil bool emitted")
			}
			if len(body["customClaims"]) != 16384 {
				t.Fatal("claims byte boundary changed")
			}
			return response(`{"authenticationTokenId":"id","jwtContent":{"jwtValue":"jwt"}}`), nil
		}
		input = validGeneration()
		input.Expiration = pointer(duration)
		input.CustomClaims = map[string]interface{}{"x": strings.Repeat("x", 16376)}
		if _, err := client.GenerateJWTAuthenticationToken(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOtherInputValidation(t *testing.T) {
	p, h := &fakeProvider{}, &fakeHTTP{}
	client := newClient(t, p, h)
	ctx := context.Background()
	invalid := []func() error{
		func() error { _, e := client.GetAPIKey(ctx, " "); return e },
		func() error { _, e := client.ObtainJWTAuthenticationToken(ctx, "", "id"); return e },
		func() error { _, e := client.ObtainJWTAuthenticationToken(ctx, "consumer", ""); return e },
		func() error { _, e := client.ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, ""); return e },
		func() error {
			_, e := client.ListAuthenticationTokens(ctx, pam.ListAuthenticationTokensRequest{})
			return e
		},
		func() error {
			_, e := client.ListAuthenticationTokens(ctx, pam.ListAuthenticationTokensRequest{ConsumerID: "consumer"})
			return e
		},
		func() error {
			_, e := client.ListAuthenticationTokens(ctx, pam.ListAuthenticationTokensRequest{ConsumerID: "consumer", CredentialProviderIdentifier: "provider", MaxResults: pointer(int64(0))})
			return e
		},
		func() error { _, e := client.ValidateAuthenticationToken(ctx, "", nil); return e },
		func() error {
			_, e := client.ValidateAuthenticationToken(ctx, "token", &pam.TokenOptions{TokenTypeHint: pointer(" ")})
			return e
		},
		func() error { return client.RevokeAuthenticationToken(ctx, "", nil) },
		func() error {
			return client.ReinstateAuthenticationToken(ctx, "token", &pam.TokenOptions{TokenTypeHint: pointer("")})
		},
		func() error { return client.RevokeAuthenticationTokenByConsumer(ctx, "", "provider") },
		func() error { return client.ReinstateAuthenticationTokenByConsumer(ctx, "consumer", "") },
		func() error { _, e := client.ObtainAccessCredential(ctx, ""); return e },
	}
	for _, call := range invalid {
		var configError *coreerrors.ConfigError
		if !errors.As(call(), &configError) {
			t.Fatal("expected configuration error")
		}
	}
	if p.calls != 0 || h.calls != 0 {
		t.Fatal("invalid inputs used dependencies")
	}
}
