package pam_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func TestBusinessMethodsProtocol(t *testing.T) {
	contract := readPublicContract(t)
	operations := make(map[string]publicOperation, len(contract.Operations))
	for _, operation := range contract.Operations {
		if _, exists := operations[operation.HTTP.Path]; exists {
			t.Fatal("duplicate operation path")
		}
		operations[operation.HTTP.Path] = operation
	}
	ctx := context.WithValue(context.Background(), contextKey{}, "request-context")
	jwt := `{"authenticationTokenId":"test-token-id","consumerId":"test-consumer","consumerType":"custom","jwtContent":{"jwtValue":"test-jwt","derivedShortToken":"test-short"}}`
	tests := []struct {
		name   string
		method string
		path   string
		query  url.Values
		body   map[string]interface{}
		result string
		auth   bool
		call   func(*pam.Client) (interface{}, error)
	}{
		{"api-key", "GET", "/credentials/_/actions/obtain", url.Values{"credentialIdentifier": {"key +/标识"}}, nil,
			`{"credentialContent":{"apiKeyContent":{"apiKey":"test-key"}}}`, true,
			func(c *pam.Client) (interface{}, error) { return c.GetAPIKey(ctx, "key +/标识") }},
		{"generate", "POST", "/authenticationTokens/_/actions/generateJwt", nil,
			map[string]interface{}{"credentialProviderIdentifier": "provider", "subject": "subject", "audiences": []interface{}{"aud"}, "issuer": "issuer", "customClaims": map[string]interface{}{}, "expiration": float64(42), "includeDerivedShortToken": false}, jwt, true,
			func(c *pam.Client) (interface{}, error) {
				return c.GenerateJWTAuthenticationToken(ctx, pam.GenerateJWTAuthenticationTokenRequest{CredentialProviderIdentifier: "provider", Subject: "subject", Audiences: []string{"aud"}, Issuer: pointer("issuer"), CustomClaims: map[string]interface{}{}, Expiration: pointer(int64(42)), IncludeDerivedShortToken: pointer(false)})
			}},
		{"obtain", "POST", "/authenticationTokens/_/actions/obtainJwt", nil,
			map[string]interface{}{"consumerId": "consumer", "authenticationTokenId": "token-id"}, jwt, true,
			func(c *pam.Client) (interface{}, error) {
				return c.ObtainJWTAuthenticationToken(ctx, "consumer", "token-id")
			}},
		{"short", "POST", "/authenticationTokens/_/actions/obtainJwtByDerivedShortToken", nil,
			map[string]interface{}{"derivedShortToken": "short"}, jwt, false,
			func(c *pam.Client) (interface{}, error) {
				return c.ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, "short")
			}},
		{"list", "GET", "/authenticationTokens", url.Values{"consumerId": {"consumer"}, "credentialProviderIdentifier": {"provider"}, "nextToken": {"next+/"}, "maxResults": {"9223372036854775807"}, "revoked": {"false"}, "expired": {"false"}}, nil,
			`{"entities":[],"totalCount":0,"maxResults":23,"nextToken":null}`, true,
			func(c *pam.Client) (interface{}, error) {
				return c.ListAuthenticationTokens(ctx, pam.ListAuthenticationTokensRequest{ConsumerID: "consumer", CredentialProviderIdentifier: "provider", NextToken: "next+/", MaxResults: pointer(int64(9223372036854775807)), Revoked: pointer(false), Expired: pointer(false)})
			}},
		{"validate", "POST", "/authenticationTokens/_/actions/validate", nil,
			map[string]interface{}{"token": "token", "token_type_hint": "hint"}, `{"active":false}`, false,
			func(c *pam.Client) (interface{}, error) {
				return c.ValidateAuthenticationToken(ctx, "token", &pam.TokenOptions{TokenTypeHint: pointer("hint")})
			}},
		{"revoke", "POST", "/authenticationTokens/_/actions/revoke", nil,
			map[string]interface{}{"token": "token"}, "", true,
			func(c *pam.Client) (interface{}, error) { return nil, c.RevokeAuthenticationToken(ctx, "token", nil) }},
		{"reinstate", "POST", "/authenticationTokens/_/actions/reinstate", nil,
			map[string]interface{}{"token": "token", "token_type_hint": "hint"}, "", true,
			func(c *pam.Client) (interface{}, error) {
				return nil, c.ReinstateAuthenticationToken(ctx, "token", &pam.TokenOptions{TokenTypeHint: pointer("hint")})
			}},
		{"revoke-consumer", "POST", "/authenticationTokens/_/actions/revokeByConsumer", nil,
			map[string]interface{}{"consumerId": "consumer", "credentialProviderIdentifier": "provider"}, "", true,
			func(c *pam.Client) (interface{}, error) {
				return nil, c.RevokeAuthenticationTokenByConsumer(ctx, "consumer", "provider")
			}},
		{"reinstate-consumer", "POST", "/authenticationTokens/_/actions/reinstateByConsumer", nil,
			map[string]interface{}{"consumerId": "consumer", "credentialProviderIdentifier": "provider"}, "", true,
			func(c *pam.Client) (interface{}, error) {
				return nil, c.ReinstateAuthenticationTokenByConsumer(ctx, "consumer", "provider")
			}},
		{"sts", "GET", "/cloudAccountRoles/_/actions/obtainAccessCredential", url.Values{"cloudAccountRoleExternalId": {"role +/"}}, nil,
			`{"cloudAccountRoleAccessCredential":{"awsStsToken":{"accessKeyId":"test-id"}}}`, true,
			func(c *pam.Client) (interface{}, error) { return c.ObtainAccessCredential(ctx, "role +/") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation, exists := operations[test.path]
			if !exists || operation.HTTP.Method != test.method || operation.HTTP.Bearer != test.auth {
				t.Fatal("protocol test and public contract differ")
			}
			provider := &fakeProvider{get: func(got context.Context) (credential.IDaaSCredential, error) {
				if got != ctx {
					t.Error("provider context changed")
				}
				return &credential.IDaaSTokenResponse{AccessToken: "test-bearer"}, nil
			}}
			http := &fakeHTTP{handle: func(got context.Context, request *domain.HttpRequest) (*domain.HttpResponse, error) {
				if got != ctx {
					t.Error("HTTP context changed")
				}
				if string(request.Method) != test.method {
					t.Error("wrong HTTP method")
				}
				u, err := url.Parse(request.URL)
				if err != nil {
					t.Fatal(err)
				}
				if u.Host != "pam.example.test" || u.EscapedPath() != "/base/v2/instance:+%20%2F%E8%A7%92%E8%89%B2"+test.path {
					t.Errorf("wrong URL %s", request.URL)
				}
				if !reflect.DeepEqual(request.QueryParams, test.query) {
					t.Errorf("query mismatch %v", request.QueryParams)
				}
				for _, field := range operation.Required {
					if test.method == "GET" && request.QueryParams.Get(field) == "" {
						t.Errorf("missing required query field %s", field)
					}
					if test.method == "POST" {
						if _, exists := test.body[field]; !exists {
							t.Errorf("missing required body field %s", field)
						}
					}
				}
				if (request.Headers["Authorization"] == "Bearer test-bearer") != test.auth {
					t.Error("wrong authentication")
				}
				if test.body != nil {
					if request.ContentType != "JSON" {
						t.Error("missing JSON content type")
					}
					encoded, err := json.Marshal(request.Body)
					if err != nil {
						t.Fatal(err)
					}
					var body map[string]interface{}
					if err := json.Unmarshal(encoded, &body); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(body, test.body) {
						t.Errorf("body mismatch %v", body)
					}
				} else if request.Body != nil {
					t.Error("unexpected body")
				}
				return response(test.result), nil
			}}
			client := newClient(t, provider, http)
			if provider.calls != 0 {
				t.Fatal("constructor fetched credentials")
			}
			result, err := test.call(client)
			if err != nil {
				t.Fatal(err)
			}
			wantProviderCalls := int64(0)
			if test.auth {
				wantProviderCalls = 1
			}
			if provider.calls != wantProviderCalls || http.calls != 1 {
				t.Fatal("incorrect dependency calls")
			}
			switch value := result.(type) {
			case *string:
				if value == nil || *value != "test-key" {
					t.Fatal("incorrect API key")
				}
			case *pam.JWTTokenResponse:
				if value.AuthenticationTokenID != "test-token-id" || value.JWTContent.JWTValue != "test-jwt" || *value.ConsumerType != "custom" {
					t.Fatal("incorrect JWT response")
				}
			case *pam.JWTContent:
				if value.JWTValue != "test-jwt" || *value.DerivedShortToken != "test-short" {
					t.Fatal("incorrect JWT content")
				}
			case *pam.AuthenticationTokenPage:
				if value.Entities == nil || len(value.Entities) != 0 || *value.TotalCount != 0 || value.NextToken != "" {
					t.Fatal("incorrect empty page")
				}
			case bool:
				if value {
					t.Fatal("active=false was lost")
				}
			case *pam.CloudAccountRoleAccessCredential:
				if value.AWSSTSToken == nil || *value.AWSSTSToken.AccessKeyID != "test-id" || value.AWSSTSToken.SecretAccessKey != nil {
					t.Fatal("incorrect partial STS result")
				}
			}
		})
	}
	if len(tests) != len(operations) {
		t.Fatal("every public operation must have a protocol scenario")
	}
}

func TestAPIKeyNullAndLoggerIsolation(t *testing.T) {
	for _, panicLogger := range []bool{false, true} {
		log := &fakeLogger{panic: panicLogger}
		http := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
			return response(`{"credentialContent":{"apiKeyContent":null}}`), nil
		}}
		client, err := pam.NewClient(pam.Config{DeveloperAPIEndpoint: "pam.example.test", IDaaSInstanceID: "instance", CredentialProvider: &fakeProvider{}, HTTPClient: http, Logger: log})
		if err != nil {
			t.Fatal(err)
		}
		key, err := client.GetAPIKey(context.Background(), "identifier")
		if err != nil || key != nil || log.info != 1 {
			t.Fatal("legal null or INFO event lost")
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if http.closed != 0 {
			t.Fatal("injected HTTP client closed")
		}
	}
}

func TestHTTPFailuresPreserveDiagnostics(t *testing.T) {
	for _, status := range []int{301, 401, 403, 500, 503} {
		provider := &fakeProvider{}
		http := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: status, Body: []byte(`{"error":"denied","error_description":"plain description test-bearer token=test-secret apiKey=test-key","request_id":"test-request"}`)}, nil
		}}
		client := newClient(t, provider, http)
		_, err := client.GetAPIKey(context.Background(), "identifier")
		if err == nil {
			t.Fatal("HTTP failure accepted")
		}
		var sdkError coreerrors.IDaaSError
		var httpError *coreerrors.HttpError
		if !errors.As(err, &sdkError) || sdkError.ErrorCode() != "denied" || sdkError.RequestId() != "test-request" || !strings.Contains(sdkError.ErrorMessage(), "plain description") {
			t.Fatal("lost public error fields")
		}
		if !errors.As(err, &httpError) || httpError.StatusCode != status {
			t.Fatal("lost HTTP status")
		}
		if status >= 500 {
			var server *coreerrors.ServerError
			if !errors.As(err, &server) {
				t.Fatal("wrong server classification")
			}
		} else {
			var clientError *coreerrors.ClientError
			if !errors.As(err, &clientError) {
				t.Fatal("wrong client classification")
			}
		}
		for current := err; current != nil; current = errors.Unwrap(current) {
			var original coreerrors.IDaaSError
			if !errors.As(current, &original) || !strings.Contains(original.ErrorMessage(), "plain description") {
				t.Fatal("public description lost through error chain")
			}
			for _, secret := range []string{"test-bearer", "test-secret", "test-key"} {
				if strings.Contains(current.Error(), secret) || strings.Contains(original.ErrorMessage(), secret) {
					t.Fatal("credential present in public error chain")
				}
			}
		}
	}
}
