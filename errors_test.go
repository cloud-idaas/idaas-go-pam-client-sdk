package pam_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func TestHTTPErrorMetadataIsPreserved(t *testing.T) {
	for _, status := range []int{400, 503} {
		for _, metadata := range []struct{ code, requestID string }{
			{"E1001", "request-123"},
			{"token=public-code", "password=public-request-id"},
			{strings.Repeat("code", 140), strings.Repeat("request", 100)},
		} {
			t.Run(fmt.Sprintf("%d/%s", status, metadata.code[:4]), func(t *testing.T) {
				body, err := json.Marshal(map[string]string{
					"error": metadata.code, "request_id": metadata.requestID,
					"error_description": "access_token=private-description-token",
				})
				if err != nil {
					t.Fatal(err)
				}
				h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
					return &domain.HttpResponse{StatusCode: status, Body: body}, nil
				}}
				_, err = newClient(t, &fakeProvider{}, h).ListAuthenticationTokens(context.Background(), pam.ListAuthenticationTokensRequest{
					ConsumerID: "consumer", CredentialProviderIdentifier: "provider", MaxResults: pointer(int64(1)),
				})
				assertErrorMetadata(t, err, metadata.code, metadata.requestID)
				for current := err; current != nil; current = errors.Unwrap(current) {
					var sdkError coreerrors.IDaaSError
					if !errors.As(current, &sdkError) || strings.Contains(sdkError.ErrorMessage(), "private-description-token") {
						t.Fatal("HTTP error description changed")
					}
				}
			})
		}
	}
}

func assertErrorMetadata(t *testing.T, err error, code, requestID string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	for current := err; current != nil; current = errors.Unwrap(current) {
		var sdkError coreerrors.IDaaSError
		if !errors.As(current, &sdkError) {
			continue
		}
		if sdkError.ErrorCode() != code || sdkError.RequestId() != requestID {
			t.Fatalf("error metadata changed: %v", current)
		}
	}
}

func TestDependencyErrorMetadataIsPreserved(t *testing.T) {
	const code = "token=key"
	const requestID = "password=key-request"
	const private = "private-description-token"
	for _, failure := range []error{
		coreerrors.NewCredentialError(code, private, errors.New(private)).WithRequestId(requestID),
		coreerrors.NewHttpError(code, private, 502, errors.New(private)).WithRequestId(requestID),
		coreerrors.NewOAuth2Error(401, code, private, private, nil).WithRequestId(requestID),
		coreerrors.NewServerError(code, private, 503, coreerrors.NewOAuth2Error(503, code, private, private, nil).WithRequestId(requestID)).WithRequestId(requestID),
	} {
		for _, fromProvider := range []bool{false, true} {
			t.Run(fmt.Sprintf("%T/provider=%t", failure, fromProvider), func(t *testing.T) {
				p := &fakeProvider{}
				h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return nil, failure }}
				if fromProvider {
					p.get = func(context.Context) (credential.IDaaSCredential, error) { return nil, failure }
				}
				_, err := newClient(t, p, h).GetAPIKey(context.Background(), "key")
				assertErrorMetadata(t, err, code, requestID)
				var oauth *coreerrors.OAuth2Error
				if errors.As(err, &oauth) && (oauth.OAuthCode != code || oauth.RawBody != "") {
					t.Fatal("OAuth code or raw body changed")
				}
			})
		}
	}
}

func TestResponseErrorsPreserveRequestID(t *testing.T) {
	const requestID = "password=public-request-id"
	for _, body := range []string{`not-json`, `{}`} {
		h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 200, Body: []byte(body), Headers: map[string][]string{"X-Request-ID": {requestID}}}, nil
		}}
		_, err := newClient(t, &fakeProvider{}, h).GetAPIKey(context.Background(), "key")
		var sdkError coreerrors.IDaaSError
		if !errors.As(err, &sdkError) || sdkError.RequestId() != requestID {
			t.Fatalf("response error request ID changed: %v", err)
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "private-timeout-material" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestDependencyErrorsAreSanitized(t *testing.T) {
	const private = "private-provider-material"
	tests := []struct {
		name    string
		failure error
		check   func(error) bool
	}{
		{"config", coreerrors.NewConfigError("ProviderConfig", private, errors.New(private)), func(e error) bool { var target *coreerrors.ConfigError; return errors.As(e, &target) }},
		{"credential", coreerrors.NewCredentialError("ProviderCredential", private, errors.New(private)).WithRequestId("request"), func(e error) bool {
			var target *coreerrors.CredentialError
			return errors.As(e, &target) && target.RequestId() == "request"
		}},
		{"encoding", coreerrors.NewEncodingError("ProviderEncoding", private, errors.New(private)), func(e error) bool {
			var target *coreerrors.EncodingError
			return errors.As(e, &target)
		}},
		{"oauth", coreerrors.NewOAuth2Error(401, "invalid_grant", private, private, errors.New(private)), func(e error) bool {
			var target *coreerrors.OAuth2Error
			return errors.As(e, &target) && target.HTTPStatus == 401 && target.OAuthCode == "invalid_grant" && target.RawBody == ""
		}},
		{"server", coreerrors.NewServerError("ProviderServer", private, 503, errors.New(private)), func(e error) bool {
			var target *coreerrors.ServerError
			return errors.As(e, &target) && target.StatusCode == 503
		}},
		{"server with oauth cause", coreerrors.NewServerError("temporarily_unavailable", private, 503,
			coreerrors.NewOAuth2Error(503, "temporarily_unavailable", private, private, errors.New(private))).WithRequestId("server-request"), func(e error) bool {
			var server *coreerrors.ServerError
			var oauth *coreerrors.OAuth2Error
			return errors.As(e, &server) && server.StatusCode == 503 && server.RequestId() == "server-request" &&
				errors.As(e, &oauth) && oauth.HTTPStatus == 503 && oauth.OAuthCode == "temporarily_unavailable" &&
				oauth.RawBody == "" && oauth.RequestId() == "server-request" && !strings.Contains(oauth.ErrorMessage(), private)
		}},
		{"server with oauth deadline", coreerrors.NewServerError("temporarily_unavailable", private, 503,
			coreerrors.NewOAuth2Error(503, "temporarily_unavailable", private, private, context.DeadlineExceeded)), func(e error) bool {
			var server *coreerrors.ServerError
			var oauth *coreerrors.OAuth2Error
			return errors.As(e, &server) && errors.As(e, &oauth) && errors.Is(e, context.DeadlineExceeded)
		}},
		{"server with credential cancellation", coreerrors.NewServerError("ProviderServer", private, 503,
			coreerrors.NewCredentialError("ProviderCredential", private, context.Canceled)), func(e error) bool {
			var server *coreerrors.ServerError
			return errors.As(e, &server) && server.StatusCode == 503 && errors.Is(e, context.Canceled)
		}},
		{"server with credential timeout", coreerrors.NewServerError("ProviderServer", private, 503,
			coreerrors.NewCredentialError("ProviderCredential", private, timeoutError{})), func(e error) bool {
			var server *coreerrors.ServerError
			var networkError net.Error
			return errors.As(e, &server) && server.StatusCode == 503 && errors.As(e, &networkError) && networkError.Timeout()
		}},
		{"client", coreerrors.NewClientError("ProviderClient", private, errors.New(private)), func(e error) bool { var target *coreerrors.ClientError; return errors.As(e, &target) }},
		{"http", coreerrors.NewHttpError("ProviderHTTP", private, 502, errors.New(private)), func(e error) bool {
			var target *coreerrors.HttpError
			return errors.As(e, &target) && target.StatusCode == 502
		}},
		{"unknown", fmt.Errorf("custom %s", private), func(e error) bool { var target *coreerrors.HttpError; return errors.As(e, &target) }},
		{"canceled", fmt.Errorf("%s: %w", private, context.Canceled), func(e error) bool { return errors.Is(e, context.Canceled) }},
		{"deadline", fmt.Errorf("%s: %w", private, context.DeadlineExceeded), func(e error) bool { return errors.Is(e, context.DeadlineExceeded) }},
		{"timeout", timeoutError{}, func(e error) bool { var target net.Error; return errors.As(e, &target) && target.Timeout() }},
		{"core wrapped timeout", fmt.Errorf("%s: %w", private, coreerrors.NewHttpError("ConnectTimeOut", private, 0, timeoutError{}).WithRequestId("timeout-request")), func(e error) bool {
			var networkError net.Error
			var httpError *coreerrors.HttpError
			return errors.As(e, &networkError) && networkError.Timeout() &&
				errors.As(e, &httpError) && httpError.ErrorCode() == "ConnectTimeOut" && httpError.RequestId() == "timeout-request"
		}},
		{"credential wrapped timeout", coreerrors.NewCredentialError("ProviderTimeout", private, timeoutError{}), func(e error) bool {
			var networkError net.Error
			var credentialError *coreerrors.CredentialError
			return errors.As(e, &networkError) && networkError.Timeout() &&
				errors.As(e, &credentialError) && credentialError.ErrorCode() == "ProviderTimeout"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, fromProvider := range []bool{false, true} {
				p := &fakeProvider{}
				h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return nil, test.failure }}
				if fromProvider {
					p.get = func(context.Context) (credential.IDaaSCredential, error) { return nil, test.failure }
				}
				client := newClient(t, p, h)
				_, err := client.GetAPIKey(context.Background(), "key")
				if err == nil || !test.check(err) {
					t.Fatalf("classification lost %v", err)
				}
				if fromProvider && h.calls != 0 {
					t.Fatal("provider error fell through to HTTP")
				}
				for current := err; current != nil; current = errors.Unwrap(current) {
					if strings.Contains(current.Error(), private) || strings.Contains(current.Error(), "private-timeout-material") {
						t.Fatal("custom error leaked")
					}
				}
			}
		})
	}
}

func TestDependencyErrorsPreserveOutermostClassification(t *testing.T) {
	const private = "private-nested-provider-material"
	tests := []struct {
		name    string
		failure coreerrors.IDaaSError
		status  int
	}{
		{"server credential", coreerrors.NewServerError("OuterServer", private, 503, coreerrors.NewCredentialError("InnerCredential", private, nil)).WithRequestId("outer-request"), 503},
		{"server config", coreerrors.NewServerError("OuterServer", private, 502, coreerrors.NewConfigError("InnerConfig", private, nil)).WithRequestId("outer-request"), 502},
		{"server encoding", coreerrors.NewServerError("OuterServer", private, 500, coreerrors.NewEncodingError("InnerEncoding", private, nil)).WithRequestId("outer-request"), 500},
		{"client credential", coreerrors.NewClientError("OuterClient", private, coreerrors.NewCredentialError("InnerCredential", private, nil)).WithRequestId("outer-request"), 0},
		{"oauth credential", coreerrors.NewOAuth2Error(401, "invalid_grant", private, private, coreerrors.NewCredentialError("InnerCredential", private, nil)).WithRequestId("outer-request"), 401},
		{"http credential", coreerrors.NewHttpError("OuterHTTP", private, 504, coreerrors.NewCredentialError("InnerCredential", private, nil)).WithRequestId("outer-request"), 504},
		{"credential config", coreerrors.NewCredentialError("OuterCredential", private, coreerrors.NewConfigError("InnerConfig", private, nil)).WithRequestId("outer-request"), 0},
		{"encoding credential", coreerrors.NewEncodingError("OuterEncoding", private, coreerrors.NewCredentialError("InnerCredential", private, nil)).WithRequestId("outer-request"), 0},
		{"config credential", coreerrors.NewConfigError("OuterConfig", private, coreerrors.NewCredentialError("InnerCredential", private, nil).WithRequestId("inner-request")), 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, wrapped := range []bool{false, true} {
				var failure error = test.failure
				if wrapped {
					failure = fmt.Errorf("%s: %w", private, failure)
				}
				for _, fromProvider := range []bool{false, true} {
					p := &fakeProvider{}
					h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return nil, failure }}
					if fromProvider {
						p.get = func(context.Context) (credential.IDaaSCredential, error) { return nil, failure }
					}
					_, err := newClient(t, p, h).GetAPIKey(context.Background(), "key")
					var actual coreerrors.IDaaSError
					if !errors.As(err, &actual) || reflect.TypeOf(actual) != reflect.TypeOf(test.failure) {
						t.Fatalf("outer classification lost: got %T, want %T", actual, test.failure)
					}
					if actual.ErrorCode() != test.failure.ErrorCode() || actual.RequestId() != test.failure.RequestId() {
						t.Fatal("outer error code or request ID lost")
					}
					status := 0
					switch e := actual.(type) {
					case *coreerrors.ServerError:
						status = e.StatusCode
					case *coreerrors.HttpError:
						status = e.StatusCode
					case *coreerrors.OAuth2Error:
						status = e.HTTPStatus
						if e.RawBody != "" || e.OAuthCode != "invalid_grant" {
							t.Fatal("OAuth classification or body sanitization lost")
						}
					}
					if status != test.status {
						t.Fatalf("HTTP status lost: got %d, want %d", status, test.status)
					}
					if fromProvider && h.calls != 0 {
						t.Fatal("provider error reached HTTP")
					}
					for current := err; current != nil; current = errors.Unwrap(current) {
						if strings.Contains(current.Error(), private) {
							t.Fatal("nested dependency error leaked")
						}
					}
				}
			}
		})
	}
}

func TestInvalidCredentialsAndNilResponse(t *testing.T) {
	var typedNil *credential.IDaaSTokenResponse
	for _, value := range []credential.IDaaSCredential{nil, typedNil, &credential.IDaaSTokenResponse{}, &credential.IDaaSTokenResponse{AccessToken: "bad\r\nheader"}, &credential.IDaaSTokenResponse{AccessToken: " "}} {
		p := &fakeProvider{get: func(context.Context) (credential.IDaaSCredential, error) { return value, nil }}
		h := &fakeHTTP{}
		client := newClient(t, p, h)
		_, err := client.GetAPIKey(context.Background(), "key")
		var credentialError *coreerrors.CredentialError
		if !errors.As(err, &credentialError) || h.calls != 0 {
			t.Fatal("invalid credential reached HTTP")
		}
	}
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return nil, nil }}
	client := newClient(t, &fakeProvider{}, h)
	if _, err := client.GetAPIKey(context.Background(), "key"); err == nil {
		t.Fatal("nil HTTP response accepted")
	}
	for _, body := range []string{`private-response-material`, `{"error":false}`, `{}`} {
		h.handle = func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
			return &domain.HttpResponse{StatusCode: 500, Body: []byte(body)}, nil
		}
		_, err := client.GetAPIKey(context.Background(), "key")
		var server *coreerrors.ServerError
		if !errors.As(err, &server) || server.ErrorCode() != "PAMRequestFailed" || strings.Contains(err.Error(), "private-response-material") {
			t.Fatal("malformed HTTP error classification or sanitization failed")
		}
	}
}

func TestErrorDescriptionsAreBoundedAndValidUTF8(t *testing.T) {
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
		return &domain.HttpResponse{StatusCode: 403, Body: []byte(`{"error":"denied","error_description":"line\n` + strings.Repeat("界", 300) + `"}`)}, nil
	}}
	client := newClient(t, &fakeProvider{}, h)
	_, err := client.GetAPIKey(context.Background(), "key")
	var sdkError coreerrors.IDaaSError
	if !errors.As(err, &sdkError) {
		t.Fatal("expected classified HTTP error")
	}
	message := sdkError.ErrorMessage()
	if len(message) > 512 || !utf8.ValidString(message) || strings.Contains(message, "\n") {
		t.Fatal("description bound or sanitization failed")
	}
}

func TestQuotedCredentialsInServerDescriptionsAreRedacted(t *testing.T) {
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
		return &domain.HttpResponse{StatusCode: 403, Body: []byte(`{"error":"denied","error_description":"upstream {\"password\":\"private spaced password\",\"accessKeySecret\":\"private-secret\",\"apiKey\":\"private-key\"}"}`)}, nil
	}}
	client := newClient(t, &fakeProvider{}, h)
	_, err := client.GetAPIKey(context.Background(), "key")
	if err == nil {
		t.Fatal("expected server rejection")
	}
	for current := err; current != nil; current = errors.Unwrap(current) {
		for _, secret := range []string{"private spaced password", "private-secret", "private-key"} {
			if strings.Contains(current.Error(), secret) {
				t.Fatal("quoted credential leaked in the public error chain")
			}
		}
	}
}

func TestCloudSecretsInErrorDescriptionsAreRedacted(t *testing.T) {
	for _, field := range []string{
		"accessKeySecret", "access_key_secret", "access-key-secret", "ACCESSKEYSECRET",
		"secretAccessKey", "secret_access_key", "secret-access-key", "SECRETACCESSKEY",
		"tmpSecretKey", "tmp_secret_key", "tmp-secret-key", "TMPSECRETKEY",
	} {
		t.Run(field, func(t *testing.T) {
			const secret = "private cloud secret"
			description, err := json.Marshal(map[string]string{field: secret})
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]string{"error": "denied", "error_description": "upstream " + string(description)})
			if err != nil {
				t.Fatal(err)
			}
			h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
				return &domain.HttpResponse{StatusCode: 403, Body: body}, nil
			}}
			client := newClient(t, &fakeProvider{}, h)
			// This identifier also appears in snake/kebab-case field names;
			// literal redaction must not prevent assignment redaction.
			_, err = client.GetAPIKey(context.Background(), "key")
			if err == nil {
				t.Fatal("expected server rejection")
			}
			for current := err; current != nil; current = errors.Unwrap(current) {
				var sdkError coreerrors.IDaaSError
				if strings.Contains(current.Error(), secret) ||
					(errors.As(current, &sdkError) && strings.Contains(sdkError.ErrorMessage(), secret)) {
					t.Fatal("cloud secret leaked in public error fields")
				}
			}
			if !strings.Contains(err.Error(), "upstream") || !strings.Contains(err.Error(), "***") {
				t.Fatal("safe diagnostic context or redaction marker lost")
			}
		})
	}
}
