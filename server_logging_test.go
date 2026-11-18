package pam_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

type serverErrorLogger struct {
	fakeLogger
	onError func(context.Context, string, ...interface{})
}

func (l *serverErrorLogger) Error(ctx context.Context, message string, kv ...interface{}) {
	l.onError(ctx, message, kv...)
}

func TestServerErrorLogging(t *testing.T) {
	for _, status := range []int{200, 401, 500, 503} {
		for _, loggerPanics := range []bool{false, true} {
			t.Run(fmt.Sprintf("status=%d/loggerPanics=%t", status, loggerPanics), func(t *testing.T) {
				ctx := context.WithValue(context.Background(), contextKey{}, "logging-context")
				calls := 0
				logger := &serverErrorLogger{onError: func(got context.Context, message string, kv ...interface{}) {
					calls++
					want := []interface{}{"event", "pam.http.server_error", "method", "POST",
						"path", "/authenticationTokens/_/actions/validate", "http_status", status, "request_id", "logging-request"}
					if got != ctx || message != "PAM API server error" || !reflect.DeepEqual(kv, want) {
						t.Error("server error event changed or included unexpected diagnostic data")
					}
					if loggerPanics {
						panic("host logger failure")
					}
				}}
				h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
					return &domain.HttpResponse{StatusCode: status,
						Body:    []byte(`{"active":true,"error":"service_failure","error_description":"original-service-description"}`),
						Headers: map[string][]string{"X-Request-ID": {"logging-request"}}}, nil
				}}
				client, err := pam.NewClient(pam.Config{DeveloperAPIEndpoint: "https://pam.example.test",
					IDaaSInstanceID: "instance", CredentialProvider: &fakeProvider{}, HTTPClient: h, Logger: logger})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				active, err := client.ValidateAuthenticationToken(ctx, "confidential-request-token", nil)
				wantCalls := 0
				if status >= 500 {
					wantCalls = 1
					var server *coreerrors.ServerError
					var httpError *coreerrors.HttpError
					if active || !errors.As(err, &server) || !errors.As(err, &httpError) ||
						server.StatusCode != status || httpError.StatusCode != status ||
						server.ErrorCode() != "service_failure" || server.ErrorMessage() != "original-service-description" ||
						server.RequestId() != "logging-request" {
						t.Fatal("logging changed the original server error")
					}
				} else if status == 200 {
					if !active || err != nil {
						t.Fatal("successful validation changed")
					}
				} else {
					var clientError *coreerrors.ClientError
					if !errors.As(err, &clientError) {
						t.Fatal("client error classification changed")
					}
				}
				if calls != wantCalls {
					t.Fatalf("ERROR events = %d, want %d", calls, wantCalls)
				}
			})
		}
	}
}
