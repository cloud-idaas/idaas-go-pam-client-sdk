package jwtflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
	"github.com/cloud-idaas/idaas-go-pam-client-sdk/samples/internal/jwtflow"
)

type fakeProvider struct{}

func (fakeProvider) GetCredential() (credential.IDaaSCredential, error) {
	return &credential.IDaaSTokenResponse{AccessToken: "synthetic-access-token"}, nil
}
func (p fakeProvider) GetCredentialWithContext(context.Context) (credential.IDaaSCredential, error) {
	return p.GetCredential()
}

type fakeHTTP struct {
	t          *testing.T
	actions    []string
	subject    string
	active     bool
	fail       string
	mismatch   bool
	omitShort  bool
	wrongState bool
	cancel     context.CancelFunc
}

func (f *fakeHTTP) ExecuteContext(ctx context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	f.t.Helper()
	action := req.URL[strings.LastIndex(req.URL, "/")+1:]
	f.actions = append(f.actions, action)
	if action == "validate" || action == "obtainJwtByDerivedShortToken" {
		if req.Headers["Authorization"] != "" {
			f.t.Fatal("unauthenticated operation sent a bearer credential")
		}
	}
	if action == f.fail {
		f.fail = ""
		return &domain.HttpResponse{StatusCode: 503, Body: []byte("{}")}, nil
	}
	encoded, err := json.Marshal(req.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(encoded, &body); err != nil {
		f.t.Fatal(err)
	}
	result := map[string]interface{}{}
	switch action {
	case "generateJwt":
		f.subject, _ = body["subject"].(string)
		if !strings.HasPrefix(f.subject, "go-pam-sample-") {
			f.t.Fatal("subject is not run-specific")
		}
		consumer := f.subject
		if f.mismatch {
			consumer = "existing-consumer"
		}
		content := map[string]interface{}{"jwtValue": "synthetic-jwt"}
		if !f.omitShort {
			content["derivedShortToken"] = "synthetic-short-token"
		}
		result = map[string]interface{}{"authenticationTokenId": "synthetic-token-id", "consumerId": consumer, "jwtContent": content}
		if f.cancel != nil {
			f.cancel()
		}
	case "obtainJwt":
		if body["consumerId"] != f.subject || body["authenticationTokenId"] != "synthetic-token-id" {
			f.t.Fatal("JWT lookup did not use the generated identity")
		}
		result["jwtContent"] = map[string]interface{}{"jwtValue": "synthetic-jwt"}
	case "obtainJwtByDerivedShortToken":
		if body["derivedShortToken"] != "synthetic-short-token" {
			f.t.Fatal("wrong derived token")
		}
		result["jwtContent"] = map[string]interface{}{"jwtValue": "synthetic-jwt"}
	case "revoke", "revokeByConsumer":
		if action == "revoke" {
			if ctx.Err() != nil {
				f.t.Fatal("cleanup inherited a canceled context")
			}
			if body["token"] != "synthetic-jwt" {
				f.t.Fatal("cleanup did not target the generated token")
			}
		}
		if action == "revokeByConsumer" && body["consumerId"] != f.subject {
			f.t.Fatal("bulk revocation targeted an existing consumer")
		}
		f.active = false
	case "reinstate", "reinstateByConsumer":
		if action == "reinstateByConsumer" && body["consumerId"] != f.subject {
			f.t.Fatal("bulk reinstatement targeted an existing consumer")
		}
		f.active = true
	case "validate":
		result["active"] = f.active && !f.wrongState
	default:
		f.t.Fatalf("unexpected action %s", action)
	}
	encoded, err = json.Marshal(result)
	if err != nil {
		f.t.Fatal(err)
	}
	return &domain.HttpResponse{StatusCode: 200, Body: encoded}, nil
}
func (*fakeHTTP) Execute(*domain.HttpRequest) (*domain.HttpResponse, error)   { panic("use context") }
func (*fakeHTTP) Get(string, map[string]string) (*domain.HttpResponse, error) { panic("use context") }
func (*fakeHTTP) Post(string, map[string]string, interface{}) (*domain.HttpResponse, error) {
	panic("use context")
}

func clientFor(t *testing.T, http *fakeHTTP) *pam.Client {
	t.Helper()
	client, err := pam.NewClient(pam.Config{DeveloperAPIEndpoint: "https://pam.example.test", IDaaSInstanceID: "synthetic-instance", CredentialProvider: fakeProvider{}, HTTPClient: http})
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

func TestWorkflowsAndCleanup(t *testing.T) {
	tests := []struct {
		mode    string
		actions []string
	}{
		{"generate-jwt", []string{"generateJwt", "revoke"}},
		{"obtain-jwt", []string{"generateJwt", "obtainJwt", "obtainJwtByDerivedShortToken", "revoke"}},
		{"token-lifecycle", []string{"generateJwt", "validate", "revoke", "validate", "reinstate", "validate", "revoke"}},
		{"consumer-lifecycle", []string{"generateJwt", "revokeByConsumer", "validate", "reinstateByConsumer", "validate", "revoke"}},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			http := &fakeHTTP{t: t, active: true}
			if err := jwtflow.Run(context.Background(), clientFor(t, http), tt.mode, "provider", "audience"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(http.actions, tt.actions) {
				t.Fatalf("actions %v, want %v", http.actions, tt.actions)
			}
			if http.active {
				t.Fatal("generated token was not revoked")
			}
		})
	}
}

func TestFailureStillCleansUp(t *testing.T) {
	for _, action := range []string{"obtainJwt", "obtainJwtByDerivedShortToken", "revokeByConsumer", "reinstateByConsumer", "validate", "reinstate"} {
		t.Run(action, func(t *testing.T) {
			mode := "token-lifecycle"
			if strings.HasPrefix(action, "obtain") {
				mode = "obtain-jwt"
			}
			if strings.HasSuffix(action, "ByConsumer") {
				mode = "consumer-lifecycle"
			}
			http := &fakeHTTP{t: t, active: true, fail: action}
			if err := jwtflow.Run(context.Background(), clientFor(t, http), mode, "provider", "audience"); err == nil {
				t.Fatal("failure was swallowed")
			}
			if http.actions[len(http.actions)-1] != "revoke" || http.active {
				t.Fatal("failed workflow did not revoke its token")
			}
		})
	}
}

func TestIdentityAndResponseGuards(t *testing.T) {
	for _, kind := range []string{"consumer", "short-token", "state", "cleanup", "generation", "mode"} {
		t.Run(kind, func(t *testing.T) {
			http := &fakeHTTP{t: t, active: true}
			mode := "obtain-jwt"
			switch kind {
			case "consumer":
				http.mismatch = true
				mode = "consumer-lifecycle"
			case "short-token":
				http.omitShort = true
			case "state":
				http.wrongState = true
				mode = "token-lifecycle"
			case "cleanup":
				http.fail = "revoke"
			case "generation":
				http.fail = "generateJwt"
			case "mode":
				mode = "unknown"
			}
			if err := jwtflow.Run(context.Background(), clientFor(t, http), mode, "provider", "audience"); err == nil {
				t.Fatal("invalid response or failure was accepted")
			}
			if kind == "mode" && len(http.actions) != 0 {
				t.Fatal("invalid mode made a request")
			}
			if kind != "mode" && kind != "generation" && http.actions[len(http.actions)-1] != "revoke" {
				t.Fatal("cleanup was not attempted")
			}
			for _, action := range http.actions {
				if kind == "consumer" && strings.HasSuffix(action, "ByConsumer") {
					t.Fatal("identity mismatch reached a bulk operation")
				}
			}
		})
	}
}

func TestCleanupUsesIndependentContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	http := &fakeHTTP{t: t, active: true, cancel: cancel}
	err := jwtflow.Run(ctx, clientFor(t, http), "token-lifecycle", "provider", "audience")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not preserved: %v", err)
	}
	if http.active || http.actions[len(http.actions)-1] != "revoke" {
		t.Fatal("cancellation prevented cleanup")
	}
}
