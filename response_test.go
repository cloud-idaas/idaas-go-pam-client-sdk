package pam_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func TestMalformedResponses(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		call   func(*pam.Client) error
		bodies []string
	}{
		{"api key", func(c *pam.Client) error { _, e := c.GetAPIKey(ctx, "key"); return e }, []string{
			``, `not-json`, `null`, `[]`, `{}`, `{"credentialContent":null}`, `{"credentialContent":[]}`, `{"credentialContent":{}}`,
			`{"credentialContent":{"apiKeyContent":7}}`, `{"credentialContent":{"apiKeyContent":{}}}`, `{"credentialContent":{"apiKeyContent":{"apiKey":null}}}`,
			`{"credentialContent":{"apiKeyContent":{"apiKey":" "}}}`, `{"credentialContent":{"apiKeyContent":{"apiKey":7}}}`,
		}},
		{"generate", func(c *pam.Client) error {
			_, e := c.GenerateJWTAuthenticationToken(ctx, pam.GenerateJWTAuthenticationTokenRequest{CredentialProviderIdentifier: "provider", Subject: "subject", Audiences: []string{"aud"}})
			return e
		}, []string{
			`not-json`, `{}`, `{"authenticationTokenId":""}`, `{"authenticationTokenId":"id"}`, `{"authenticationTokenId":"id","jwtContent":null}`,
			`{"authenticationTokenId":"id","jwtContent":{}}`, `{"authenticationTokenId":"id","jwtContent":{"jwtValue":""}}`,
			`{"authenticationTokenId":"id","jwtContent":{"jwtValue":"jwt","derivedShortToken":null}}`,
			`{"authenticationTokenId":"id","jwtContent":{"jwtValue":"jwt"},"consumerType":false}`,
			`{"authenticationTokenId":"id","jwtContent":{"jwtValue":"jwt"},"consumerId":null}`,
		}},
		{"obtain", func(c *pam.Client) error { _, e := c.ObtainJWTAuthenticationToken(ctx, "consumer", "id"); return e }, []string{`[]`, `{}`, `{"jwtContent":false}`, `{"jwtContent":{"jwtValue":5}}`}},
		{"validate", func(c *pam.Client) error { _, e := c.ValidateAuthenticationToken(ctx, "token", nil); return e }, []string{`not-json`, `{}`, `{"active":null}`, `{"active":"false"}`}},
		{"list", func(c *pam.Client) error {
			_, e := c.ListAuthenticationTokens(ctx, pam.ListAuthenticationTokensRequest{ConsumerID: "consumer", CredentialProviderIdentifier: "provider"})
			return e
		}, []string{
			`not-json`, `{}`, `{"entities":null}`, `{"entities":{}}`, `{"entities":[null]}`, `{"entities":[5]}`,
			`{"entities":[{"instanceId":false}]}`, `{"entities":[{"consumerId":null}]}`, `{"entities":[{"createTime":1.5}]}`, `{"entities":[{"expirationTime":9223372036854775808}]}`,
			`{"entities":[{"revoked":null}]}`, `{"entities":[],"totalCount":1.5}`, `{"entities":[],"maxResults":null}`, `{"entities":[],"nextToken":false}`,
		}},
		{"sts", func(c *pam.Client) error { _, e := c.ObtainAccessCredential(ctx, "role"); return e }, []string{
			`not-json`, `{}`, `{"cloudAccountRoleAccessCredential":null}`, `{"cloudAccountRoleAccessCredential":{}}`,
			`{"cloudAccountRoleAccessCredential":{"accessCredentialExpiresAt":null}}`,
			`{"cloudAccountRoleAccessCredential":{"alibabaCloudStsToken":null}}`,
			`{"cloudAccountRoleAccessCredential":{"alibabaCloudStsToken":{"accessKeyId":null}}}`,
			`{"cloudAccountRoleAccessCredential":{"alibabaCloudStsToken":{"expiration":""}}}`,
			`{"cloudAccountRoleAccessCredential":{"awsStsToken":[]}}`,
			`{"cloudAccountRoleAccessCredential":{"awsStsToken":{"sessionToken":false}}}`,
			`{"cloudAccountRoleAccessCredential":{"tencentCloudStsToken":5}}`,
			`{"cloudAccountRoleAccessCredential":{"tencentCloudStsToken":{"expiredTime":1.5}}}`,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for index, body := range test.bodies {
				t.Run(fmt.Sprint(index), func(t *testing.T) {
					h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return response(body), nil }}
					client := newClient(t, &fakeProvider{}, h)
					err := test.call(client)
					var sdkError coreerrors.IDaaSError
					if !errors.As(err, &sdkError) || sdkError.RequestId() != "test-request" {
						t.Fatalf("expected classified response error with request ID, got %v", err)
					}
					if sdkError.ErrorCode() != "InvalidResponse" && sdkError.ErrorCode() != "DecodeFailed" {
						t.Fatal("wrong response classification")
					}
				})
			}
		})
	}
}

func TestTokenMetadataPrecisionAndOptionalValues(t *testing.T) {
	const body = `{"entities":[{"instanceId":"instance","authenticationTokenId":"id","authenticationTokenType":"jwt","credentialProviderId":"provider","creatorType":"application","creatorId":"creator","consumerType":"custom","consumerId":"consumer","revoked":false,"createTime":1700000000123,"updateTime":1700000000456,"expirationTime":9223372036854775807},{"unknownFutureField":true}],"totalCount":9223372036854775807,"maxResults":2,"nextToken":"next"}`
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return response(body), nil }}
	client := newClient(t, &fakeProvider{}, h)
	page, err := client.ListAuthenticationTokens(context.Background(), pam.ListAuthenticationTokensRequest{ConsumerID: "consumer", CredentialProviderIdentifier: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entities) != 2 || *page.TotalCount != 9223372036854775807 || page.NextToken != "next" {
		t.Fatal("page precision lost")
	}
	first := page.Entities[0]
	if *first.CreateTime != 1700000000123 || *first.UpdateTime != 1700000000456 || *first.ExpirationTime != 9223372036854775807 || *first.Revoked {
		t.Fatal("metadata precision or false lost")
	}
	if page.Entities[1].Revoked != nil || page.Entities[1].CreateTime != nil || page.Entities[1].ConsumerID != nil {
		t.Fatal("missing metadata filled with zero values")
	}
	for _, next := range []string{``, `,"nextToken":null`, `,"nextToken":""`} {
		h.handle = func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
			return response(`{"entities":[]` + next + `}`), nil
		}
		page, err = client.ListAuthenticationTokens(context.Background(), pam.ListAuthenticationTokensRequest{ConsumerID: "consumer", CredentialProviderIdentifier: "provider"})
		if err != nil || page.Entities == nil || page.NextToken != "" || page.TotalCount != nil {
			t.Fatal("optional pagination not preserved")
		}
	}
}

func TestTokenPageCountBounds(t *testing.T) {
	for _, test := range []struct {
		name, fields string
		invalid      bool
	}{
		{"absent", ``, false},
		{"zero", `,"totalCount":0,"maxResults":0`, false},
		{"positive", `,"totalCount":1,"maxResults":20`, false},
		{"negative total", `,"totalCount":-1,"maxResults":20`, true},
		{"negative page size", `,"totalCount":0,"maxResults":-1`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
				return response(`{"entities":[]` + test.fields + `}`), nil
			}}
			client := newClient(t, &fakeProvider{}, h)
			page, err := client.ListAuthenticationTokens(context.Background(), pam.ListAuthenticationTokensRequest{
				ConsumerID: "consumer", CredentialProviderIdentifier: "provider",
			})
			if test.invalid {
				var target *coreerrors.CredentialError
				if page != nil || !errors.As(err, &target) || target.ErrorCode() != "InvalidResponse" || target.RequestId() != "test-request" {
					t.Fatalf("expected InvalidResponse with request ID and no page, got %v, %v", page, err)
				}
				return
			}
			if err != nil || page == nil || page.Entities == nil {
				t.Fatalf("valid page rejected: %v", err)
			}
			if test.name == "absent" {
				if page.TotalCount != nil || page.MaxResults != nil {
					t.Fatal("absent counts were filled")
				}
			} else {
				var want struct{ TotalCount, MaxResults int64 }
				if err := json.Unmarshal([]byte(`{`+test.fields[1:]+`}`), &want); err != nil {
					t.Fatal(err)
				}
				if page.TotalCount == nil || page.MaxResults == nil || *page.TotalCount != want.TotalCount || *page.MaxResults != want.MaxResults {
					t.Fatal("valid counts changed")
				}
			}
		})
	}
}

func TestOmittedEntitiesOnExplicitEmptyPage(t *testing.T) {
	for _, test := range []struct {
		name, body string
		valid      bool
	}{
		{"terminal zero page", `{"totalCount":0,"maxResults":20}`, true},
		{"null end cursor", `{"totalCount":0,"maxResults":20,"nextToken":null}`, true},
		{"empty end cursor", `{"totalCount":0,"maxResults":0,"nextToken":""}`, true},
		{"unknown total", `{"maxResults":20}`, false},
		{"unknown page size", `{"totalCount":0}`, false},
		{"nonzero total", `{"totalCount":1,"maxResults":20}`, false},
		{"another page", `{"totalCount":0,"maxResults":20,"nextToken":"next"}`, false},
		{"null array", `{"entities":null,"totalCount":0,"maxResults":20}`, false},
		{"invalid count type", `{"totalCount":"0","maxResults":20}`, false},
		{"negative page size", `{"totalCount":0,"maxResults":-1}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
				return response(test.body), nil
			}}
			client := newClient(t, &fakeProvider{}, h)
			page, err := client.ListAuthenticationTokens(context.Background(), pam.ListAuthenticationTokensRequest{
				ConsumerID: "consumer", CredentialProviderIdentifier: "provider",
			})
			if test.valid {
				if err != nil || page == nil || page.Entities == nil || len(page.Entities) != 0 || page.TotalCount == nil || *page.TotalCount != 0 || page.NextToken != "" {
					t.Fatalf("expected a valid terminal empty page: %v, %v", page, err)
				}
				return
			}
			var sdkError *coreerrors.CredentialError
			if page != nil || !errors.As(err, &sdkError) || sdkError.ErrorCode() != "InvalidResponse" || sdkError.RequestId() != "test-request" {
				t.Fatalf("expected a classified invalid response: %v, %v", page, err)
			}
		})
	}
}

func TestCloudCredentialWireFields(t *testing.T) {
	const body = `{"cloudAccountRoleAccessCredential":{"accessCredentialExpiresAt":2051222400,"alibabaCloudStsToken":{"accessKeyId":"ali-id","accessKeySecret":"ali-secret","securityToken":"ali-token","expiration":"2035-01-01T00:00:00Z"},"awsStsToken":{"accessKeyId":"aws-id","secretAccessKey":"aws-secret","sessionToken":"aws-token","expiration":"2035-01-01T00:00:00Z"},"tencentCloudStsToken":{"tmpSecretId":"tencent-id","tmpSecretKey":"tencent-secret","token":"tencent-token","expiration":"2035-01-01T00:00:00Z","expiredTime":2051222400}}}`
	h := &fakeHTTP{handle: func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) { return response(body), nil }}
	client := newClient(t, &fakeProvider{}, h)
	result, err := client.ObtainAccessCredential(context.Background(), "role")
	if err != nil {
		t.Fatal(err)
	}
	if *result.AccessCredentialExpiresAt != 2051222400 || *result.TencentCloudSTSToken.ExpiredTime != 2051222400 {
		t.Fatal("STS second units lost")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	var actual map[string]interface{}
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(root["cloudAccountRoleAccessCredential"], actual) {
		t.Fatal("wire fields changed")
	}
	for _, cloud := range []string{"alibabaCloudStsToken", "awsStsToken", "tencentCloudStsToken"} {
		h.handle = func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
			return response(`{"cloudAccountRoleAccessCredential":{"` + cloud + `":{}}}`), nil
		}
		if _, err := client.ObtainAccessCredential(context.Background(), "role"); err != nil {
			t.Fatal("partial cloud response rejected")
		}
	}
	h.handle = func(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
		return response(`{"cloudAccountRoleAccessCredential":{"accessCredentialExpiresAt":-1,"awsStsToken":{"accessKeyId":"exact-id","AccessKeyId":"alias-id","SecretAccessKey":"alias-secret"},"tencentCloudStsToken":{"expiredTime":0}}}`), nil
	}
	result, err = client.ObtainAccessCredential(context.Background(), "role")
	if err != nil {
		t.Fatal(err)
	}
	if *result.AWSSTSToken.AccessKeyID != "exact-id" || result.AWSSTSToken.SecretAccessKey != nil {
		t.Fatal("unknown case aliases overwrote exact wire fields")
	}
	if *result.AccessCredentialExpiresAt != -1 || *result.TencentCloudSTSToken.ExpiredTime != 0 {
		t.Fatal("raw optional timestamp values changed")
	}
}
