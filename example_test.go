package pam_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

// exampleProvider makes unexpected authentication visible in this offline example.
type exampleProvider struct{}

func (exampleProvider) GetCredential() (credential.IDaaSCredential, error) {
	return nil, errors.New("this example uses an unauthenticated operation")
}
func (p exampleProvider) GetCredentialWithContext(context.Context) (credential.IDaaSCredential, error) {
	return p.GetCredential()
}

// exampleHTTP supplies an offline Developer API response through the Core interface.
type exampleHTTP struct{}

func (exampleHTTP) ExecuteContext(context.Context, *domain.HttpRequest) (*domain.HttpResponse, error) {
	return &domain.HttpResponse{StatusCode: 200, Body: []byte(`{"active":false}`)}, nil
}
func (h exampleHTTP) Execute(request *domain.HttpRequest) (*domain.HttpResponse, error) {
	return h.ExecuteContext(context.Background(), request)
}
func (exampleHTTP) Get(string, map[string]string) (*domain.HttpResponse, error) {
	return nil, errors.New("use ExecuteContext")
}
func (exampleHTTP) Post(string, map[string]string, interface{}) (*domain.HttpResponse, error) {
	return nil, errors.New("use ExecuteContext")
}

func ExampleClient_ValidateAuthenticationToken() {
	client, err := pam.NewClient(pam.Config{
		DeveloperAPIEndpoint: "https://pam.example.test",
		IDaaSInstanceID:      "example-instance",
		CredentialProvider:   exampleProvider{},
		HTTPClient:           exampleHTTP{},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	active, err := client.ValidateAuthenticationToken(context.Background(), "example-token", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(active)
	if err := client.Close(); err != nil {
		fmt.Println(err)
	}
	// Output: false
}

func ExampleNewBuilder() {
	client, err := pam.NewBuilder().
		DeveloperAPIEndpoint("https://pam.example.test").
		IDaaSInstanceID("example-instance").
		CredentialProvider(exampleProvider{}).
		HTTPClient(exampleHTTP{}).
		Build()
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := client.Close(); err != nil {
		fmt.Println(err)
		return
	}
	_, err = client.ValidateAuthenticationToken(context.Background(), "example-token", nil)
	fmt.Println(errors.Is(err, pam.ErrClosed))
	// Output: true
}
