package consumer_test

import (
	"context"
	"testing"

	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	corehttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
	corelogger "github.com/cloud-idaas/idaas-go-core-sdk/logger"
	coreprovider "github.com/cloud-idaas/idaas-go-core-sdk/provider"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

// Compile against the public package without access to its implementation.
var (
	_ func(pam.Config) (*pam.Client, error)                                                                         = pam.NewClient
	_ func() (*pam.Client, error)                                                                                   = pam.NewDefaultClient
	_ func() *pam.Builder                                                                                           = pam.NewBuilder
	_ func(*pam.Builder) (*pam.Client, error)                                                                       = (*pam.Builder).Build
	_ func(*pam.Builder, string) *pam.Builder                                                                       = (*pam.Builder).DeveloperAPIEndpoint
	_ func(*pam.Builder, string) *pam.Builder                                                                       = (*pam.Builder).IDaaSInstanceID
	_ func(*pam.Builder, coreprovider.IDaaSCredentialProvider) *pam.Builder                                         = (*pam.Builder).CredentialProvider
	_ func(*pam.Builder, corehttp.HttpClient) *pam.Builder                                                          = (*pam.Builder).HTTPClient
	_ func(*pam.Builder, *coreconfig.HttpConfiguration) *pam.Builder                                                = (*pam.Builder).HTTPConfiguration
	_ func(*pam.Builder, corelogger.Logger) *pam.Builder                                                            = (*pam.Builder).Logger
	_ func(*pam.Client, context.Context, string) (*string, error)                                                   = (*pam.Client).GetAPIKey
	_ func(*pam.Client, context.Context, pam.GenerateJWTAuthenticationTokenRequest) (*pam.JWTTokenResponse, error)  = (*pam.Client).GenerateJWTAuthenticationToken
	_ func(*pam.Client, context.Context, string, string) (*pam.JWTContent, error)                                   = (*pam.Client).ObtainJWTAuthenticationToken
	_ func(*pam.Client, context.Context, string) (*pam.JWTContent, error)                                           = (*pam.Client).ObtainJWTAuthenticationTokenByDerivedShortToken
	_ func(*pam.Client, context.Context, pam.ListAuthenticationTokensRequest) (*pam.AuthenticationTokenPage, error) = (*pam.Client).ListAuthenticationTokens
	_ func(*pam.Client, context.Context, string, *pam.TokenOptions) (bool, error)                                   = (*pam.Client).ValidateAuthenticationToken
	_ func(*pam.Client, context.Context, string, *pam.TokenOptions) error                                           = (*pam.Client).RevokeAuthenticationToken
	_ func(*pam.Client, context.Context, string, *pam.TokenOptions) error                                           = (*pam.Client).ReinstateAuthenticationToken
	_ func(*pam.Client, context.Context, string, string) error                                                      = (*pam.Client).RevokeAuthenticationTokenByConsumer
	_ func(*pam.Client, context.Context, string, string) error                                                      = (*pam.Client).ReinstateAuthenticationTokenByConsumer
	_ func(*pam.Client, context.Context, string) (*pam.CloudAccountRoleAccessCredential, error)                     = (*pam.Client).ObtainAccessCredential
	_ func(*pam.Client) error                                                                                       = (*pam.Client).Close
)

func TestConfigurationErrorsAreReturned(t *testing.T) {
	_, err := pam.NewClient(pam.Config{DeveloperAPIEndpoint: "://invalid"})
	if err == nil {
		t.Fatal("invalid explicit configuration must return an error")
	}
}
