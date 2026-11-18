package pam

import (
	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	corehttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
	corelogger "github.com/cloud-idaas/idaas-go-core-sdk/logger"
	coreprovider "github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// Builder assembles client configuration for use by a single goroutine.
// Each successful Build creates independent client state. Injected dependencies
// retain their original references and may be shared by the resulting clients.
type Builder struct {
	config Config
}

// NewBuilder returns an empty builder whose missing values use the Core factory.
func NewBuilder() *Builder { return &Builder{} }

// DeveloperAPIEndpoint sets the trusted Developer API base endpoint.
// An empty value selects the Core factory default.
func (b *Builder) DeveloperAPIEndpoint(value string) *Builder {
	b.config.DeveloperAPIEndpoint = value
	return b
}

// IDaaSInstanceID sets the target instance ID.
// An empty value selects the Core factory default.
func (b *Builder) IDaaSInstanceID(value string) *Builder {
	b.config.IDaaSInstanceID = value
	return b
}

// CredentialProvider sets a caller-owned credential provider.
func (b *Builder) CredentialProvider(value coreprovider.IDaaSCredentialProvider) *Builder {
	b.config.CredentialProvider = value
	return b
}

// HTTPClient sets a caller-owned Core HTTP client.
func (b *Builder) HTTPClient(value corehttp.HttpClient) *Builder {
	b.config.HTTPClient = value
	return b
}

// HTTPConfiguration sets options for an SDK-owned HTTP client.
// Timeouts use milliseconds. Build copies the configuration; an injected
// HTTP client is not reconfigured.
func (b *Builder) HTTPConfiguration(value *coreconfig.HttpConfiguration) *Builder {
	b.config.HTTPConfiguration = value
	return b
}

// Logger sets the host application's logger.
func (b *Builder) Logger(value corelogger.Logger) *Builder {
	b.config.Logger = value
	return b
}

// Build resolves and validates the accumulated configuration through NewClient.
// Missing required settings need an initialized Core factory.
func (b *Builder) Build() (*Client, error) { return NewClient(b.config) }
