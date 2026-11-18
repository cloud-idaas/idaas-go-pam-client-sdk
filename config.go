package pam

import (
	"net/url"
	"reflect"
	"strings"

	coreconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	corehttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
	corelogger "github.com/cloud-idaas/idaas-go-core-sdk/logger"
	coreprovider "github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// Scope is the PAM authorization scope requested for a default Core provider.
const Scope = "urn:cloud:idaas:pam|.all"

// Config configures a Client. Empty required values use the initialized Core
// factory. Injected dependencies remain owned by the caller.
// Providers, HTTP clients, and loggers must support concurrent calls.
type Config struct {
	// DeveloperAPIEndpoint is the trusted Developer API base endpoint.
	// A scheme-less host uses HTTPS. Empty uses the Core factory snapshot.
	DeveloperAPIEndpoint string
	// IDaaSInstanceID selects the target instance. Empty uses the Core snapshot.
	IDaaSInstanceID string
	// CredentialProvider supplies AccessTokens for authenticated operations.
	// Nil resolves a Core provider for Scope. The caller owns an injected provider.
	CredentialProvider coreprovider.IDaaSCredentialProvider
	// HTTPClient executes requests through the Core HTTP contract.
	// Nil creates a PAM-owned client with same-origin redirects only.
	// Injected clients and provider transports remain caller-managed.
	HTTPClient corehttp.HttpClient
	// HTTPConfiguration supplies options for an SDK-created HTTP client.
	// Timeouts use milliseconds; zero selects defaults and negative values are invalid.
	// ConnectTimeout defaults to 5000ms. ReadTimeout defaults to 10000ms and limits
	// response-header waiting and the entire HTTP request, including body reading.
	// Request contexts can impose an earlier deadline, including credential retrieval.
	// When Core supplies missing required settings, nil inherits its HTTP configuration.
	// Explicit HTTP configuration is not merged with Core configuration.
	// Configuration is copied at construction and does not reconfigure injected clients.
	HTTPConfiguration *coreconfig.HttpConfiguration
	// Logger receives SDK events. Nil uses Core's default logger, which drops INFO.
	// An injected logger remains caller-owned.
	Logger corelogger.Logger
}

// NewDefaultClient is equivalent to NewClient(Config{}).
// Initialize the Core factory before calling it.
func NewDefaultClient() (*Client, error) {
	return NewClient(Config{})
}

// NewClient validates configuration, copies HTTP options, and binds dependencies.
// It does not fetch credentials. Explicit endpoint, instance ID, and provider
// settings avoid Core factory lookups; missing settings require initialization.
// Serialize Core initialization/reset with factory-backed construction and
// recreate affected clients after rebuilding Core.
func NewClient(cfg Config) (*Client, error) {
	if err := validateExplicitConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.DeveloperAPIEndpoint == "" || cfg.IDaaSInstanceID == "" || cfg.CredentialProvider == nil {
		f := factory.GetInstance() //nolint:staticcheck // Core exposes complete configuration snapshots only through the instance API.
		if !f.IsInitialized() {
			return nil, configError("Core factory must be initialized to supply missing configuration")
		}
		snapshot := f.GetConfig()
		if snapshot == nil {
			return nil, configError("Core factory configuration is unavailable")
		}
		if cfg.DeveloperAPIEndpoint == "" {
			cfg.DeveloperAPIEndpoint = snapshot.DeveloperApiEndpoint
		}
		if cfg.IDaaSInstanceID == "" {
			cfg.IDaaSInstanceID = snapshot.InstanceId
		}
		if cfg.HTTPConfiguration == nil {
			cfg.HTTPConfiguration = snapshot.HttpConfiguration
		}
		if cfg.CredentialProvider == nil {
			p, err := f.GetIDaaSCredentialProviderByScope(Scope)
			if err != nil {
				return nil, dependencyError(err)
			}
			cfg.CredentialProvider = p
		}
	}
	endpoint, err := normalizeEndpoint(cfg.DeveloperAPIEndpoint)
	if err != nil {
		return nil, err
	}
	if err := required(cfg.IDaaSInstanceID, "IDaaSInstanceID"); err != nil {
		return nil, err
	}
	if isNil(cfg.CredentialProvider) {
		return nil, configError("CredentialProvider must be configured")
	}
	httpConfig := coreconfig.DefaultHttpConfiguration()
	if cfg.HTTPConfiguration != nil {
		*httpConfig = *cfg.HTTPConfiguration
		httpConfig.ApplyDefaults()
	}
	if err := validateHTTPConfig(httpConfig); err != nil {
		return nil, err
	}
	ownedHTTP := cfg.HTTPClient == nil
	if ownedHTTP {
		cfg.HTTPClient = newSafeHTTPClient(httpConfig)
	}
	if cfg.Logger == nil {
		cfg.Logger = corelogger.Default()
	}
	return &Client{
		baseURL:   endpoint + "/v2/" + escapeSegment(cfg.IDaaSInstanceID),
		provider:  cfg.CredentialProvider,
		http:      cfg.HTTPClient,
		logger:    cfg.Logger,
		ownedHTTP: ownedHTTP,
	}, nil
}

func validateExplicitConfig(cfg Config) error {
	if cfg.DeveloperAPIEndpoint != "" {
		if _, err := normalizeEndpoint(cfg.DeveloperAPIEndpoint); err != nil {
			return err
		}
	}
	if cfg.IDaaSInstanceID != "" {
		if err := required(cfg.IDaaSInstanceID, "IDaaSInstanceID"); err != nil {
			return err
		}
	}
	for _, dependency := range []interface{}{cfg.CredentialProvider, cfg.HTTPClient, cfg.Logger} {
		if dependency != nil && isNil(dependency) {
			return configError("Injected dependencies must not contain typed nil values")
		}
	}
	return validateHTTPConfig(cfg.HTTPConfiguration)
}

func validateHTTPConfig(cfg *coreconfig.HttpConfiguration) error {
	if cfg != nil && (cfg.ConnectTimeout < 0 || cfg.ReadTimeout < 0) {
		return configError("HTTP timeouts must be nonnegative milliseconds")
	}
	return nil
}

func normalizeEndpoint(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) != raw {
		return "", configError("DeveloperAPIEndpoint must be a valid HTTP(S) endpoint")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Scheme != "https" && u.Scheme != "http") {
		return "", configError("DeveloperAPIEndpoint must be an HTTP(S) endpoint without user info, query, or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func escapeSegment(value string) string {
	if value == "." || value == ".." {
		return strings.ReplaceAll(value, ".", "%2E")
	}
	return url.PathEscape(value)
}

func isNil(value interface{}) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
