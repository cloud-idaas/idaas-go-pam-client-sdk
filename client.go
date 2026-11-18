package pam

import (
	"context"
	"net/url"
	"sync"

	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	corehttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
	corelogger "github.com/cloud-idaas/idaas-go-core-sdk/logger"
	coreprovider "github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// Client calls the PAM Developer API. Construct it with NewClient,
// NewDefaultClient, or NewBuilder; its zero value is not ready for use.
// A Client supports concurrent calls; injected dependencies must do so as well.
// Do not copy a Client or modify request values while a call is in progress.
type Client struct {
	baseURL   string
	provider  coreprovider.IDaaSCredentialProvider
	http      corehttp.HttpClient
	logger    corelogger.Logger
	ownedHTTP bool
	mu        sync.RWMutex
	closed    bool
}

// Close releases SDK-owned idle connections and is concurrent-safe and idempotent.
// New calls return errors matching ErrClosed through errors.Is. Calls already in
// the HTTP phase retain their original context. Injected dependencies remain
// caller-owned; Close does not cancel calls or wait for application goroutines.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		if c.ownedHTTP {
			if closer, ok := c.http.(corehttp.ResourceCloser); ok {
				closer.CloseIdleConnections()
			}
		}
	}
	return nil
}

func (c *Client) checkOpen(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return closedError()
	}
	if ctx == nil {
		return configError("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return dependencyError(err)
	}
	return nil
}

// GetAPIKey retrieves an API Key by credential identifier.
// Null apiKeyContent returns nil, nil; missing or malformed fields return an error.
func (c *Client) GetAPIKey(ctx context.Context, credentialIdentifier string) (*string, error) {
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	if err := required(credentialIdentifier, "credentialIdentifier"); err != nil {
		return nil, err
	}
	response, err := c.request(ctx, enums.HttpMethodGet, "/credentials/_/actions/obtain", nil,
		url.Values{"credentialIdentifier": {credentialIdentifier}}, true)
	if err != nil {
		return nil, err
	}
	result, err := parseAPIKey(response.Body)
	if err != nil {
		return nil, withResponseID(err, response)
	}
	if result == nil {
		c.logNullAPIKey(ctx)
	}
	return result, nil
}

// GenerateJWTAuthenticationToken generates a JWT with optional claims and lifetime.
// Generation is not guaranteed to be idempotent and is not automatically retried.
// After a timeout, cancellation, or parsing error, check the service result
// before retrying; a token may already have been created.
func (c *Client) GenerateJWTAuthenticationToken(ctx context.Context, input GenerateJWTAuthenticationTokenRequest) (*JWTTokenResponse, error) {
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	body, err := generationBody(input)
	if err != nil {
		return nil, err
	}
	response, err := c.request(ctx, enums.HttpMethodPost, "/authenticationTokens/_/actions/generateJwt", body, nil, true)
	if err != nil {
		return nil, err
	}
	result, err := parseJWTResponse(response.Body)
	return result, withResponseID(err, response)
}

// ObtainJWTAuthenticationToken retrieves a JWT by consumer and authentication Token ID.
// Both identifiers must be nonblank.
func (c *Client) ObtainJWTAuthenticationToken(ctx context.Context, consumerID, authenticationTokenID string) (*JWTContent, error) {
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	if err := required(consumerID, "consumerId"); err != nil {
		return nil, err
	}
	if err := required(authenticationTokenID, "authenticationTokenId"); err != nil {
		return nil, err
	}
	return c.obtainJWT(ctx, "/authenticationTokens/_/actions/obtainJwt", map[string]interface{}{
		"consumerId": consumerID, "authenticationTokenId": authenticationTokenID,
	}, true)
}

// ObtainJWTAuthenticationTokenByDerivedShortToken exchanges a short token
// without requesting or sending a Bearer credential.
func (c *Client) ObtainJWTAuthenticationTokenByDerivedShortToken(ctx context.Context, derivedShortToken string) (*JWTContent, error) {
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	if err := required(derivedShortToken, "derivedShortToken"); err != nil {
		return nil, err
	}
	return c.obtainJWT(ctx, "/authenticationTokens/_/actions/obtainJwtByDerivedShortToken",
		map[string]interface{}{"derivedShortToken": derivedShortToken}, false)
}

func (c *Client) obtainJWT(ctx context.Context, path string, body interface{}, authenticated bool) (*JWTContent, error) {
	response, err := c.request(ctx, enums.HttpMethodPost, path, body, nil, authenticated)
	if err != nil {
		return nil, err
	}
	result, err := parseJWT(response.Body)
	return result, withResponseID(err, response)
}

// ListAuthenticationTokens lists token metadata with filters and pagination.
// Empty input NextToken selects the first page; empty output NextToken marks the last.
func (c *Client) ListAuthenticationTokens(ctx context.Context, input ListAuthenticationTokensRequest) (*AuthenticationTokenPage, error) {
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	query, err := listQuery(input)
	if err != nil {
		return nil, err
	}
	response, err := c.request(ctx, enums.HttpMethodGet, "/authenticationTokens", nil, query, true)
	if err != nil {
		return nil, err
	}
	result, err := parseTokenPage(response.Body)
	return result, withResponseID(err, response)
}

// ValidateAuthenticationToken returns the active flag without Bearer authentication.
// An inactive token returns false, nil. Nil options omit the token-type hint.
func (c *Client) ValidateAuthenticationToken(ctx context.Context, token string, options *TokenOptions) (bool, error) {
	if err := c.checkOpen(ctx); err != nil {
		return false, err
	}
	body, err := tokenBody(token, options)
	if err != nil {
		return false, err
	}
	response, err := c.request(ctx, enums.HttpMethodPost, "/authenticationTokens/_/actions/validate", body, nil, false)
	if err != nil {
		return false, err
	}
	object, err := decodeObject(response.Body)
	if err != nil {
		return false, withResponseID(err, response)
	}
	active, err := readField[bool](object, "active", true)
	if err != nil {
		return false, withResponseID(err, response)
	}
	return *active, nil
}

// RevokeAuthenticationToken revokes a single token.
// token is the token value, not its AuthenticationTokenID, and must be nonblank.
// Nil options omit the service token-type hint.
func (c *Client) RevokeAuthenticationToken(ctx context.Context, token string, options *TokenOptions) error {
	return c.tokenAction(ctx, "revoke", token, options)
}

// ReinstateAuthenticationToken reinstates a single token.
// token is the token value, not its AuthenticationTokenID, and must be nonblank.
// Nil options omit the service token-type hint.
func (c *Client) ReinstateAuthenticationToken(ctx context.Context, token string, options *TokenOptions) error {
	return c.tokenAction(ctx, "reinstate", token, options)
}

func (c *Client) tokenAction(ctx context.Context, action, token string, options *TokenOptions) error {
	if err := c.checkOpen(ctx); err != nil {
		return err
	}
	body, err := tokenBody(token, options)
	if err != nil {
		return err
	}
	_, err = c.request(ctx, enums.HttpMethodPost, "/authenticationTokens/_/actions/"+action, body, nil, true)
	return err
}

// RevokeAuthenticationTokenByConsumer revokes all matching tokens for a consumer
// and credential provider. Both parameters must be nonblank; use the provider's
// configured identifier, not its CredentialProviderID.
func (c *Client) RevokeAuthenticationTokenByConsumer(ctx context.Context, consumerID, credentialProviderIdentifier string) error {
	return c.consumerAction(ctx, "revokeByConsumer", consumerID, credentialProviderIdentifier)
}

// ReinstateAuthenticationTokenByConsumer reinstates all matching tokens for a
// consumer and credential provider. Both parameters must be nonblank; use the
// provider's configured identifier, not its CredentialProviderID.
func (c *Client) ReinstateAuthenticationTokenByConsumer(ctx context.Context, consumerID, credentialProviderIdentifier string) error {
	return c.consumerAction(ctx, "reinstateByConsumer", consumerID, credentialProviderIdentifier)
}

func (c *Client) consumerAction(ctx context.Context, action, consumerID, identifier string) error {
	if err := c.checkOpen(ctx); err != nil {
		return err
	}
	if err := required(consumerID, "consumerId"); err != nil {
		return err
	}
	if err := required(identifier, "credentialProviderIdentifier"); err != nil {
		return err
	}
	_, err := c.request(ctx, enums.HttpMethodPost, "/authenticationTokens/_/actions/"+action,
		map[string]interface{}{"consumerId": consumerID, "credentialProviderIdentifier": identifier}, nil, true)
	return err
}

// ObtainAccessCredential retrieves cloud STS fields by a nonblank role external ID.
// Validate required fields and effective expiration before use, or use a cloud
// adapter. See CloudAccountRoleAccessCredential for response field semantics.
func (c *Client) ObtainAccessCredential(ctx context.Context, roleExternalID string) (*CloudAccountRoleAccessCredential, error) {
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	if err := required(roleExternalID, "cloudAccountRoleExternalId"); err != nil {
		return nil, err
	}
	response, err := c.request(ctx, enums.HttpMethodGet, "/cloudAccountRoles/_/actions/obtainAccessCredential", nil,
		url.Values{"cloudAccountRoleExternalId": {roleExternalID}}, true)
	if err != nil {
		return nil, err
	}
	result, err := parseCloudCredential(response.Body)
	return result, withResponseID(err, response)
}

func (c *Client) logNullAPIKey(ctx context.Context) {
	// A host logger must not change a successful business result.
	defer func() { _ = recover() }()
	c.logger.Info(ctx, "API key content is null", "event", "pam.api_key.null")
}
