package pam

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

func (c *Client) request(ctx context.Context, method enums.HttpMethod, path string, body interface{}, query url.Values, authenticated bool) (*domain.HttpResponse, error) {
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	request := &domain.HttpRequest{
		Method: method, URL: c.baseURL + path,
		Headers: map[string]string{"Accept": "application/json"}, QueryParams: query,
	}
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, configError("PAM request body must be JSON encodable")
		}
		request.Body = json.RawMessage(encoded)
		request.ContentType = enums.ContentTypeJson
	}
	var accessToken string
	if authenticated {
		credential, err := c.provider.GetCredentialWithContext(ctx)
		if err != nil {
			return nil, dependencyError(err)
		}
		if isNil(credential) {
			return nil, coreerrors.NewCredentialError("InvalidCredential", "Credential provider returned no credential", nil)
		}
		token := credential.GetAccessToken()
		if !validBearer(token) {
			return nil, coreerrors.NewCredentialError("InvalidCredential", "Credential provider returned an invalid access token", nil)
		}
		request.Headers["Authorization"] = "Bearer " + token
		accessToken = token
	}
	// Recheck closure and cancellation after credential resolution. A successful
	// check commits the call to the HTTP phase; injected code runs without the lock.
	if err := c.checkOpen(ctx); err != nil {
		return nil, err
	}
	response, err := c.http.ExecuteContext(ctx, request)
	if err != nil {
		return nil, dependencyError(err)
	}
	if response == nil {
		return nil, responseError("HTTP response")
	}
	if !response.IsSuccess() {
		if response.StatusCode >= 500 && response.StatusCode < 600 {
			c.logServerError(ctx, method, path, response)
		}
		return nil, httpResponseError(response, accessToken)
	}
	return response, nil
}

func (c *Client) logServerError(ctx context.Context, method enums.HttpMethod, path string, response *domain.HttpResponse) {
	// Host logger failures must not replace the original service error.
	defer func() { _ = recover() }()
	c.logger.Error(ctx, "PAM API server error", "event", "pam.http.server_error",
		"method", string(method), "path", path, "http_status", response.StatusCode, "request_id", response.RequestId())
}
