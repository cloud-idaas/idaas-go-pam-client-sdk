package pam

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// ErrClosed identifies calls rejected after the client has been closed.
var ErrClosed = errors.New("PAM client is closed")

var credentialAssignment = regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?key[_-]?id|secret[_-]?access[_-]?key|tmp[_-]?secret[_-]?key|tmp[_-]?secret[_-]?id|security[_-]?token|session[_-]?token|refresh[_-]?token|access[_-]?token|client[_-]?secret|token|password|secret|assertion)(["']?\s*[=:]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s&,"'}]+)`)

func configError(message string) error {
	return coreerrors.NewConfigError("InvalidConfiguration", message, nil)
}

func required(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return configError(field + " must not be empty")
	}
	return nil
}

func closedError() error {
	return coreerrors.NewConfigError("Closed", "PAM client is closed", ErrClosed)
}

func responseError(field string) error {
	return coreerrors.NewCredentialError("InvalidResponse", "Invalid PAM response field "+field, nil)
}

func safeText(value string, secrets ...string) string {
	// Normalize service descriptions for public diagnostics.
	value = credentialAssignment.ReplaceAllString(coreerrors.RedactDescription(value), "${1}${2}***")
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "***")
		}
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	if len(value) > 512 {
		end := 512
		for !utf8.RuneStart(value[end]) {
			end--
		}
		value = value[:end]
	}
	return value
}

// dependencyError rebuilds Core errors with stable classifications and diagnostics.
func dependencyError(err error) error {
	const message = "PAM dependency failed"
	var cause error
	switch {
	case errors.Is(err, context.Canceled):
		cause = context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		cause = context.DeadlineExceeded
	}
	// Retain timeout classification when rebuilding the Core error.
	var networkError net.Error
	if cause == nil && errors.As(err, &networkError) && !isNil(networkError) && networkError.Timeout() {
		cause = safeTimeoutError{}
	}
	var source coreerrors.IDaaSError
	if errors.As(err, &source) && !isNil(source) {
		code := source.ErrorCode()
		requestID := source.RequestId()
		var oauth *coreerrors.OAuth2Error
		// The outermost SDK error determines the public classification.
		switch typed := source.(type) {
		case *coreerrors.ConfigError:
			result := coreerrors.NewConfigError(code, message, cause)
			_ = result.WithRequestId(requestID) // Fluent setter returns the embedded ClientError.
			return result
		case *coreerrors.CredentialError:
			return coreerrors.NewCredentialError(code, message, cause).WithRequestId(requestID)
		case *coreerrors.EncodingError:
			return coreerrors.NewEncodingError(code, message, cause).WithRequestId(requestID)
		case *coreerrors.ServerError:
			// Core OAuth 5xx responses retain both ServerError and OAuth2Error.
			if errors.As(typed.Cause, &oauth) && !isNil(oauth) {
				cause = coreerrors.NewOAuth2Error(oauth.HTTPStatus, oauth.OAuthCode, message, "", cause).WithRequestId(requestID)
			}
			return coreerrors.NewServerError(code, message, typed.StatusCode, cause).WithRequestId(requestID)
		case *coreerrors.OAuth2Error:
			return coreerrors.NewOAuth2Error(typed.HTTPStatus, typed.OAuthCode, message, "", cause).WithRequestId(requestID)
		case *coreerrors.ClientError:
			return coreerrors.NewClientError(code, message, cause).WithRequestId(requestID)
		default:
			var httpError *coreerrors.HttpError
			status := 0
			if errors.As(err, &httpError) && httpError != nil {
				status = httpError.StatusCode
			}
			return coreerrors.NewHttpError(code, message, status, cause).WithRequestId(requestID)
		}
	}
	return coreerrors.NewHttpError("TransportError", message, 0, cause)
}

type safeTimeoutError struct{}

func (safeTimeoutError) Error() string   { return "PAM request timed out" }
func (safeTimeoutError) Timeout() bool   { return true }
func (safeTimeoutError) Temporary() bool { return true }

func httpResponseError(response *domain.HttpResponse, secrets ...string) error {
	var wire struct {
		Code        string `json:"error"`
		Description string `json:"error_description"`
	}
	// Unparseable error bodies use fallback diagnostics with the HTTP classification.
	if err := json.Unmarshal(response.Body, &wire); err != nil {
		wire.Code, wire.Description = "", ""
	}
	code := wire.Code
	if code == "" {
		code = "PAMRequestFailed"
	}
	message := safeText(wire.Description, secrets...)
	if message == "" {
		message = "PAM API request failed"
	}
	requestID := response.RequestId()
	cause := coreerrors.NewHttpError(code, message, response.StatusCode, nil).WithRequestId(requestID)
	if response.StatusCode >= 500 {
		return coreerrors.NewServerError(code, message, response.StatusCode, cause).WithRequestId(requestID)
	}
	return coreerrors.NewClientError(code, message, cause).WithRequestId(requestID)
}
