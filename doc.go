// Package pam implements the IDaaS PAM Developer API for API Keys, JWTs,
// authentication token lifecycle operations, and cloud role STS queries.
//
// Use NewClient, NewDefaultClient, or NewBuilder to construct a Client.
// Core providers handle authentication, AccessToken caching, and refresh.
// Short-token exchange and token validation omit Bearer authentication.
// PAM does not cache cloud STS credentials.
//
// Business methods require a non-nil context.Context. Clients support concurrent
// calls and must not be copied. Injected dependencies must support concurrent
// use. Builders are intended for one goroutine. Keep request maps, slices, and
// pointer values unchanged until their calls return.
//
// In Client responses, absent optional fields remain nil, valid zero values
// are preserved, and unknown fields are ignored. Explicit null is invalid for
// consumed fields except API Key content and the pagination cursor. GetAPIKey
// returns nil, nil for null apiKeyContent. ListAuthenticationTokens returns a
// non-nil Entities slice and an empty NextToken at the end of pagination.
// Invalid response fields produce InvalidResponse; JSON decoding failures
// produce DecodeFailed.
//
// Use errors.As to inspect Core error types, codes, and Request IDs. Cancellation
// and deadlines support errors.Is; network timeouts support net.Error.Timeout.
// Error messages are diagnostic text, not a programmatic contract.
//
// Close is idempotent and releases SDK-owned idle HTTP connections. It does not
// close injected dependencies or cancel or wait for application goroutines.
// New calls after Close support errors.Is(err, ErrClosed). Serialize Core factory
// initialization and reset with factory-backed client construction.
//
// Use trusted HTTPS endpoints with certificate verification. Keep credentials
// and response models out of logs. See SECURITY.md for configuration guidance.
package pam
