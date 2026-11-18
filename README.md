# IDaaS Go PAM Client SDK

English | [简体中文](README_zh.md)

Retrieve API Keys, generate and obtain JWTs, manage authentication tokens, and obtain temporary cloud credentials (STS) for Alibaba Cloud, AWS and Tencent Cloud through IDaaS PAM.

The PAM SDK calls the Developer API. The [Core SDK](https://github.com/cloud-idaas/idaas-go-core-sdk) handles application authentication and AccessToken caching and refresh. Use a cloud adapter to integrate STS refresh with a cloud SDK.

[Quick start](#quick-start-retrieve-an-api-key) · [Common operations](#common-operations) · [Client configuration](#customize-a-client) · [Error handling](#error-handling)

## Installation

Requires Go 1.18 or later. Use a supported, security-patched Go release. Install in an existing Go module:

```sh
go get github.com/cloud-idaas/idaas-go-pam-client-sdk
```

For a new project, run `go mod init example.com/pam-demo` first. The Core SDK is installed as a dependency.

## Quick start: retrieve an API Key

### 1. Prepare an application and credential

Prepare an IDaaS application, grant it the required PAM operations and access to the target resources, and create or select an API Key credential. Have the following settings ready:

| Setting | Purpose |
| --- | --- |
| Instance ID, application Client ID and Client Secret | Authenticate the application through Core |
| Issuer and Token Endpoint | Use the authentication settings for that application |
| Developer API Endpoint | The target instance's Developer API base endpoint, without `/v2/{instanceId}` or an operation path |
| Credential identifier | The API Key credential's business identifier, passed to `GetAPIKey` |

This example uses `CLIENT_SECRET_POST`. For other authentication methods, see the [Core configuration guide](https://github.com/cloud-idaas/idaas-go-core-sdk/blob/main/README.md). Requesting a scope does not grant permissions; the application still needs authorization for the target operations.

### 2. Configure authentication

Save the following as `client-config.json` outside your checkout and replace the example values with your environment's settings. You can also copy the [configuration template](samples/client-config.example.json).

```json
{
  "clientId": "app_example",
  "idaasInstanceId": "idaas_example",
  "issuer": "https://tenant.example.invalid",
  "tokenEndpoint": "https://tenant.example.invalid/api/v2/iauths_system/oauth2/token",
  "developerApiEndpoint": "https://developerapi.example.invalid",
  "scope": "urn:cloud:idaas:pam|.all",
  "authnConfiguration": {
    "identityType": "CLIENT",
    "authnMethod": "CLIENT_SECRET_POST",
    "clientSecretEnvVarName": "IDAAS_CLIENT_SECRET"
  },
  "httpConfiguration": {
    "connectTimeout": 5000,
    "readTimeout": 10000,
    "unsafeIgnoreSslCert": false
  }
}
```

`clientSecretEnvVarName` is the name of an environment variable; the runtime supplies its secret value. Use trusted HTTPS endpoints and keep certificate verification enabled.

```sh
export CLOUD_IDAAS_CONFIG_PATH="/absolute/path/to/client-config.json"
export IDAAS_CLIENT_SECRET="your-client-secret"
export PAM_CREDENTIAL_IDENTIFIER="your-api-key-credential-identifier"
```

These are placeholders. Inject real secrets through your runtime or secret manager; do not put them in configuration files or source control.

### 3. Create a client and make a request

Save as `main.go`:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	pam "github.com/cloud-idaas/idaas-go-pam-client-sdk"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	identifier := os.Getenv("PAM_CREDENTIAL_IDENTIFIER")
	if identifier == "" {
		return errors.New("PAM_CREDENTIAL_IDENTIFIER must be set")
	}
	if err := factory.Init(); err != nil {
		return err
	}
	client, err := pam.NewDefaultClient()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key, err := client.GetAPIKey(ctx, identifier)
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("no API key is available for this credential")
	}
	// Pass *key to the service that requires it; do not print the key.
	fmt.Println("API key retrieved")
	return nil
}
```

```sh
go mod tidy
go run .
```

A successful request prints `API key retrieved`. Access the actual key through `*key` and pass it to the service that needs it. When `err == nil`, `key == nil` means the service explicitly returned no available API Key; a failed request returns a non-nil `error`.

## Common operations

Add the following functions to the quick start's `main.go`, reusing its imports. To switch operations, remove the code at the start of `run` that reads and checks `PAM_CREDENTIAL_IDENTIFIER`. Keep Core initialization, client construction and cleanup, and context setup. Replace the API Key query and the remaining return logic with one of the calls below, and replace each example's business identifiers.

| Example | Call from `run` |
| --- | --- |
| Generate a JWT | `return generateJWT(ctx, client)` |
| List tokens | `return listTokens(ctx, client)` |
| Validate a token | `return checkToken(ctx, client, os.Getenv("PAM_TOKEN"))`; supply the token through the runtime's `PAM_TOKEN` environment variable |
| Obtain STS | `return obtainSTS(ctx, client)` |

All business methods take a non-nil `context.Context` first and return an error last. Reuse clients and set an appropriate context deadline for each business operation.

### Generate a JWT

The credential provider must support JWT generation, and the subject and audience must satisfy its configuration.

```go
func generateJWT(ctx context.Context, client *pam.Client) error {
	lifetime := int64(300)
	includeShortToken := true
	result, err := client.GenerateJWTAuthenticationToken(ctx, pam.GenerateJWTAuthenticationTokenRequest{
		CredentialProviderIdentifier: "your-jwt-provider-identifier",
		Subject:                      "your-subject",
		Audiences:                    []string{"your-audience"},
		Expiration:                   &lifetime,
		IncludeDerivedShortToken:     &includeShortToken,
	})
	if err != nil {
		return err
	}
	// Use result.JWTContent.JWTValue to authenticate to the target service.
	// result.JWTContent.DerivedShortToken is optional; check for nil before use.
	fmt.Printf("Token created: %s\n", result.AuthenticationTokenID)
	return nil
}
```

`Expiration` is in seconds; nil uses the service default. Set `Issuer` to override the issuer or `CustomClaims` to supply custom claims. See the [request types](models.go) for field constraints.

The response contains `AuthenticationTokenID` and `JWTContent`. Subsequent operations include:

| Scenario | Call and return values |
| --- | --- |
| Obtain a JWT by consumer and Token ID | `ObtainJWTAuthenticationToken(ctx, consumerID, authenticationTokenID)` → `*JWTContent, error` |
| Exchange a derived short token for a JWT | `ObtainJWTAuthenticationTokenByDerivedShortToken(ctx, shortToken)` → `*JWTContent, error` |

`JWTContent.JWTValue` contains the JWT; `DerivedShortToken` is an optional pointer. Treat both as credentials and do not print them.

### List tokens with pagination

```go
func listTokens(ctx context.Context, client *pam.Client) error {
	pageSize := int64(20)
	revoked := false
	input := pam.ListAuthenticationTokensRequest{
		ConsumerID:                   "your-consumer-id",
		CredentialProviderIdentifier: "your-jwt-provider-identifier",
		MaxResults:                   &pageSize,
		Revoked:                      &revoked,
	}
	for {
		page, err := client.ListAuthenticationTokens(ctx, input)
		if err != nil {
			return err
		}
		fmt.Printf("Tokens in this page: %d\n", len(page.Entities))
		if page.NextToken == "" {
			return nil
		}
		if page.NextToken == input.NextToken {
			return errors.New("server repeated the pagination cursor")
		}
		input.NextToken = page.NextToken
	}
}
```

`ConsumerID` identifies the token's consumer. `CredentialProviderIdentifier` is the provider's business identifier; do not substitute the response metadata's `CredentialProviderID`. An empty response `NextToken` ends pagination; otherwise pass it unchanged to the next request.

Optional `Revoked` and `Expired` filters use `*bool`: nil omits the parameter and leaves its default behavior to the service, while pointers to false or true explicitly filter that state. `MaxResults` is an optional positive integer. Token metadata timestamps use Unix milliseconds.

### Validate, revoke and reinstate tokens

```go
func checkToken(ctx context.Context, client *pam.Client, token string) error {
	active, err := client.ValidateAuthenticationToken(ctx, token, nil)
	if err != nil {
		return err
	}
	fmt.Printf("Token active: %t\n", active)
	return nil
}
```

| Operation | Call and return values |
| --- | --- |
| Validate a token | `ValidateAuthenticationToken(ctx, token, nil)` → `bool, error` |
| Revoke a token | `RevokeAuthenticationToken(ctx, token, nil)` → `error` |
| Reinstate a token | `ReinstateAuthenticationToken(ctx, token, nil)` → `error` |
| Revoke by consumer | `RevokeAuthenticationTokenByConsumer(ctx, consumerID, providerIdentifier)` → `error` |
| Reinstate by consumer | `ReinstateAuthenticationTokenByConsumer(ctx, consumerID, providerIdentifier)` → `error` |

Single-token operations take the **token value, not its Token ID**. Their last argument is an optional `*pam.TokenOptions`; pass nil when no hint is needed, or set `TokenTypeHint`. Validation returns `false, nil` for an inactive token. Consumer operations affect all matching tokens for that consumer and credential provider.

### Obtain cloud role STS credentials

```go
func obtainSTS(ctx context.Context, client *pam.Client) error {
	result, err := client.ObtainAccessCredential(ctx, "your-cloud-role-external-id")
	if err != nil {
		return err
	}
	// Select the token for your cloud, then validate its fields and expiration
	// before constructing cloud SDK credentials. Do not log credential values.
	fmt.Printf("STS available: Alibaba Cloud=%t AWS=%t Tencent Cloud=%t\n",
		result.AlibabaCloudSTSToken != nil,
		result.AWSSTSToken != nil,
		result.TencentCloudSTSToken != nil)
	return nil
}
```

Pass the cloud account role's external ID. The response provides `AlibabaCloudSTSToken`, `AWSSTSToken` or `TencentCloudSTSToken` for the corresponding cloud. Check that the object and all required fields are present before use.

See the [response types](models.go) for STS fields and expiration conventions. PAM does not cache STS; use the [Alibaba Cloud](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter), [AWS](https://github.com/cloud-idaas/idaas-go-akless-aws-adapter) or [Tencent Cloud](https://github.com/cloud-idaas/idaas-go-akless-tencent-adapter) adapter for automatic refresh and cloud SDK integration.

See [samples](samples/README.md) for complete runnable workflows and their environment variables. JWT and lifecycle samples generate, revoke or reinstate real tokens; use dedicated test resources.

## Customize a client

Most applications can use `NewDefaultClient()` as shown in the quick start. Use `NewClient(Config)` or Builder when supplying an existing Core provider, selecting an instance or endpoint, or configuring HTTP behavior.

For example, after `factory.Init()` succeeds, replace the default client construction with:

```go
provider, err := factory.GetIDaaSCredentialProviderByScope(pam.Scope)
if err != nil {
	return err
}
client, err := pam.NewClient(pam.Config{
	DeveloperAPIEndpoint: "https://your-developer-api-endpoint",
	IDaaSInstanceID:      "your-idaas-instance-id",
	CredentialProvider:   provider,
})
if err != nil {
	return err
}
defer func() { _ = client.Close() }()
```

You can inject the same provider through Builder. `Build()` returns `(*pam.Client, error)`; handle the error and close the client as above:

```go
client, err := pam.NewBuilder().
	DeveloperAPIEndpoint("https://your-developer-api-endpoint").
	IDaaSInstanceID("your-idaas-instance-id").
	CredentialProvider(provider).
	Build()
```

| `pam.Config` field / Builder method | Purpose and default |
| --- | --- |
| `DeveloperAPIEndpoint` | Developer API base endpoint; empty reads from Core |
| `IDaaSInstanceID` | Target instance ID; empty reads from Core |
| `CredentialProvider` | Core provider; nil resolves a Core provider for `pam.Scope` |
| `HTTPConfiguration` | Options for the SDK-created HTTP client; timeouts use milliseconds |
| `HTTPClient` | Custom Core `http.HttpClient`; nil creates an SDK-owned client |
| `Logger` | Core logger; nil uses Core's default logger |

Supplying the endpoint, instance ID and provider lets you construct a client without initializing the Core factory. If any is missing, initialize Core first to supply the missing configuration.

`HTTPConfiguration` applies only to SDK-created HTTP clients. The default connection timeout is 5 seconds, and the entire HTTP request timeout is 10 seconds. Use a context to cancel or impose an earlier deadline. See [Config](config.go) for inheritance and override rules. Injected HTTP clients and providers use their own transport configuration.

Reuse clients concurrently; do not copy clients or modify request data before a call returns. Builders do not support concurrent configuration. Wait for application requests to finish before calling `Close()`. It does not cancel or wait for in-flight requests, or close caller-injected dependencies. See the [package documentation](doc.go) for further lifecycle conventions.

## Error handling

Return or handle operation errors as appropriate for your application. To distinguish cancellation, timeouts and SDK errors, add this import to the quick start:

```go
coreerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
```

Then call `reportError(err)` from the error branch in `main`:

```go
func reportError(err error) {
	var sdkErr coreerrors.IDaaSError
	switch {
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "Operation canceled")
	case errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(os.Stderr, "Operation timed out")
	case errors.Is(err, pam.ErrClosed):
		fmt.Fprintln(os.Stderr, "PAM client is closed")
	case errors.As(err, &sdkErr):
		fmt.Fprintf(os.Stderr, "code=%s requestID=%s: %v\n",
			sdkErr.ErrorCode(), sdkErr.RequestId(), err)
	default:
		fmt.Fprintln(os.Stderr, err)
	}
}
```

The SDK uses Core error types. Retain error codes and Request IDs when investigating service requests.

The SDK does not automatically retry business operations. JWT generation is not guaranteed to be idempotent: after a timeout, cancellation or response parsing failure, check the service result before deciding whether to retry. Do not log keys, tokens or raw credential responses. See the [security policy](SECURITY.md) for secure configuration and transport guidance.

## More resources

### Usage reference

- [Complete examples](samples/README.md)
- [Request and response types](models.go)
- [Go package documentation](https://pkg.go.dev/github.com/cloud-idaas/idaas-go-pam-client-sdk)

### Support and contributions

- [Issue tracker](https://github.com/cloud-idaas/idaas-go-pam-client-sdk/issues)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

### Releases and licensing

- [Release guide](RELEASE.md)
- [Changelog](CHANGELOG.md)
- [Apache License 2.0](LICENSE)
