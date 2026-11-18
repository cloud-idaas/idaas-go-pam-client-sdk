# PAM service samples

These commands belong to the SDK module and use Go 1.18-compatible syntax.
Each runnable workflow has its own directory and `main` package. A workflow can
demonstrate several public operations. The commands add no cloud
vendor SDK dependencies. Run commands from the repository root.

## Configuration

Copy [client-config.example.json](client-config.example.json) to a location
outside the checkout. Replace its placeholder application, instance, issuer,
Token Endpoint and Developer API endpoint with your environment's trusted
settings. The instance ID is configured as `idaasInstanceId`.
Keep HTTPS and certificate verification enabled; do not accept endpoints from
end users.

Set `CLOUD_IDAAS_CONFIG_PATH` to that external file's absolute path.
For CLIENT_SECRET_POST, the template names the secret environment variable
`IDAAS_CLIENT_SECRET`. Set that variable securely in your local environment.
The JSON contains the variable name, never its value. Authorize the application
for the intended operations and configure scope `urn:cloud:idaas:pam|.all`.
HTTP timeout fields use milliseconds.

```sh
export CLOUD_IDAAS_CONFIG_PATH=/absolute/path/outside-checkout/client-config.json
# Set IDAAS_CLIENT_SECRET securely outside source control.
export PAM_CREDENTIAL_IDENTIFIER=example-api-key
go run ./samples/get-api-key
```

Core supports other authentication methods through the same configuration
schema. See the [Core configuration guide](https://github.com/cloud-idaas/idaas-go-core-sdk/blob/main/README.md#configuration-file-description)
for those methods; PAM does not duplicate the Core authentication implementations.

Before running service examples, review the secure configuration and transport
verification guidance in [SECURITY.md](../SECURITY.md). PAM's HTTP configuration
applies to Developer API calls; credential providers manage their own transports.

## Commands

| Directory | Additional environment variables | Behavior |
| --- | --- | --- |
| `get-api-key` | `PAM_CREDENTIAL_IDENTIFIER` | Reports whether API Key content is present |
| `generate-jwt` | `PAM_CREDENTIAL_PROVIDER_IDENTIFIER`, `PAM_AUDIENCE` | Generates a short-lived JWT and revokes it |
| `obtain-jwt` | Same as `generate-jwt` | Generates a token, retrieves its JWT by consumer/Token ID and by derived short token, then revokes it |
| `token-lifecycle` | Same as `generate-jwt` | Generates a token, validates it, revokes it, validates inactive, reinstates it, validates active and finally revokes it |
| `consumer-lifecycle` | Same as `generate-jwt` | Generates a token for a unique consumer, revokes/reinstates that consumer's tokens, checks state and finally revokes the generated token |
| `list-tokens` | `PAM_CREDENTIAL_PROVIDER_IDENTIFIER`, `PAM_CONSUMER_ID` | Follows pagination and reports only the total number of tokens |
| `obtain-sts` | `PAM_ROLE_EXTERNAL_ID` | Reports which cloud STS objects are present |
| `explicit-config` | `PAM_CREDENTIAL_IDENTIFIER` | Supplies all required PAM Config fields and queries an API Key |
| `builder` | `PAM_CREDENTIAL_IDENTIFIER` | Supplies all required settings through Builder and queries an API Key |

```sh
go build ./...
go run ./samples/get-api-key
go run ./samples/generate-jwt
go run ./samples/obtain-jwt
go run ./samples/token-lifecycle
go run ./samples/consumer-lifecycle
go run ./samples/list-tokens
go run ./samples/obtain-sts
go run ./samples/explicit-config
go run ./samples/builder
```

Run only the command you intend to exercise. JWT workflow commands perform
real generation and revocation; lifecycle commands also perform reinstatement.
Use a dedicated test provider and approved audience. Each workflow generates
a random `go-pam-sample-...` subject, prints that run identifier and requires
the returned consumer ID to match before any bulk mutation. They do not accept
an existing consumer ID or subject for mutation.

Generated tokens have a 300-second lifetime. Single-token revocation is
attempted on every exit after successful generation, under a fresh 30-second
deadline even when the operation context was canceled. Cleanup errors cause
failure. After an interruption, cleanup failure or an ambiguous generation
timeout, inspect the printed subject in the console and revoke any generated
tokens. Process termination can interrupt cleanup.

The provider must support JWT generation and map the supplied subject to the
consumer ID; `obtain-jwt` additionally requires derived short tokens.
State checks report mismatches as failures; the examples assume lifecycle
changes are visible to validation when the subsequent request completes.

## Errors and output

The explicit Config and Builder commands use `errors.Is` for cancellation,
deadlines and `pam.ErrClosed`, and `errors.As` for Core error classification.
They report the SDK error code and Request ID without dumping the cause chain.

Commands use 30-second operation deadlines. They do not print API Keys, JWTs,
short tokens, STS secrets or raw responses. STS object presence is not proof of
complete, unexpired credentials; production consumers must validate required
fields and expiration or use a cloud adapter.

See [example_test.go](../example_test.go) for executable offline examples and
[CONTRIBUTING.md](../CONTRIBUTING.md) for development checks.
