# Contributing

## Development conventions

Keep source compatible with Go 1.18 and run development tools on a supported,
security-patched Go release. Use English Go documentation, comments and
diagnostics. Keep [README.md](README.md) and [README_zh.md](README_zh.md) aligned.

Use Core's public credential, HTTP, logging and error contracts. Preserve
protocol names, time units, optional values, error classifications and resource
ownership. Pass request contexts through credential and HTTP calls. Public
types and methods require Go documentation covering non-obvious behavior.

Never commit credentials, tenant configuration, raw responses, local paths or
generated test artifacts. Keep real configuration outside the checkout.

## Source layout

The module root is the public `pam` package. Files separate responsibilities
within that package; moving exported types to another directory changes their
import path.

| Files | Responsibility |
| --- | --- |
| `doc.go` | Package documentation |
| `config.go`, `builder.go` | Construction and configuration resolution |
| `client.go` | Client state, lifecycle and business methods |
| `transport.go` | Shared HTTP execution and request authentication |
| `safe_http.go` | PAM-owned HTTP transport, redirect policy and network error classification |
| `models.go` | Public request and response types |
| `request.go` | Input validation, payload and query encoding |
| `response.go` | Private wire decoding and response validation |
| `errors.go` | Error classification, diagnostic preservation and closed-client sentinel |
| `*_test.go` | Public contract tests in `pam_test`; private transport tests in `pam` |
| `test_helpers_test.go` | Shared test doubles and fixture helpers |
| `example_test.go` | Executable offline documentation |
| `samples/<operation>/main.go` | Runnable service examples |
| `samples/internal/jwtflow/` | Shared sample workflows and offline tests |
| `.github/workflows/` | Compatibility, quality and transport security checks |

## Local checks

```sh
gofmt -w .
go mod verify
go build ./...
go vet -tags=pam_transport_security ./...
go test -race -count=1 -coverpkg=github.com/cloud-idaas/idaas-go-pam-client-sdk -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go test -race -count=1 -cover ./samples/internal/jwtflow
golangci-lint run --build-tags=pam_transport_security ./...
govulncheck ./...
```

Use the tool versions pinned in [CI](.github/workflows/ci.yml).
CI checks the Go 1.18 compatibility floor and supported toolchains. The older
toolchain verifies source compatibility, not production security.

The SDK root package requires at least 90% statement coverage. Coverage is
distinct from branch coverage. The command above instruments the SDK package
and runs tests in all packages; sample command entry points are built but do
not count toward the SDK threshold.

Tests use synthetic providers and HTTP responses, with no cloud credentials.
Keep assertions on observable behavior, error semantics, context propagation
and cleanup. Run sample workflows offline during automated checks; running
service examples explicitly can create, revoke or reinstate tokens.

## Cross-repository public names

The regular Go suite verifies Go operation and Builder mappings. The independent
consumer compiles the constructor, Builder and business method signatures.
The `cross-repository-names` CI job checks mapped client and Builder classes,
business method names, constructor parameter lists and required argument counts,
and Builder factory, configuration and build method parameter lists against the
public SDK revisions in [cross-repo-baselines.json](contracts/cross-repo-baselines.json).
These checks parse declarations without importing or executing the SDKs.
They do not compare foreign parameter or return types, default values or response behavior.

For a local source checkout, use Python 3.10 or later in a temporary virtual
environment, install `scripts/requirements-contracts.txt`, and run:

```sh
python -m unittest discover -s scripts -p 'test_*.py'
python scripts/check_cross_repo_contract.py --language java --repo /path/to/java-sdk
python scripts/check_cross_repo_contract.py --language python --repo /path/to/python-sdk
python scripts/check_cross_repo_contract.py --language typescript --repo /path/to/typescript-sdk
```

Local commands inspect the selected checkout, including its working changes;
CI checks the pinned commit. When changing a baseline, review the source change
and update `implementedIn` in [pam-api.json](contracts/pam-api.json) if availability
changes. Every declared implementation must have a matching public method;
unimplemented mappings are reported separately and cannot count as verified methods.
Construction forms and configuration method names are mapped in
[pam-construction.json](contracts/pam-construction.json). Go-only configuration
methods remain explicit extensions; mappings cover the capabilities each Builder exposes.
Public Go APIs follow Go naming conventions. Cross-language mappings preserve
business meaning while allowing idiomatic request and response types.

## Default transport security

The transport suite exercises the actual PAM default HTTP implementation with
loopback servers and synthetic credentials:

```sh
go test -tags=pam_transport_security -race -count=1 -timeout=60s -run '^TestDefaultTransport' ./...
```

The suite verifies the documented default transport contract and is separate
from injected-HTTP unit tests. It is required for release.
Internal transport tests also cover encoding, response limits, TLS and
error classifications. This suite covers PAM's default transport; verify
credential-provider and injected-client transports separately as described in
[SECURITY.md](SECURITY.md).

## Submitting changes

Use conventional commit subjects, describe the resulting behavior and report
the checks performed. Update public documentation and [CHANGELOG.md](CHANGELOG.md)
when behavior changes. Review exported API and wire-contract changes for
compatibility.

Check independent consumption with a temporary consumer-local workspace or
module binding. Published-version availability must also be checked before
release. Record cross-language and real-service acceptance separately from
local unit tests, including skipped cases and resource cleanup.

See [samples](samples/README.md) for execution instructions,
[SECURITY.md](SECURITY.md) for private vulnerability reporting, and
[RELEASE.md](RELEASE.md) for the release checklist.
