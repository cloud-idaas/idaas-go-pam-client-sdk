# Security policy

## Reporting vulnerabilities

Use [GitHub private vulnerability reporting](https://github.com/cloud-idaas/idaas-go-pam-client-sdk/security/advisories/new).
Include the affected SDK and dependency versions, reproduction conditions and
a minimal example using synthetic data. Do not include credentials, customer
data or raw production responses, and do not disclose sensitive findings in
public issues.

Coordinate public disclosure with the affected maintainers after remediation
and upgrade guidance are available.

Private reporting availability must be verified before publication. If the
entry is unavailable, maintainers must provide a confirmed private contact
before accepting sensitive reports.

## Secure configuration

- Use trusted application settings for endpoints and credential providers.
  Do not pass end-user URLs into SDK configuration.
- Use HTTPS and certificate verification for credential-bearing traffic.
- Keep Go and dependencies supported and security-patched. Go 1.18 is the
  source compatibility floor, not a recommended production runtime.
- Grant applications only the permissions required for their PAM operations.
- Do not log API Keys, JWTs, short tokens, STS secrets or raw response models.
  Request IDs can be used to correlate service errors.
- Validate cloud credential completeness and effective expiration before use.
- Injected HTTP and credential implementations must preserve context, resource
  ownership and transport security contracts.

## PAM default transport

When `Config.HTTPClient` is nil, PAM creates an internal HTTP implementation of
Core's public interface. See [client configuration](README.md#customize-a-client)
for HTTP options. Certificate verification is enabled by default. The transport
applies configured timeouts, follows at most four same-origin redirects, limits
response bodies to 4 MiB and supports idle connection cleanup. Injected HTTP
clients retain their own transport policy and must enforce equivalent credential
protection.

## Transport ownership and verification

PAM's HTTP configuration applies to Developer API traffic. Credential providers
and caller-injected HTTP clients manage their own transports. Configure and
verify each transport according to its security requirements, including TLS
verification, credential protection, timeouts and context cancellation.

Keep the `default-transport-security` CI job required for PAM releases. It tests
PAM's default transport; provider and injected-client verification is separate.

The regression uses loopback servers and synthetic tokens. Its local command
is documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## Release checks

Review dependencies, secrets, licenses, public module availability and the
private reporting channel for each release. The complete checklist is in
[RELEASE.md](RELEASE.md).
