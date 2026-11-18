# Release checklist

## API and documentation

- Verify the 11 business operations and all three construction entry points
  against the public contract.
- Check optional-value behavior, time units, error classification, Request IDs,
  concurrency and resource ownership.
- Align the bilingual READMEs, package documentation, configuration template
  and [samples](samples/README.md) with the source.
- Summarize the release capabilities in [CHANGELOG.md](CHANGELOG.md).
- Review the license and applicable dependency notices.

## Verification

- Pass every [CI](.github/workflows/ci.yml) job and the checks in
  [CONTRIBUTING.md](CONTRIBUTING.md).
- Pass the PAM default transport security gate. Separately verify credential
  provider and injected HTTP transports against their security requirements;
  see [SECURITY.md](SECURITY.md).
- Verify the Go compatibility floor, supported toolchains, race checks, SDK
  coverage, lint, vulnerability scan and module checksums.
- Build all examples and run the offline sample workflow tests.
- Execute the applicable cross-language contract and real-service acceptance
  suites. Record source and dependency versions, skipped or blocked cases and
  test-resource cleanup. Local unit tests do not substitute for service
  acceptance.
- Scan release contents for secrets and review dependency licenses.
- Verify private vulnerability reporting from an external reporter account,
  or publish a confirmed alternative private contact.

## Publication

1. Select the release version and review its exact source revision.
2. Confirm the public repository, dependency versions and module paths are
   available without private credentials.
3. Create the version tag and release through the project's delivery process.
4. Install the actual version from a clean consumer without local workspaces
   or replace directives, then build and test it.

The CI consumer uses a temporary local binding to verify package consumption;
it does not prove that a published version can be downloaded. The CI workflow
performs validation and does not automatically create tags or GitHub releases.
