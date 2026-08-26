# Changelog

Notable changes to modelmoat. Versions follow [semantic versioning](https://semver.org).

## Unreleased

Nothing here has been published to PyPI yet. `0.1.0` is still the released
version.

### Added

- VEC-002 flags a self-hosted Weaviate that accepts unauthenticated requests,
  read from a `helm_release` value or a container environment variable on
  `kubernetes_deployment` and `kubernetes_stateful_set`. It fires only on an
  explicitly enabled value, never on absence, because the value legitimately
  arrives through a values.yaml file or a Secret the scanner cannot read.
  Enabled means any of `on`, `enabled`, `1`, `true`, matching Weaviate's own
  truthiness helper.
- PIN-001 flags Pinecone `OrgOwner` granted at organization scope to a service
  account or API key. `OrgManager` is deliberately not flagged: it grants only
  viewing the organization and creating projects.
- `--sarif` emits SARIF 2.1.0, so findings reach the GitHub Security tab and
  pull request annotations instead of only CI logs. CRITICAL and HIGH arrive as
  errors, MEDIUM as a warning, LOW as a note. Output is validated against the
  OASIS SARIF 2.1.0 schema.
- `--baseline` and `--write-baseline` let a team adopt modelmoat on an existing
  codebase and report only findings added afterwards. Writing a baseline exits 0
  so adoption does not break the same build. Scans report how many findings a
  baseline suppressed, how many entries no longer match anything, and warn when
  a suppressed finding has become more severe than when it was recorded.
- `--fail-on-parse-error` exits non-zero when a file could not be read. Off by
  default, so HCL the parser does not support cannot break a pipeline.
- Findings carry a `detail` token and a `fingerprint`, both included in `--json`
  output.

### Fixed

- Finding fingerprints collided when one check reported several problems against
  the same resource, which collapsed 18 findings to 12 identities on the test
  fixture. Baselining the MEDIUM node-to-node encryption finding on an OpenSearch
  domain would have silently suppressed the CRITICAL finding that the same domain
  was publicly reachable, and SARIF consumers deduplicate on the same value.
  Fingerprints now include a per-finding `detail` token, and a test asserts every
  finding in a scan has a unique identity.
- CI ran on pushes to `main`, but the repository branch is `master`, so the
  behavior gate that requires zero findings on the secure fixture had never
  actually run.

## 0.1.0

First release. Five checks across SageMaker networking, AI service IAM grants,
model artifact buckets, PrivateLink coverage for AI traffic, and vector data
store posture. JSON output, severity filtering, and tunable CI exit codes.
