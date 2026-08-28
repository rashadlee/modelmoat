# Changelog

Notable changes to modelmoat. Versions follow [semantic versioning](https://semver.org).

## 0.3.0 - 2026-08-28

### Added

- AZR-001 flags an `azurerm_cognitive_account` (Azure OpenAI or AI Services)
  reachable from the public internet: `public_network_access_enabled`
  defaults to `true` when omitted, so an account with no explicit setting is
  exposed by default, and only a `network_acls` block with
  `default_action = "Deny"` narrows that down. Scoped to `kind = "OpenAI"`
  and `kind = "AIServices"`, not every Cognitive Services type. Every
  request still requires an API key or Entra ID credential regardless of
  network configuration, so the finding says this is network exposure, not
  an unauthenticated endpoint - the same framing SMK-001 uses for the
  equivalent SageMaker case.
- BRK-001 flags an `aws_bedrockagentcore_gateway` with
  `authorizer_type = "NONE"`, which disables authentication on the side
  that faces calling agents. Unlike SMK-001 or AZR-001, this resource has
  no fallback authentication when set to `NONE` - the default endpoint
  sits on AWS's standard regional network path, and PrivateLink is opt-in
  rather than default, so the finding is CRITICAL: proven network
  reachability combined with proven absent authentication, not just
  exposure with a mandatory auth layer still in place.
- GCP-001 flags a `google_vertex_ai_reasoning_engine` (Agent Engine) missing
  either of two independent controls: a Private Service Connect
  `network_attachment`, since the resource keeps default public network
  access without one, or a CMEK `encryption_spec`, since there is no
  Google-managed-key fallback to credit - the block is either present or
  entirely absent. A resource missing both gets two findings with distinct
  detail tokens, not one, so baselining either never silently suppresses
  the other. Reaching the engine still requires standard Google Cloud IAM
  authentication regardless of network configuration - Vertex AI has no
  equivalent of Bedrock AgentCore's `authorizer_type = "NONE"` - so both
  findings are HIGH, the same tier as SMK-001 and AZR-001, not CRITICAL.

## 0.2.1 - 2026-08-27

### Fixed

- The banner and screenshot images in the README used relative paths, which
  render fine on GitHub but show as broken images on PyPI, since PyPI's
  long_description has no access to the rest of the repo tree. The 0.2.0
  package on PyPI shipped with these broken - now absolute
  `raw.githubusercontent.com` URLs pinned to `master`.

## 0.2.0 - 2026-08-26

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
