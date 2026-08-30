# Changelog

Notable changes to modelmoat. Versions follow [semantic versioning](https://semver.org).

## 0.4.0 - 2026-08-30

### Changed

- `--json` and `--sarif` now fail closed by default on a parse error: a scan
  exits 1 and no longer looks like a clean pass when a file could not be
  read. Previously the error only showed up in `parse_errors` without
  affecting the exit code, so a partial scan and a complete one were
  indistinguishable to CI. `--allow-partial` restores the old lenient
  behavior for interactive use.
- A scan target with no supported Terraform files anywhere (no `.tf` or
  `.tf.json`) is now a hard error by default instead of a silent
  zero-finding pass. `--allow-empty` restores the old behavior.

If you pipe modelmoat's machine output into something else, either of these
can change what your pipeline does on inputs it previously accepted quietly.

### Added

- AGW-001 flags an `aws_api_gateway_method` with `authorization = "NONE"`
  whose integration proves, through the provider's documented
  AWS-service-proxy `uri` format, that the backend is a SageMaker or Bedrock
  runtime invocation. Scoped to REST API v1 only - API Gateway v2 has no
  `integration_subtype` for either service, so the only v2 path there runs
  through an opaque Lambda proxy, which is unprovable. CRITICAL: reachability
  and absent auth are both proven, with no fallback credential check on the
  client side.
- VEC-003 flags a known self-hosted vector database image (`qdrant/qdrant`,
  `semitechnologies/weaviate`, `milvusdb/milvus`) running on an
  `aws_ecs_service` with `launch_type = "FARGATE"` and
  `assign_public_ip = true`. HIGH, reachability only - none of the three
  engines expose a Terraform-visible setting whose absence safely proves
  authentication is off, the same trap VEC-002 already avoids for Weaviate.
- VEC-001 now also covers OpenSearch Serverless: an
  `aws_opensearchserverless_security_policy` (`type = "network"`) with
  `AllowFromPublic = true` on a collection-type rule. HIGH, not CRITICAL - a
  data access policy and SigV4-signed credentials are still required for
  every request regardless of network settings.
- VPC-001 now also covers ECS Fargate: a task calling Bedrock or SageMaker
  with no matching interface VPC endpoint. MEDIUM only, never LOW, since
  Fargate's `awsvpc` networking mode has no "outside a VPC" state the way a
  Lambda does.
- SMK-001 now also covers SageMaker Studio domains:
  `app_network_access_type` absent or explicitly `"PublicInternetOnly"`.
  HIGH, matching the existing model finding - non-EFS app traffic exits
  through a SageMaker-managed network interface instead of your VPC, though
  Studio access itself always requires IAM or SSO authentication regardless
  of this setting.
- S3-001 now also treats a bucket as AI-relevant when an
  `aws_bedrockagent_data_source` points its `bucket_arn` at it, even when
  the bucket's own name and tags give the keyword matcher nothing. A direct
  reference is stronger evidence than a name guess, so it is checked first
  and supersedes the keyword scan when it hits.

### Fixed

An independent security review of 0.3.0 by Matthew Figueroa
([@MathewFigueroa](https://github.com/MathewFigueroa)) found 21 issues in
the scanner's own detection integrity, fail-safety, and release pipeline -
0 Critical, 9 High, 8 Medium, 4 Low. All are resolved:

- Terraform module boundaries were never tracked, so an identically-labeled
  resource in an unrelated directory (a sibling module, a vendored copy)
  could stand in for the real one during cross-resource correlation. Every
  resource now carries its module, and correlation is scoped to it.
- A resource with a literal `count = 0` or empty `for_each` registered as
  deployed, so a disabled decoy control could prove a real exposure safe.
  Proven-zero cardinality now excludes a resource from the graph; unresolved
  (variable-driven) cardinality is tracked separately, so a risky resource
  with unprovable cardinality still gets evaluated, while a compensating
  control with unprovable cardinality never gets credited as protecting
  anything.
- S3-001 could report several distinct problems on one bucket under a
  single fingerprint, so baselining the mildest silently suppressed the
  worst. Every branch now has its own detail token.
- A finding that grew more severe than its recorded baseline entry stayed
  suppressed instead of becoming active, so accepted low-risk debt could
  become a Critical exposure without failing CI.
- A parse failure and a `.tf.json` file (previously silently unscanned)
  could each produce a clean-looking zero-finding scan - covered by the
  behavior change above.
- S3 and OpenSearch policy checks did not resolve a
  `data.aws_iam_policy_document` reference, so a public policy authored
  that way was invisible. IAM-001 did not evaluate `NotAction`/`NotResource`,
  so a policy granting nearly everything except a short exclusion list
  passed as safe.
- Discovery followed symlinks and had no size or file-count limits, so
  scanning an untrusted checkout could read outside the requested root or
  exhaust memory on a crafted input.
- VPC endpoint matching credited any service-name substring anywhere in the
  project, regardless of module, VPC, or region, so an unrelated endpoint
  could suppress a real finding.
- A crafted or partially-edited attribute (a boolean where a list was
  expected) could crash a check and take down the whole scan silently.
  Each check's failures are now isolated and reported, never swallowed.
- Public-principal detection ignored policy `Condition` blocks entirely, so
  `Principal: "*"` narrowed by `aws:PrincipalOrgID` or a VPC endpoint
  condition was still reported as open to the entire internet.
- Human-readable output interpolated resource names directly into terminal
  markup, so a maliciously named resource could throw an exception and lose
  every finding, or forge terminal styling.
- Line-number lookup rescanned the whole file per resource, which made
  large generated Terraform disproportionately expensive to scan.
- SARIF output was not validated against the official schema, and there was
  no test that installed the actual packaged wheel and ran it.
- Managed-policy detection suffix-matched an ARN, so a customer-managed
  policy merely named to look like `AmazonBedrockFullAccess` matched as if
  it were AWS's own. A variable-driven public-access-block flag was
  described as "disabled" instead of unresolved.
- Release asset generation could silently use the wrong version and did not
  verify its own fixture results before writing output.

### CI and release hardening

- GitHub Actions are pinned to full commit SHAs instead of mutable tags,
  with `permissions: contents: read`, `persist-credentials: false`, a job
  timeout, and cancel-in-progress concurrency.
- Dependencies are locked and hash-verified in CI
  (`pip install --require-hashes`) instead of resolved from an open range
  on every run.
- A new release workflow builds once, attests build provenance, and
  publishes to PyPI through Trusted Publishing (OIDC) - no long-lived token
  stored anywhere.

### Acknowledgments

Thanks to Matthew Figueroa ([@MathewFigueroa](https://github.com/MathewFigueroa))
for the independent security review behind most of this release.

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
