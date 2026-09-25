# Changelog

Notable changes to modelmoat. Versions follow [semantic versioning](https://semver.org).

## 0.7.0 - 2026-09-21

### Added

- DBX-003 flags four Unity Catalog securable objects -
  `databricks_catalog`, `databricks_schema`, `databricks_storage_credential`,
  `databricks_external_location` - whose `isolation_mode` defaults to
  `"ISOLATION_MODE_OPEN"`, making them accessible from every workspace
  attached to the metastore. MEDIUM: reaching data through an OPEN object
  still requires an explicit Unity Catalog GRANT regardless of this
  setting.
- GCF-001 flags a `google_cloudfunctions2_function` granting
  `roles/cloudfunctions.invoker` to `allUsers` while running as a service
  account with a Vertex AI role - a distinct resource from GCP-002's Cloud
  Run check, with its own IAM member resource GCP-002's correlation logic
  cannot match. CRITICAL: Google requires authentication credentials by
  default, and granting the invoker role to allUsers removes that
  requirement entirely.
- VAS-001 flags a `google_discovery_engine_data_store` (Vertex AI Search)
  with `acl_enabled` absent or false, which drops source-system
  permissions (for example Cloud Storage ACLs) when documents are
  imported for indexing. HIGH, scoped to where Google's own documented
  caution applies: `industry_vertical = "GENERIC"` and
  `content_config != "PUBLIC_WEBSITE"`.
- AZR-001 and AZR-002 now also cover `azurerm_cognitive_account` accounts
  of kind `FormRecognizer` (Document Intelligence), `ContentSafety`, and
  `SpeechServices`, not just `OpenAI`/`AIServices` - confirmed to be the
  identical resource, fields, and documented defaults, not a kind-specific
  carve-out.
- DBX-004 flags a publicly reachable Databricks workspace with no
  `databricks_ip_access_list` resource anywhere in the project granting
  `ALLOW` access. LOW: a documented, off-by-default control per
  Microsoft's own Azure security baseline for Databricks, distinct from
  DBX-001's own reachability finding on the same resource.

## 0.6.0 - 2026-09-20

### Added

- AZR-002 flags an `azurerm_cognitive_account` allowing local (API key)
  authentication instead of Microsoft Entra ID only -
  `local_auth_enabled` defaults to `true`, backed by a built-in Azure
  Policy definition. MEDIUM, not HIGH: the account still requires some
  form of authentication either way, so this is a blast-radius finding (a
  leaked key authenticates with no tie to a real identity and no
  per-identity revocation), not a reachability one like AZR-001.
- BRK-002 flags an `aws_bedrockagentcore_gateway` with
  `exception_level = "DEBUG"`, which returns granular internal error
  detail (Lambda errors, egress authorizer errors, parameter validation
  errors) instead of the sanitized messages AWS returns by default.
  MEDIUM, independent of BRK-001 on the same resource.
- AGW-002 flags an API Gateway REST API's resource policy granting
  `Principal "*"` on `execute-api:Invoke`. AWS's own authorization docs
  state a permissive resource policy overrides individually-authenticated
  methods, so a method requiring `AWS_IAM` is not actually protected when
  this is present. CRITICAL, gated on the same AI-backend proof AGW-001
  already requires.
- VPC-001 extended from Bedrock/SageMaker to eight more AI services
  already in IAM-001's action list: Comprehend, Rekognition, Textract,
  Translate, Polly, Lex, Personalize, Forecast - each verified against
  AWS's PrivateLink support reference first. Signal detection switched
  from substring to whole-token matching in the same change, since short
  names like "lex" and "polly" can otherwise collide with ordinary words.
- AML-001: a new Azure Machine Learning check family. Both
  `azurerm_machine_learning_workspace.public_network_access_enabled` and
  `azurerm_machine_learning_compute_instance.node_public_ip_enabled`
  default to `true`, confirmed against Microsoft's own security baseline
  and an Azure Policy built-in definition. MEDIUM: Entra ID authentication
  is still required regardless of network settings. Extended in the same
  release to `azurerm_ai_foundry` hubs, a newer resource on the identical
  ARM API family, defaulting `public_network_access` to `"Enabled"`.
- GCP-001 extended to `google_vertex_ai_endpoint` (the same
  public-by-default, IAM-still-required shape as Reasoning Engine, HIGH)
  and `google_workbench_instance` (`disable_public_ip` defaults to
  `false`, MEDIUM; `notebook-disable-root` metadata defaults to `"false"`,
  LOW - the same blast-radius shape as SMK-001's `root_access` finding).
- ASR-001: a new Azure AI Search check family.
  `public_network_access_enabled` and `local_authentication_enabled` both
  default to `true` on `azurerm_search_service`, each backed by its own
  Azure Policy built-in definition. MEDIUM on both - Microsoft's own
  security baseline confirms a caller must still present a valid
  authorization token even with public network access enabled.
- DBX-001: a new Azure Databricks check family.
  `azurerm_databricks_workspace.public_network_access_enabled` defaults to
  `true`, confirmed against Microsoft's own Databricks security baseline
  and an Azure Policy built-in definition. MEDIUM - Entra ID authentication
  is required for data-plane access regardless of this setting.
- DBX-002 flags a `databricks_cluster` with `data_security_mode` explicitly
  set to `"NONE"` or its legacy alias `"NO_ISOLATION"`, which runs code
  from every attached user in the same shared environment. Databricks's
  own admin documentation states a higher-privileged user's token becomes
  visible to every other attached user. HIGH, and - unlike almost every
  other finding in this project - fires only on an explicit insecure
  value, never on absence, since Databricks's own docs state omission
  enables default security features.
- CMP-001: a new Comprehend check family, distinct from VPC-001's existing
  caller-side check. `aws_comprehend_entity_recognizer` and
  `aws_comprehend_document_classifier` training jobs with no `vpc_config`
  reach AWS resources over the internet rather than staying inside a VPC,
  per AWS's own Comprehend VPC documentation. HIGH.
- LFU-001 flags an `aws_lambda_function_url` with
  `authorization_type = "NONE"` and a matching `aws_lambda_permission`
  granting public `lambda:InvokeFunctionUrl` access, calling Bedrock or
  SageMaker. AWS's own docs state this performs no authentication at all
  before invoking the function - a genuine zero-authentication path,
  unlike this project's usual "reachable but still signed" shape. CRITICAL.
- GCP-002 flags a `google_cloud_run_v2_service` granting
  `roles/run.invoker` to `allUsers` while running as a service account
  holding a `roles/aiplatform.*` grant. Google's own IAM documentation
  confirms this is a genuine zero-authentication path, and that ingress
  settings do not substitute for it. CRITICAL.

### Changed

- Human-readable output now collapses a check that produces many LOW
  findings into a single summary line, instead of printing each one in
  full. This only affects the default terminal view - `--json`, `--sarif`,
  `--write-baseline`, and `--fail-on`'s exit code all still see every
  finding individually regardless, and MEDIUM/HIGH/CRITICAL findings never
  collapse no matter how many there are. Pass `--no-group` to restore the
  previous flat listing in human-readable output.

## 0.5.0 - 2026-09-07

### Added

- SMK-001 now also covers SageMaker notebook instances:
  `direct_internet_access` absent or explicitly `"Enabled"` (HIGH -
  non-VPC-CIDR traffic, including SageMaker API and training/hosting calls,
  exits through a second, SageMaker-managed interface regardless of whether
  `subnet_id` is also set), and `root_access` absent or explicitly
  `"Enabled"` (LOW - blast radius on the instance, not a network exposure,
  judged and reported independently of the network finding).
- SMK-001 now also covers SageMaker training jobs: no `vpc_config` (HIGH,
  the same finding shape as the existing model check - training data
  channels and inter-container traffic run on the SageMaker managed network
  instead of the VPC), and `enable_inter_container_traffic_encryption`
  absent or `false` on a job with more than one instance (MEDIUM - protects
  model weights and gradients moving between compute instances, not the raw
  training dataset; meaningless below two instances per AWS's own docs, so
  it is only evaluated once `instance_count` is provably greater than one).
- New check SMK-002: an `aws_sagemaker_model_package_group_policy` granting
  `Principal "*"`. HIGH, not CRITICAL - SageMaker's control plane always
  requires a signed request regardless of this policy, so `"*"` removes the
  account-scoping that cross-account model registry sharing is supposed to
  have, rather than creating anonymous access the way an S3 bucket policy
  with the same principal would.

### Fixed

- The shared policy-document parser failed to parse an entire policy
  document whenever any field held a bare, unquoted resource-attribute
  reference (`Resource = [aws_x.name.arn]`, the idiomatic HCL form for a
  resource-level action with nothing to append) - even when a field as
  load-bearing as `Principal` sat right next to it, fully static and
  provable regardless of what that reference resolved to. Bare references
  are now replaced with an opaque placeholder during parsing instead of
  failing the whole document, which can only surface a previously-missed
  finding, never manufacture a new one. Affects every check that evaluates
  a policy document: S3-001, AGW-001, IAM-001, and the new SMK-002.

## 0.4.2 - 2026-08-30

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
- The first two release attempts under this workflow (0.4.0, 0.4.1) each
  failed at the build stage before anything reached PyPI - a locked
  dependency (`rpds-py`) had silently dropped Python 3.10 support, and the
  build job was missing the `id-token`/`attestations` permissions its own
  provenance-attestation step needs. Neither is visible from `pyproject.toml`
  or the package itself, only from the two now-abandoned tags. Both are
  fixed, and both now have a check that would have caught them before a tag
  was ever pushed: `scripts/check_lockfile_python_support.py` verifies every
  locked package against every Python version this project claims to
  support, and `test_every_job_has_the_permissions_its_own_actions_require`
  statically checks each workflow job's permissions against what its own
  steps actually require.

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
