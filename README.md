# modelmoat

Static analysis for AI infrastructure security in Terraform. It reads your `.tf`
files and finds the misconfigurations that show up specifically when teams ship
Bedrock, SageMaker, and vector databases: blanket `bedrock:*` grants, model
artifact buckets open to the internet, embedding stores without encryption, and
inference traffic that never touches your private network.

General IaC scanners check hundreds of AWS resource types and cover some of this
ground. modelmoat is the one that treats AI infrastructure as its own category,
with checks written around how these services actually fail rather than a
generic encryption rule applied to every database in the account.

Findings run against the whole project at once, not file by file, because
Terraform spreads related resources across files. A bucket in `s3.tf` and its
public access block in `security.tf` are one decision, and modelmoat reads them
that way.

## Install

    pipx install modelmoat

Or with pip:

    pip install modelmoat

Python 3.10 or newer. modelmoat only reads local files. It never contacts your
AWS account, reads state files, or touches credentials.

## Usage

    modelmoat scan .
    modelmoat scan infra/ modules/ --min-severity HIGH
    modelmoat scan . --json > findings.json

Real output from the test fixtures in this repo:

```
modelmoat 0.1.0 scanned 6 Terraform file(s)
  CRITICAL: 4  HIGH: 7  MEDIUM: 4  LOW: 3

CRITICAL S3-001  aws_s3_bucket.datasets
         tests/fixtures/insecure/s3_bad.tf:11
         S3 bucket 'datasets' looks AI/ML related (matched: datasets) and its
         bucket policy allows Principal "*". Anyone on the internet can perform
         the granted actions.
         fix: Restrict the policy principal to specific roles or accounts and
         add an aws_s3_bucket_public_access_block with all four protections
         enabled.

HIGH     IAM-001  aws_iam_role_policy_attachment.full_access
         tests/fixtures/insecure/iam_bad.tf:12
         Role 'agent_role' attaches AWS managed policy
         'arn:aws:iam::aws:policy/AmazonBedrockFullAccess', which grants blanket
         AI service access. The role is used by Lambda function(s) public_agent,
         vpc_agent.
```

## Checks

| ID | What it finds | Severity range |
|----|---------------|----------------|
| SMK-001 | SageMaker models with no `vpc_config`, so containers run on the managed network with direct internet egress | HIGH |
| IAM-001 | Wildcard AI grants (`bedrock:*`, `sagemaker:*` on `Resource "*"`) in inline policies, customer managed policies, policy documents, or attached AWS `FullAccess` policies | HIGH |
| S3-001 | AI-related buckets exposed by a public ACL or a `Principal "*"` policy, plus weakened or missing public access blocks | CRITICAL to LOW |
| VPC-001 | Lambda functions calling Bedrock or SageMaker with no matching interface VPC endpoint in the project | MEDIUM to LOW |
| VEC-001 | OpenSearch, pgvector-capable Postgres, and AI-named ElastiCache missing encryption or network isolation | CRITICAL to LOW |

## Exit codes and CI

`modelmoat scan` exits 1 when findings at or above `--fail-on` exist, and 0
otherwise. The default is `HIGH`, so hygiene findings do not break builds.
Exit code 2 means bad arguments.

```yaml
- name: Scan AI infrastructure
  run: |
    pip install modelmoat
    modelmoat scan infra/ --fail-on HIGH
```

Tighten with `--fail-on MEDIUM` once your baseline is clean, or loosen to
`CRITICAL` while you work through a backlog. `--min-severity` controls what gets
printed and is separate from what fails the build, so you can see everything
while only blocking on the serious findings.

## How severity is decided

CRITICAL means the configuration itself proves internet reachability with weak
or absent authentication. A bucket policy granting `Principal "*"` qualifies. A
SageMaker model outside a VPC does not, because invoking it still requires a
SigV4-signed IAM request, and modelmoat says exactly that in the finding rather
than claiming anyone with the URL can hit your model.

HIGH covers missing encryption and permissions broad enough to reach any AI
resource in the account. MEDIUM and LOW are hygiene: a missing public access
block is LOW, since account defaults have blocked public access on new buckets
since April 2023, and calling it CRITICAL would be wrong.

## Design notes

Values that come from variables or expressions are unknown, and modelmoat does
not flag what it cannot prove. `storage_encrypted = var.encrypt_storage` produces
no finding either way.

Keyword matching is on whole tokens, never substrings. A bucket named
`email-archive` does not match `ai`, and `html-assets` does not match `ml`. Both
appear in the test suite as negative controls that must stay silent.

The test suite has one rule above all others: the secure fixture must produce
zero findings. A scanner that fires on correct infrastructure trains people to
ignore it, so CI runs both directions on every push, requiring a clean pass on
nine files of best-practice Terraform and a failing exit code on the insecure
fixture.

## Limitations

modelmoat reads HCL statically. It does not evaluate modules, resolve variable
files, expand `for_each`, or read remote state, so a security control defined in
a module that this project only calls will not be seen. Coverage is AWS only
today, and provider-specific vector databases like Pinecone and Weaviate are not
yet checked.

Static analysis cannot tell you whether a security group actually permits the
traffic you fear, or whether an IAM permission is used. Treat findings as places
to look, not verdicts.

## Roadmap

Pinecone and Weaviate providers, SARIF output for GitHub code scanning, Azure AI
and Vertex AI resources, and a `--baseline` file for adopting the tool on an
existing codebase without a wall of findings on day one.

## Contributing

False positive reports are as welcome as new checks and get the same priority.
See CONTRIBUTING.md for the rules every check follows and SECURITY.md for
reporting a vulnerability in the tool itself.

## License

Apache-2.0.
