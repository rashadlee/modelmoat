# Security Policy

modelmoat is a static analysis tool. It reads Terraform files and never touches
your cloud accounts, state files, or credentials.

## Reporting a vulnerability

If you find a security issue in modelmoat itself, open a private report through
GitHub Security Advisories on this repository. Please do not open a public
issue for exploitable problems. Reports get a response within 7 days.

## Reporting a false positive or false negative

Detection quality bugs are tracked as regular GitHub issues. Include the
smallest Terraform snippet that reproduces the problem. False positives are
treated with the same priority as missed findings.
