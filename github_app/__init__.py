"""The modelmoat GitHub App: native PR review comments instead of a SARIF upload step.

This lives outside the modelmoat package on purpose. modelmoat is a pip
package; the App is a hosted service with its own dependencies (a web
framework, a GitHub API client) that CLI users should never have to install.
The App imports modelmoat as a library and never duplicates its scanning
logic - only comment placement is app-specific.
"""
