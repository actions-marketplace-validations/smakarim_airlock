# Security Policy

## Supported versions

airlock is pre-1.0 and experimental. Security fixes are applied to the latest
tagged release and the `main` branch. Older tags are not maintained.

| Version | Supported |
|---------|-----------|
| latest `0.x` tag | yes |
| `main` | yes |
| older | no |

## Reporting a vulnerability

Please do not open a public issue for security problems.

Preferred: open a private report through GitHub's "Report a vulnerability"
button under the repository **Security** tab (Security Advisories).

Alternative: email **imsyedkarim@gmail.com** with a description, reproduction
steps, and impact. Please allow up to 7 days for an initial response.

## Scope

airlock is a static auditor that fetches npm registry metadata and reads
package tarball contents. It never executes install hooks. Reports of
particular interest:

- A malicious package shape that airlock fails to flag (a false negative
  that lets install-time malice through).
- A crafted lockfile, registry response, or tarball that causes airlock to
  crash, hang, consume unbounded resources, or execute attacker input.

Findings that improve detection coverage are also welcome as regular issues
or pull requests once they are not themselves sensitive.
