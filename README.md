# airlock

> **Pre-1.0 / experimental.** API and signal names may change before v1.0.

Audit the npm packages a pull request **adds or bumps**, before they execute, to catch typosquat, dependency-confusion, and malicious-install-hook packages that CVE-based scanners are structurally blind to.

## The problem

CVE scanners catch *known-bad* versions of *known* packages. They have a structural blind spot: a brand-new package with zero CVEs and a `postinstall` script that reads `AWS_SECRET_ACCESS_KEY` and phones home scores perfectly clean. This is exactly the attack shape exploited in the 2025 and 2026 wave of supply-chain campaigns: publish a convincing typosquat or an internal-package name (dependency confusion), win the first `npm install` on a CI runner, and exfiltrate cloud credentials before any human looks at a diff.

`airlock` checks *new* packages at diff time by inspecting registry metadata and static hook content, before `npm install` ever runs.

## Quick start

```sh
go install github.com/smakarim/airlock/cmd/airlock@latest
```

```sh
airlock audit \
  --base base-package-lock.json \
  --head head-package-lock.json
```

### Generating the two lockfiles in CI

The `--base` file is the target branch's `package-lock.json`; `--head` is the PR branch's. A minimal GitHub Actions setup:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

# Check out the target branch lockfile into a temp path
- run: git show origin/${{ github.base_ref }}:package-lock.json > /tmp/base-lock.json

# The PR branch lockfile is already present in the workspace
- run: airlock audit --base /tmp/base-lock.json --head package-lock.json
```

See `action.yml` at the root of this repo for a ready-made composite Action that also emits SARIF for GitHub code-scanning.

## Example output

```
[CRITICAL] reqeusts@0.0.1
    - name.typosquat: name is 1 edit(s) from popular package "requests"
    - hook.lifecycle: declares install lifecycle hook(s): postinstall
    - inspect.exfil: install hook reads AWS credentials file and imports a network module

airlock: 1 package(s) flagged
```

`reqeusts` (transposed `eu`) is one edit from `requests`. Its `postinstall` script calls `node ./harvest.js`, which reads `~/.aws/credentials` and sends it to an attacker-controlled host. Both conditions (credential read and network egress) trigger the `inspect.exfil` signal at CRITICAL.

## Detection model

airlock runs two detection paths:

**IDENTITY.** Flags names that are within 2 edits (OSA, a restricted Damerau-Levenshtein distance) of a bundled list of popular npm packages (`name.typosquat`), or that carry implausible version strings used to win dependency-confusion resolution races such as `99.99.99` (`name.depconfusion`). The engine *will* gate identity findings down to LOW for packages that registry metadata confirms as well-established (old, widely downloaded, with a declared source repository), so genuinely popular packages with slightly unusual spellings do not produce false positives. That downgrade activates only once the weekly-downloads signal is wired (v1.1). In v1 this gate is dormant and fails safe: it never suppresses a finding.

**BEHAVIOR.** Inspects `preinstall`, `install`, and `postinstall` lifecycle hooks and the `.js` files they invoke. `hook.lifecycle` (LOW) fires on mere presence. If a script reads credential material (env vars like `AWS_SECRET_ACCESS_KEY`, `VAULT_TOKEN`, `GITHUB_TOKEN`, or files like `.npmrc`, `.aws/credentials`, `id_rsa`) *and* performs network egress (`curl`, `fetch`, `https.get`, `child_process`, and similar), severity escalates to CRITICAL (`inspect.exfil`). Credential read without egress is HIGH (`inspect.credread`); egress without a credential read is LOW (`inspect.egress`).

Tiers in ascending severity: CLEAR, LOW, MEDIUM, HIGH, CRITICAL.

## Allowlist (`.airlockignore`)

Every suppression requires an auditable reason. Create `.airlockignore` in your project root:

```
# .airlockignore: one entry per line, "name@version reason".
# Wildcards suppress all versions of a package.

node-gyp@10.2.0  internal build tooling, postinstall is well-known native compilation
esbuild@*        approved bundler, install script downloads platform binary via npm
```

Format: `name@version reason text` or `name@* reason text`. Lines starting with `#` are comments. An entry without a reason is a parse error (intentional: every suppression must be justified).

Pass a custom path with `--allowlist /path/to/file`.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--base` | *(required)* | Path to base `package-lock.json` (PR target branch) |
| `--head` | *(required)* | Path to head `package-lock.json` (PR branch) |
| `--registry` | `https://registry.npmjs.org` | npm registry base URL (useful for private registries) |
| `--fail-on` | `high` | Minimum tier that causes a non-zero exit: `low\|medium\|high\|critical` |
| `--format` | `human` | Output format: `human\|json\|sarif` |
| `--allowlist` | `.airlockignore` | Path to allowlist file (missing file is silently ignored) |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Operational error (missing or unreadable lockfile, bad arguments) |

## Non-goals

- **Not a CVE / vulnerability scanner.** airlock does not check NVD, OSV, or GitHub Advisory data. Use [trivy](https://github.com/aquasecurity/trivy), [grype](https://github.com/anchore/grype), or [osv-scanner](https://github.com/google/osv-scanner) alongside airlock; they are complementary, not overlapping.
- **npm only in v1.** PyPI, RubyGems, Maven, and other ecosystems are not supported.
- **PR-check shape only.** airlock audits the diff between two lockfiles. A true pre-install wrapper that intercepts `npm install` in real time is future work.
- **Reputation gate dormant in v1.** The metadata reputation gate that downgrades typosquat findings on well-established packages is present but dormant in v1; it activates once weekly-download data is wired (v1.1). Until then airlock errs toward flagging (fails safe).

## Design note

airlock has no runtime dependencies outside the Go standard library. A supply-chain security tool with a large supply chain of its own would be ironic.

## License

[MIT](LICENSE)
