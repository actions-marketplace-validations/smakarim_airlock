# Design: Install-Time npm Package Auditor (working name: `snare`)

**Date:** 2026-06-07
**Status:** Draft for review
**Author:** Abdul Karim

---

## 1. Problem

SBOM/dependency scanners (trivy, grype, osv-scanner, dependabot, snyk OSS) match
`installed version → CVE database`. They are structurally blind to **brand-new
malicious packages**, because a package published an hour ago is in no CVE feed.

Yet that is exactly the live, high-impact attack vector as of 2026:

- Coordinated npm campaigns (14-, 33-, and 176-package clusters) used
  **typosquatting** and **dependency confusion** (inflated versions like
  `99.99.99` / `100.100.100` to win resolution races against internal packages).
- Payloads execute via **`preinstall` / `install` / `postinstall` lifecycle
  hooks** — running on every `npm install`, *before any application, build, or
  test code*. `--require()` from victim code is not needed.
- The payloads are **credential harvesters**: AWS STS/IMDSv2, Secrets Manager,
  Vault tokens, npm publish tokens (enabling further supply-chain pivoting), and
  GitHub Actions context.

Existing mitigations are inadequate: `--ignore-scripts` breaks legitimate native
builds; Socket is closed-source paid SaaS; the OpenSSF malicious-packages feed is
reactive (lists malice only after it's reported). There is **no strong
open-source CLI** that proactively flags a suspicious package *before* it runs.

### Evidence basis
- Microsoft Security blog (2026-05-28, 2026-05-29): preinstall/postinstall
  credential-harvesting campaigns.
- Sonatype (176-package dependency-confusion campaign).
- ConfuGuard (arXiv 2502.20528): lexical typosquat detection is ~80% false
  positive **alone**; adding package **metadata** signals cuts FP to ~28%.
- OpenSSF / Sonatype state-of-supply-chain: install-script abuse in >60% of
  malicious npm packages.

## 2. Goal & Strategy

Open-source-first Go CLI, CI-pipeline-shaped (the trivy/semgrep/trufflehog
playbook): win developer adoption first, add a paid team/cloud layer later.

**The moat is the detection engine** — given a package, how suspicious is it, with
*low false positives*. FP-discipline is not a feature; it is THE product. A tool
that cries wolf dies.

### Scope decisions (locked during brainstorming)
- **Outcome:** OSS now, commercialize later.
- **Space:** software supply chain / dependency security.
- **Chosen gap:** install-time malicious-package detection (typosquat /
  dependency-confusion / malicious lifecycle hooks), credential-theft focused.
- **Product shape (v1):** detection engine wrapped as a **lockfile-diff PR/CI
  auditor** — runs in the pull-request pipeline against only the packages a PR
  adds/bumps; advisory + exit-code, not an install-path interceptor. This yields
  ~90% of a true gate's protective value (malice never merges to main / reaches
  prod) at ~30% of the engineering risk.
- **Ecosystem (v1):** **npm only.** All 2026 attack evidence is npm; richest
  registry metadata API; clearest lifecycle-hook model.

### Non-goals (v1)
- True pre-install wrapper / registry firewall that intercepts `npm install`
  on a developer laptop → **v2**.
- PyPI / Maven / Cargo / Go ecosystems → later.
- Known-CVE vulnerability scanning / reachability analysis → out of scope (that's
  trivy/grype/govulncheck territory; we deliberately do NOT compete there).
- Heavy account-takeover / behavioral ML modeling → v2.

## 3. Architecture & Data Flow

```
PR opens / CI runs
      │
      ▼
[1] Diff resolver ──► extracts ONLY packages this PR adds/bumps
      │               (parse package-lock.json, compare base vs head;
      │                or `npm install --dry-run --json` for resolved set)
      ▼
[2] Fetcher ────────► npm registry metadata + tarball per candidate
      │               (concurrent, content-addressed cache, offline-replayable)
      ▼
[3] Scoring engine ─► Path 1 (identity) + Path 2 (behavior)
      │               pluggable signal modules; each returns EVIDENCE, not a bool
      │               → risk score + structured reasons
      ▼
[4] Reporter ───────► policy threshold → exit code
                      human-readable + JSON + SARIF; PR comment with per-package
                      "why flagged"
```

Four units, each independently testable with one clear responsibility:

| Unit | Responsibility | Depends on | Testable via |
|------|----------------|------------|--------------|
| **resolver** | input formats → candidate package set (the diff) | filesystem, optionally npm | lockfile fixtures |
| **fetcher** | candidate → {registry metadata, tarball} | network, cache | recorded HTTP fixtures (offline) |
| **engine** | package data → risk score + reasons | nothing (pure) | in-memory fixtures, golden tests |
| **reporter** | score+reasons → output formats & exit code | nothing (pure) | golden output tests |

The **engine is pure and offline** — critical, because FP-discipline is enforced
by a regression corpus of real packages (known-good and known-malicious) that the
engine must score correctly on every commit.

## 4. The Scoring Engine (the core)

Two independent evidence paths converge on one risk score. They catch different
attacks and cross-check each other.

### Path 1 — Identity / reputation ("who is this package?")
- **Name analysis (candidate-finder):** edit-distance + keyboard-adjacency +
  homoglyph similarity to a curated set of popular npm packages; scope/internal-
  name impersonation; suspicious version anomalies (`99.99.99`, `100.100.100`,
  version far ahead of registry history → dependency-confusion tell).
- **Metadata signals (FP-killers, non-negotiable):** package age, total/recent
  download counts, maintainer count & account age, presence/validity of a source
  repository, whether name resolves against a known-popular package.

Name analysis ALONE is ~80% FP; **gated by metadata it drops toward ~28%.**
Neither ships without the other.

### Path 2 — Behavior ("what does it do at install?")
- **Lifecycle-hook detection:** does `package.json` declare
  `preinstall`/`install`/`postinstall`? Resolve the script(s) they invoke.
- **Install-script static inspection:** scan referenced scripts + obvious entry
  files in the tarball for high-signal patterns — network egress
  (`curl|sh`, `http(s)` to non-registry hosts), reads of credential paths
  (`~/.aws`, `~/.npmrc`, `process.env` secret keys, `~/.ssh`), base64/obfuscated
  blobs, spawning compiled/second-stage binaries, `child_process` exec of
  downloaded content.

Path 2 is high-precision: an install hook exfiltrating credentials is near-certain
malice *regardless* of name or age.

### Convergence & cross-check
- Path 1 high + Path 2 high → **top-confidence** (classic typosquat-with-payload).
- Path 1 "reputable/old/popular" + Path 2 "new weird exfil hook" → **account-
  takeover signal** that neither path catches alone.
- Each signal emits structured `Evidence{signal, severity, explanation,
  locator}`; the engine combines evidence into a tiered score. **Metadata
  evidence can veto/downweight name-only suspicion** (the FP guardrail).

### Light maintainer/release anomaly (cheap, in-scope)
Burst-publishing (e.g. 14 packages in a 4-hour window), brand-new maintainer
account, first-ever publish — derived from registry metadata, no extra crawl.
Heavy modeling deferred to v2.

## 5. Risk Scoring & Policy

- Output tiers: **CRITICAL / HIGH / MEDIUM / LOW / CLEAR**, each with the
  contributing evidence attached (never a bare number).
- Configurable `--fail-on <tier>` (default: HIGH). Exit non-zero at/above
  threshold so CI fails the build / blocks the PR.
- Allowlist file (`.snareignore` or config) for accepted packages, with required
  reason + optional expiry, so suppressing a FP is auditable.
- Every flag includes a human-readable **"why"** and a locator (file/line in
  manifest or tarball) — explainability is part of FP-trust.

## 6. Output & Integration

- **Human:** colorized table, grouped by tier, with reasons. Default for terminal.
- **JSON:** full structured result for programmatic use.
- **SARIF:** so GitHub code-scanning / other CI surfaces render findings inline.
- **PR comment mode:** post a comment summarizing newly-added risky packages with
  per-package "why flagged" (advisory tone — a FP here is annoying, not build-
  breaking, which is why the PR-check shape is FP-forgiving by design).
- Single static Go binary; `npx`-free; trivial to drop into any CI as one step.

## 7. Error Handling & Resilience

- **Network/registry failures:** retry with backoff; on hard failure, FAIL OPEN
  with a clear warning (a flaky registry must not block all PRs) — but exit code
  distinguishes "clean" from "could-not-evaluate".
- **Malformed lockfile/manifest:** explicit parse error naming the file; never a
  silent pass.
- **Tarball bombs / oversized packages:** size & time caps on fetch and static
  scan; cap is logged, not silently truncated.
- **Cache:** content-addressed by package@version+integrity hash; corrupt entries
  re-fetched.
- **Determinism:** same inputs → same output (required for golden tests & for
  trustworthy CI).

## 8. Testing Strategy

- **Engine unit tests (TDD):** each signal module tested in isolation with crafted
  package fixtures.
- **FP regression corpus:** a checked-in set of (a) popular legitimate packages
  with legitimate install scripts (node-gyp/native builds) that MUST score CLEAR,
  and (b) sanitized known-malicious samples from the 2026 campaigns that MUST
  score HIGH+. CI fails if FP/FN rates regress. **This corpus is the product's
  quality bar.**
- **Fetcher tests:** recorded registry HTTP fixtures, fully offline.
- **Golden output tests:** human/JSON/SARIF renderers.
- **End-to-end:** sample repo with a crafted malicious dep added in a "PR" diff →
  tool flags it and exits non-zero.

## 9. Milestones (rough, for the plan to refine)

1. Repo skeleton, CLI scaffold, lockfile-diff resolver + fixtures.
2. Fetcher + cache + offline HTTP fixtures.
3. Engine: Path 1 (name + metadata) with FP corpus passing.
4. Engine: Path 2 (lifecycle-hook + static inspection).
5. Reporter (human/JSON/SARIF) + policy/exit codes + allowlist.
6. PR-comment mode + GitHub Action wrapper; docs; first release.

## 10. Open Questions (carry into planning)

- Source of the "popular packages" baseline for typosquat distance — bundle a
  snapshot (offline, stale) vs fetch live (network, fresh)? Likely bundled
  snapshot + optional refresh.
- Exact static-inspection depth before diminishing returns / FP risk — heuristics
  vs a light JS parser for hook scripts.
- Sanitized malicious-sample sourcing for the corpus (legal/safe handling).
- Final name (`snare` is provisional) + npm/GitHub availability check.
```
