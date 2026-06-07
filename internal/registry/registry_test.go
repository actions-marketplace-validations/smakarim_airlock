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
