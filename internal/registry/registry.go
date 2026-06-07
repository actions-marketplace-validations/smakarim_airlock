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
	Name     string `json:"name"`
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Time        map[string]string `json:"time"` // "created", "<version>" -> RFC3339
	Maintainers []struct {
		Name string `json:"name"`
	} `json:"maintainers"`
	Versions map[string]struct {
		Name       string            `json:"name"`
		Version    string            `json:"version"`
		Scripts    map[string]string `json:"scripts"`
		Repository json.RawMessage   `json:"repository"`
		Dist       struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
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
