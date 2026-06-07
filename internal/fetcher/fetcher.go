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

	"github.com/smakarim/airlock/internal/model"
	"github.com/smakarim/airlock/internal/registry"
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
