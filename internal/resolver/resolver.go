// Package resolver turns a pair of package-lock.json files into the set of
// packages a PR adds or bumps.
package resolver

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/smakarim/airlock/internal/model"
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
// relative to base. The returned slice order is unspecified.
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
