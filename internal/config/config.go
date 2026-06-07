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
