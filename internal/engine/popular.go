package engine

import (
	_ "embed"
	"strings"
	"time"
)

//go:embed data/popular.txt
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
func Default(now time.Time) []Signal {
	return []Signal{
		NewNameSignal(PopularSet()),
		NewMetadataSignal(now),
		HookSignal{},
		InspectSignal{},
	}
}
