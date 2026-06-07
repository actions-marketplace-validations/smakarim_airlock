package engine

import (
	"sort"
	"strings"

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
	names := make([]string, 0, len(p.Scripts))
	for k := range p.Scripts {
		names = append(names, k)
	}
	sort.Strings(names)
	return []model.Evidence{{
		Signal:      "hook.lifecycle",
		Tier:        model.Low,
		Explanation: "declares install lifecycle hook(s): " + strings.Join(names, ", "),
		Locator:     "package.json#scripts",
	}}
}
