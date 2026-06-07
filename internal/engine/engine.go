// Package engine scores a package for install-time risk. It is pure: no network,
// no filesystem, so it is fully testable from fixtures.
package engine

import (
	"strings"

	"github.com/syedkarim/snare/internal/model"
)

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
	gate(&res)
	return res
}

// gate applies the false-positive guardrail. If a metadata signal marked the
// package as well-established, identity-path suspicion (name.*) is downgraded to
// LOW — a years-old, widely-used package with a repo is not a fresh typosquat.
// The internal marker is then removed so it never surfaces in reports.
func gate(res *model.Result) {
	established := false
	for _, e := range res.Evidence {
		if e.Signal == establishedMarker {
			established = true
			break
		}
	}
	kept := res.Evidence[:0]
	for _, e := range res.Evidence {
		if e.Signal == establishedMarker {
			continue // drop the internal marker
		}
		if established && strings.HasPrefix(e.Signal, "name.") {
			e.Tier = model.Low
			e.Explanation += " (downgraded: package is well-established)"
		}
		kept = append(kept, e)
	}
	res.Evidence = kept
}
