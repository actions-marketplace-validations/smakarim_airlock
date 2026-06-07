// Package engine scores a package for install-time risk. It is pure: no network,
// no filesystem, so it is fully testable from fixtures.
package engine

import "github.com/syedkarim/snare/internal/model"

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
	return res
}
