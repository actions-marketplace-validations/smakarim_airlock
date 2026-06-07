package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

// stubSignal emits a fixed evidence (or none).
type stubSignal struct{ ev *model.Evidence }

func (s stubSignal) Name() string { return "stub" }
func (s stubSignal) Evaluate(model.PackageData) []model.Evidence {
	if s.ev == nil {
		return nil
	}
	return []model.Evidence{*s.ev}
}

func TestEngineAggregatesEvidence(t *testing.T) {
	e := New([]Signal{
		stubSignal{ev: &model.Evidence{Signal: "a", Tier: model.Medium}},
		stubSignal{ev: &model.Evidence{Signal: "b", Tier: model.High}},
		stubSignal{ev: nil},
	})
	res := e.Score(model.PackageData{})
	if res.TopTier() != model.High {
		t.Errorf("TopTier = %v, want High", res.TopTier())
	}
	if len(res.Evidence) != 2 {
		t.Errorf("evidence count = %d, want 2", len(res.Evidence))
	}
}
