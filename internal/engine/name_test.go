package engine

import (
	"testing"

	"github.com/smakarim/airlock/internal/model"
)

func popularSet() map[string]bool {
	return map[string]bool{"react": true, "requests": true, "lodash": true, "express": true}
}

func TestNameSignalFlagsTyposquat(t *testing.T) {
	s := NewNameSignal(popularSet())
	ev := s.Evaluate(model.PackageData{Candidate: model.Candidate{Name: "reqeusts", Version: "0.0.1"}})
	if len(ev) == 0 {
		t.Fatal("expected typosquat evidence for reqeusts")
	}
	if ev[0].Signal != "name.typosquat" {
		t.Errorf("signal = %q", ev[0].Signal)
	}
}

func TestNameSignalIgnoresExactPopular(t *testing.T) {
	s := NewNameSignal(popularSet())
	if ev := s.Evaluate(model.PackageData{Candidate: model.Candidate{Name: "react", Version: "18.3.0"}}); len(ev) != 0 {
		t.Errorf("exact popular name should not be flagged, got %v", ev)
	}
}

func TestNameSignalFlagsVersionAnomaly(t *testing.T) {
	s := NewNameSignal(popularSet())
	ev := s.Evaluate(model.PackageData{Candidate: model.Candidate{Name: "internal-corp-utils", Version: "99.99.99"}})
	found := false
	for _, e := range ev {
		if e.Signal == "name.depconfusion" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected depconfusion evidence, got %v", ev)
	}
}

// TestNameSignalTyposquatDeterministic verifies that when a candidate is within
// distance 2 of multiple popular names, Evaluate always picks the same
// (lexicographically-smallest closest) match regardless of map iteration order.
//
// Popular set: {"react","reacts","reactt"}
//   - "reactx" vs "react"  → distance 1  (substitute x for nothing? no: react=5, reactx=6 → insert)
//   - "reactx" vs "reacts" → distance 1  (substitute x→s)
//   - "reactx" vs "reactt" → distance 1  (substitute x→t)
//
// All three are at distance 1; lexicographically smallest is "react".
func TestNameSignalTyposquatDeterministic(t *testing.T) {
	pop := map[string]bool{
		"react":  true,
		"reacts": true,
		"reactt": true,
	}
	s := NewNameSignal(pop)

	var firstExplanation string
	for i := 0; i < 20; i++ {
		ev := s.Evaluate(model.PackageData{Candidate: model.Candidate{Name: "reactx", Version: "1.0.0"}})
		if len(ev) == 0 {
			t.Fatalf("iteration %d: expected typosquat evidence, got none", i)
		}
		var typoEv *model.Evidence
		for j := range ev {
			if ev[j].Signal == "name.typosquat" {
				typoEv = &ev[j]
				break
			}
		}
		if typoEv == nil {
			t.Fatalf("iteration %d: no name.typosquat evidence in %v", i, ev)
		}
		if i == 0 {
			firstExplanation = typoEv.Explanation
			// The closest AND lexicographically smallest popular name is "react".
			want := `name is 1 edit(s) from popular package "react"`
			if firstExplanation != want {
				t.Errorf("iteration 0: explanation = %q, want %q", firstExplanation, want)
			}
		} else if typoEv.Explanation != firstExplanation {
			t.Errorf("iteration %d: non-deterministic result: got %q, want %q",
				i, typoEv.Explanation, firstExplanation)
		}
	}
}
