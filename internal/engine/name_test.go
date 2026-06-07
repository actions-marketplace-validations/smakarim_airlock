package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
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
