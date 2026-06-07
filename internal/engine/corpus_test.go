package engine_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syedkarim/snare/internal/engine"
	"github.com/syedkarim/snare/internal/model"
)

// corpusCase is a stored PackageData fixture plus its expected tier bound.
type corpusCase struct {
	Data    model.PackageData `json:"data"`
	MaxTier string            `json:"max_tier,omitempty"` // good/: must NOT exceed this
	MinTier string            `json:"min_tier,omitempty"` // malicious/: must reach this
}

func loadCases(t *testing.T, dir string) map[string]corpusCase {
	t.Helper()
	cases := map[string]corpusCase{}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return cases
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		buf, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var c corpusCase
		if err := json.Unmarshal(buf, &c); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		// Guard against the embedded-Candidate JSON pitfall: a fixture that nests
		// Name/Version under "Candidate" instead of promoting them leaves Name empty.
		if c.Data.Name == "" {
			t.Fatalf("%s: fixture has empty package Name — put \"Name\"/\"Version\" at the TOP LEVEL of data (Candidate is an embedded struct)", e.Name())
		}
		cases[e.Name()] = c
	}
	return cases
}

func tierVal(t *testing.T, name, s string) model.Tier {
	t.Helper()
	switch s {
	case "CRITICAL":
		return model.Critical
	case "HIGH":
		return model.High
	case "MEDIUM":
		return model.Medium
	case "LOW":
		return model.Low
	case "CLEAR":
		return model.Clear
	default:
		t.Fatalf("%s: unknown tier %q (want CRITICAL|HIGH|MEDIUM|LOW|CLEAR)", name, s)
		return model.Clear // unreachable
	}
}

func TestCorpusGoodStaysQuiet(t *testing.T) {
	eng := engine.New(engine.Default(time.Now()))
	cases := loadCases(t, "../../testdata/corpus/good")
	if len(cases) == 0 {
		t.Fatal("no good-corpus fixtures found — expected at least one (FP regression gate is the product's quality bar)")
	}
	for name, c := range cases {
		bound := tierVal(t, name, c.MaxTier)
		if got := eng.Score(c.Data).TopTier(); got > bound {
			t.Errorf("%s: scored %v, exceeds allowed max %v (FALSE POSITIVE)", name, got, bound)
		}
	}
}

func TestCorpusMaliciousIsCaught(t *testing.T) {
	eng := engine.New(engine.Default(time.Now()))
	cases := loadCases(t, "../../testdata/corpus/malicious")
	if len(cases) == 0 {
		t.Fatal("no malicious-corpus fixtures found — expected at least one (FN regression gate is the product's quality bar)")
	}
	for name, c := range cases {
		floor := tierVal(t, name, c.MinTier)
		if got := eng.Score(c.Data).TopTier(); got < floor {
			t.Errorf("%s: scored %v, below required min %v (FALSE NEGATIVE)", name, got, floor)
		}
	}
}
