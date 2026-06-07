package engine

import (
	"testing"

	"github.com/smakarim/airlock/internal/model"
)

func establishedPkg(name string) model.PackageData {
	return model.PackageData{
		Candidate: model.Candidate{Name: name, Version: "1.2.3"},
		Registry: model.RegistryInfo{
			FirstPublished:  "2015-01-01T00:00:00Z",
			WeeklyDownloads: 5_000_000,
			Maintainers:     4,
			Repository:      "git+https://github.com/x/y.git",
		},
	}
}

func TestMetadataFlagsBrandNewZeroDownload(t *testing.T) {
	s := NewMetadataSignal(refNow)
	p := model.PackageData{
		Candidate: model.Candidate{Name: "reqeusts", Version: "0.0.1"},
		Registry:  model.RegistryInfo{FirstPublished: "2026-06-06T00:00:00Z", WeeklyDownloads: 3, Maintainers: 1},
	}
	ev := s.Evaluate(p)
	if len(ev) == 0 {
		t.Fatal("expected metadata risk evidence for brand-new low-download package")
	}
}

func TestGateDowngradesTyposquatOnEstablishedPackage(t *testing.T) {
	// "preact" is 1 edit from "react" -> name signal flags it HIGH.
	// But preact is old + popular, so the gate must downgrade it.
	e := New([]Signal{
		NewNameSignal(map[string]bool{"react": true}),
		NewMetadataSignal(refNow),
	})
	res := e.Score(establishedPkg("preact"))
	if res.TopTier() >= model.High {
		t.Errorf("established near-name package should be downgraded below HIGH, got %v", res.TopTier())
	}
	// The internal marker must not leak into the reported evidence.
	for _, ev := range res.Evidence {
		if ev.Signal == "metadata.established" {
			t.Error("established marker should be removed from evidence before reporting")
		}
	}
}
