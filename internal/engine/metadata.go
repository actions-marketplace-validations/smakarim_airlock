package engine

import (
	"time"

	"github.com/syedkarim/snare/internal/model"
)

// refNow is the reference "now" used by tests for deterministic age math.
// Production constructs the metadata signal with time.Now().
var refNow = mustTime("2026-06-07T00:00:00Z")

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// establishedMarker is an internal, Clear-tier evidence the metadata signal emits
// for clearly-established packages. The engine gate consumes it to downgrade
// identity-path suspicion, then removes it before reporting.
const establishedMarker = "metadata.established"

// MetadataSignal scores reputation: new + low-download + no-repo = risk. For
// clearly-established packages it instead emits the established marker.
type MetadataSignal struct{ now time.Time }

func NewMetadataSignal(now time.Time) MetadataSignal { return MetadataSignal{now: now} }

func (MetadataSignal) Name() string { return "metadata" }

func (s MetadataSignal) Evaluate(p model.PackageData) []model.Evidence {
	if isEstablished(p, s.now) {
		return []model.Evidence{{
			Signal:      establishedMarker,
			Tier:        model.Clear,
			Explanation: "package is well-established (old, widely downloaded, has a repository)",
			Locator:     "registry",
		}}
	}
	var ev []model.Evidence
	age := ageDays(p, s.now)
	young := age >= 0 && age <= 30
	lowDL := p.Registry.WeeklyDownloads >= 0 && p.Registry.WeeklyDownloads < 100
	if young && lowDL {
		ev = append(ev, model.Evidence{
			Signal:      "metadata.new_unpopular",
			Tier:        model.Medium,
			Explanation: "package is <30 days old with <100 weekly downloads",
			Locator:     "registry",
		})
	}
	if p.Registry.Repository == "" {
		ev = append(ev, model.Evidence{
			Signal:      "metadata.no_repository",
			Tier:        model.Low,
			Explanation: "package declares no source repository",
			Locator:     "registry",
		})
	}
	return ev
}

// isEstablished is the FP guardrail: old, widely-downloaded, has a repo.
func isEstablished(p model.PackageData, now time.Time) bool {
	old := ageDays(p, now) > 365
	popular := p.Registry.WeeklyDownloads > 10_000
	return old && popular && p.Registry.Repository != ""
}

// ageDays returns the package age in days, or -1 if unknown.
func ageDays(p model.PackageData, now time.Time) int {
	if p.Registry.FirstPublished == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, p.Registry.FirstPublished)
	if err != nil {
		return -1
	}
	return int(now.Sub(t).Hours() / 24)
}
