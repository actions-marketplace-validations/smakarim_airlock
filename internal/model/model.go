// Package model holds the shared data types passed between snare's units.
package model

// Tier is an ordered severity level. Higher value = more severe.
type Tier int

const (
	Clear Tier = iota // no finding — safe to proceed
	Low
	Medium
	High
	Critical
)

func (t Tier) AtLeast(o Tier) bool { return t >= o }

// String returns the upper-case name of the tier.
func (t Tier) String() string {
	switch t {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "CLEAR"
	}
}

// Candidate is one package@version the PR adds or bumps.
type Candidate struct {
	Name    string
	Version string
}

// PackageData is everything fetched about a candidate needed for scoring.
type PackageData struct {
	Candidate
	// Manifest is the parsed package.json of this version.
	Manifest Manifest
	// Registry is registry-level metadata about the package (all versions).
	Registry RegistryInfo
	// Scripts maps lifecycle name (preinstall/install/postinstall) to script body.
	Scripts map[string]string
	// Files maps tarball-relative path to file contents (text files only, size-capped).
	Files map[string]string
}

// Manifest is the subset of package.json we use.
type Manifest struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

// RegistryInfo is package-level registry metadata.
type RegistryInfo struct {
	// FirstPublished is the time the very first version was published (RFC3339), "" if unknown.
	FirstPublished string
	// VersionPublished is when THIS version was published (RFC3339), "" if unknown.
	VersionPublished string
	// WeeklyDownloads is the most recent weekly download count, -1 if unknown.
	WeeklyDownloads int
	// Maintainers is the count of maintainers, -1 if unknown.
	Maintainers int
	// Repository is the declared source repo URL, "" if absent.
	Repository string
	// LatestVersion is the registry's current "latest" dist-tag.
	LatestVersion string
}

// Evidence is one finding from one signal. Never a bare boolean.
type Evidence struct {
	Signal      string // e.g. "name.typosquat"
	Tier        Tier
	Explanation string // human-readable "why"
	Locator     string // file/field this came from, "" if N/A
}

// Result is the full scored outcome for one candidate.
type Result struct {
	Candidate Candidate
	Evidence  []Evidence
	// Errored is true when the candidate could not be fully evaluated.
	Errored bool
	ErrMsg  string
}

// TopTier returns the highest evidence tier, or Clear when Evidence is empty or all tiers are Clear.
func (r Result) TopTier() Tier {
	top := Clear
	for _, e := range r.Evidence {
		if e.Tier > top {
			top = e.Tier
		}
	}
	return top
}
