package engine

import (
	"sort"
	"strconv"

	"github.com/smakarim/airlock/internal/model"
)

// NameSignal flags typosquats (lexically near a popular name) and
// dependency-confusion version tells.
type NameSignal struct{ popular map[string]bool }

func NewNameSignal(popular map[string]bool) NameSignal { return NameSignal{popular: popular} }

func (NameSignal) Name() string { return "name" }

// depConfusionVersions are absurd versions used to win resolution races.
var depConfusionVersions = map[string]bool{
	"99.99.99": true, "100.100.100": true, "999.999.999": true,
}

func (s NameSignal) Evaluate(p model.PackageData) []model.Evidence {
	var ev []model.Evidence
	name := p.Candidate.Name

	if depConfusionVersions[p.Candidate.Version] {
		ev = append(ev, model.Evidence{
			Signal:      "name.depconfusion",
			Tier:        model.High,
			Explanation: "version " + p.Candidate.Version + " is an implausible value commonly used to win dependency-confusion resolution races",
			Locator:     "version",
		})
	}

	if s.popular[name] {
		return ev // exact match to a popular package is not a typosquat
	}

	// Build a sorted slice so iteration order is deterministic.
	// On a tie in edit distance the lexicographically smallest popular name wins
	// (sorted order + strict-less-than comparison guarantees this).
	sorted := make([]string, 0, len(s.popular))
	for pop := range s.popular {
		sorted = append(sorted, pop)
	}
	sort.Strings(sorted)

	bestPop := ""
	bestDist := 3 // sentinel — anything > 2 means "no match yet"
	for _, pop := range sorted {
		if d := osaDistance(name, pop); d > 0 && d <= 2 {
			if d < bestDist {
				bestPop = pop
				bestDist = d
			}
		}
	}

	if bestPop != "" {
		// One evidence item is sufficient — we don't accumulate one per near-name.
		ev = append(ev, model.Evidence{
			Signal:      "name.typosquat",
			Tier:        model.High,
			Explanation: "name is " + strconv.Itoa(bestDist) + " edit(s) from popular package \"" + bestPop + "\"",
			Locator:     "name",
		})
	}
	return ev
}

// osaDistance computes the Optimal String Alignment distance (restricted
// Damerau-Levenshtein): like Levenshtein but also counts a single adjacent
// transposition (e.g. reqeusts<->requests) as one edit.
// Note: this is OSA, not true Damerau-Levenshtein — it does not allow a
// character to be edited more than once, so the triangle inequality does not
// strictly hold.
//
// It compares bytes, which is fine because npm package names are lowercase
// URL-safe ASCII.
func osaDistance(a, b string) int {
	la, lb := len(a), len(b)
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if t := d[i-2][j-2] + 1; t < d[i][j] {
					d[i][j] = t
				}
			}
		}
	}
	return d[la][lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
