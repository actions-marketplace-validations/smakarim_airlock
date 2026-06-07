package engine

import (
	"strconv"

	"github.com/syedkarim/snare/internal/model"
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
	for pop := range s.popular {
		if d := damerau(name, pop); d > 0 && d <= 2 {
			ev = append(ev, model.Evidence{
				Signal:      "name.typosquat",
				Tier:        model.High,
				Explanation: "name is " + strconv.Itoa(d) + " edit(s) from popular package \"" + pop + "\"",
				Locator:     "name",
			})
			break
		}
	}
	return ev
}

// damerau computes Damerau-Levenshtein distance (handles adjacent transpositions
// like reqeusts<->requests).
func damerau(a, b string) int {
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
