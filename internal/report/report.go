// Package report renders scored results to human/JSON/SARIF and computes the
// process exit code.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/syedkarim/snare/internal/model"
)

// ExitCode returns 1 if any result meets or exceeds failOn, else 0.
func ExitCode(results []model.Result, failOn model.Tier) int {
	for _, r := range results {
		if r.TopTier().AtLeast(failOn) {
			return 1
		}
	}
	return 0
}

func Human(results []model.Result) string {
	var b strings.Builder
	flagged := 0
	for _, r := range results {
		if r.Errored {
			fmt.Fprintf(&b, "[ERROR] %s@%s: could not evaluate — %s\n", r.Candidate.Name, r.Candidate.Version, r.ErrMsg)
			flagged++
			continue
		}
		if r.TopTier() == model.Clear {
			continue
		}
		flagged++
		fmt.Fprintf(&b, "[%s] %s@%s\n", r.TopTier(), r.Candidate.Name, r.Candidate.Version)
		for _, e := range r.Evidence {
			fmt.Fprintf(&b, "    - %s: %s\n", e.Signal, e.Explanation)
		}
	}
	if flagged == 0 {
		return "snare: no risky packages found in diff\n"
	}
	fmt.Fprintf(&b, "\nsnare: %d package(s) flagged\n", flagged)
	return b.String()
}

func JSON(results []model.Result) string {
	type jsonEvidence struct {
		Signal, Explanation, Locator, Tier string
	}
	type jsonResult struct {
		Name     string        `json:"name"`
		Version  string        `json:"version"`
		Tier     string        `json:"tier"`
		Errored  bool          `json:"errored"`
		ErrMsg   string        `json:"errMsg,omitempty"`
		Evidence []jsonEvidence `json:"evidence,omitempty"`
	}
	// JSON intentionally includes ALL results (full audit trail), not just flagged ones.
	var out []jsonResult
	for _, r := range results {
		jr := jsonResult{
			Name:    r.Candidate.Name,
			Version: r.Candidate.Version,
			Tier:    r.TopTier().String(),
			Errored: r.Errored,
			ErrMsg:  r.ErrMsg,
		}
		for _, e := range r.Evidence {
			jr.Evidence = append(jr.Evidence, jsonEvidence{e.Signal, e.Explanation, e.Locator, e.Tier.String()})
		}
		out = append(out, jr)
	}
	buf, _ := json.MarshalIndent(out, "", "  ")
	return string(buf)
}

// SARIF emits a minimal SARIF 2.1.0 log so GitHub code-scanning renders findings.
func SARIF(results []model.Result) string {
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	}
	var rs []sarifResult
	for _, r := range results {
		name, version := r.Candidate.Name, r.Candidate.Version
		if r.Errored {
			var sr sarifResult
			sr.RuleID = "snare.evaluation_error"
			sr.Level = "note"
			sr.Message.Text = fmt.Sprintf("%s@%s: could not evaluate — %s", name, version, r.ErrMsg)
			rs = append(rs, sr)
		}
		for _, e := range r.Evidence {
			var sr sarifResult
			sr.RuleID = e.Signal
			sr.Level = sarifLevel(e.Tier)
			sr.Message.Text = fmt.Sprintf("%s@%s: %s", name, version, e.Explanation)
			rs = append(rs, sr)
		}
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "snare", "rules": []any{}}},
			"results": rs,
		}},
	}
	buf, _ := json.MarshalIndent(doc, "", "  ")
	return string(buf)
}

func sarifLevel(t model.Tier) string {
	switch t {
	case model.Critical, model.High:
		return "error"
	case model.Medium:
		return "warning"
	default:
		return "note"
	}
}
