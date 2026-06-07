package report

import (
	"strings"
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

func sampleResults() []model.Result {
	return []model.Result{{
		Candidate: model.Candidate{Name: "reqeusts", Version: "0.0.1"},
		Evidence: []model.Evidence{{
			Signal: "name.typosquat", Tier: model.High,
			Explanation: "name is 2 edit(s) from popular package \"requests\"", Locator: "name",
		}},
	}}
}

func TestExitCodeAtThreshold(t *testing.T) {
	if code := ExitCode(sampleResults(), model.High); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if code := ExitCode(sampleResults(), model.Critical); code != 0 {
		t.Errorf("below threshold should exit 0, got %d", code)
	}
}

func TestHumanReportMentionsPackageAndReason(t *testing.T) {
	out := Human(sampleResults())
	if !strings.Contains(out, "reqeusts@0.0.1") || !strings.Contains(out, "HIGH") {
		t.Errorf("human report missing package or tier:\n%s", out)
	}
}

func TestJSONReportIsValid(t *testing.T) {
	out := JSON(sampleResults())
	if !strings.Contains(out, `"name.typosquat"`) {
		t.Errorf("json missing signal:\n%s", out)
	}
}

func TestSARIFHasRuleAndResult(t *testing.T) {
	out := SARIF(sampleResults())
	if !strings.Contains(out, `"ruleId"`) || !strings.Contains(out, "name.typosquat") {
		t.Errorf("sarif missing ruleId/result:\n%s", out)
	}
}
