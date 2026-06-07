package engine

import (
	"testing"

	"github.com/smakarim/airlock/internal/model"
)

func TestHookSignalFlagsInstallHooks(t *testing.T) {
	p := model.PackageData{Scripts: map[string]string{"postinstall": "node x.js"}}
	ev := HookSignal{}.Evaluate(p)
	if len(ev) == 0 || ev[0].Signal != "hook.lifecycle" {
		t.Fatalf("expected hook.lifecycle evidence, got %v", ev)
	}
}

func TestHookSignalSilentWithoutHooks(t *testing.T) {
	if ev := (HookSignal{}).Evaluate(model.PackageData{}); len(ev) != 0 {
		t.Errorf("no hooks should mean no evidence, got %v", ev)
	}
}
