package resolver

import (
	"reflect"
	"sort"
	"testing"

	"github.com/syedkarim/snare/internal/model"
)

const baseLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/react": {"version": "18.2.0"}
  }
}`

const headLock = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/react": {"version": "18.3.0"},
    "node_modules/reqeusts": {"version": "0.0.1"}
  }
}`

func TestDiffAddedAndBumped(t *testing.T) {
	got, err := Diff([]byte(baseLock), []byte(headLock))
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	want := []model.Candidate{
		{Name: "react", Version: "18.3.0"},   // bumped
		{Name: "reqeusts", Version: "0.0.1"}, // added (typosquat of requests)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Diff = %#v, want %#v", got, want)
	}
}

func TestDiffUnchangedIsEmpty(t *testing.T) {
	got, err := Diff([]byte(baseLock), []byte(baseLock))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected no candidates, got %#v", got)
	}
}

func TestDiffBadJSON(t *testing.T) {
	if _, err := Diff([]byte("{"), []byte(headLock)); err == nil {
		t.Error("expected error on malformed base lockfile")
	}
	if _, err := Diff([]byte(baseLock), []byte("{")); err == nil {
		t.Error("expected error on malformed head lockfile")
	}
}
