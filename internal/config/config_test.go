package config

import "testing"

func TestAllowlistMatches(t *testing.T) {
	al, err := ParseAllowlist([]byte("# comment\nleft-pad@1.3.0 known-good\nfoo@*  internal\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !al.Allowed("left-pad", "1.3.0") {
		t.Error("left-pad@1.3.0 should be allowed")
	}
	if al.Allowed("left-pad", "1.4.0") {
		t.Error("left-pad@1.4.0 should NOT be allowed (version-specific)")
	}
	if !al.Allowed("foo", "9.9.9") {
		t.Error("foo@* should allow any version")
	}
}
