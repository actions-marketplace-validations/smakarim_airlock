package config

import "testing"

func TestAllowlistMissingReason(t *testing.T) {
	if _, err := ParseAllowlist([]byte("left-pad@1.3.0\n")); err == nil {
		t.Error("expected error for entry missing a reason")
	}
}

func TestAllowlistBadEntry(t *testing.T) {
	if _, err := ParseAllowlist([]byte("noatsign reason\n")); err == nil {
		t.Error("expected error for entry with no @")
	}
}

func TestAllowlistEmptyVersion(t *testing.T) {
	if _, err := ParseAllowlist([]byte("pkg@ reason\n")); err == nil {
		t.Error("expected error for entry with empty version")
	}
}

func TestAllowlistScopedPackage(t *testing.T) {
	al, err := ParseAllowlist([]byte("@scope/pkg@1.0.0 reviewed\n@other/x@* internal\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !al.Allowed("@scope/pkg", "1.0.0") {
		t.Error("@scope/pkg@1.0.0 should be allowed")
	}
	if al.Allowed("@scope/pkg", "2.0.0") {
		t.Error("@scope/pkg@2.0.0 should NOT be allowed")
	}
	if !al.Allowed("@other/x", "9.9.9") {
		t.Error("@other/x@* should allow any version")
	}
}

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
