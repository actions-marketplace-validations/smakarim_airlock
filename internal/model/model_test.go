package model

import "testing"

func TestTierAtLeast(t *testing.T) {
	if !High.AtLeast(Medium) {
		t.Error("High should be >= Medium")
	}
	if Low.AtLeast(High) {
		t.Error("Low should not be >= High")
	}
}

func TestResultTopTier(t *testing.T) {
	r := Result{Evidence: []Evidence{{Tier: Low}, {Tier: High}, {Tier: Medium}}}
	if got := r.TopTier(); got != High {
		t.Errorf("TopTier = %v, want High", got)
	}
}

func TestResultTopTierEmpty(t *testing.T) {
	r := Result{}
	if got := r.TopTier(); got != Clear {
		t.Errorf("empty TopTier = %v, want Clear", got)
	}
}
