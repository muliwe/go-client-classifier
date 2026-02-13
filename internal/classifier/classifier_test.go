package classifier

import "testing"

// Tests are in tests/unit/classifier_test.go
// This file exists to satisfy go test ./... discovery

func TestClassifierPackage(t *testing.T) {
	// Verify package is testable
	cfg := DefaultConfig()
	if cfg.Threshold != 0 {
		t.Error("DefaultConfig should have Threshold=0")
	}
}
