package fingerprint

import "testing"

// Tests are in tests/unit/ja4h_test.go and tests/unit/signals_test.go
// This file exists to satisfy go test ./... discovery

func TestFingerprintPackage(t *testing.T) {
	// Verify package is testable
	c := NewCollector()
	if c == nil {
		t.Error("NewCollector should not return nil")
	}
}
