package logger

import "testing"

// Tests are in tests/unit/logger_test.go
// This file exists to satisfy go test ./... discovery

func TestLoggerPackage(t *testing.T) {
	// Verify package is testable
	cfg := DefaultConfig()
	if cfg.LogDir != "logs" {
		t.Error("DefaultConfig should have LogDir=logs")
	}
}
