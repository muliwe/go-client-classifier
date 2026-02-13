package server

import (
	"testing"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

// Tests are in tests/unit/server_test.go
// This file exists to satisfy go test ./... discovery

func TestServerPackage(t *testing.T) {
	// Verify package is testable
	collector := fingerprint.NewCollector()
	cls := classifier.New(classifier.DefaultConfig())
	h := NewHandler(collector, cls, nil)
	if h == nil {
		t.Error("NewHandler should not return nil")
	}
}
