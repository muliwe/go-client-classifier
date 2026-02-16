package unit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	// Stub JA4DB path and forbid download so tests never hit the network
	_ = os.Setenv("JA4DB_SKIP_DOWNLOAD", "1")
	dir, _ := os.Getwd()
	for dir != "" && dir != string(filepath.Separator) {
		stub := filepath.Join(dir, "testdata", "ja4db_fixture.json")
		if _, err := os.Stat(stub); err == nil {
			_ = os.Setenv("JA4DB_PATH", stub)
			break
		}
		dir = filepath.Dir(dir)
	}
	os.Exit(m.Run())
}
