package unit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/logger"
)

func TestLoggerDefaultConfig(t *testing.T) {
	cfg := logger.DefaultConfig()

	if cfg.LogDir != "logs" {
		t.Errorf("DefaultConfig().LogDir = %q, want %q", cfg.LogDir, "logs")
	}
	if cfg.FileName != "requests.jsonl" {
		t.Errorf("DefaultConfig().FileName = %q, want %q", cfg.FileName, "requests.jsonl")
	}
	if cfg.Stdout != false {
		t.Error("DefaultConfig().Stdout should be false")
	}
}

func TestLoggerNew(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := logger.Config{
		LogDir:   tmpDir,
		FileName: "test.jsonl",
		Stdout:   false,
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = l.Close() }()

	if l == nil {
		t.Fatal("New() returned nil")
	}

	// Check file was created
	logPath := filepath.Join(tmpDir, "test.jsonl")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Errorf("Log file was not created at %s", logPath)
	}
}

func TestLoggerNew_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "logs")

	cfg := logger.Config{
		LogDir:   nestedDir,
		FileName: "test.jsonl",
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = l.Close() }()

	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("New() should create nested directories")
	}
}

func TestLoggerLog(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := logger.Config{
		LogDir:   tmpDir,
		FileName: "test.jsonl",
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	entry := logger.LogEntry{
		Timestamp:      time.Now().UTC(),
		RequestID:      "test-123",
		RemoteAddr:     "127.0.0.1:12345",
		Classification: "bot",
		Confidence:     0.95,
		Score:          -5,
		Reason:         "test reason",
		ResponseTimeMs: 10,
	}

	if err := l.Log(entry); err != nil {
		t.Errorf("Log() error = %v", err)
	}

	if err := l.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Read and verify log file
	data, err := os.ReadFile(filepath.Join(tmpDir, "test.jsonl"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var logged logger.LogEntry
	if err := json.Unmarshal(data, &logged); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if logged.RequestID != "test-123" {
		t.Errorf("Logged RequestID = %q, want %q", logged.RequestID, "test-123")
	}
	if logged.Classification != "bot" {
		t.Errorf("Logged Classification = %q, want %q", logged.Classification, "bot")
	}
}

func TestLoggerLogResult(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := logger.Config{
		LogDir:   tmpDir,
		FileName: "test.jsonl",
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := fingerprint.ClassificationResult{
		RequestID:      "result-456",
		Timestamp:      time.Now().UTC(),
		Classification: "browser",
		Confidence:     0.99,
		Score:          15,
		Reason:         "browser indicators",
	}

	if err := l.LogResult(result, "192.168.1.1:54321", 5); err != nil {
		t.Errorf("LogResult() error = %v", err)
	}

	if err := l.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "test.jsonl"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var logged logger.LogEntry
	if err := json.Unmarshal(data, &logged); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if logged.RequestID != "result-456" {
		t.Errorf("Logged RequestID = %q, want %q", logged.RequestID, "result-456")
	}
	if logged.RemoteAddr != "192.168.1.1:54321" {
		t.Errorf("Logged RemoteAddr = %q, want %q", logged.RemoteAddr, "192.168.1.1:54321")
	}
}

func TestLoggerLogPath(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := logger.Config{
		LogDir:   tmpDir,
		FileName: "test.jsonl",
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = l.Close() }()

	path := l.LogPath()
	if !strings.HasSuffix(path, "test.jsonl") {
		t.Errorf("LogPath() = %q, should end with test.jsonl", path)
	}
}

func TestLoggerClose(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := logger.Config{
		LogDir:   tmpDir,
		FileName: "test.jsonl",
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := l.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}
