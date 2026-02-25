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
	"github.com/muliwe/go-client-classifier/internal/metrics"
)

func TestLoggerDefaultConfig(t *testing.T) {
	cfg := logger.DefaultConfig()

	if cfg.LogDir != "logs" {
		t.Errorf("DefaultConfig().LogDir = %q, want %q", cfg.LogDir, "logs")
	}
	if cfg.FileName != "requests.jsonl" {
		t.Errorf("DefaultConfig().FileName = %q, want %q", cfg.FileName, "requests.jsonl")
	}
	if cfg.Daily != true {
		t.Error("DefaultConfig().Daily should be true")
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
		Daily:    false,
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
		Daily:    false,
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

	if err := l.LogResult(result, "192.168.1.1:54321", 5, nil, nil); err != nil {
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
	// When challenge_state and request_metrics are nil, they must be omitted (omitempty)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}
	if _, ok := raw["challenge_state"]; ok {
		t.Error("challenge_state should be omitted when nil")
	}
	if _, ok := raw["request_metrics"]; ok {
		t.Error("request_metrics should be omitted when nil")
	}
}

// TestLoggerLogResult_withChallengeState verifies challenge_state is written to JSONL when non-nil (parity with /debug).
func TestLoggerLogResult_withChallengeState(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := logger.Config{LogDir: tmpDir, FileName: "test.jsonl", Daily: false}
	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	challengeState := map[string]interface{}{
		"ja4h_hash":   "ge11cn29ruru_519069e5ca79_240160034d89_bf55df7f5c1e",
		"nonce_c_d":   "240160034d89_bf55df7f5c1e",
		"empty_nonce": false,
		"in_store":    false,
		"expired":     false,
		"enabled":     true,
	}
	result := fingerprint.ClassificationResult{
		RequestID: "req-cs", Timestamp: time.Now().UTC(),
		Classification: "browser", Confidence: 0.99, Score: 10, Reason: "test",
	}
	if err := l.LogResult(result, "10.0.0.1", 3, challengeState, nil); err != nil {
		t.Fatalf("LogResult: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "test.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := raw["challenge_state"]; !ok {
		t.Fatal("challenge_state must be present in JSONL when set")
	}
	var cs map[string]interface{}
	if err := json.Unmarshal(raw["challenge_state"], &cs); err != nil {
		t.Fatalf("Unmarshal challenge_state: %v", err)
	}
	if v, _ := cs["enabled"].(bool); !v {
		t.Errorf("challenge_state.enabled = %v, want true", cs["enabled"])
	}
	if v, _ := cs["nonce_c_d"].(string); v != "240160034d89_bf55df7f5c1e" {
		t.Errorf("challenge_state.nonce_c_d = %q", v)
	}
}

// TestLoggerLogResult_withRequestMetrics verifies request_metrics is written to JSONL when non-nil (parity with /debug).
func TestLoggerLogResult_withRequestMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := logger.Config{LogDir: tmpDir, FileName: "test.jsonl", Daily: false}
	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	requestMetrics := &metrics.RequestMetrics{
		WindowSec:       300,
		IP:              "192.168.1.1",
		IPRequestCount:  5,
		IPRequestAgoSec: []float64{0, 1.5, 3.2},
		IPDerived: &metrics.DerivedStats{
			RequestRatePerMin:     2.5,
			InterArrivalMedianSec: 1.5,
			InterArrivalMeanSec:   1.8,
		},
	}
	result := fingerprint.ClassificationResult{
		RequestID: "req-rm", Timestamp: time.Now().UTC(),
		Classification: "bot", Confidence: 0.9, Score: -4, Reason: "test",
	}
	if err := l.LogResult(result, "192.168.1.1", 12, nil, requestMetrics); err != nil {
		t.Fatalf("LogResult: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "test.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var logged logger.LogEntry
	if err := json.Unmarshal(data, &logged); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if logged.RequestMetrics == nil {
		t.Fatal("request_metrics must be present in JSONL when set")
	}
	if logged.RequestMetrics.WindowSec != 300 || logged.RequestMetrics.IP != "192.168.1.1" {
		t.Errorf("request_metrics: window_sec=%d ip=%q", logged.RequestMetrics.WindowSec, logged.RequestMetrics.IP)
	}
	if logged.RequestMetrics.IPRequestCount != 5 || len(logged.RequestMetrics.IPRequestAgoSec) != 3 {
		t.Errorf("request_metrics: ip_request_count=%d len(ip_request_ago_sec)=%d", logged.RequestMetrics.IPRequestCount, len(logged.RequestMetrics.IPRequestAgoSec))
	}
	if logged.RequestMetrics.IPDerived == nil || logged.RequestMetrics.IPDerived.RequestRatePerMin != 2.5 {
		t.Errorf("request_metrics.ip_derived: %v", logged.RequestMetrics.IPDerived)
	}
}

// TestLoggerLogResult_withBoth verifies challenge_state and request_metrics are both written when both set (full /debug parity).
func TestLoggerLogResult_withBoth(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := logger.Config{LogDir: tmpDir, FileName: "test.jsonl", Daily: false}
	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	challengeState := map[string]interface{}{"enabled": true, "in_store": true}
	requestMetrics := &metrics.RequestMetrics{WindowSec: 60, IP: "127.0.0.1", IPRequestCount: 1}
	result := fingerprint.ClassificationResult{
		RequestID: "req-both", Timestamp: time.Now().UTC(),
		Classification: "browser", Confidence: 1.0, Score: 2, Reason: "ok",
	}
	if err := l.LogResult(result, "127.0.0.1", 1, challengeState, requestMetrics); err != nil {
		t.Fatalf("LogResult: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, "test.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := raw["challenge_state"]; !ok {
		t.Error("challenge_state must be present")
	}
	if _, ok := raw["request_metrics"]; !ok {
		t.Error("request_metrics must be present")
	}
	var logged logger.LogEntry
	if err := json.Unmarshal(data, &logged); err != nil {
		t.Fatalf("Unmarshal LogEntry: %v", err)
	}
	if logged.RequestMetrics == nil || logged.RequestMetrics.WindowSec != 60 {
		t.Errorf("request_metrics: %v", logged.RequestMetrics)
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
		Daily:    false,
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := l.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestLoggerDailyFileName(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := logger.Config{
		LogDir: tmpDir,
		Daily:  true,
	}

	l, err := logger.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = l.Close() }()

	path := l.LogPath()
	expectedSuffix := "requests_" + time.Now().UTC().Format("20060102") + ".jsonl"
	if !strings.HasSuffix(path, expectedSuffix) {
		t.Errorf("LogPath() = %q, should end with %q", path, expectedSuffix)
	}

	// File should exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("Daily log file was not created at %s", path)
	}
}
