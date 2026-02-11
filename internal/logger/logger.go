package logger

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/muliwe/go-client-slassifier/internal/fingerprint"
)

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp      time.Time               `json:"timestamp"`
	RequestID      string                  `json:"request_id"`
	RemoteAddr     string                  `json:"remote_addr"`
	Classification string                  `json:"classification"`
	Confidence     float64                 `json:"confidence"`
	Fingerprint    fingerprint.Fingerprint `json:"fingerprint"`
	Signals        fingerprint.Signals     `json:"signals"`
	Score          int                     `json:"score"`
	Reason         string                  `json:"reason"`
	ResponseTimeMs int64                   `json:"response_time_ms"`
}

// Logger handles structured JSON logging
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	writers []io.Writer
}

// Config holds logger configuration
type Config struct {
	LogDir   string // Directory for log files
	FileName string // Log file name (default: requests.jsonl)
	Stdout   bool   // Also write to stdout
}

// DefaultConfig returns default logger configuration
func DefaultConfig() Config {
	return Config{
		LogDir:   "logs",
		FileName: "requests.jsonl",
		Stdout:   false,
	}
}

// New creates a new logger instance
func New(cfg Config) (*Logger, error) {
	// Ensure log directory exists
	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return nil, err
	}

	// Open log file in append mode
	logPath := filepath.Join(cfg.LogDir, cfg.FileName)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	writers := []io.Writer{file}
	if cfg.Stdout {
		writers = append(writers, os.Stdout)
	}

	// Create multi-writer if needed
	var writer io.Writer
	if len(writers) == 1 {
		writer = writers[0]
	} else {
		writer = io.MultiWriter(writers...)
	}

	return &Logger{
		file:    file,
		encoder: json.NewEncoder(writer),
		writers: writers,
	}, nil
}

// Log writes a classification result to the log
func (l *Logger) Log(entry LogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.encoder.Encode(entry)
}

// LogResult logs a ClassificationResult with additional metadata
func (l *Logger) LogResult(result fingerprint.ClassificationResult, remoteAddr string, responseTimeMs int64) error {
	entry := LogEntry{
		Timestamp:      result.Timestamp,
		RequestID:      result.RequestID,
		RemoteAddr:     remoteAddr,
		Classification: result.Classification,
		Confidence:     result.Confidence,
		Fingerprint:    result.Fingerprint,
		Signals:        result.Signals,
		Score:          result.Score,
		Reason:         result.Reason,
		ResponseTimeMs: responseTimeMs,
	}
	return l.Log(entry)
}

// Close closes the logger
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// LogPath returns the path to the log file
func (l *Logger) LogPath() string {
	if l.file != nil {
		return l.file.Name()
	}
	return ""
}
