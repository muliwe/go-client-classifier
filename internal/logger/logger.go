package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/muliwe/go-client-classifier/internal/fingerprint"
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
	mu          sync.Mutex
	file        *os.File
	encoder     *json.Encoder
	writers     []io.Writer
	cfg         Config
	currentDate string // YYYYMMDD for daily rotation
}

// Config holds logger configuration
type Config struct {
	LogDir   string // Directory for log files
	FileName string // Log file name when Daily is false (default: requests.jsonl)
	Daily    bool   // If true, write to requests_YYYYMMDD.jsonl and rotate by day (default: true)
	Stdout   bool   // Also write to stdout
}

// DefaultConfig returns default logger configuration.
// By default logs are written to requests_YYYYMMDD.jsonl (one file per day).
func DefaultConfig() Config {
	return Config{
		LogDir:   "logs",
		FileName: "requests.jsonl",
		Daily:    true,
		Stdout:   false,
	}
}

// logPath returns the path for the given date (YYYYMMDD). When cfg.Daily is false, date is ignored.
func (cfg Config) logPath(date string) string {
	if cfg.Daily {
		return filepath.Join(cfg.LogDir, fmt.Sprintf("requests_%s.jsonl", date))
	}
	return filepath.Join(cfg.LogDir, cfg.FileName)
}

// New creates a new logger instance
func New(cfg Config) (*Logger, error) {
	// Ensure log directory exists
	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return nil, err
	}

	date := time.Now().UTC().Format("20060102")
	logPath := cfg.logPath(date)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	writers := []io.Writer{file}
	if cfg.Stdout {
		writers = append(writers, os.Stdout)
	}

	var writer io.Writer
	if len(writers) == 1 {
		writer = writers[0]
	} else {
		writer = io.MultiWriter(writers...)
	}

	return &Logger{
		file:        file,
		encoder:     json.NewEncoder(writer),
		writers:     writers,
		cfg:         cfg,
		currentDate: date,
	}, nil
}

// rotate closes the current file and opens a new one for the current date (daily rotation).
// Caller must hold l.mu.
func (l *Logger) rotate() error {
	if !l.cfg.Daily || l.file == nil {
		return nil
	}
	today := time.Now().UTC().Format("20060102")
	if today == l.currentDate {
		return nil
	}
	_ = l.file.Close()
	l.file = nil

	l.currentDate = today
	logPath := l.cfg.logPath(today)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	l.file = file
	writers := []io.Writer{file}
	if l.cfg.Stdout {
		writers = append(writers, os.Stdout)
	}
	var writer io.Writer
	if len(writers) == 1 {
		writer = writers[0]
	} else {
		writer = io.MultiWriter(writers...)
	}
	l.encoder = json.NewEncoder(writer)
	l.writers = writers
	return nil
}

// Log writes a classification result to the log
func (l *Logger) Log(entry LogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.cfg.Daily {
		if err := l.rotate(); err != nil {
			return err
		}
	}
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

// LogPath returns the path to the current log file
func (l *Logger) LogPath() string {
	if l.file != nil {
		return l.file.Name()
	}
	if l.cfg.Daily && l.currentDate != "" {
		return l.cfg.logPath(l.currentDate)
	}
	return l.cfg.logPath(time.Now().UTC().Format("20060102"))
}
