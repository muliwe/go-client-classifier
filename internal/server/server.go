package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/logger"
)

// Config holds server configuration
type Config struct {
	Addr          string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	EnableDebug   bool
	LoggerConfig  logger.Config
	ClassifierCfg classifier.Config
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Addr:          ":8080",
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  10 * time.Second,
		IdleTimeout:   120 * time.Second,
		EnableDebug:   true,
		LoggerConfig:  logger.DefaultConfig(),
		ClassifierCfg: classifier.DefaultConfig(),
	}
}

// Server represents the HTTP server
type Server struct {
	cfg        Config
	httpServer *http.Server
	handler    *Handler
	logger     *logger.Logger
}

// New creates a new server instance
func New(cfg Config) (*Server, error) {
	// Initialize logger
	l, err := logger.New(cfg.LoggerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize components
	collector := fingerprint.NewCollector()
	clf := classifier.New(cfg.ClassifierCfg)
	handler := NewHandler(collector, clf, l)

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler.HandleClassify)
	mux.HandleFunc("/health", handler.HandleHealth)
	if cfg.EnableDebug {
		mux.HandleFunc("/debug", handler.HandleDebug)
	}

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return &Server{
		cfg:        cfg,
		httpServer: httpServer,
		handler:    handler,
		logger:     l,
	}, nil
}

// Start starts the server and blocks until shutdown
func (s *Server) Start() error {
	// Setup graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Bot Detector Server starting on %s", s.cfg.Addr)
		log.Printf("Endpoints: / (classify), /health (health check)")
		if s.cfg.EnableDebug {
			log.Printf("Debug endpoint enabled: /debug")
		}
		log.Printf("Logs: %s", s.logger.LogPath())

		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-done
	log.Println("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	if err := s.logger.Close(); err != nil {
		log.Printf("Error closing logger: %v", err)
	}

	log.Println("Server stopped")
	return nil
}

// Close gracefully shuts down the server
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	return s.logger.Close()
}
