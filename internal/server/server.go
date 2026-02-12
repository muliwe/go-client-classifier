package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/psanford/tlsfingerprint/fingerprintlistener"

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

	// TLS configuration
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
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
		TLSEnabled:    false,
	}
}

// Server represents the HTTP server
type Server struct {
	cfg        Config
	httpServer *http.Server
	handler    *Handler
	logger     *logger.Logger
	listener   net.Listener
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

	// Configure TLS if enabled
	if cfg.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"}, // Enable HTTP/2
		}
		httpServer.TLSConfig = tlsConfig

		// Set ConnContext to inject TLS fingerprint into request context
		// The connection is wrapped: tls.Conn -> fingerprintlistener.Conn -> net.Conn
		// We need to unwrap tls.Conn first to get the fingerprint connection
		httpServer.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			// Unwrap TLS connection to get the underlying fingerprint connection
			if tlsConn, ok := c.(*tls.Conn); ok {
				c = tlsConn.NetConn()
			}

			if fpConn, ok := c.(fingerprintlistener.Conn); ok {
				fp := fpConn.Fingerprint()
				if fp != nil {
					return TLSFingerprintToContext(ctx, fp)
				}
			}
			return ctx
		}
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
		protocol := "HTTP"
		if s.cfg.TLSEnabled {
			protocol = "HTTPS (TLS fingerprinting enabled)"
		}
		log.Printf("Bot Detector Server starting on %s (%s)", s.cfg.Addr, protocol)
		log.Printf("Endpoints: / (classify), /health (health check)")
		if s.cfg.EnableDebug {
			log.Printf("Debug endpoint enabled: /debug")
		}
		log.Printf("Logs: %s", s.logger.LogPath())

		var err error
		if s.cfg.TLSEnabled {
			log.Printf("TLS Certificate: %s", s.cfg.TLSCertFile)
			err = s.startTLS()
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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

	if s.listener != nil {
		_ = s.listener.Close()
	}

	if err := s.logger.Close(); err != nil {
		log.Printf("Error closing logger: %v", err)
	}

	log.Println("Server stopped")
	return nil
}

// startTLS starts the server with TLS and fingerprint listener
func (s *Server) startTLS() error {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Create base TCP listener
	tcpListener, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}

	// Wrap with fingerprint listener to capture ClientHello
	fpListener := fingerprintlistener.NewListener(tcpListener)
	s.listener = fpListener

	// Configure TLS on the http.Server (not on listener)
	// This way ServeTLS wraps the connection, but we can unwrap in ConnContext
	s.httpServer.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	log.Printf("TLS fingerprinting active (JA3/JA4)")
	// Use ServeTLS which handles TLS on top of our fingerprint listener
	return s.httpServer.ServeTLS(fpListener, "", "")
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
