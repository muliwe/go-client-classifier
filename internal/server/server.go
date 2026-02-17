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
	TLSAddr     string // HTTPS listen address (e.g. ":8443"); when set with TLSEnabled, HTTP stays on Addr and HTTPS on TLSAddr
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

// Server represents the HTTP server (and optional HTTPS server when TLSAddr is set)
type Server struct {
	cfg        Config
	httpServer *http.Server
	tlsServer  *http.Server
	handler    *Handler
	logger     *logger.Logger
	listener   net.Listener // TLS listener (for shutdown in dual or TLS-only mode)
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

	var tlsServer *http.Server
	if cfg.TLSEnabled && cfg.TLSAddr != "" {
		// Dual mode: HTTP on Addr, HTTPS on TLSAddr
		tlsServer = &http.Server{
			Addr:         cfg.TLSAddr,
			Handler:      mux,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2", "http/1.1"},
			},
			ConnContext: connContextWithTLSFingerprint,
		}
	} else if cfg.TLSEnabled {
		// TLS-only mode (single listener on Addr)
		httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"}, // Enable HTTP/2
		}
		httpServer.ConnContext = connContextWithTLSFingerprint
	}

	return &Server{
		cfg:        cfg,
		httpServer: httpServer,
		tlsServer:  tlsServer,
		handler:    handler,
		logger:     l,
	}, nil
}

func connContextWithTLSFingerprint(ctx context.Context, c net.Conn) context.Context {
	if tlsConn, ok := c.(*tls.Conn); ok {
		c = tlsConn.NetConn()
	}
	if fpConn, ok := c.(fingerprintlistener.Conn); ok {
		if fp := fpConn.Fingerprint(); fp != nil {
			return TLSFingerprintToContext(ctx, fp)
		}
	}
	return ctx
}

// Start starts the server and blocks until shutdown
func (s *Server) Start() error {
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	if s.tlsServer != nil {
		// Dual mode: HTTP on Addr, HTTPS on TLSAddr
		log.Printf("Bot Detector Server starting: HTTP %s, HTTPS %s (TLS fingerprinting)", s.cfg.Addr, s.cfg.TLSAddr)
		log.Printf("Endpoints: / (classify), /health (health check)")
		if s.cfg.EnableDebug {
			log.Printf("Debug endpoint enabled: /debug")
		}
		log.Printf("Logs: %s", s.logger.LogPath())
		log.Printf("TLS Certificate: %s", s.cfg.TLSCertFile)

		go func() {
			if err := s.runHTTP(); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		}()
		go func() {
			if err := s.runTLS(); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTPS server error: %v", err)
			}
		}()
	} else {
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
			if s.cfg.TLSEnabled {
				log.Printf("TLS Certificate: %s", s.cfg.TLSCertFile)
			}

			var err error
			if s.cfg.TLSEnabled {
				err = s.startTLS()
			} else {
				err = s.httpServer.ListenAndServe()
			}
			if err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
		}()
	}

	<-done
	log.Println("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("HTTP server shutdown failed: %w", err)
	}
	if s.tlsServer != nil {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		if err := s.tlsServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("HTTPS server shutdown failed: %w", err)
		}
	} else if s.listener != nil {
		_ = s.listener.Close()
	}

	if err := s.logger.Close(); err != nil {
		log.Printf("Error closing logger: %v", err)
	}

	log.Println("Server stopped")
	return nil
}

func (s *Server) runHTTP() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) runTLS() error {
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	tcpListener, err := net.Listen("tcp", s.cfg.TLSAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.TLSAddr, err)
	}
	fpListener := fingerprintlistener.NewListener(tcpListener)
	s.listener = fpListener
	s.tlsServer.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	log.Printf("TLS fingerprinting active (JA3/JA4) on %s", s.cfg.TLSAddr)
	return s.tlsServer.ServeTLS(fpListener, "", "")
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
