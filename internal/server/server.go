package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/psanford/tlsfingerprint/fingerprintlistener"
	"github.com/redis/go-redis/v9"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/logger"
	"github.com/muliwe/go-client-classifier/internal/metrics"
)

// RedisConfig holds Redis connection and key-prefix options. When REDIS_URL is set,
// the nonce challenge store is backed by Redis instead of in-memory; behavioral
// metrics are collected per IP and per __ch_nonce (see METHODOLOGY.md Appendix L).
// References: Redis rate-limiting patterns (Redis.io); BOTracle (Kadel et al., arXiv:2412.02266).
type RedisConfig struct {
	Client *redis.Client

	// ChallengePrefix is the key prefix for nonce→User-Agent entries (e.g. "ch" → "ch:nonce:<nonce>").
	ChallengePrefix string
	// MetricsPrefix is the key prefix for behavioral metrics sorted sets (e.g. "metrics").
	MetricsPrefix string
	// MetricsTTLSec is the TTL in seconds for metrics keys (e.g. 86400 for 24h for IP).
	MetricsTTLSec int
	// MetricsWindowSec is the sliding-window length in seconds for request counts (e.g. 60 or 300).
	// Aligns with inter-arrival and rate-based features (Cresci et al., Knowledge-Based Systems, 2021).
	MetricsWindowSec int
}

// redisPingerAdapter adapts *redis.Client to RedisPinger for /health. Startup does not fail if Redis is down.
type redisPingerAdapter struct{ client *redis.Client }

func (a redisPingerAdapter) Ping(ctx context.Context) error { return a.client.Ping(ctx).Err() }

// Config holds server configuration
type Config struct {
	Addr          string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	EnableDebug   bool
	LoggerConfig  logger.Config
	ClassifierCfg classifier.Config

	// Client Hints behavioral challenge (Appendix K)
	ChallengeEnabled bool          // if false, challenge store is nil and challenge is disabled
	ChallengeTTL     time.Duration // TTL for nonce→UA store; default 120s

	// Redis is set when REDIS_URL is configured; enables Redis-backed challenge store and metrics collection.
	Redis *RedisConfig

	// Behavioral edges and bot_scores for request_metrics-based signals (Appendix M). When set, ApplyBehavioralSignals is called before challenge.
	BehavioralEdges *classifier.BehavioralEdges
	BotScores       map[string]int

	// TLS configuration
	TLSEnabled  bool
	TLSAddr     string // HTTPS listen address (e.g. ":8443"); when set with TLSEnabled, HTTP stays on Addr and HTTPS on TLSAddr
	TLSCertFile string
	TLSKeyFile  string

	// ProxyProtocol enables PROXY protocol on the TLS listener (for nginx stream with proxy_protocol on → real client IP in logs).
	ProxyProtocol bool
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Addr:             ":8080",
		ReadTimeout:      5 * time.Second,
		WriteTimeout:     10 * time.Second,
		IdleTimeout:      120 * time.Second,
		EnableDebug:      true,
		LoggerConfig:     logger.DefaultConfig(),
		ClassifierCfg:    classifier.DefaultConfig(),
		ChallengeEnabled: true,
		ChallengeTTL:     120 * time.Second,
		TLSEnabled:       false,
	}
}

// serverTLSConfig returns a permissive TLS config: accept TLS 1.0+ and all ALPN
// protocols we can handle (including legacy/spdy/h2c/hq). Goal: accept connections
// and classify as bot from fingerprint, not reject at handshake.
func serverTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		NextProtos: []string{
			"h2", "http/1.1",
			"http/1.0", "http/0.9",
			"spdy/3", "spdy/2", "spdy/1",
			"h2c", "hq",
		},
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
	var challengeStore ChallengeStore
	if cfg.ChallengeEnabled {
		ttl := cfg.ChallengeTTL
		if ttl <= 0 {
			ttl = 120 * time.Second
		}
		// When REDIS_URL is set, the nonce challenge store is backed by Redis instead of in-memory.
		if cfg.Redis != nil && cfg.Redis.Client != nil {
			prefix := cfg.Redis.ChallengePrefix
			if prefix == "" {
				prefix = "ch"
			}
			challengeStore = NewRedisChallengeStore(cfg.Redis.Client, prefix, ttl)
		} else {
			challengeStore = NewChallengeStore(ttl)
		}
	}
	var redisPinger RedisPinger
	var metricsCollector *metrics.Collector
	if cfg.Redis != nil && cfg.Redis.Client != nil {
		redisPinger = redisPingerAdapter{client: cfg.Redis.Client}
		prefix := cfg.Redis.MetricsPrefix
		if prefix == "" {
			prefix = "metrics"
		}
		windowSec := cfg.Redis.MetricsWindowSec
		if windowSec <= 0 {
			windowSec = 300
		}
		ipTTL := 24 * time.Hour
		if cfg.Redis.MetricsTTLSec > 0 {
			ipTTL = time.Duration(cfg.Redis.MetricsTTLSec) * time.Second
		}
		// Nonce metrics TTL synced with challenge store and cookie: same as ChallengeTTL so behavioral window for nonce matches cookie lifetime.
		nonceTTL := cfg.ChallengeTTL
		if nonceTTL <= 0 {
			nonceTTL = 120 * time.Second
		}
		metricsCollector = metrics.NewCollector(cfg.Redis.Client, metrics.CollectorConfig{
			Prefix:    prefix,
			WindowSec: windowSec,
			IPTTL:     ipTTL,
			NonceTTL:  nonceTTL,
		})
	}
	cookieMaxAgeSec := 120
	if cfg.ChallengeTTL > 0 {
		cookieMaxAgeSec = int(cfg.ChallengeTTL.Seconds())
	}
	handler := NewHandler(HandlerOptions{
		Collector:                collector,
		Classifier:               clf,
		Logger:                   l,
		ChallengeStore:           challengeStore,
		RedisPinger:              redisPinger,
		MetricsCollector:         metricsCollector,
		ChallengeCookieMaxAgeSec: cookieMaxAgeSec,
		BehavioralEdges:          cfg.BehavioralEdges,
		BotScores:                cfg.BotScores,
	})

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
			TLSConfig:    serverTLSConfig(),
			ConnContext:  connContextWithTLSFingerprint,
		}
	} else if cfg.TLSEnabled {
		// TLS-only mode (single listener on Addr)
		httpServer.TLSConfig = serverTLSConfig()
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
	listener := net.Listener(tcpListener)
	if s.cfg.ProxyProtocol {
		listener = &proxyproto.Listener{
			Listener:          tcpListener,
			ReadHeaderTimeout: 10 * time.Second,
		}
		log.Printf("PROXY protocol enabled on %s (real client IP from nginx stream)", s.cfg.TLSAddr)
	}
	fpListener := fingerprintlistener.NewListener(listener)
	// Wrap so Accept() errors from a single connection (EOF, reset) don't kill Serve()
	s.listener = &acceptRetryListener{inner: fpListener}
	cfg := serverTLSConfig().Clone()
	cfg.Certificates = []tls.Certificate{cert}
	s.tlsServer.TLSConfig = cfg
	log.Printf("TLS fingerprinting active (JA3/JA4) on %s", s.cfg.TLSAddr)
	return s.tlsServer.ServeTLS(s.listener, "", "")
}

// acceptRetryListener wraps a net.Listener so that the TLS server never exits on its own:
// only net.ErrClosed (listener closed at shutdown) is returned; all other errors are
// logged and Accept() is retried. This covers EOF, connection reset, timeouts, PROXY
// parse errors, and any other per-connection or transient failure from the chain
// (fingerprintlistener, proxyproto, etc.).
type acceptRetryListener struct {
	inner net.Listener
}

func (l *acceptRetryListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err == nil {
			return conn, nil
		}
		if errors.Is(err, net.ErrClosed) {
			return nil, err
		}
		// Any other error: do not propagate (would exit http.Serve). Log and retry.
		if isAcceptTransient(err) {
			log.Printf("TLS Accept: transient error, retrying: %v", err)
		} else {
			log.Printf("TLS Accept: error (retrying to keep listener up): %v", err)
			time.Sleep(time.Second) // avoid tight loop on persistent unknown errors
		}
		continue
	}
}

func (l *acceptRetryListener) Close() error   { return l.inner.Close() }
func (l *acceptRetryListener) Addr() net.Addr { return l.inner.Addr() }

// isAcceptTransient returns true for errors that are clearly per-connection (no sleep).
func isAcceptTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "connection aborted")
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
	cfg := serverTLSConfig().Clone()
	cfg.Certificates = []tls.Certificate{cert}
	s.httpServer.TLSConfig = cfg

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
