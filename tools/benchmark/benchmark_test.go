package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunBenchmark_usesGivenURL(t *testing.T) {
	var requestCount atomic.Int64
	var lastPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		lastPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	targetURL := server.URL + "/custom/route"
	duration := 80 * time.Millisecond
	concurrency := 3

	requests, errors := runBenchmark(targetURL, duration, concurrency, false)

	if errors > 0 {
		t.Errorf("expected no errors, got %d", errors)
	}
	if requests == 0 {
		t.Errorf("expected at least one request, got 0")
	}
	if lastPath != "/custom/route" {
		t.Errorf("benchmark should hit given path: got %q", lastPath)
	}
	gotCount := requestCount.Load()
	if gotCount != requests {
		t.Errorf("server request count %d != reported requests %d", gotCount, requests)
	}
}

func TestRunBenchmark_differentPaths(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Benchmark /health
	requests, _ := runBenchmark(server.URL+"/health", 50*time.Millisecond, 2, false)
	if requests == 0 {
		t.Error("expected requests to /health")
	}
	mu.Lock()
	gotPaths := paths
	mu.Unlock()
	if len(gotPaths) == 0 {
		t.Fatal("server received no requests")
	}
	for _, p := range gotPaths {
		if p != "/health" {
			t.Errorf("expected path /health, got %q", p)
		}
	}
}
