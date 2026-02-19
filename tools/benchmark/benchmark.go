// Package main provides a simple HTTP benchmark tool
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// runBenchmark runs the benchmark against targetURL for the given duration.
// It returns the number of successful requests and the number of errors.
func runBenchmark(targetURL string, duration time.Duration, concurrency int, insecure bool) (requests, errors int64) {
	fmt.Printf("Benchmarking %s\n", targetURL)
	fmt.Printf("Duration: %v, Concurrency: %d\n\n", duration, concurrency)

	tr := &http.Transport{
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: concurrency * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	var (
		totalRequests int64
		totalErrors   int64
		totalLatency  int64 // in microseconds
		minLatency    int64 = 1<<63 - 1
		maxLatency    int64
		wg            sync.WaitGroup
		stop          = make(chan struct{})
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					start := time.Now()
					resp, err := client.Get(targetURL)
					latency := time.Since(start).Microseconds()

					if err != nil {
						atomic.AddInt64(&totalErrors, 1)
					} else {
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()

						if resp.StatusCode == http.StatusOK {
							atomic.AddInt64(&totalRequests, 1)
							atomic.AddInt64(&totalLatency, latency)

							for {
								old := atomic.LoadInt64(&minLatency)
								if latency >= old || atomic.CompareAndSwapInt64(&minLatency, old, latency) {
									break
								}
							}
							for {
								old := atomic.LoadInt64(&maxLatency)
								if latency <= old || atomic.CompareAndSwapInt64(&maxLatency, old, latency) {
									break
								}
							}
						} else {
							atomic.AddInt64(&totalErrors, 1)
						}
					}
				}
			}
		}()
	}

	ticker := time.NewTicker(time.Second)
	go func() {
		elapsed := 0
		for range ticker.C {
			elapsed++
			reqs := atomic.LoadInt64(&totalRequests)
			errs := atomic.LoadInt64(&totalErrors)
			fmt.Printf("[%ds] Requests: %d, Errors: %d, RPS: %.0f\n",
				elapsed, reqs, errs, float64(reqs)/float64(elapsed))
		}
	}()

	time.Sleep(duration)
	close(stop)
	ticker.Stop()
	wg.Wait()

	reqs := atomic.LoadInt64(&totalRequests)
	errs := atomic.LoadInt64(&totalErrors)
	latencyTotal := atomic.LoadInt64(&totalLatency)
	minLat := atomic.LoadInt64(&minLatency)
	maxLat := atomic.LoadInt64(&maxLatency)

	avgLatency := float64(0)
	if reqs > 0 {
		avgLatency = float64(latencyTotal) / float64(reqs)
	}

	rps := float64(reqs) / duration.Seconds()
	rpm := rps * 60

	fmt.Println("\n========== RESULTS ==========")
	fmt.Printf("Total requests:  %d\n", reqs)
	fmt.Printf("Total errors:    %d\n", errs)
	fmt.Printf("Duration:        %v\n", duration)
	fmt.Printf("Concurrency:     %d\n", concurrency)
	fmt.Println()
	fmt.Printf("RPS:             %.2f\n", rps)
	fmt.Printf("RPM:             %.0f\n", rpm)
	fmt.Println()
	fmt.Printf("Latency avg:     %.2f µs (%.3f ms)\n", avgLatency, avgLatency/1000)
	fmt.Printf("Latency min:     %d µs (%.3f ms)\n", minLat, float64(minLat)/1000)
	fmt.Printf("Latency max:     %d µs (%.3f ms)\n", maxLat, float64(maxLat)/1000)

	return reqs, errs
}

func main() {
	url := flag.String("url", "http://localhost:8080/", "Target URL")
	duration := flag.Duration("duration", 10*time.Second, "Test duration")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	flag.Parse()

	_, errs := runBenchmark(*url, *duration, *concurrency, *insecure)
	if errs > 0 {
		os.Exit(1)
	}
}
