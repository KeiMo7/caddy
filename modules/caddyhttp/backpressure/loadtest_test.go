// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backpressure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestLoadComparison runs a reproducible, same-process load comparison when
// CADDY_BACKPRESSURE_LOADTEST=1 is set. It is skipped by default because it
// intentionally saturates the machine and produces timing-sensitive data.
func TestLoadComparison(t *testing.T) {
	if os.Getenv("CADDY_BACKPRESSURE_LOADTEST") != "1" {
		t.Skip("set CADDY_BACKPRESSURE_LOADTEST=1 to run the load comparison")
	}
	if testing.Short() {
		t.Skip("skipping load comparison in short mode")
	}

	const (
		upstreamLatency   = 100 * time.Millisecond
		requestsPerWorker = 4
		maxConcurrency    = 16
		queueSize         = 32
		queueTimeout      = 50 * time.Millisecond
	)

	gradients := []int{16, 64, 256}
	results := make([]loadResult, 0, len(gradients)*2)

	for _, concurrency := range gradients {
		for _, enabled := range []bool{false, true} {
			results = append(results, runLoadChild(t, loadScenario{
				Concurrency:        concurrency,
				RequestsPerWorker:  requestsPerWorker,
				UpstreamLatencyMS:  upstreamLatency.Milliseconds(),
				Backpressure:       enabled,
				MaxConcurrency:     maxConcurrency,
				QueueSize:          queueSize,
				QueueTimeoutMS:     queueTimeout.Milliseconds(),
				UpstreamWorkingSet: 512 << 10,
			}))
		}
	}

	t.Log("\n" + formatLoadResults(results))
	if outputPath := os.Getenv("CADDY_BACKPRESSURE_LOADTEST_OUT"); outputPath != "" {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			t.Fatalf("marshaling load results: %v", err)
		}
		if err := os.WriteFile(outputPath, append(data, '\n'), 0o600); err != nil {
			t.Fatalf("writing load results: %v", err)
		}
	}
}

// TestLoadScenarioWorker runs exactly one scenario in a fresh process so RSS
// measurements are not polluted by earlier scenarios.
func TestLoadScenarioWorker(t *testing.T) {
	if os.Getenv("CADDY_BACKPRESSURE_LOAD_WORKER") != "1" {
		t.Skip("load scenario worker is started by TestLoadComparison")
	}

	var scenario loadScenario
	if err := json.Unmarshal([]byte(os.Getenv("CADDY_BACKPRESSURE_LOAD_SCENARIO")), &scenario); err != nil {
		t.Fatalf("decoding load scenario: %v", err)
	}
	result := runLoadScenario(t, scenario)
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshaling load result: %v", err)
	}
	if err := os.WriteFile(os.Getenv("CADDY_BACKPRESSURE_LOAD_RESULT"), data, 0o600); err != nil {
		t.Fatalf("writing load result: %v", err)
	}
}

type loadScenario struct {
	Concurrency        int   `json:"concurrency"`
	RequestsPerWorker  int   `json:"requests_per_worker"`
	UpstreamLatencyMS  int64 `json:"upstream_latency_ms"`
	Backpressure       bool  `json:"backpressure"`
	MaxConcurrency     int   `json:"max_concurrency"`
	QueueSize          int   `json:"queue_size"`
	QueueTimeoutMS     int64 `json:"queue_timeout_ms"`
	UpstreamWorkingSet int   `json:"upstream_working_set"`
}

type loadResult struct {
	Concurrency        int     `json:"concurrency"`
	Backpressure       bool    `json:"backpressure"`
	Requests           int64   `json:"requests"`
	Rejected           int64   `json:"rejected"`
	RejectedRatio      float64 `json:"rejected_ratio"`
	Failed             int64   `json:"failed"`
	PeakConnections    int64   `json:"peak_connections"`
	PeakInflight       int64   `json:"peak_inflight"`
	HeapPeakMiB        float64 `json:"heap_peak_mib"`
	RSSPeakMiB         float64 `json:"rss_peak_mib,omitempty"`
	DurationMS         int64   `json:"duration_ms"`
	UpstreamWorkingSet int     `json:"upstream_working_set"`
}

func runLoadChild(t *testing.T, scenario loadScenario) loadResult {
	t.Helper()

	scenarioJSON, err := json.Marshal(scenario)
	if err != nil {
		t.Fatalf("marshaling load scenario: %v", err)
	}
	resultFile, err := os.CreateTemp(t.TempDir(), "backpressure-load-result-*.json")
	if err != nil {
		t.Fatalf("creating load result file: %v", err)
	}
	resultPath := resultFile.Name()
	if err := resultFile.Close(); err != nil {
		t.Fatalf("closing load result file: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLoadScenarioWorker$")
	cmd.Env = append(os.Environ(),
		"CADDY_BACKPRESSURE_LOAD_WORKER=1",
		"CADDY_BACKPRESSURE_LOAD_SCENARIO="+string(scenarioJSON),
		"CADDY_BACKPRESSURE_LOAD_RESULT="+resultPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load worker failed for concurrency %d, backpressure=%t: %v\n%s", scenario.Concurrency, scenario.Backpressure, err, output)
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("reading load result: %v", err)
	}
	var result loadResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decoding load result: %v", err)
	}
	return result
}

func runLoadScenario(t *testing.T, scenario loadScenario) loadResult {
	t.Helper()

	upstreamLatency := time.Duration(scenario.UpstreamLatencyMS) * time.Millisecond
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workingSet := make([]byte, scenario.UpstreamWorkingSet)
		if len(workingSet) > 0 {
			workingSet[0] = 1
			workingSet[len(workingSet)-1] = 1
		}
		time.Sleep(upstreamLatency)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
		runtime.KeepAlive(workingSet)
	})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		upstream.ServeHTTP(w, r)
		return nil
	})

	var handler *Handler
	if scenario.Backpressure {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		defer cancel()
		handler = &Handler{
			MaxConcurrency: scenario.MaxConcurrency,
			QueueSize:      scenario.QueueSize,
			QueueTimeout:   caddy.Duration(time.Duration(scenario.QueueTimeoutMS) * time.Millisecond),
		}
		if err := handler.Provision(ctx); err != nil {
			t.Fatalf("provisioning backpressure handler: %v", err)
		}
		defer handler.Cleanup()
	}

	var (
		peakConnections atomic.Int64
		peakInflight    atomic.Int64
		inflight        atomic.Int64
		openConnections atomic.Int64
	)
	updatePeakInt64(&peakConnections, openConnections.Load())

	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := inflight.Add(1)
		updatePeakInt64(&peakInflight, current)
		defer inflight.Add(-1)

		recorder := &loadResponseWriter{ResponseWriter: w}
		var err error
		if handler != nil {
			err = handler.ServeHTTP(recorder, r, next)
		} else {
			err = next.ServeHTTP(recorder, r)
		}
		if err != nil {
			http.Error(recorder, err.Error(), http.StatusInternalServerError)
		}
		recorder.finish()
	}))
	front.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			updatePeakInt64(&peakConnections, openConnections.Add(1))
		case http.StateClosed, http.StateHijacked:
			openConnections.Add(-1)
		}
	}
	front.Start()
	defer front.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			MaxConnsPerHost:   scenario.Concurrency,
		},
		Timeout: 10 * time.Second,
	}
	defer client.CloseIdleConnections()

	runtime.GC()

	stopSampling := make(chan struct{})
	samplingDone := make(chan struct{})
	var heapPeakMiB, rssPeakMiB atomic.Uint64
	sampleMemory(&heapPeakMiB, &rssPeakMiB)
	go func() {
		defer close(samplingDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sampleMemory(&heapPeakMiB, &rssPeakMiB)
			case <-stopSampling:
				sampleMemory(&heapPeakMiB, &rssPeakMiB)
				return
			}
		}
	}()

	var (
		totalRequests atomic.Int64
		rejected      atomic.Int64
		failed        atomic.Int64
		wg            sync.WaitGroup
	)
	start := time.Now()
	for range scenario.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range scenario.RequestsPerWorker {
				totalRequests.Add(1)
				res, err := client.Get(front.URL)
				if err != nil {
					failed.Add(1)
					continue
				}
				_, readErr := io.Copy(io.Discard, res.Body)
				closeErr := res.Body.Close()
				if readErr != nil || closeErr != nil {
					failed.Add(1)
					continue
				}
				if res.StatusCode == http.StatusServiceUnavailable &&
					res.Header.Get(rejectHeader) == "rejected" {
					rejected.Add(1)
				} else if res.StatusCode >= http.StatusInternalServerError {
					failed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	duration := time.Since(start)
	close(stopSampling)
	<-samplingDone

	requests := totalRequests.Load()
	rejectedRequests := rejected.Load()
	return loadResult{
		Concurrency:        scenario.Concurrency,
		Backpressure:       scenario.Backpressure,
		Requests:           requests,
		Rejected:           rejectedRequests,
		RejectedRatio:      float64(rejectedRequests) / float64(requests),
		Failed:             failed.Load(),
		PeakConnections:    peakConnections.Load(),
		PeakInflight:       peakInflight.Load(),
		HeapPeakMiB:        float64(heapPeakMiB.Load()) / (1 << 20),
		RSSPeakMiB:         float64(rssPeakMiB.Load()) / (1 << 20),
		DurationMS:         duration.Milliseconds(),
		UpstreamWorkingSet: scenario.UpstreamWorkingSet,
	}
}

func sampleMemory(heapPeakMiB, rssPeakMiB *atomic.Uint64) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	updatePeakUint64(heapPeakMiB, stats.HeapAlloc)
	if rss, ok := currentRSS(); ok {
		updatePeakUint64(rssPeakMiB, rss)
	}
}

func updatePeakUint64(peak *atomic.Uint64, value uint64) {
	for {
		observed := peak.Load()
		if value <= observed || peak.CompareAndSwap(observed, value) {
			return
		}
	}
}

func updatePeakInt64(peak *atomic.Int64, value int64) {
	for {
		observed := peak.Load()
		if value <= observed || peak.CompareAndSwap(observed, value) {
			return
		}
	}
}

func currentRSS() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}

func formatLoadResults(results []loadResult) string {
	var out strings.Builder
	out.WriteString("concurrency  mode        requests  rejected  reject%  peak_conns  peak_inflight  heap_peak_MiB  rss_peak_MiB  duration_ms\n")
	for _, result := range results {
		mode := "disabled"
		if result.Backpressure {
			mode = "enabled"
		}
		fmt.Fprintf(
			&out,
			"%11d  %-10s  %8d  %8d  %7.2f%%  %10d  %13d  %13.2f  %12.2f  %11d\n",
			result.Concurrency,
			mode,
			result.Requests,
			result.Rejected,
			result.RejectedRatio*100,
			result.PeakConnections,
			result.PeakInflight,
			result.HeapPeakMiB,
			result.RSSPeakMiB,
			result.DurationMS,
		)
	}
	return out.String()
}

type loadResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *loadResponseWriter) WriteHeader(statusCode int) {
	if w.status == 0 {
		w.status = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *loadResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *loadResponseWriter) finish() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
}
