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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestValidate(t *testing.T) {
	for i, tc := range []struct {
		name    string
		handler Handler
		wantErr bool
	}{
		{
			name:    "zero concurrency",
			handler: Handler{},
			wantErr: true,
		},
		{
			name:    "negative queue",
			handler: Handler{MaxConcurrency: 1, QueueSize: -1},
			wantErr: true,
		},
		{
			name:    "negative timeout",
			handler: Handler{MaxConcurrency: 1, QueueTimeout: caddy.Duration(-time.Second)},
			wantErr: true,
		},
		{
			name:    "invalid exempt path",
			handler: Handler{MaxConcurrency: 1, ExemptPaths: []string{"healthz"}},
			wantErr: true,
		},
		{
			name:    "valid",
			handler: Handler{MaxConcurrency: 1, QueueSize: 2},
		},
	} {
		err := tc.handler.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("Test %d (%s): expected an error, got nil", i, tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
		}
	}
}

func TestSlowUpstreamRejectsAtThreshold(t *testing.T) {
	handler := newTestHandler(t, 1, 0, 0)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
		return nil
	})

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/slow", nil), next)
	}()
	<-entered

	rec := httptest.NewRecorder()
	start := time.Now()
	err := handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/slow", nil), next)
	if err != nil {
		t.Fatalf("rejection returned an error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("rejection took %s, want an immediate response", elapsed)
	}
	assertRejection(t, rec, rejectReasonOverloaded)

	stats := handler.Stats()
	if stats.RejectedOverload != 1 {
		t.Fatalf("rejected overload = %d, want 1", stats.RejectedOverload)
	}
	if stats.Admitted != 1 {
		t.Fatalf("admitted = %d, want 1", stats.Admitted)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request failed: %v", err)
	}
}

func TestQueueFullRejectsWithoutBlocking(t *testing.T) {
	handler := newTestHandler(t, 1, 1, time.Second)
	release := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		<-release
		w.WriteHeader(http.StatusOK)
		return nil
	})

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
	}()
	waitFor(t, func() bool { return handler.Stats().Active == 1 })

	queuedDone := make(chan error, 1)
	go func() {
		queuedDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
	}()
	waitFor(t, func() bool { return handler.Stats().Queued == 1 })

	rec := httptest.NewRecorder()
	err := handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
	if err != nil {
		t.Fatalf("queue overflow returned an error: %v", err)
	}
	assertRejection(t, rec, rejectReasonOverloaded)

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if err := <-queuedDone; err != nil {
		t.Fatalf("queued request failed: %v", err)
	}
	if stats := handler.Stats(); stats.RejectedOverload != 1 {
		t.Fatalf("rejected overload = %d, want 1", stats.RejectedOverload)
	}
}

func TestQueueTimeout(t *testing.T) {
	handler := newTestHandler(t, 1, 1, 20*time.Millisecond)
	release := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		<-release
		w.WriteHeader(http.StatusOK)
		return nil
	})

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
	}()
	waitFor(t, func() bool { return handler.Stats().Active == 1 })

	rec := httptest.NewRecorder()
	start := time.Now()
	err := handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
	if err != nil {
		t.Fatalf("queue timeout returned an error: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Fatalf("queue attempt returned after %s, want it to wait for the timeout", elapsed)
	}
	assertRejection(t, rec, rejectReasonQueueTimeout)

	if stats := handler.Stats(); stats.RejectedQueueTimeout != 1 || stats.Queued != 0 {
		t.Fatalf("unexpected stats after timeout: %+v", stats)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request failed: %v", err)
	}
}

func TestRecoveryDrainsFIFOWithoutExceedingLimit(t *testing.T) {
	const (
		maxConcurrency = 2
		queueSize      = 3
	)

	handler := newTestHandler(t, maxConcurrency, queueSize, 5*time.Second)
	started := make(chan string, maxConcurrency+queueSize)
	finishMu := new(sync.Mutex)
	finishChannels := make(map[string]chan struct{}, maxConcurrency+queueSize)
	active := atomic.Int64{}
	maxActive := atomic.Int64{}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		id := r.Header.Get("X-Test-ID")
		current := active.Add(1)
		for {
			observed := maxActive.Load()
			if current <= observed || maxActive.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- id
		finishMu.Lock()
		finish := finishChannels[id]
		finishMu.Unlock()
		<-finish
		active.Add(-1)
		w.WriteHeader(http.StatusOK)
		return nil
	})
	finishRequest := func(id string) {
		t.Helper()
		finishMu.Lock()
		finish := finishChannels[id]
		finishMu.Unlock()
		if finish == nil {
			t.Fatalf("request %q has not started", id)
		}
		close(finish)
	}

	type result struct {
		id  string
		err error
	}
	results := make(chan result, maxConcurrency+queueSize)
	launch := func(id string) {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			req.Header.Set("X-Test-ID", id)
			finishMu.Lock()
			finishChannels[id] = make(chan struct{})
			finishMu.Unlock()
			results <- result{
				id:  id,
				err: handler.ServeHTTP(httptest.NewRecorder(), req, next),
			}
		}()
	}
	waitStarted := func(want string) {
		t.Helper()
		select {
		case got := <-started:
			if got != want {
				t.Fatalf("started request %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for request %q to start", want)
		}
	}

	launch("0")
	waitStarted("0")
	launch("1")
	waitStarted("1")

	for i, id := range []string{"2", "3", "4"} {
		launch(id)
		wantQueued := int64(i + 1)
		waitFor(t, func() bool { return handler.Stats().Queued == wantQueued })
	}

	for _, id := range []string{"0", "1", "2", "3", "4"} {
		finishRequest(id)
		if id == "0" || id == "1" || id == "2" {
			waitStarted(nextRequestID(id))
		}
	}

	for range maxConcurrency + queueSize {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("request %q failed: %v", result.id, result.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for recovery to drain")
		}
	}

	if got := maxActive.Load(); got > maxConcurrency {
		t.Fatalf("maximum concurrent handlers = %d, want at most %d", got, maxConcurrency)
	}
	if stats := handler.Stats(); stats.Active != 0 || stats.Queued != 0 {
		t.Fatalf("limiter did not drain: %+v", stats)
	}
}

func TestStreamingReleasesSlotAtFirstByte(t *testing.T) {
	handler := newTestHandler(t, 1, 0, 0)
	firstByte := make(chan struct{})
	releaseStream := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if r.URL.Path == "/stream" {
			close(firstByte)
			<-releaseStream
		}
		_, err := io.WriteString(w, "ok")
		return err
	})

	streamDone := make(chan error, 1)
	go func() {
		streamDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/stream", nil), next)
	}()
	<-firstByte

	rec := httptest.NewRecorder()
	err := handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/normal", nil), next)
	if err != nil {
		t.Fatalf("request after first byte failed: %v", err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("second response = %d %q, want 200 %q", rec.Code, rec.Body.String(), "ok")
	}
	if stats := handler.Stats(); stats.Active != 0 {
		t.Fatalf("active slots after streaming first byte = %d, want 0", stats.Active)
	}

	close(releaseStream)
	if err := <-streamDone; err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
}

func TestUpgradeReleasesSlotAtSwitchingProtocols(t *testing.T) {
	handler := newTestHandler(t, 1, 0, 0)
	upgraded := make(chan struct{})
	releaseUpgrade := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.URL.Path == "/upgrade" {
			w.WriteHeader(http.StatusSwitchingProtocols)
			close(upgraded)
			<-releaseUpgrade
			return nil
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	upgradeDone := make(chan error, 1)
	go func() {
		upgradeDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/upgrade", nil), next)
	}()
	<-upgraded

	rec := httptest.NewRecorder()
	if err := handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/normal", nil), next); err != nil {
		t.Fatalf("request after upgrade failed: %v", err)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("second response = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if stats := handler.Stats(); stats.Active != 0 {
		t.Fatalf("active slots while upgraded connection is open = %d, want 0", stats.Active)
	}

	close(releaseUpgrade)
	if err := <-upgradeDone; err != nil {
		t.Fatalf("upgrade request failed: %v", err)
	}
}

func TestHealthCheckBypassesSaturation(t *testing.T) {
	handler := newTestHandler(t, 1, 0, 0)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
		return nil
	})

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/slow", nil), next)
	}()
	<-entered

	rec := httptest.NewRecorder()
	err := handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/healthz", nil), next)
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("health status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if stats := handler.Stats(); stats.HealthBypassed != 1 {
		t.Fatalf("health bypass count = %d, want 1", stats.HealthBypassed)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("slow request failed: %v", err)
	}
}

func TestCleanupReleasesQueuedWaiters(t *testing.T) {
	handler := newTestHandler(t, 1, 2, time.Minute)
	release := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		<-release
		w.WriteHeader(http.StatusOK)
		return nil
	})

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
	}()
	waitFor(t, func() bool { return handler.Stats().Active == 1 })

	queuedDone := make([]chan error, 0, 2)
	queuedRecorders := make([]*httptest.ResponseRecorder, 0, 2)
	for range 2 {
		done := make(chan error, 1)
		rec := httptest.NewRecorder()
		queuedDone = append(queuedDone, done)
		queuedRecorders = append(queuedRecorders, rec)
		go func() {
			done <- handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
		}()
		waitFor(t, func() bool { return handler.Stats().Queued > 0 })
	}
	waitFor(t, func() bool { return handler.Stats().Queued == 2 })

	if err := handler.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	waitFor(t, func() bool { return handler.Stats().RejectedShuttingDown == 2 })
	if stats := handler.Stats(); stats.Queued != 0 {
		t.Fatalf("queued after cleanup = %d, want 0", stats.Queued)
	}
	for i, done := range queuedDone {
		if err := <-done; err != nil {
			t.Fatalf("queued request %d returned an error during cleanup: %v", i, err)
		}
		assertRejection(t, queuedRecorders[i], rejectReasonShuttingDown)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("active request failed: %v", err)
	}
}

func TestRejectionAndUpstreamTimeoutMetricsAreDistinct(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	handler := &Handler{MaxConcurrency: 1}
	if err := handler.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	t.Cleanup(func() { _ = handler.Cleanup() })

	release := make(chan struct{})
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		<-release
		w.WriteHeader(http.StatusOK)
		return nil
	})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
	}()
	waitFor(t, func() bool { return handler.Stats().Active == 1 })

	rec := httptest.NewRecorder()
	if err := handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next); err != nil {
		t.Fatalf("rejection returned an error: %v", err)
	}
	assertRejection(t, rec, rejectReasonOverloaded)
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	timeoutNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusGatewayTimeout, os.ErrDeadlineExceeded)
	})
	err := handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), timeoutNext)
	if err == nil {
		t.Fatal("expected the upstream timeout error to propagate")
	}

	stats := handler.Stats()
	if stats.RejectedOverload != 1 {
		t.Fatalf("backpressure rejections = %d, want 1", stats.RejectedOverload)
	}
	if stats.UpstreamTimeouts != 1 {
		t.Fatalf("upstream timeouts = %d, want 1", stats.UpstreamTimeouts)
	}

	families, err := ctx.GetMetricsRegistry().Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	if got := counterValue(t, families, "caddy_http_backpressure_rejected_total", "reason", rejectReasonOverloaded); got != 1 {
		t.Fatalf("overload metric = %v, want 1", got)
	}
	if got := counterValue(t, families, "caddy_http_backpressure_rejected_total", "reason", rejectReasonQueueTimeout); got != 0 {
		t.Fatalf("queue timeout metric = %v, want 0", got)
	}
	if got := counterValue(t, families, "caddy_http_backpressure_upstream_timeouts_total"); got != 1 {
		t.Fatalf("upstream timeout metric = %v, want 1", got)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	handler := new(Handler)
	input := `backpressure {
		max_concurrency 7
		queue_size 3
		queue_timeout 250ms
		exempt /health /internal/ready
	}`
	if err := handler.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("unmarshaling Caddyfile: %v", err)
	}
	if handler.MaxConcurrency != 7 || handler.QueueSize != 3 {
		t.Fatalf("unexpected limiter config: %+v", handler)
	}
	if handler.QueueTimeout != caddy.Duration(250*time.Millisecond) {
		t.Fatalf("queue timeout = %v, want 250ms", handler.QueueTimeout)
	}
	if strings.Join(handler.ExemptPaths, ",") != "/health,/internal/ready" {
		t.Fatalf("exempt paths = %v", handler.ExemptPaths)
	}
	if err := handler.Validate(); err != nil {
		t.Fatalf("parsed config is invalid: %v", err)
	}
}

func TestCaddyfileAdaptation(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter is not registered")
	}
	result, _, err := adapter.Adapt([]byte(`
:9080 {
	backpressure {
		max_concurrency 7
		queue_size 3
		queue_timeout 250ms
	}
	respond "ok"
}
`), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}
	if !strings.Contains(string(result), `"handler":"backpressure"`) {
		t.Fatalf("adapted config does not contain backpressure handler: %s", result)
	}
	if !strings.Contains(string(result), `"max_concurrency":7`) {
		t.Fatalf("adapted config does not contain max_concurrency: %s", result)
	}
}

func TestConcurrentAdmissionInvariants(t *testing.T) {
	handler := newTestHandler(t, 4, 8, 5*time.Millisecond)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		time.Sleep(time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	const requests = 200
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(ctx)
			if i%3 == 0 {
				timer := time.AfterFunc(2*time.Millisecond, cancel)
				defer timer.Stop()
			}
			defer cancel()
			_ = handler.ServeHTTP(httptest.NewRecorder(), req, next)
		}()
	}
	wg.Wait()
	waitFor(t, func() bool {
		stats := handler.Stats()
		return stats.Active == 0 && stats.Queued == 0
	})

	stats := handler.Stats()
	if stats.Admitted != stats.Completed {
		t.Fatalf("admitted = %d, completed = %d; admission slot leaked", stats.Admitted, stats.Completed)
	}
	if stats.Active != 0 || stats.Queued != 0 {
		t.Fatalf("limiter retained state after load: %+v", stats)
	}
}

func newTestHandler(t *testing.T, maxConcurrency, queueSize int, queueTimeout time.Duration) *Handler {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	handler := &Handler{
		MaxConcurrency: maxConcurrency,
		QueueSize:      queueSize,
		QueueTimeout:   caddy.Duration(queueTimeout),
	}
	if err := handler.Provision(ctx); err != nil {
		t.Fatalf("provisioning handler: %v", err)
	}
	t.Cleanup(func() { _ = handler.Cleanup() })
	return handler
}

func assertRejection(t *testing.T, rec *httptest.ResponseRecorder, reason string) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got := rec.Header().Get(rejectHeader); got != "rejected" {
		t.Fatalf("%s = %q, want %q", rejectHeader, got, "rejected")
	}
	if got := rec.Header().Get(rejectReasonHeader); got != reason {
		t.Fatalf("%s = %q, want %q", rejectReasonHeader, got, reason)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want %q", got, "1")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not met before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func nextRequestID(id string) string {
	switch id {
	case "0":
		return "2"
	case "1":
		return "3"
	case "2":
		return "4"
	default:
		return ""
	}
}

func counterValue(t *testing.T, families []*dto.MetricFamily, name string, label ...string) float64 {
	t.Helper()
	var labelName, labelValue string
	if len(label) == 2 {
		labelName, labelValue = label[0], label[1]
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if labelName == "" {
				return metric.GetCounter().GetValue()
			}
			for _, label := range metric.GetLabel() {
				if label.GetName() == labelName && label.GetValue() == labelValue {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("metric %s with %s=%s not found", name, labelName, labelValue)
	return 0
}
