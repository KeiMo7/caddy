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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	rejectHeader       = "X-Caddy-Backpressure"
	rejectReasonHeader = "X-Caddy-Backpressure-Reason"

	rejectReasonOverloaded   = "overloaded"
	rejectReasonQueueTimeout = "queue-timeout"
	rejectReasonShuttingDown = "shutting-down"
)

// defaultQueueTimeout is applied when queuing is enabled without an explicit
// timeout. It prevents waiters from occupying queue positions forever.
const defaultQueueTimeout = time.Second

// defaultExemptPaths keeps common health and readiness endpoints available
// even while the route is saturated.
var defaultExemptPaths = []string{
	"/health",
	"/healthz",
	"/healthcheck",
	"/live",
	"/livez",
	"/ready",
	"/readyz",
	"/_health",
	"/_healthz",
}

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler provides admission control for slow upstream-backed routes.
//
// A request occupies an admission slot until the first final response byte,
// or until the downstream handler returns without writing a response. This
// means long-lived streaming response bodies do not hold admission slots for
// their entire transfer. Requests that cannot acquire a slot enter a bounded
// FIFO queue when QueueSize is non-zero, or are rejected immediately.
//
// The module is inactive unless explicitly configured in the route. Health
// and readiness paths are exempt by default so probes continue to work while
// the route is saturated.
type Handler struct {
	// Maximum number of concurrent requests allowed to wait for the first
	// response byte. Must be greater than zero when this handler is configured.
	MaxConcurrency int `json:"max_concurrency,omitempty"`

	// Maximum number of requests allowed to wait for an admission slot.
	// Zero rejects overflow immediately instead of queuing.
	QueueSize int `json:"queue_size,omitempty"`

	// Maximum time a request may spend waiting in the queue. If queuing is
	// enabled and this is zero, it defaults to one second.
	QueueTimeout caddy.Duration `json:"queue_timeout,omitempty"`

	// Paths which bypass admission control. A path matches itself and all
	// of its descendants. Common health and readiness paths are exempt by
	// default.
	ExemptPaths []string `json:"exempt_paths,omitempty"`

	state   *handlerState
	metrics *metricsCollector
}

type handlerState struct {
	owner        *Handler
	queueSize    int
	queueTimeout time.Duration
	exemptPaths  []string
	tokens       chan struct{}

	mu      sync.Mutex
	waiters []*waiter
	closed  atomic.Bool

	stats handlerStats
}

type handlerStats struct {
	active               atomic.Int64
	queued               atomic.Int64
	admitted             atomic.Uint64
	completed            atomic.Uint64
	rejectedOverload     atomic.Uint64
	rejectedQueueTimeout atomic.Uint64
	rejectedShuttingDown atomic.Uint64
	queueCanceled        atomic.Uint64
	healthBypassed       atomic.Uint64
	upstreamTimeouts     atomic.Uint64
}

// Stats is a point-in-time snapshot of a backpressure handler's counters.
// Reading a snapshot does not lock the request path.
type Stats struct {
	Active               int64
	Queued               int64
	Admitted             uint64
	Completed            uint64
	RejectedOverload     uint64
	RejectedQueueTimeout uint64
	RejectedShuttingDown uint64
	QueueCanceled        uint64
	HealthBypassed       uint64
	UpstreamTimeouts     uint64
}

type waiterState uint32

const (
	waiterWaiting waiterState = iota
	waiterAdmitted
	waiterCanceled
)

type waiterCancelReason uint32

const (
	waiterCancelTimeout waiterCancelReason = iota
	waiterCancelShutdown
	waiterCancelClient
)

type waiter struct {
	ready  chan struct{}
	state  atomic.Uint32
	reason atomic.Uint32
}

type admission struct {
	handler *Handler
	once    sync.Once
}

func (a *admission) release() {
	if a == nil {
		return
	}
	a.once.Do(a.handler.release)
}

type admissionOutcome uint8

const (
	outcomeAdmitted admissionOutcome = iota
	outcomeOverloaded
	outcomeQueueTimeout
	outcomeShuttingDown
	outcomeClientCanceled
)

type firstByteWriter struct {
	*caddyhttp.ResponseWriterWrapper
	admission *admission
}

func (w *firstByteWriter) WriteHeader(statusCode int) {
	w.ResponseWriterWrapper.WriteHeader(statusCode)
	if statusCode < 100 || statusCode >= 200 || statusCode == http.StatusSwitchingProtocols {
		w.admission.release()
	}
}

func (w *firstByteWriter) Write(p []byte) (int, error) {
	w.admission.release()
	return w.ResponseWriterWrapper.Write(p)
}

func (w *firstByteWriter) ReadFrom(r io.Reader) (int64, error) {
	w.admission.release()
	return w.ResponseWriterWrapper.ReadFrom(r)
}

func (w *firstByteWriter) Flush() {
	w.admission.release()
	//nolint:bodyclose
	_ = http.NewResponseController(w.ResponseWriterWrapper).Flush()
}

func (w *firstByteWriter) FlushError() error {
	w.admission.release()
	//nolint:bodyclose
	return http.NewResponseController(w.ResponseWriterWrapper).Flush()
}

func (w *firstByteWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.admission.release()
	//nolint:bodyclose
	return http.NewResponseController(w.ResponseWriterWrapper).Hijack()
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.backpressure",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision prepares the admission limiter and metrics for h.
func (h *Handler) Provision(ctx caddy.Context) error {
	if err := h.Validate(); err != nil {
		return err
	}

	state := &handlerState{
		owner:        h,
		queueSize:    h.QueueSize,
		queueTimeout: time.Duration(h.QueueTimeout),
		exemptPaths:  h.ExemptPaths,
		tokens:       make(chan struct{}, h.MaxConcurrency),
	}
	if h.QueueSize > 0 && state.queueTimeout == 0 {
		state.queueTimeout = defaultQueueTimeout
	}
	if len(state.exemptPaths) == 0 {
		state.exemptPaths = defaultExemptPaths
	}
	state.exemptPaths = normalizeExemptPaths(state.exemptPaths)
	h.state = state

	h.metrics = newMetricsCollector(h)
	if err := ctx.GetMetricsRegistry().Register(h.metrics); err != nil {
		return fmt.Errorf("registering backpressure metrics: %w", err)
	}
	return nil
}

// Validate checks the admission limiter configuration.
func (h Handler) Validate() error {
	if h.MaxConcurrency <= 0 {
		return fmt.Errorf("max_concurrency must be greater than zero")
	}
	if h.QueueSize < 0 {
		return fmt.Errorf("queue_size must not be negative")
	}
	if h.QueueTimeout < 0 {
		return fmt.Errorf("queue_timeout must not be negative")
	}
	for _, exemptPath := range h.ExemptPaths {
		if exemptPath == "" || !strings.HasPrefix(exemptPath, "/") {
			return fmt.Errorf("exempt path %q must start with '/'", exemptPath)
		}
	}
	return nil
}

// Cleanup releases queued waiters and stops admitting new requests.
func (h *Handler) Cleanup() error {
	if h == nil || h.state == nil {
		return nil
	}
	state := h.state
	state.closed.Store(true)

	state.mu.Lock()
	waiters := state.waiters
	state.waiters = nil

	var canceled int64
	for _, w := range waiters {
		w.reason.Store(uint32(waiterCancelShutdown))
		if waiterState(w.state.Load()) == waiterWaiting && w.state.CompareAndSwap(uint32(waiterWaiting), uint32(waiterCanceled)) {
			canceled++
			w.ready <- struct{}{}
		}
	}
	state.stats.queued.Add(-canceled)
	state.stats.rejectedShuttingDown.Add(uint64(canceled))
	state.mu.Unlock()
	return nil
}

// ServeHTTP enforces admission control before calling the next handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h == nil || h.state == nil || h.MaxConcurrency <= 0 {
		return next.ServeHTTP(w, r)
	}
	state := h.state

	if state.isExempt(r.URL.Path) {
		state.stats.healthBypassed.Add(1)
		return next.ServeHTTP(w, r)
	}

	adm, outcome := state.acquire(r.Context())
	switch outcome {
	case outcomeAdmitted:
		defer adm.release()
		err := next.ServeHTTP(&firstByteWriter{
			ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
			admission:             adm,
		}, r)
		if isUpstreamTimeout(err) {
			state.stats.upstreamTimeouts.Add(1)
		}
		return err
	case outcomeQueueTimeout:
		return reject(w, rejectReasonQueueTimeout)
	case outcomeShuttingDown:
		return reject(w, rejectReasonShuttingDown)
	case outcomeClientCanceled:
		return r.Context().Err()
	default:
		return reject(w, rejectReasonOverloaded)
	}
}

// Stats returns a lock-free snapshot of h's counters.
func (h *Handler) Stats() Stats {
	if h == nil || h.state == nil {
		return Stats{}
	}
	stats := &h.state.stats
	return Stats{
		Active:               stats.active.Load(),
		Queued:               stats.queued.Load(),
		Admitted:             stats.admitted.Load(),
		Completed:            stats.completed.Load(),
		RejectedOverload:     stats.rejectedOverload.Load(),
		RejectedQueueTimeout: stats.rejectedQueueTimeout.Load(),
		RejectedShuttingDown: stats.rejectedShuttingDown.Load(),
		QueueCanceled:        stats.queueCanceled.Load(),
		HealthBypassed:       stats.healthBypassed.Load(),
		UpstreamTimeouts:     stats.upstreamTimeouts.Load(),
	}
}

func (s *handlerState) isExempt(requestPath string) bool {
	for _, exemptPath := range s.exemptPaths {
		if requestPath == exemptPath || strings.HasPrefix(requestPath, exemptPath+"/") {
			return true
		}
	}
	return false
}

func (s *handlerState) acquire(ctx context.Context) (*admission, admissionOutcome) {
	if s.closed.Load() {
		return nil, outcomeShuttingDown
	}

	select {
	case s.tokens <- struct{}{}:
		if s.closed.Load() {
			<-s.tokens
			return nil, outcomeShuttingDown
		}
		s.stats.admitted.Add(1)
		s.stats.active.Add(1)
		return &admission{handler: s.owner}, outcomeAdmitted
	default:
	}

	if s.queueSize == 0 {
		s.stats.rejectedOverload.Add(1)
		return nil, outcomeOverloaded
	}

	w := &waiter{ready: make(chan struct{}, 1)}

	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		s.stats.rejectedShuttingDown.Add(1)
		return nil, outcomeShuttingDown
	}
	if len(s.waiters) >= s.queueSize {
		s.mu.Unlock()
		s.stats.rejectedOverload.Add(1)
		return nil, outcomeOverloaded
	}
	s.waiters = append(s.waiters, w)
	s.stats.queued.Add(1)
	s.mu.Unlock()

	timer := time.NewTimer(s.queueTimeout)
	defer timer.Stop()

	select {
	case <-w.ready:
		return s.waiterOutcome(w)
	case <-timer.C:
		return s.cancelWaiter(w, waiterCancelTimeout)
	case <-ctx.Done():
		return s.cancelWaiter(w, waiterCancelClient)
	}
}

func (s *handlerState) waiterOutcome(w *waiter) (*admission, admissionOutcome) {
	switch waiterState(w.state.Load()) {
	case waiterAdmitted:
		return &admission{handler: s.owner}, outcomeAdmitted
	case waiterCanceled:
		switch waiterCancelReason(w.reason.Load()) {
		case waiterCancelTimeout:
			return nil, outcomeQueueTimeout
		case waiterCancelShutdown:
			return nil, outcomeShuttingDown
		default:
			return nil, outcomeClientCanceled
		}
	default:
		return nil, outcomeClientCanceled
	}
}

func (s *handlerState) cancelWaiter(w *waiter, reason waiterCancelReason) (*admission, admissionOutcome) {
	s.mu.Lock()
	if w.state.CompareAndSwap(uint32(waiterWaiting), uint32(waiterCanceled)) {
		w.reason.Store(uint32(reason))
		for i, queued := range s.waiters {
			if queued == w {
				s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
				break
			}
		}
		s.stats.queued.Add(-1)
		switch reason {
		case waiterCancelTimeout:
			s.stats.rejectedQueueTimeout.Add(1)
			s.mu.Unlock()
			return nil, outcomeQueueTimeout
		case waiterCancelShutdown:
			s.stats.rejectedShuttingDown.Add(1)
			s.mu.Unlock()
			return nil, outcomeShuttingDown
		default:
			s.stats.queueCanceled.Add(1)
			s.mu.Unlock()
			return nil, outcomeClientCanceled
		}
	}
	state := waiterState(w.state.Load())
	s.mu.Unlock()

	if state == waiterAdmitted {
		return &admission{handler: s.owner}, outcomeAdmitted
	}
	return s.waiterOutcome(w)
}

func (h *Handler) release() {
	h.state.release()
}

func (s *handlerState) release() {
	s.stats.completed.Add(1)

	s.mu.Lock()
	for len(s.waiters) > 0 {
		w := s.waiters[0]
		s.waiters = s.waiters[1:]
		if w.state.CompareAndSwap(uint32(waiterWaiting), uint32(waiterAdmitted)) {
			s.stats.queued.Add(-1)
			s.stats.admitted.Add(1)
			w.ready <- struct{}{}
			s.mu.Unlock()
			return
		}
	}
	s.mu.Unlock()

	<-s.tokens
	s.stats.active.Add(-1)
}

func normalizeExemptPaths(paths []string) []string {
	normalized := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, exemptPath := range paths {
		clean := path.Clean(exemptPath)
		if clean == "." {
			clean = "/"
		}
		if clean == "/" {
			clean = ""
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		normalized = append(normalized, clean)
	}
	return normalized
}

func reject(w http.ResponseWriter, reason string) error {
	w.Header().Set(rejectHeader, "rejected")
	w.Header().Set(rejectReasonHeader, reason)
	w.Header().Set("Retry-After", "1")
	http.Error(w, "request rejected by backpressure: "+reason, http.StatusServiceUnavailable)
	return nil
}

func isUpstreamTimeout(err error) bool {
	if err == nil {
		return false
	}
	var handlerErr caddyhttp.HandlerError
	if errors.As(err, &handlerErr) && handlerErr.StatusCode == http.StatusGatewayTimeout {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	backpressure [<matcher>] {
//	    max_concurrency <count>
//	    queue_size      <count>
//	    queue_timeout   <duration>
//	    exempt          <path...>
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "max_concurrency":
			value, err := singleIntArg(d)
			if err != nil {
				return err
			}
			h.MaxConcurrency = value
		case "queue_size":
			value, err := singleIntArg(d)
			if err != nil {
				return err
			}
			h.QueueSize = value
		case "queue_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing queue_timeout: %v", err)
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			h.QueueTimeout = caddy.Duration(timeout)
		case "exempt":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.ExemptPaths = append(h.ExemptPaths, args...)
		default:
			return d.Errf("unrecognized backpressure subdirective %q", d.Val())
		}
	}
	return nil
}

func singleIntArg(d *caddyfile.Dispenser) (int, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	value, err := strconv.Atoi(d.Val())
	if err != nil {
		return 0, d.Errf("parsing integer %q: %v", d.Val(), err)
	}
	if d.NextArg() {
		return 0, d.ArgErr()
	}
	return value, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ http.ResponseWriter         = (*firstByteWriter)(nil)
	_ http.Flusher                = (*firstByteWriter)(nil)
	_ http.Hijacker               = (*firstByteWriter)(nil)
	_ io.ReaderFrom               = (*firstByteWriter)(nil)
)
