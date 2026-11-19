package reverseproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// prepareTestRequest injects the context values that ServeHTTP and
// proxyLoopIteration require (caddy.ReplacerCtxKey, VarsCtxKey, etc.) using
// the same helper that the real HTTP server uses.
//
// A zero-value Server is passed so that caddyhttp.ServerCtxKey is set to a
// non-nil pointer; reverseProxy dereferences it to check ShouldLogCredentials.
func prepareTestRequest(req *http.Request) *http.Request {
	repl := caddy.NewReplacer()
	return caddyhttp.PrepareRequest(req, repl, nil, &caddyhttp.Server{})
}

// closeOnCloseReader is an io.ReadCloser whose Close method actually makes
// subsequent reads fail, mimicking the behaviour of a real HTTP request body
// (as opposed to io.NopCloser, whose Close is a no-op and would mask the bug
// we are testing).
type closeOnCloseReader struct {
	mu     sync.Mutex
	r      *strings.Reader
	closed bool
}

func newCloseOnCloseReader(s string) *closeOnCloseReader {
	return &closeOnCloseReader{r: strings.NewReader(s)}
}

func (c *closeOnCloseReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("http: invalid Read on closed Body")
	}
	return c.r.Read(p)
}

func (c *closeOnCloseReader) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// deadUpstreamAddr returns a TCP address that is guaranteed to refuse
// connections: we bind a listener, note its address, close it immediately,
// and return the address. Any dial to that address will get ECONNREFUSED.
func deadUpstreamAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create dead upstream listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// testTransport wraps http.Transport to:
//  1. Set the URL scheme to "http" when it is empty (matching what
//     HTTPTransport.SetScheme does in production; cloneRequest strips the
//     scheme intentionally so a plain *http.Transport would fail with
//     "unsupported protocol scheme").
//  2. Wrap dial errors as DialError so that tryAgain correctly identifies them
//     as safe-to-retry regardless of request method (as HTTPTransport does in
//     production via its custom dialer).
type testTransport struct{ *http.Transport }

func (t testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		// Wrap dial errors as DialError to match production behaviour.
		// Without this wrapping, tryAgain treats ECONNREFUSED on a POST
		// request as non-retryable (only GET is retried by default when
		// the error is not a DialError).
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return nil, DialError{err}
		}
	}
	return resp, err
}

// minimalHandler returns a Handler with only the fields required by ServeHTTP
// set directly, bypassing Provision (which requires a full Caddy runtime).
// RoundRobinSelection is used so that successive iterations of the proxy loop
// advance through the upstream pool in a predictable order.
func minimalHandler(retries int, upstreams ...*Upstream) *Handler {
	return &Handler{
		logger:    zap.NewNop(),
		Transport: testTransport{&http.Transport{}},
		Upstreams: upstreams,
		LoadBalancing: &LoadBalancing{
			Retries:         retries,
			SelectionPolicy: &RoundRobinSelection{},
			// RetryMatch intentionally nil: dial errors are always retried
			// regardless of RetryMatch or request method.
		},
		// ctx, connections, connectionsMu, events: zero/nil values are safe
		// for the code paths exercised by these tests (TryInterval=0 so
		// ctx.Done() is never consulted; no WebSocket hijacking; no passive
		// health-check event emission).
	}
}

// TestDialErrorBodyRetry verifies that a POST request whose body has NOT been
// pre-buffered via request_buffers can still be retried after a dial error.
//
// Before the fix, a dial error caused Go's transport to close the shared body
// (via cloneRequest's shallow copy), so the retry attempt would read from an
// already-closed io.ReadCloser and produce:
//
//	http: invalid Read on closed Body → HTTP 502
//
// After the fix the handler wraps the body in noCloseBody when retries are
// configured, preventing the transport's Close() from propagating to the
// shared body. Since dial errors never read any bytes, the body remains at
// position 0 for the retry.
func TestDialErrorBodyRetry(t *testing.T) {
	// Good upstream: echoes the request body with 200 OK.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(goodServer.Close)

	const requestBody = "hello, retry"

	tests := []struct {
		name       string
		method     string
		body       string
		retries    int
		wantStatus int
		wantBody   string
	}{
		{
			// Core regression case: POST with a body, no request_buffers,
			// dial error on first upstream → retry to second upstream succeeds.
			name:       "POST body retried after dial error",
			method:     http.MethodPost,
			body:       requestBody,
			retries:    1,
			wantStatus: http.StatusOK,
			wantBody:   requestBody,
		},
		{
			// Dial errors are always retried regardless of method, but there
			// is no body to re-read, so GET has always worked. Keep it as a
			// sanity check that we did not break the no-body path.
			name:       "GET without body retried after dial error",
			method:     http.MethodGet,
			body:       "",
			retries:    1,
			wantStatus: http.StatusOK,
			wantBody:   "",
		},
		{
			// Without any retry configuration the handler must give up on the
			// first dial error and return a 502. Confirms no wrapping occurs
			// in the no-retry path.
			name:       "no retries configured returns 502 on dial error",
			method:     http.MethodPost,
			body:       requestBody,
			retries:    0,
			wantStatus: http.StatusBadGateway,
			wantBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dead := deadUpstreamAddr(t)

			// Build the upstream pool. RoundRobinSelection starts its
			// counter at 0 and increments before returning, so with a
			// two-element pool it picks index 1 first, then index 0.
			// Put the good upstream at index 0 and the dead one at
			// index 1 so that:
			//   attempt 1 → pool[1] = dead → DialError (ECONNREFUSED)
			//   attempt 2 → pool[0] = good → 200
			upstreams := []*Upstream{
				{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
				{Host: new(Host), Dial: dead},
			}
			if tc.retries == 0 {
				// For the "no retries" case use only the dead upstream so
				// there is nowhere to retry to.
				upstreams = []*Upstream{
					{Host: new(Host), Dial: dead},
				}
			}

			h := minimalHandler(tc.retries, upstreams...)

			// Use closeOnCloseReader so that Close() truly prevents further
			// reads, matching real http.body semantics. io.NopCloser would
			// mask the bug because its Close is a no-op.
			var bodyReader io.ReadCloser
			if tc.body != "" {
				bodyReader = newCloseOnCloseReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, "http://example.com/", bodyReader)
			if bodyReader != nil {
				// httptest.NewRequest wraps the reader in NopCloser; replace
				// it with our close-aware reader so Close() is propagated.
				req.Body = bodyReader
				req.ContentLength = int64(len(tc.body))
			}
			req = prepareTestRequest(req)

			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))

			// For error cases (e.g. 502) ServeHTTP returns a HandlerError
			// rather than writing the status itself.
			gotStatus := rec.Code
			if err != nil {
				if herr, ok := err.(caddyhttp.HandlerError); ok {
					gotStatus = herr.StatusCode
				}
			}

			if gotStatus != tc.wantStatus {
				t.Errorf("status: got %d, want %d (err=%v)", gotStatus, tc.wantStatus, err)
			}
			if tc.wantBody != "" && rec.Body.String() != tc.wantBody {
				t.Errorf("body: got %q, want %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

// newExpressionMatcher provisions a MatchExpression for use in tests
func newExpressionMatcher(t *testing.T, expr string) *caddyhttp.MatchExpression {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	m := &caddyhttp.MatchExpression{Expr: expr}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("failed to provision expression %q: %v", expr, err)
	}
	return m
}

// minimalHandlerWithRetryMatch is like minimalHandler but also configures
// RetryMatch so that response-based retry can be tested
func minimalHandlerWithRetryMatch(retries int, retryMatch caddyhttp.MatcherSets, upstreams ...*Upstream) *Handler {
	h := minimalHandler(retries, upstreams...)
	h.LoadBalancing.RetryMatch = retryMatch
	return h
}

// TestResponseRetryStatusCode verifies that when an upstream returns a status
// code matching a retry_match expression, the request is retried on the next
// upstream
func TestResponseRetryStatusCode(t *testing.T) {
	for _, expr := range []string{
		"{http.reverse_proxy.status_code} in [502, 503]",
		`ph(req, "http.reverse_proxy.status_code") in [502, 503]`,
	} {
		t.Run(expr, func(t *testing.T) {
			// Bad upstream: returns 502
			badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
			}))
			t.Cleanup(badServer.Close)

			// Good upstream: returns 200
			goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))
			t.Cleanup(goodServer.Close)

			retryMatch := caddyhttp.MatcherSets{
				caddyhttp.MatcherSet{
					newExpressionMatcher(t, expr),
				},
			}

			// RoundRobin picks index 1 first, then 0
			upstreams := []*Upstream{
				{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
				{Host: new(Host), Dial: badServer.Listener.Addr().String()},
			}

			h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req = prepareTestRequest(req)
			rec := httptest.NewRecorder()

			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))

			gotStatus := rec.Code
			if err != nil {
				if herr, ok := err.(caddyhttp.HandlerError); ok {
					gotStatus = herr.StatusCode
				}
			}

			if gotStatus != http.StatusOK {
				t.Errorf("status: got %d, want %d (err=%v)", gotStatus, http.StatusOK, err)
			}
		})
	}
}

// TestResponseRetryUnknownLengthEmptyBody verifies that a bodyless request with
// an unknown length (as HTTP/3 GET requests have) remains retryable even though
// the transport probes its body, while a non-empty streaming body does not.
func TestResponseRetryUnknownLengthEmptyBody(t *testing.T) {
	for _, tc := range []struct {
		body     string
		wantCode int
		wantBad  int32
		wantGood int32
	}{
		{body: "", wantCode: http.StatusOK, wantBad: 1, wantGood: 1},
		{body: "synthetic", wantCode: http.StatusBadGateway, wantBad: 1, wantGood: 0},
	} {
		t.Run(fmt.Sprintf("body=%q", tc.body), func(t *testing.T) {
			var badCalls, goodCalls atomic.Int32
			badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				badCalls.Add(1)
				w.WriteHeader(http.StatusBadGateway)
			}))
			t.Cleanup(badServer.Close)
			goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				goodCalls.Add(1)
				if got, err := io.ReadAll(r.Body); err != nil || len(got) != 0 {
					t.Errorf("good upstream body = %q, %v", got, err)
				}
				w.Write([]byte("ok"))
			}))
			t.Cleanup(goodServer.Close)

			retryMatch := caddyhttp.MatcherSets{
				caddyhttp.MatcherSet{
					newExpressionMatcher(t, "{http.reverse_proxy.status_code} == 502"),
				},
			}
			// RoundRobin picks index 1 first, then 0
			h := minimalHandlerWithRetryMatch(1, retryMatch,
				&Upstream{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
				&Upstream{Host: new(Host), Dial: badServer.Listener.Addr().String()})

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", io.NopCloser(strings.NewReader(tc.body)))
			req.ContentLength = -1
			req = prepareTestRequest(req)
			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				return nil
			}))

			gotCode := rec.Code
			if herr, ok := err.(caddyhttp.HandlerError); ok {
				gotCode = herr.StatusCode
			}
			if gotCode != tc.wantCode {
				t.Errorf("status = %d, want %d (err=%v)", gotCode, tc.wantCode, err)
			}
			if badCalls.Load() != tc.wantBad || goodCalls.Load() != tc.wantGood {
				t.Errorf("upstream calls: bad=%d good=%d, want bad=%d good=%d",
					badCalls.Load(), goodCalls.Load(), tc.wantBad, tc.wantGood)
			}
		})
	}
}

// TestResponseRetryHeader verifies that response header matching triggers
// retries via a CEL expression checking {rp.header.*}
func TestResponseRetryHeader(t *testing.T) {
	// Bad upstream: returns 200 but with X-Upstream-Retry header
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Retry", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bad"))
	}))
	t.Cleanup(badServer.Close)

	// Good upstream: returns 200 without retry header
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("good"))
	}))
	t.Cleanup(goodServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, `{http.reverse_proxy.header.X-Upstream-Retry} == "true"`),
		},
	}

	// RoundRobin picks index 1 first, then 0
	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "good" {
		t.Errorf("body: got %q, want %q (retried to wrong upstream)", rec.Body.String(), "good")
	}
}

// TestResponseRetryNoMatchNoRetry verifies that when no retry_match entries
// match the response, the original response is returned without retrying
func TestResponseRetryNoMatchNoRetry(t *testing.T) {
	var hits atomic.Int32

	// Server that returns 500 - but retry_match only matches 502/503
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.status_code} in [502, 503]"),
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	// Only one hit - no retry since 500 doesn't match [502, 503]
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (should not have retried)", hits.Load())
	}
}

// TestResponseRetryExhaustedPreservesStatusCode verifies that when retries
// are exhausted, the actual upstream status code (e.g. 503) is reported
// to the client, not a generic 502
func TestResponseRetryExhaustedPreservesStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // 503
	}))
	t.Cleanup(server.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.status_code} == 503"),
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	// Must return 503 (actual upstream status), not 502 (generic proxy error)
	if gotStatus != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want %d (status code not preserved)", gotStatus, http.StatusServiceUnavailable)
	}
}

// TestResponseRetryHeaderCleanup verifies that stale response header
// placeholders from a previous upstream attempt are cleaned up before the
// next retry evaluation. Without cleanup, a header like X-Retry: true from
// upstream A would leak into the retry match for upstream B even if B does
// not set that header
func TestResponseRetryHeaderCleanup(t *testing.T) {
	// First upstream: returns 200 with X-Retry header (triggers retry)
	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Retry", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("first"))
	}))
	t.Cleanup(firstServer.Close)

	// Second upstream: returns 200 WITHOUT X-Retry header (should NOT retry)
	secondServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("second"))
	}))
	t.Cleanup(secondServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, `{http.reverse_proxy.header.X-Retry} == "true"`),
		},
	}

	// RoundRobin picks index 1 first, then 0
	upstreams := []*Upstream{
		{Host: new(Host), Dial: secondServer.Listener.Addr().String()},
		{Host: new(Host), Dial: firstServer.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get "second" - the first upstream's X-Retry header must not
	// leak into the second upstream's retry evaluation
	if rec.Body.String() != "second" {
		t.Errorf("body: got %q, want %q (stale header leaked between retries)", rec.Body.String(), "second")
	}
}

// TestRequestOnlyMatcherDoesNotRetryResponses verifies that a pure request
// matcher like method PUT in lb_retry_match does NOT trigger response-based
// retries. Only expression matchers (which can reference response data)
// should trigger response retries
func TestRequestOnlyMatcherDoesNotRetryResponses(t *testing.T) {
	var hits atomic.Int32

	// Server returns 200 OK for all requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	// method PUT matcher - should NOT trigger response retries
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			caddyhttp.MatchMethod{"PUT"},
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodPut, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should hit only once - no retry for 200 OK even though method matches
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (should not retry successful responses)", hits.Load())
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestRequestOnlyExpressionDoesNotRetryResponses verifies that an expression
// matcher that only tests the request or the selected upstream (no response
// placeholders) does not cause successful responses to be retried
func TestRequestOnlyExpressionDoesNotRetryResponses(t *testing.T) {
	for _, expr := range []string{
		`{http.request.method} == "POST"`,
		`{http.reverse_proxy.upstream.host} == "127.0.0.1"`,
		`{http.request.uri.path} != "\{http.reverse_proxy.status_code}"`,
		`{http.reverse_proxy.status_codes} == null`,
	} {
		t.Run(expr, func(t *testing.T) {
			var hits atomic.Int32

			// Server returns 200 OK for all requests
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))
			t.Cleanup(server.Close)

			retryMatch := caddyhttp.MatcherSets{
				caddyhttp.MatcherSet{
					newExpressionMatcher(t, expr),
				},
			}

			upstreams := []*Upstream{
				{Host: new(Host), Dial: server.Listener.Addr().String()},
				{Host: new(Host), Dial: server.Listener.Addr().String()},
			}

			h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

			req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("order=1"))
			req = prepareTestRequest(req)
			rec := httptest.NewRecorder()

			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if hits.Load() != 1 {
				t.Errorf("upstream hits: got %d, want 1 (should not retry successful responses)", hits.Load())
			}
			if rec.Code != http.StatusOK {
				t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
			}
			if rec.Body.String() != "ok" {
				t.Errorf("body: got %q, want %q", rec.Body.String(), "ok")
			}
		})
	}
}

// brokenUpstreamAddr returns the address of a TCP listener that accepts
// connections but immediately closes them, causing a transport error (not
// a dial error). This simulates an upstream that is reachable but broken
func brokenUpstreamAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// TestTransportErrorPlaceholder verifies that the is_transport_error
// placeholder is set to true during transport error evaluation in tryAgain()
// and that expression matchers using {rp.is_transport_error} can match it
func TestTransportErrorPlaceholder(t *testing.T) {
	broken := brokenUpstreamAddr(t)

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(goodServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.is_transport_error} == true"),
		},
	}

	// RoundRobin picks index 1 first (broken), then 0 (good)
	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: broken},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	// POST transport error should be retried because is_transport_error matched
	if gotStatus != http.StatusOK {
		t.Errorf("status: got %d, want %d (transport error should have been retried)", gotStatus, http.StatusOK)
	}
}

// TestTransportErrorPlaceholderNotSetForResponses verifies that the
// is_transport_error placeholder is NOT set when evaluating response
// matchers, so {rp.is_transport_error} is false for response retries
func TestTransportErrorPlaceholderNotSetForResponses(t *testing.T) {
	var hits atomic.Int32

	// Server returns 502 - but the matcher only checks is_transport_error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	// Only matches transport errors, not response errors
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.is_transport_error} == true"),
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	// Should hit only once - is_transport_error is false during response
	// evaluation so the 502 is NOT retried
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (is_transport_error should be false for responses)", hits.Load())
	}
}

// TestRetryMatchAllowsExpressionMixedWithOtherMatchers verifies that
// lb_retry_match accepts a block mixing expression with other matchers
func TestRetryMatchAllowsExpressionMixedWithOtherMatchers(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "expression alone",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					expression ` + "`{rp.status_code} in [502, 503]`" + `
				}
			}`,
		},
		{
			name: "method alone",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					method PUT
				}
			}`,
		},
		{
			name: "expression mixed with method",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					method POST
					expression ` + "`{rp.status_code} in [502, 503]`" + `
				}
			}`,
		},
		{
			name: "expression mixed with path",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					path /api*
					expression ` + "`{rp.status_code} == 502`" + `
				}
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			d := caddyfile.NewTestDispenser(tc.input)
			err := h.UnmarshalCaddyfile(d)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestSubrouteErrorFallbackWithBody is similar to TestDialErrorBodyRetry but
// mimics Subroute's Error handler rather than testing retries specifically
func TestSubrouteErrorFallbackWithBody(t *testing.T) {
	// Good upstream: echoes the request body with 200 OK.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(body)
		if err != nil {
			t.Errorf("error writing in good server: %v", err)
		}
	}))
	t.Cleanup(goodServer.Close)

	// Handler which will dial error
	badProxy := minimalHandler(0, &Upstream{Host: new(Host), Dial: deadUpstreamAddr(t)})

	bodyReader := newCloseOnCloseReader("hello world")
	req := httptest.NewRequest("POST", "http://localhost/", bodyReader)
	// httptest.NewRequest wraps the reader in NopCloser; replace
	// it with our close-aware reader so Close() is propagated.
	req.Body = bodyReader

	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()
	err := badProxy.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err == nil {
		t.Fatalf("Expected error from badProxy.ServeHTTP")
	}

	// Simulate the Subroute's Error handler by calling another handler with the
	// same request and recorder
	goodProxy := minimalHandler(0, &Upstream{Host: new(Host), Dial: goodServer.Listener.Addr().String()})
	err = goodProxy.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	if err != nil {
		t.Fatalf("Expected no error from goodProxy.ServeHTTP, got: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	expectedBody := "hello world"
	if rec.Body.String() != expectedBody {
		t.Errorf("body: got %q, want %q", rec.Body.String(), expectedBody)
	}
}

// TestTryAgainDialErrorBehindForwardProxy verifies that tryAgain recognizes
// a DialError even when it is wrapped. When a forward proxy is configured,
// net/http wraps dial errors in a *net.OpError with Op "proxyconnect", and
// the DialError produced by our dialer ends up inside it. Errors that do not
// contain a DialError must still not be retried for non-GET requests, since
// the request may have reached the proxy or the upstream.
func TestTryAgainDialErrorBehindForwardProxy(t *testing.T) {
	dialErr := DialError{errors.New("dial tcp 127.0.0.1:3128: connect: connection refused")}

	for i, tc := range []struct {
		name   string
		err    error
		method string
		want   bool
	}{
		{
			name:   "unwrapped dial error",
			err:    dialErr,
			method: http.MethodPost,
			want:   true,
		},
		{
			name:   "dial error wrapped by forward proxy",
			err:    &net.OpError{Op: "proxyconnect", Net: "tcp", Err: dialErr},
			method: http.MethodPost,
			want:   true,
		},
		{
			name:   "dial error wrapped with fmt.Errorf",
			err:    fmt.Errorf("round trip: %w", dialErr),
			method: http.MethodPost,
			want:   true,
		},
		{
			name:   "proxyconnect error without a dial error",
			err:    &net.OpError{Op: "proxyconnect", Net: "tcp", Err: errors.New("Bad Gateway")},
			method: http.MethodPost,
			want:   false,
		},
		{
			name:   "non-dial error",
			err:    errors.New("read: connection reset by peer"),
			method: http.MethodPost,
			want:   false,
		},
		{
			name:   "non-dial error on GET",
			err:    errors.New("read: connection reset by peer"),
			method: http.MethodGet,
			want:   true,
		},
	} {
		lb := LoadBalancing{Retries: 1}
		req := httptest.NewRequest(tc.method, "http://example.com/", nil)

		got := lb.tryAgain(caddy.Context{}, time.Now(), 0, tc.err, req, zap.NewNop())
		if got != tc.want {
			t.Errorf("Test %d (%s): expected tryAgain=%t, got %t", i, tc.name, tc.want, got)
		}
	}
}

// TestForwardProxyDialErrorRetried verifies end-to-end that when the
// configured forward proxy cannot be reached, a non-GET request is retried
// just like a GET request, because no connection was ever established.
// It uses a real HTTPTransport so that the error is wrapped exactly as
// net/http does in production.
func TestForwardProxyDialErrorRetried(t *testing.T) {
	deadProxy := deadUpstreamAddr(t)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			ht := &HTTPTransport{
				NetworkProxyRaw: json.RawMessage(fmt.Sprintf(`{"from": "url", "url": "http://%s"}`, deadProxy)),
			}
			if err := ht.Provision(ctx); err != nil {
				t.Fatalf("provisioning transport: %v", err)
			}

			// each round trip consults the proxy function exactly once,
			// so counting calls counts the attempts made by the handler
			var attempts atomic.Int32
			proxyFunc := ht.Transport.Proxy
			ht.Transport.Proxy = func(r *http.Request) (*url.URL, error) {
				attempts.Add(1)
				return proxyFunc(r)
			}

			h := minimalHandler(1,
				&Upstream{Host: new(Host), Dial: "upstream-a.example.com:80"},
				&Upstream{Host: new(Host), Dial: "upstream-b.example.com:80"},
			)
			h.Transport = ht

			var body io.Reader
			if method == http.MethodPost {
				body = strings.NewReader("payload")
			}
			req := prepareTestRequest(httptest.NewRequest(method, "http://example.com/", body))

			err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))

			var herr caddyhttp.HandlerError
			if !errors.As(err, &herr) || herr.StatusCode != http.StatusBadGateway {
				t.Fatalf("expected a 502 handler error, got %v", err)
			}
			if got := attempts.Load(); got != 2 {
				t.Errorf("expected 2 attempts (1 try + 1 retry), got %d", got)
			}
		})
	}
}

func minimalHandlerWithRetryPolicy(t *testing.T, policy *RetryPolicy, upstreams ...*Upstream) *Handler {
	t.Helper()
	h := minimalHandler(0, upstreams...)
	h.LoadBalancing.RetryPolicy = policy
	if err := policy.compile(h.LoadBalancing); err != nil {
		t.Fatalf("compiling retry policy: %v", err)
	}
	return h
}

type sequenceTransport struct {
	mu    sync.Mutex
	calls int
	next  func(call int, req *http.Request) (*http.Response, error)
}

func (t *sequenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	call := t.calls
	t.calls++
	t.mu.Unlock()
	return t.next(call, req)
}

func (t *sequenceTransport) Calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

func testProxyResponse(req *http.Request, statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
	}
}

func serveProxyRequest(t *testing.T, h *Handler, req *http.Request) (int, string, error) {
	t.Helper()
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	}))
	status := rec.Code
	if err != nil {
		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) {
			status = handlerErr.StatusCode
		}
	}
	return status, rec.Body.String(), err
}

func TestRetryPolicyResponseStatusCodes(t *testing.T) {
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("bad"))
	}))
	t.Cleanup(badServer.Close)

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("good"))
	}))
	t.Cleanup(goodServer.Close)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}

	for _, tc := range []struct {
		name             string
		retryStatusCodes []int
		neverStatusCodes []int
		wantStatus       int
		wantBody         string
	}{
		{
			name:             "configured status retries",
			retryStatusCodes: []int{http.StatusServiceUnavailable},
			wantStatus:       http.StatusOK,
			wantBody:         "good",
		},
		{
			name:             "unlisted status is returned",
			retryStatusCodes: []int{http.StatusBadGateway},
			wantStatus:       http.StatusServiceUnavailable,
			wantBody:         "bad",
		},
		{
			name:             "never retry status wins",
			retryStatusCodes: []int{http.StatusServiceUnavailable},
			neverStatusCodes: []int{http.StatusServiceUnavailable},
			wantStatus:       http.StatusServiceUnavailable,
			wantBody:         "bad",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
				RetryStatusCodes:      tc.retryStatusCodes,
				NeverRetryStatusCodes: tc.neverStatusCodes,
				MaxRetries:            1,
				TotalBudget:           caddy.Duration(time.Second),
			}, upstreams...)

			status, body, err := serveProxyRequest(t, h, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if status != tc.wantStatus || body != tc.wantBody {
				t.Errorf("response = %d %q, want %d %q", status, body, tc.wantStatus, tc.wantBody)
			}
		})
	}
}

func TestRetryPolicyMethodIdempotency(t *testing.T) {
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("bad"))
	}))
	t.Cleanup(badServer.Close)

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("good"))
	}))
	t.Cleanup(goodServer.Close)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}

	for _, tc := range []struct {
		name               string
		method             string
		idempotencyKey     string
		retryNonIdempotent bool
		wantStatus         int
		wantBody           string
	}{
		{
			name:       "POST defaults to one attempt",
			method:     http.MethodPost,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "bad",
		},
		{
			name:               "POST without key still does not retry",
			method:             http.MethodPost,
			retryNonIdempotent: true,
			wantStatus:         http.StatusServiceUnavailable,
			wantBody:           "bad",
		},
		{
			name:               "POST with key may retry",
			method:             http.MethodPost,
			idempotencyKey:     "order-42",
			retryNonIdempotent: true,
			wantStatus:         http.StatusOK,
			wantBody:           "good",
		},
		{
			name:       "PUT is idempotent",
			method:     http.MethodPut,
			wantStatus: http.StatusOK,
			wantBody:   "good",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
				RetryStatusCodes:   []int{http.StatusServiceUnavailable},
				MaxRetries:         1,
				TotalBudget:        caddy.Duration(time.Second),
				RetryNonIdempotent: tc.retryNonIdempotent,
			}, upstreams...)

			req := httptest.NewRequest(tc.method, "http://example.com/", nil)
			if tc.idempotencyKey != "" {
				req.Header.Set(defaultIdempotencyKeyHeader, tc.idempotencyKey)
			}
			status, body, err := serveProxyRequest(t, h, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if status != tc.wantStatus || body != tc.wantBody {
				t.Errorf("response = %d %q, want %d %q", status, body, tc.wantStatus, tc.wantBody)
			}
		})
	}
}

func TestRetryPolicyRequestBodyReplay(t *testing.T) {
	const payload = "order payload"

	for _, tc := range []struct {
		name        string
		bufferSize  int64
		wantStatus  int
		wantBody    string
		wantGoodHit int32
	}{
		{name: "buffered body is replayed", bufferSize: 1024, wantStatus: http.StatusOK, wantBody: payload, wantGoodHit: 1},
		{name: "unbuffered consumed body is not replayed", bufferSize: 0, wantStatus: http.StatusServiceUnavailable, wantBody: "bad", wantGoodHit: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var goodHits atomic.Int32
			badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Consume the body before failing; a retry without replay would
				// send an empty body to the next upstream.
				_, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("bad"))
			}))
			t.Cleanup(badServer.Close)
			goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				goodHits.Add(1)
				body, _ := io.ReadAll(r.Body)
				if string(body) != payload {
					t.Errorf("good upstream received body %q, want %q", body, payload)
				}
				_, _ = w.Write(body)
			}))
			t.Cleanup(goodServer.Close)

			h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
				RetryStatusCodes: []int{http.StatusServiceUnavailable},
				MaxRetries:       1,
				TotalBudget:      caddy.Duration(time.Second),
			},
				&Upstream{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
				&Upstream{Host: new(Host), Dial: badServer.Listener.Addr().String()},
			)
			h.RequestBuffers = tc.bufferSize

			req := httptest.NewRequest(http.MethodPut, "http://example.com/", strings.NewReader(payload))
			status, body, err := serveProxyRequest(t, h, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if status != tc.wantStatus || body != tc.wantBody {
				t.Errorf("response = %d %q, want %d %q", status, body, tc.wantStatus, tc.wantBody)
			}
			if got := goodHits.Load(); got != tc.wantGoodHit {
				t.Errorf("good upstream hits = %d, want %d", got, tc.wantGoodHit)
			}
		})
	}
}

func TestRetryPolicyExhaustionPreservesLastResponse(t *testing.T) {
	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("first"))
	}))
	t.Cleanup(firstServer.Close)
	lastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Last-Upstream", "true")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("last"))
	}))
	t.Cleanup(lastServer.Close)

	h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
		RetryStatusCodes: []int{http.StatusServiceUnavailable},
		MaxRetries:       1,
		TotalBudget:      caddy.Duration(time.Second),
	},
		&Upstream{Host: new(Host), Dial: lastServer.Listener.Addr().String()},
		&Upstream{Host: new(Host), Dial: firstServer.Listener.Addr().String()},
	)

	status, body, err := serveProxyRequest(t, h, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusServiceUnavailable || body != "last" {
		t.Errorf("response = %d %q, want 503 %q", status, body, "last")
	}
}

func TestRetryPolicyConnectionFailureClasses(t *testing.T) {
	refused := DialError{&net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
	}}
	timeout := DialError{&net.OpError{Op: "dial", Net: "tcp", Err: timeoutError{}}}

	for _, tc := range []struct {
		name      string
		failure   error
		retryOn   []string
		wantCalls int
		wantCode  int
	}{
		{
			name:      "connection refused retries",
			failure:   refused,
			retryOn:   []string{"connection_refused"},
			wantCalls: 2,
			wantCode:  http.StatusOK,
		},
		{
			name:      "connection timeout disabled does not retry",
			failure:   timeout,
			retryOn:   []string{"connection_refused"},
			wantCalls: 1,
			wantCode:  http.StatusGatewayTimeout,
		},
		{
			name:      "tls handshake retries when enabled",
			failure:   tlsHandshakeError{errors.New("tls: handshake failure")},
			retryOn:   []string{"tls_handshake"},
			wantCalls: 2,
			wantCode:  http.StatusOK,
		},
		{
			name:      "tls handshake disabled does not retry",
			failure:   tlsHandshakeError{errors.New("tls: handshake failure")},
			retryOn:   []string{"connection_refused"},
			wantCalls: 1,
			wantCode:  http.StatusBadGateway,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &sequenceTransport{next: func(call int, req *http.Request) (*http.Response, error) {
				if call == 0 {
					return nil, tc.failure
				}
				return testProxyResponse(req, http.StatusOK, "ok"), nil
			}}
			h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
				RetryOn:     tc.retryOn,
				MaxRetries:  1,
				TotalBudget: caddy.Duration(time.Second),
			},
				&Upstream{Host: new(Host), Dial: "upstream-a.example.com:80"},
				&Upstream{Host: new(Host), Dial: "upstream-b.example.com:80"},
			)
			h.Transport = transport

			status, _, _ := serveProxyRequest(t, h, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
			if status != tc.wantCode {
				t.Errorf("status = %d, want %d", status, tc.wantCode)
			}
			if got := transport.Calls(); got != tc.wantCalls {
				t.Errorf("attempts = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}

func TestRetryPolicyStopsWhenClientDisconnects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &sequenceTransport{next: func(call int, req *http.Request) (*http.Response, error) {
		cancel()
		return testProxyResponse(req, http.StatusServiceUnavailable, "disconnected"), nil
	}}
	h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
		RetryStatusCodes: []int{http.StatusServiceUnavailable},
		MaxRetries:       5,
		TotalBudget:      caddy.Duration(time.Second),
	}, &Upstream{Host: new(Host), Dial: "upstream.example.com:80"})
	h.Transport = transport

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(ctx)
	start := time.Now()
	status, _, _ := serveProxyRequest(t, h, req)
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", status, http.StatusServiceUnavailable)
	}
	if got := transport.Calls(); got != 1 {
		t.Errorf("attempts = %d, want 1 after client cancellation", got)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Errorf("retry loop took %s after client cancellation", elapsed)
	}
}

func TestRetryPolicyTotalBudget(t *testing.T) {
	transport := &sequenceTransport{next: func(call int, req *http.Request) (*http.Response, error) {
		return testProxyResponse(req, http.StatusServiceUnavailable, "busy"), nil
	}}
	h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
		RetryStatusCodes: []int{http.StatusServiceUnavailable},
		MaxRetries:       10,
		TotalBudget:      caddy.Duration(70 * time.Millisecond),
		InitialInterval:  caddy.Duration(10 * time.Millisecond),
		MaxInterval:      caddy.Duration(20 * time.Millisecond),
		Jitter:           0.1,
	}, &Upstream{Host: new(Host), Dial: "upstream.example.com:80"})
	h.Transport = transport

	start := time.Now()
	status, body, err := serveProxyRequest(t, h, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusServiceUnavailable || body != "busy" {
		t.Errorf("response = %d %q, want 503 %q", status, body, "busy")
	}
	if calls := transport.Calls(); calls < 2 || calls > 7 {
		t.Errorf("attempts = %d, want between 2 and 7", calls)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("elapsed = %s, total budget was 70ms", elapsed)
	}
}

type partialErrorBody struct {
	sent bool
}

func (b *partialErrorBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "partial"), nil
	}
	return 0, errors.New("upstream body failed")
}

func (b *partialErrorBody) Close() error { return nil }

func TestRetryPolicyDoesNotRetryAfterPartialResponse(t *testing.T) {
	transport := &sequenceTransport{next: func(call int, req *http.Request) (*http.Response, error) {
		res := testProxyResponse(req, http.StatusOK, "")
		res.Body = &partialErrorBody{}
		res.ContentLength = -1
		return res, nil
	}}
	h := minimalHandlerWithRetryPolicy(t, &RetryPolicy{
		RetryStatusCodes: []int{http.StatusServiceUnavailable},
		MaxRetries:       3,
		TotalBudget:      caddy.Duration(time.Second),
	}, &Upstream{Host: new(Host), Dial: "upstream.example.com:80"})
	h.Transport = transport

	func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
				panic(recovered)
			}
		}()
		_ = h.ServeHTTP(
			httptest.NewRecorder(),
			prepareTestRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil)),
			caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
		)
	}()

	if got := transport.Calls(); got != 1 {
		t.Errorf("attempts = %d, want 1 after a partial response", got)
	}
}

func TestRetryPolicyFaultInjectionComparison(t *testing.T) {
	type result struct {
		attempts int
		success  bool
		elapsed  time.Duration
		status   int
	}

	runPost500 := func(usePolicy bool) result {
		transport := &sequenceTransport{next: func(call int, req *http.Request) (*http.Response, error) {
			if call < 2 {
				return testProxyResponse(req, http.StatusInternalServerError, "failed"), nil
			}
			return testProxyResponse(req, http.StatusOK, "created"), nil
		}}
		var h *Handler
		if usePolicy {
			h = minimalHandlerWithRetryPolicy(t, &RetryPolicy{
				RetryStatusCodes: []int{http.StatusInternalServerError},
				MaxRetries:       2,
				TotalBudget:      caddy.Duration(time.Second),
			}, &Upstream{Host: new(Host), Dial: "upstream.example.com:80"})
		} else {
			h = minimalHandler(2, &Upstream{Host: new(Host), Dial: "upstream.example.com:80"})
			h.LoadBalancing.RetryMatch = caddyhttp.MatcherSets{
				caddyhttp.MatcherSet{newExpressionMatcher(t, "{http.reverse_proxy.status_code} == 500")},
			}
		}
		h.Transport = transport
		start := time.Now()
		status, _, _ := serveProxyRequest(t, h, httptest.NewRequest(http.MethodPost, "http://example.com/", nil))
		return result{attempts: transport.Calls(), success: status == http.StatusOK, elapsed: time.Since(start), status: status}
	}

	runTimeout := func(usePolicy bool) result {
		transport := &sequenceTransport{next: func(call int, req *http.Request) (*http.Response, error) {
			select {
			case <-time.After(30 * time.Millisecond):
				return nil, DialError{&net.OpError{Op: "dial", Net: "tcp", Err: timeoutError{}}}
			case <-req.Context().Done():
				return nil, DialError{req.Context().Err()}
			}
		}}
		var h *Handler
		if usePolicy {
			h = minimalHandlerWithRetryPolicy(t, &RetryPolicy{
				RetryOn:     []string{"connection_timeout"},
				MaxRetries:  10,
				TotalBudget: caddy.Duration(50 * time.Millisecond),
			}, &Upstream{Host: new(Host), Dial: "upstream.example.com:80"})
		} else {
			h = minimalHandler(2, &Upstream{Host: new(Host), Dial: "upstream.example.com:80"})
		}
		h.Transport = transport
		start := time.Now()
		status, _, _ := serveProxyRequest(t, h, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
		return result{attempts: transport.Calls(), success: status == http.StatusOK, elapsed: time.Since(start), status: status}
	}

	for _, tc := range []struct {
		name   string
		legacy result
		policy result
	}{
		{name: "POST 500 (idempotency guard)", legacy: runPost500(false), policy: runPost500(true)},
		{name: "GET connection timeout (budget guard)", legacy: runTimeout(false), policy: runTimeout(true)},
	} {
		t.Logf("%s: legacy attempts=%d success=%t elapsed=%s status=%d | policy attempts=%d success=%t elapsed=%s status=%d",
			tc.name,
			tc.legacy.attempts, tc.legacy.success, tc.legacy.elapsed, tc.legacy.status,
			tc.policy.attempts, tc.policy.success, tc.policy.elapsed, tc.policy.status,
		)

		if tc.name == "POST 500 (idempotency guard)" {
			if tc.legacy.attempts < 2 {
				t.Errorf("legacy should have retried POST, attempts=%d", tc.legacy.attempts)
			}
			if tc.policy.attempts != 1 {
				t.Errorf("policy must send non-idempotent POST once, attempts=%d", tc.policy.attempts)
			}
		}
		if tc.name == "GET connection timeout (budget guard)" {
			if tc.policy.attempts >= tc.legacy.attempts {
				t.Errorf("policy should not multiply connection timeout: legacy=%d policy=%d", tc.legacy.attempts, tc.policy.attempts)
			}
			if tc.policy.elapsed > 150*time.Millisecond {
				t.Errorf("policy exceeded total budget by too much: %s", tc.policy.elapsed)
			}
			if tc.policy.status != http.StatusGatewayTimeout {
				t.Errorf("policy status=%d, want 504", tc.policy.status)
			}
		}
	}
}
