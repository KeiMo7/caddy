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

package requestguard

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// newTestGuard provisions a guard with a private metrics registry, applying
// defaults the way Provision does. It fails the test on error.
func newTestGuard(t *testing.T, g *RequestGuard) *RequestGuard {
	t.Helper()

	_, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	if g.MaxBodySize == 0 {
		g.MaxBodySize = defaultMaxBodySize
	}
	if g.MaxDecodedSize == 0 {
		g.MaxDecodedSize = defaultMaxDecodedSize
	}
	if g.MaxDecodedRatio == 0 {
		g.MaxDecodedRatio = defaultMaxDecodedRatio
	}
	if g.MaxConcurrent == 0 {
		g.MaxConcurrent = defaultMaxConcurrent
	}
	if g.ConcurrencyWait == 0 {
		g.ConcurrencyWait = caddy.Duration(defaultConcurrencyWait)
	}

	// Provision needs a logger and rules; build them directly to avoid a
	// full caddy runtime.
	g.logger = caddy.Log().Named("test.request_guard")
	action, err := parseAction(g.Action)
	if err != nil {
		t.Fatalf("parsing action: %v", err)
	}
	oversized, err := parsePolicy("oversized_body", g.OversizedBody)
	if err != nil {
		t.Fatalf("parsing oversized_body: %v", err)
	}
	disabled := make(map[string]struct{}, len(g.DisabledRules))
	for _, id := range g.DisabledRules {
		disabled[id] = struct{}{}
	}
	active := make([]rule, 0, len(builtinRules))
	if !g.DisableBuiltinRules {
		for _, r := range builtinRules {
			if _, skip := disabled[r.id]; skip {
				continue
			}
			active = append(active, r)
		}
	}
	custom := make([]ruleConfig, 0, len(g.Rules))
	for _, rc := range g.Rules {
		if _, skip := disabled[rc.ID]; skip {
			continue
		}
		custom = append(custom, rc)
	}
	g.rules, err = compileRules(active, custom, g.DisableBuiltinRules)
	if err != nil {
		t.Fatalf("compiling rules: %v", err)
	}
	g.action = action
	g.oversized = oversized
	g.semWait = time.Duration(g.ConcurrencyWait)
	g.sem = make(chan struct{}, g.MaxConcurrent)
	g.metrics = initGuardMetrics(prometheus.NewPedanticRegistry())
	return g
}

// newTestRequest builds a request that has the context values the handler
// expects (replacer, vars, extra log fields).
func newTestRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	repl := caddy.NewReplacer()
	r = caddyhttp.PrepareRequest(r, repl, nil, &caddyhttp.Server{})
	return r
}

// passthrough records the body the downstream handler observed and returns a
// handler that echoes it back in the response.
type passthrough struct {
	body    []byte
	called  bool
	headers http.Header
}

func (p *passthrough) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	p.called = true
	p.headers = r.Header.Clone()
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		p.body = b
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("upstream"))
	return nil
}

func TestGuardBlocksAndDoesNotReachUpstream(t *testing.T) {
	for i, tc := range []struct {
		name    string
		method  string
		target  string
		headers http.Header
		body    string
	}{
		{
			name:   "query string",
			method: http.MethodGet,
			target: "http://example.com/?q=" + url.QueryEscape("' OR 1=1 --"),
		},
		{
			name:   "path traversal",
			method: http.MethodGet,
			target: "http://example.com/" + url.PathEscape("../../etc/passwd"),
		},
		{
			name:    "header",
			method:  http.MethodGet,
			target:  "http://example.com/",
			headers: http.Header{"X-Test": {`<script>alert(1)</script>`}},
		},
		{
			name:    "cookie",
			method:  http.MethodGet,
			target:  "http://example.com/",
			headers: http.Header{"Cookie": {`session=` + url.QueryEscape("1 union select 2")}},
		},
		{
			name:    "urlencoded form",
			method:  http.MethodPost,
			target:  "http://example.com/",
			headers: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
			body:    "name=ok&bio=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		},
		{
			name:    "json body",
			method:  http.MethodPost,
			target:  "http://example.com/",
			headers: http.Header{"Content-Type": {"application/json"}},
			body:    `{"nested":{"deep":["ok","1 union select password from users"]}}`,
		},
		{
			name:    "double encoded in json",
			method:  http.MethodPost,
			target:  "http://example.com/",
			headers: http.Header{"Content-Type": {"application/json"}},
			body:    `{"v":"%253Cscript%253E"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGuard(t, &RequestGuard{Action: "block"})
			req := newTestRequest(t, tc.method, tc.target, strings.NewReader(tc.body))
			for k, vv := range tc.headers {
				for _, v := range vv {
					req.Header.Add(k, v)
				}
			}

			up := &passthrough{}
			rec := httptest.NewRecorder()
			err := g.ServeHTTP(rec, req, up)
			if err == nil {
				t.Fatalf("Test %d: expected an error, got none", i)
			}
			var he caddyhttp.HandlerError
			if !errors.As(err, &he) {
				t.Fatalf("Test %d: expected HandlerError, got %T", i, err)
			}
			if he.StatusCode != http.StatusForbidden {
				t.Errorf("Test %d: status = %d, want %d", i, he.StatusCode, http.StatusForbidden)
			}
			if up.called {
				t.Errorf("Test %d: blocked request reached the upstream", i)
			}
			if rec.Header().Get(reasonHeader) == "" {
				t.Errorf("Test %d: reason header not set", i)
			}
			if strings.Contains(err.Error(), tc.body) && tc.body != "" {
				t.Errorf("Test %d: error message leaked request body: %v", i, err)
			}
		})
	}
}

func TestGuardAllowsCleanRequestUnchanged(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	body := `{"name":"Alice","note":"hello world"}`
	req := newTestRequest(t, http.MethodPost, "http://example.com/api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	up := &passthrough{}
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req, up); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !up.called {
		t.Fatal("clean request did not reach upstream")
	}
	if string(up.body) != body {
		t.Errorf("upstream body changed: got %q, want %q", up.body, body)
	}
}

func TestGuardReplaysBodyByteForByte(t *testing.T) {
	// binary content with non-UTF8 bytes must round-trip exactly
	body := make([]byte, 4096)
	for i := range body {
		body[i] = byte(i * 7)
	}
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	req := newTestRequest(t, http.MethodPost, "http://example.com/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(body))

	up := &passthrough{}
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req, up); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(up.body, body) {
		t.Errorf("body changed: got %d bytes, want %d", len(up.body), len(body))
	}
}

func TestGuardMultipartNestedPayload(t *testing.T) {
	var b strings.Builder
	mw := multipart.NewWriter(&b)
	fw, err := mw.CreateFormField("ok")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("fine"))
	fw, _ = mw.CreateFormField("bad")
	fw.Write([]byte("1 union select 2"))
	mw.Close()

	body := b.String()
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.ContentLength = int64(len(body))

	up := &passthrough{}
	err = g.ServeHTTP(httptest.NewRecorder(), req, up)
	if err == nil {
		t.Fatal("expected a block for a payload in a multipart field")
	}
	if up.called {
		t.Error("blocked multipart request reached the upstream")
	}
}

func TestGuardLogActionForwards(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "log"})
	req := newTestRequest(t, http.MethodGet, "http://example.com/?q=%3Cscript%3E", nil)

	up := &passthrough{}
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req, up); err != nil {
		t.Fatalf("log action returned error: %v", err)
	}
	if !up.called {
		t.Error("log action did not forward the request")
	}
}

func TestGuardOffActionForwards(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "off"})
	req := newTestRequest(t, http.MethodGet, "http://example.com/?q=%3Cscript%3E", nil)

	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err != nil {
		t.Fatalf("off action returned error: %v", err)
	}
	if !up.called {
		t.Error("off action did not forward the request")
	}
}

func TestGuardOversizedReject(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block", MaxBodySize: 64, OversizedBody: "reject"})
	body := strings.Repeat("a", 4096)
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(body))

	up := &passthrough{}
	err := g.ServeHTTP(httptest.NewRecorder(), req, up)
	if err == nil {
		t.Fatal("expected rejection of an oversized body")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %v", err)
	}
	if up.called {
		t.Error("rejected oversized request reached upstream")
	}
}

func TestGuardOversizedAllowForwardsWholeBody(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block", MaxBodySize: 64, OversizedBody: "allow"})
	body := strings.Repeat("a", 1<<20)
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(body))

	up := &passthrough{}
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req, up); err != nil {
		t.Fatalf("allow policy returned error: %v", err)
	}
	if !up.called {
		t.Fatal("allowed request did not reach upstream")
	}
	if len(up.body) != len(body) {
		t.Errorf("upstream got %d bytes, want %d", len(up.body), len(body))
	}
	if rec.Header().Get(budgetHeader) == "" {
		t.Error("budget-exceeded header not set on pass-through")
	}
}

// TestGuardIncompleteBodyRejected proves a read failure mid-body is never
// treated as a clean request: it is refused, and the upstream is not reached
// with a partial body.
func TestGuardIncompleteBodyRejected(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", io.NopCloser(errReader{}))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = 100

	up := &passthrough{}
	err := g.ServeHTTP(httptest.NewRecorder(), req, up)
	if err == nil {
		t.Fatal("expected a read failure to be rejected")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %v", err)
	}
	if up.called {
		t.Error("incomplete request reached upstream")
	}
}

func TestGuardDecompressionBombRejected(t *testing.T) {
	// 8 MiB of zeros compresses to a tiny payload; a ratio limit of 100
	// must reject it without expanding it fully.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(make([]byte, 8<<20))
	zw.Close()
	compressed := buf.Bytes()

	g := newTestGuard(t, &RequestGuard{
		Action:          "block",
		MaxBodySize:     16 << 20,
		MaxDecodedSize:  16 << 20,
		MaxDecodedRatio: 100,
	})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	req.ContentLength = int64(len(compressed))

	up := &passthrough{}
	err := g.ServeHTTP(httptest.NewRecorder(), req, up)
	if err == nil {
		t.Fatal("expected a decompression bomb to be rejected")
	}
	if up.called {
		t.Error("bomb request reached upstream")
	}
}

func TestGuardCompressedCleanBodyForwardsOriginalBytes(t *testing.T) {
	payload := []byte(`{"name":"Alice"}`)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(payload)
	zw.Close()
	compressed := buf.Bytes()

	g := newTestGuard(t, &RequestGuard{Action: "block", MaxBodySize: 1 << 20})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.ContentLength = int64(len(compressed))

	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(up.body, compressed) {
		t.Error("upstream did not receive the original compressed bytes")
	}
}

func TestGuardSkipsUpgrade(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	req := newTestRequest(t, http.MethodGet, "http://example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	// a payload in the query would be blocked if the request were inspected
	req.URL.RawQuery = "q=%3Cscript%3E"

	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !up.called {
		t.Error("upgrade request was not forwarded")
	}
}

func TestGuardIndependentRequests(t *testing.T) {
	// A blocked request must not taint the next request on the same guard.
	g := newTestGuard(t, &RequestGuard{Action: "block"})

	bad := newTestRequest(t, http.MethodGet, "http://example.com/?q=%3Cscript%3E", nil)
	if err := g.ServeHTTP(httptest.NewRecorder(), bad, &passthrough{}); err == nil {
		t.Fatal("expected the first request to be blocked")
	}

	good := newTestRequest(t, http.MethodGet, "http://example.com/?q=hello", nil)
	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), good, up); err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if !up.called {
		t.Error("a clean request after a blocked one was not forwarded")
	}
}

func TestGuardConcurrencyBudget(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{
		Action:          "block",
		MaxBodySize:     1 << 20,
		MaxConcurrent:   1,
		ConcurrencyWait: caddy.Duration(1),
		OversizedBody:   "allow",
	})
	// occupy the only slot
	g.sem <- struct{}{}

	body := "hello"
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(body))

	up := &passthrough{}
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req, up); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !up.called {
		t.Error("request over the concurrency budget was not forwarded under allow")
	}
	if rec.Header().Get(budgetHeader) == "" {
		t.Error("budget header not set")
	}
	<-g.sem
}

func TestGuardConcurrencyBudgetReject(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{
		Action:          "block",
		MaxBodySize:     1 << 20,
		MaxConcurrent:   1,
		ConcurrencyWait: caddy.Duration(1),
		OversizedBody:   "reject",
	})
	g.sem <- struct{}{}

	body := "hello"
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(body))

	err := g.ServeHTTP(httptest.NewRecorder(), req, &passthrough{})
	if err == nil {
		t.Fatal("expected rejection when concurrency budget is exhausted")
	}
	<-g.sem
}

func TestGuardConcurrentRequestsAreSafe(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block", MaxConcurrent: 4})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"n":` + string(rune('0'+i%10)) + `}`
			req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.ContentLength = int64(len(body))
			_ = g.ServeHTTP(httptest.NewRecorder(), req, &passthrough{})
		}(i)
	}
	wg.Wait()
}

// errReader returns an error on the first read, simulating a client that
// disconnects mid-body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

// TestGuardBodyExactlyAtBudgetIsInspected proves a body of exactly the budget
// size is inspected rather than mistaken for oversized.
func TestGuardBodyExactlyAtBudgetIsInspected(t *testing.T) {
	const budget = 128
	g := newTestGuard(t, &RequestGuard{Action: "block", MaxBodySize: budget, OversizedBody: "reject"})

	// exactly at the budget, clean
	clean := strings.Repeat("a", budget)
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(clean))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(clean))
	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err != nil {
		t.Fatalf("clean body of exactly the budget was rejected: %v", err)
	}
	if string(up.body) != clean {
		t.Error("body at the budget was not forwarded intact")
	}

	// exactly at the budget, but malicious: must still be caught
	bad := strings.Repeat("a", budget-len("<script>")) + "<script>"
	req = newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(bad))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(bad))
	if err := g.ServeHTTP(httptest.NewRecorder(), req, &passthrough{}); err == nil {
		t.Error("payload at exactly the budget was not inspected")
	}
}

// TestGuardPreservesTrailers proves request trailers are not dropped or
// altered by buffering the body.
func TestGuardPreservesTrailers(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	body := `{"name":"Alice"}`
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	req.Trailer = http.Header{"X-Checksum": {"abc123"}}

	var gotBody []byte
	var gotTrailer http.Header
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotBody, _ = io.ReadAll(r.Body)
		gotTrailer = r.Trailer.Clone()
		return nil
	})
	if err := g.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(gotBody) != body {
		t.Errorf("body changed: got %q", gotBody)
	}
	if gotTrailer.Get("X-Checksum") != "abc123" {
		t.Errorf("trailer not preserved: %v", gotTrailer)
	}
}

// TestGuardHeaderCountsUnchangedOnCleanBody proves the guard does not add or
// remove headers when it forwards a clean request.
func TestGuardHeaderCountsUnchangedOnCleanBody(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = 5
	before := req.Header.Clone()
	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(before, up.headers) {
		t.Errorf("headers changed:\nbefore: %v\nafter:  %v", before, up.headers)
	}
	if req.ContentLength != 5 {
		t.Errorf("ContentLength changed to %d, want 5", req.ContentLength)
	}
}

// TestGuardDecompressionReasonsAreDistinguishable proves the ratio limit and
// the absolute decoded-size limit produce different reason codes, as the
// failure-handling contract requires.
func TestGuardDecompressionReasonsAreDistinguishable(t *testing.T) {
	// highly compressible input over the ratio threshold
	var ratioBuf bytes.Buffer
	zw := gzip.NewWriter(&ratioBuf)
	zw.Write(make([]byte, 4<<20))
	zw.Close()
	ratioBody := ratioBuf.Bytes()
	if len(ratioBody) < minRatioInput {
		t.Skipf("compressed bomb is only %d bytes, below the ratio threshold", len(ratioBody))
	}

	g := newTestGuard(t, &RequestGuard{
		Action:          "block",
		MaxBodySize:     64 << 20,
		MaxDecodedSize:  64 << 20,
		MaxDecodedRatio: 100,
	})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", bytes.NewReader(ratioBody))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	req.ContentLength = int64(len(ratioBody))

	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, req, &passthrough{})
	if err == nil {
		t.Fatal("expected the ratio-limited body to be refused")
	}
	if got := rec.Header().Get(reasonHeader); got != string(decodeRatio) {
		t.Errorf("ratio refusal reason = %q, want %q", got, decodeRatio)
	}

	// Now an absolute-size limit below the decoded size but with the ratio
	// disabled, so the absolute cap is what triggers.
	g2 := newTestGuard(t, &RequestGuard{
		Action:          "block",
		MaxBodySize:     64 << 20,
		MaxDecodedSize:  1 << 10,
		MaxDecodedRatio: 1 << 30,
	})
	req2 := newTestRequest(t, http.MethodPost, "http://example.com/", bytes.NewReader(ratioBody))
	req2.Header.Set("Content-Type", "text/plain")
	req2.Header.Set("Content-Encoding", "gzip")
	req2.ContentLength = int64(len(ratioBody))

	rec2 := httptest.NewRecorder()
	err = g2.ServeHTTP(rec2, req2, &passthrough{})
	if err == nil {
		t.Fatal("expected the size-limited body to be refused")
	}
	if got := rec2.Header().Get(reasonHeader); got != string(decodeSize) {
		t.Errorf("size refusal reason = %q, want %q", got, decodeSize)
	}
}

// TestGuardEmptyBodyWithEncoding proves an empty body carrying a
// Content-Encoding header is not mistaken for a corrupt compressed body.
func TestGuardEmptyBodyWithEncoding(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.ContentLength = 0

	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err != nil {
		t.Fatalf("empty encoded body was rejected: %v", err)
	}
	if !up.called {
		t.Error("empty encoded body did not reach upstream")
	}
}

// blockingAfterReader yields exactly n bytes and then blocks forever on the
// next Read. It proves a body at (budget+1) is detected as oversized without
// waiting for EOF that may never come.
type blockingAfterReader struct {
	n     int
	done  bool
	block chan struct{}
}

func newBlockingAfterReader(n int) *blockingAfterReader {
	return &blockingAfterReader{n: n, block: make(chan struct{})}
}

func (r *blockingAfterReader) Read(p []byte) (int, error) {
	if r.done {
		<-r.block // block until Close
		return 0, io.EOF
	}
	take := min(len(p), r.n)
	for i := 0; i < take; i++ {
		p[i] = 'a'
	}
	r.n -= take
	if r.n == 0 {
		r.done = true
	}
	return take, nil
}

func (r *blockingAfterReader) Close() error {
	select {
	case <-r.block:
	default:
		close(r.block)
	}
	return nil
}

func TestGuardOversizedDoesNotWaitForEOF(t *testing.T) {
	const budget = 16
	g := newTestGuard(t, &RequestGuard{Action: "block", MaxBodySize: budget, OversizedBody: "allow"})
	req := newTestRequest(t, http.MethodPost, "http://example.com/", nil)
	req.Body = newBlockingAfterReader(budget + 1)
	req.ContentLength = -1 // unknown length: the hard case
	req.Header.Set("Content-Type", "text/plain")

	// The downstream does not read the body: this isolates the guard's own
	// inspection, which must not block waiting for an EOF that may never come.
	noRead := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})
	done := make(chan error, 1)
	go func() {
		done <- g.ServeHTTP(httptest.NewRecorder(), req, noRead)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("guard blocked waiting for EOF on an oversized body")
	}
	req.Body.Close()
}

// TestGuardMalformedFormFallsBackToRawScan proves a payload in a form pair
// that url.ParseQuery cannot decode is still inspected: the parser's partial
// view is not trusted, and the raw body is scanned instead.
func TestGuardMalformedFormFallsBackToRawScan(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{Action: "block"})
	// The middle pair has a bad percent escape, so ParseQuery errors on it.
	// A naive field-only scan would drop it; the raw fallback must catch the
	// payload regardless of where the parser gave up.
	body := "good=1&bad=%zz%3Cscript%3Ealert(1)%3C%2Fscript%3E&ok=2"
	req := newTestRequest(t, http.MethodPost, "http://example.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))

	up := &passthrough{}
	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err == nil {
		t.Fatal("payload in a malformed form pair was not caught")
	}
	if up.called {
		t.Error("blocked request reached upstream")
	}
}
