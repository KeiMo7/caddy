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
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// countingSource is an io.ReadCloser that produces n bytes without ever
// holding them in memory, so a test can stream a body far larger than the
// inspection budget.
type countingSource struct {
	remaining int64
	chunk     []byte
	err       error
}

func newCountingSource(n int64) *countingSource {
	return &countingSource{remaining: n, chunk: make([]byte, 32<<10)}
}

func (s *countingSource) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > s.remaining {
		n = int(s.remaining)
	}
	if n > len(s.chunk) {
		n = len(s.chunk)
	}
	for i := 0; i < n; i++ {
		p[i] = 'a'
	}
	s.remaining -= int64(n)
	return n, nil
}

func (s *countingSource) Close() error { return nil }

// TestLargeBodyMemoryIsBounded streams a 100 MiB body through the guard and
// asserts that heap growth stays far below the body size. It exercises the
// harder case first: a body with no declared length, which the guard must
// buffer up to the budget and then stream the remainder rather than
// materializing the whole thing.
func TestLargeBodyMemoryIsBounded(t *testing.T) {
	const bodySize = 100 << 20 // 100 MiB

	// unknown-length body: the guard buffers up to the budget and streams the
	// rest, so memory must stay bounded regardless of the body size.
	t.Run("unknown length", func(t *testing.T) {
		g := newTestGuard(t, &RequestGuard{
			Action:        "block",
			MaxBodySize:   1 << 20,
			OversizedBody: "allow",
		})

		req := newTestRequest(t, http.MethodPost, "http://example.com/upload", nil)
		req.Body = newCountingSource(bodySize)
		req.ContentLength = -1 // no declared length
		req.Header.Set("Content-Type", "application/octet-stream")

		peak, live, seen := measureGuardServing(t, g, req)
		if seen != bodySize {
			t.Fatalf("upstream received %d bytes, want %d", seen, bodySize)
		}
		t.Logf("100 MiB body (no length): body=%d bytes heap_delta=%d bytes total_alloc_delta=%d bytes",
			bodySize, live, peak)

		const ceiling = 16 << 20
		if peak > ceiling {
			t.Errorf("allocated %d bytes for a %d-byte body (ceiling %d): memory scales with body size",
				peak, bodySize, ceiling)
		}
	})

	// declared-length body over the budget: the guard detects it without
	// reading and forwards the body untouched, so allocation stays tiny.
	t.Run("declared length", func(t *testing.T) {
		g := newTestGuard(t, &RequestGuard{
			Action:        "block",
			MaxBodySize:   1 << 20,
			OversizedBody: "allow",
		})

		req := newTestRequest(t, http.MethodPost, "http://example.com/upload", nil)
		req.Body = newCountingSource(bodySize)
		req.ContentLength = bodySize
		req.Header.Set("Content-Type", "application/octet-stream")

		peak, live, seen := measureGuardServing(t, g, req)
		if seen != bodySize {
			t.Fatalf("upstream received %d bytes, want %d", seen, bodySize)
		}
		t.Logf("100 MiB body (declared): body=%d bytes heap_delta=%d bytes total_alloc_delta=%d bytes",
			bodySize, live, peak)

		// The body is not buffered at all on this path.
		const ceiling = 1 << 20
		if peak > ceiling {
			t.Errorf("allocated %d bytes for a declared-oversized body (ceiling %d): body was buffered",
				peak, ceiling)
		}
	})
}

// measureGuardServing runs g over req with a discarding upstream and returns
// the total allocation, the live-heap delta, and the bytes the upstream saw.
func measureGuardServing(t *testing.T, g *RequestGuard, req *http.Request) (totalAlloc, liveHeap, seen int64) {
	t.Helper()

	up := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		n, err := io.Copy(io.Discard, r.Body)
		seen = n
		return err
	})

	// Warm up caches and allocator classes before measuring.
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	if err := g.ServeHTTP(httptest.NewRecorder(), req, up); err != nil {
		t.Fatalf("serving large body: %v", err)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	totalAlloc = int64(after.TotalAlloc - before.TotalAlloc)
	liveHeap = int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if liveHeap < 0 {
		liveHeap = 0
	}
	return totalAlloc, liveHeap, seen
}

// TestLargeBodyAllowedPassesThroughObservably documents the oversized-body
// contract: a body over the inspection budget is not inspected as a whole,
// and the route chooses between allowing it (with an observable marker) and
// rejecting it. It also proves the upstream still gets every byte.
func TestLargeBodyAllowedPassesThroughObservably(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{
		Action:        "block",
		MaxBodySize:   1 << 20,
		OversizedBody: "allow",
	})
	const size = 2 << 20
	req := newTestRequest(t, http.MethodPost, "http://example.com/upload", nil)
	req.Body = newCountingSource(size)
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")

	var seen int64
	up := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		n, err := io.Copy(io.Discard, r.Body)
		seen = n
		return err
	})

	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req, up); err != nil {
		t.Fatalf("allow policy returned error: %v", err)
	}
	if seen != size {
		t.Errorf("upstream received %d bytes, want %d", seen, size)
	}
	if rec.Header().Get(budgetHeader) == "" {
		t.Error("allowed oversized body was not marked in the response header")
	}
}

// TestDeclaredOversizedBodyIsNotBuffered proves that when Content-Length
// already exceeds the budget the body is forwarded untouched: it is never
// read by the guard, the request body is the same object, and the upstream
// still receives every byte.
func TestDeclaredOversizedBodyIsNotBuffered(t *testing.T) {
	g := newTestGuard(t, &RequestGuard{
		Action:        "block",
		MaxBodySize:   1 << 20,
		OversizedBody: "allow",
	})
	const size = 8 << 20
	src := newCountingSource(size)
	req := newTestRequest(t, http.MethodPost, "http://example.com/", nil)
	req.Body = src
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")

	var seen int64
	var bodyUnchanged bool
	up := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		bodyUnchanged = r.Body == src
		n, err := io.Copy(io.Discard, r.Body)
		seen = n
		return err
	})

	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req, up); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bodyUnchanged {
		t.Error("declared-oversized body was replaced instead of forwarded untouched")
	}
	if seen != size {
		t.Errorf("upstream received %d bytes, want %d", seen, size)
	}
	if rec.Header().Get(budgetHeader) == "" {
		t.Error("oversized pass-through was not marked")
	}
}
