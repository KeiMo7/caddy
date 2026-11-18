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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func BenchmarkNoBackpressure(b *testing.B) {
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	w := &discardResponseWriter{header: make(http.Header)}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		next.ServeHTTP(w, req)
	}
}

func BenchmarkBackpressureAdmission(b *testing.B) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler := &Handler{MaxConcurrency: 1}
	if err := handler.Provision(ctx); err != nil {
		b.Fatalf("provisioning handler: %v", err)
	}
	defer handler.Cleanup()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	w := &discardResponseWriter{header: make(http.Header)}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = handler.ServeHTTP(w, req, next)
	}
}

type discardResponseWriter struct {
	header http.Header
	status int
}

func (w *discardResponseWriter) Header() http.Header { return w.header }

func (w *discardResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

func (w *discardResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(p), nil
}
