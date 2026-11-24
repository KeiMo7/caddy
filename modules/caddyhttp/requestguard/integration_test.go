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

package requestguard_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// fakeUpstream records every request it receives and echoes the received body
// back to the caller, so a test can prove both what arrived and that it
// arrived byte-for-byte.
type fakeUpstream struct {
	srv *httptest.Server
	mu  sync.Mutex

	hits      int32
	lastBody  []byte
	lastAlert string
	lastQuery string
	lastHdr   http.Header
	lastCT    string
	lastCL    int64
	lastTE    []string
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&u.hits, 1)
		body, _ := io.ReadAll(r.Body)

		u.mu.Lock()
		u.lastBody = body
		u.lastQuery = r.URL.RawQuery
		u.lastHdr = r.Header.Clone()
		u.lastCT = r.Header.Get("Content-Type")
		u.lastCL = r.ContentLength
		u.lastTE = append([]string(nil), r.TransferEncoding...)
		u.mu.Unlock()

		w.Header().Set("X-Upstream-Body-Len", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) snapshot() (hits int32, body []byte, query string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return atomic.LoadInt32(&u.hits), bytes.Clone(u.lastBody), u.lastQuery
}

func (u *fakeUpstream) framing() (int64, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastCL, append([]string(nil), u.lastTE...)
}

// startGateway loads a real Caddy instance that proxies a fresh listener to
// upstream with the given guard config applied to its route. It returns the
// listener address.
func startGateway(t *testing.T, upstreamAddr string, guard map[string]any) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	route := map[string]any{
		"handle": []any{
			map[string]any{"handler": "request_guard", "action": guard["action"],
				"max_body_size":     guard["max_body_size"],
				"oversized_body":    guard["oversized_body"],
				"max_decoded_ratio": guard["max_decoded_ratio"],
				"max_decoded_size":  guard["max_decoded_size"],
				"max_concurrent":    guard["max_concurrent"],
			},
			map[string]any{"handler": "reverse_proxy", "upstreams": []any{
				map[string]any{"dial": upstreamAddr},
			}},
		},
	}

	cfg, err := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{"http": map[string]any{
			"grace_period": 1,
			"servers": map[string]any{"test": map[string]any{
				"listen":          []string{addr},
				"automatic_https": map[string]any{"disable": true},
				"routes":          []any{route},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("marshaling config: %v", err)
	}
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	// caddy.Load replaces the whole process config; stop at test end so the
	// next test starts clean.
	t.Cleanup(func() { _ = caddy.Stop() })

	return addr
}

func gatewayClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{},
		Timeout:   10 * time.Second,
	}
}

// TestEndToEndBlockedRequestsNeverReachUpstream covers the request shapes the
// guard must inspect before forwarding.
func TestEndToEndBlockedRequestsNeverReachUpstream(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startGateway(t, up.srv.Listener.Addr().String(), map[string]any{
		"action":         "block",
		"max_body_size":  1 << 20,
		"oversized_body": "reject",
	})
	client := gatewayClient()
	defer client.CloseIdleConnections()

	for i, tc := range []struct {
		name    string
		build   func() *http.Request
		wantErr bool
	}{
		{
			name: "query string injection",
			build: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/?id=1%20union%20select%20password", nil)
				return r
			},
		},
		{
			name: "double encoded query string",
			build: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/?x=%25253Cscript%25253E", nil)
				return r
			},
		},
		{
			name: "header payload",
			build: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
				r.Header.Set("X-Forwarded-Forerunner", `<script>alert(1)</script>`)
				return r
			},
		},
		{
			name: "cookie payload",
			build: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
				r.AddCookie(&http.Cookie{Name: "sid", Value: "1 union select 2"})
				return r
			},
		},
		{
			name: "form body payload",
			build: func() *http.Request {
				r, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/",
					strings.NewReader("ok=1&evil="+urlEncode("' OR 1=1 --")))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
		},
		{
			name: "json nested payload",
			build: func() *http.Request {
				r, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/",
					strings.NewReader(`{"a":{"b":["ok","<svg/onload=alert(1)>"]}}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
		},
		{
			name: "multipart payload",
			build: func() *http.Request {
				var b bytes.Buffer
				mw := multipart.NewWriter(&b)
				fw, _ := mw.CreateFormField("ok")
				fw.Write([]byte("fine"))
				fw, _ = mw.CreateFormField("evil")
				fw.Write([]byte("1 union select 2"))
				mw.Close()
				r, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", &b)
				r.Header.Set("Content-Type", mw.FormDataContentType())
				return r
			},
		},
		{
			name: "compressed body payload",
			build: func() *http.Request {
				var b bytes.Buffer
				zw := gzip.NewWriter(&b)
				zw.Write([]byte("value=" + urlEncode("' OR 1=1 --")))
				zw.Close()
				r, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", &b)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Content-Encoding", "gzip")
				return r
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _, _ := up.snapshot()
			resp, err := client.Do(tc.build())
			if err != nil {
				t.Fatalf("Test %d: request failed: %v", i, err)
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("Test %d: status = %d, want %d", i, resp.StatusCode, http.StatusForbidden)
			}
			after, _, _ := up.snapshot()
			if after != before {
				t.Errorf("Test %d: blocked request reached the upstream (%d -> %d hits)", i, before, after)
			}
			if resp.Header.Get("X-Request-Guard-Reason") == "" {
				t.Errorf("Test %d: reason header missing", i)
			}
			if resp.Header.Get("X-Request-Guard-Request-Id") == "" {
				t.Errorf("Test %d: request id header missing", i)
			}
		})
	}
}

func urlEncode(s string) string {
	// minimal encoding for the shapes used above
	r := strings.NewReplacer(" ", "%20", "'", "%27", "<", "%3C", ">", "%3E")
	return r.Replace(s)
}

// TestEndToEndCleanRequestsArriveUnchanged proves the guard is transparent for
// clean traffic across several body shapes.
func TestEndToEndCleanRequestsArriveUnchanged(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startGateway(t, up.srv.Listener.Addr().String(), map[string]any{
		"action":         "block",
		"max_body_size":  1 << 20,
		"oversized_body": "reject",
	})
	client := gatewayClient()
	defer client.CloseIdleConnections()

	for i, tc := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "json", contentType: "application/json", body: `{"name":"Alice","tags":["a","b"]}`},
		{name: "form", contentType: "application/x-www-form-urlencoded", body: "name=Alice&age=30"},
		{name: "text with binary bytes", contentType: "application/octet-stream", body: string([]byte{0, 1, 2, 250, 251, 252})},
		{name: "empty", contentType: "text/plain", body: ""},
		{name: "large clean json", contentType: "application/json", body: `{"blob":"` + strings.Repeat("a", 100<<10) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _, _ := up.snapshot()
			req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/api", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Test %d: request failed: %v", i, err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Test %d: status = %d, want 200", i, resp.StatusCode)
			}
			after, lastBody, _ := up.snapshot()
			if after != before+1 {
				t.Fatalf("Test %d: upstream hits = %d, want %d", i, after, before+1)
			}
			if string(lastBody) != tc.body {
				t.Errorf("Test %d: upstream body differs: got %d bytes, want %d", i, len(lastBody), len(tc.body))
			}
			if string(got) != tc.body {
				t.Errorf("Test %d: echoed body differs: got %d bytes, want %d", i, len(got), len(tc.body))
			}
		})
	}
}

// TestEndToEndCompressedReplay proves a clean compressed body is forwarded to
// the upstream still compressed, byte-for-byte.
func TestEndToEndCompressedReplay(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startGateway(t, up.srv.Listener.Addr().String(), map[string]any{
		"action":         "block",
		"max_body_size":  1 << 20,
		"oversized_body": "reject",
	})
	client := gatewayClient()
	defer client.CloseIdleConnections()

	payload := `{"name":"Alice"}`
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(payload))
	zw.Close()
	compressed := b.Bytes()

	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	_, lastBody, _ := up.snapshot()
	if !bytes.Equal(lastBody, compressed) {
		t.Errorf("upstream did not receive the original compressed bytes (%d vs %d)", len(lastBody), len(compressed))
	}
}

// TestEndToEndChunkedBody exercises a body with no declared length.
func TestEndToEndChunkedBody(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startGateway(t, up.srv.Listener.Addr().String(), map[string]any{
		"action":         "block",
		"max_body_size":  1 << 20,
		"oversized_body": "reject",
	})
	client := gatewayClient()
	defer client.CloseIdleConnections()

	body := `{"name":"Alice","note":"` + strings.Repeat("x", 64<<10) + `"}`
	pr, pw := io.Pipe()
	go func() {
		// write in chunks so the body is genuinely chunked
		for i := 0; i < len(body); i += 1024 {
			end := min(i+1024, len(body))
			pw.Write([]byte(body[i:end]))
		}
		pw.Close()
	}()

	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", pr)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1 // force chunked transfer
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	_, lastBody, _ := up.snapshot()
	if string(lastBody) != body {
		t.Errorf("chunked body changed: got %d bytes, want %d", len(lastBody), len(body))
	}
}

// TestEndToEndBytesDoNotChangeUnderEncoding proves that a body containing
// percent-like and plus characters is forwarded exactly.
func TestEndToEndBytesDoNotChangeUnderEncoding(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startGateway(t, up.srv.Listener.Addr().String(), map[string]any{
		"action":         "block",
		"max_body_size":  1 << 20,
		"oversized_body": "reject",
	})
	client := gatewayClient()
	defer client.CloseIdleConnections()

	body := "a+b%2Bc%2525d%zz+e=f&g=h"
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	_, lastBody, _ := up.snapshot()
	if string(lastBody) != body {
		t.Errorf("body changed: got %q, want %q", lastBody, body)
	}
}

// TestEndToEndFramingPreserved proves the guard does not force a buffered
// upstream transfer: a fixed-length upload keeps its Content-Length, and a
// body with no declared length stays chunked.
func TestEndToEndFramingPreserved(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startGateway(t, up.srv.Listener.Addr().String(), map[string]any{
		"action":         "block",
		"max_body_size":  1 << 20,
		"oversized_body": "reject",
	})
	client := gatewayClient()
	defer client.CloseIdleConnections()

	// fixed length
	body := strings.Repeat("x", 4096)
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if cl, te := up.framing(); cl != int64(len(body)) || len(te) != 0 {
		t.Errorf("fixed-length upload framing changed: ContentLength=%d TransferEncoding=%v", cl, te)
	}

	// no declared length
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte(body))
		pw.Close()
	}()
	req, _ = http.NewRequest(http.MethodPost, "http://"+addr+"/", pr)
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = -1
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("chunked request failed: %v", err)
	}
	resp.Body.Close()
	if cl, te := up.framing(); cl != -1 || len(te) == 0 || te[0] != "chunked" {
		t.Errorf("chunked upload framing changed: ContentLength=%d TransferEncoding=%v", cl, te)
	}
}
