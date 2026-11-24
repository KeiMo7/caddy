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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// startProxyWithRoutes loads a Caddy instance whose route list is exactly the
// given handlers, so a test can compose request_body and request_guard.
func startProxyWithRoutes(t *testing.T, upstreamAddr string, handlers []map[string]any) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg, err := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{"http": map[string]any{
			"grace_period": 1,
			"servers": map[string]any{"test": map[string]any{
				"listen":          []string{addr},
				"automatic_https": map[string]any{"disable": true},
				"routes":          []any{map[string]any{"handle": handlers}},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("marshaling config: %v", err)
	}
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	return addr
}

// TestRequestBodySizeLimitStillWins proves that the existing request_body
// max_size behaviour is preserved: a body over that limit still gets 413 with
// request_guard in the chain, and the guard does not mask the status.
func TestRequestBodySizeLimitStillWins(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startProxyWithRoutes(t, up.srv.Listener.Addr().String(), []map[string]any{
		{"handler": "request_body", "max_size": 1024},
		{"handler": "request_guard", "action": "block", "max_body_size": 1 << 20},
		{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": up.srv.Listener.Addr().String()}}},
	})

	client := gatewayClient()
	defer client.CloseIdleConnections()

	body := strings.Repeat("a", 8192)
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 from request_body", resp.StatusCode)
	}
	if hits, _, _ := up.snapshot(); hits != 0 {
		t.Errorf("oversized body reached the upstream (%d hits)", hits)
	}
}

// TestRouteWithoutGuardIsUnchanged proves that adding a separate route with no
// request_guard does not change that route's behaviour.
func TestRouteWithoutGuardIsUnchanged(t *testing.T) {
	up := newFakeUpstream(t)
	// The guard lives only on the /guarded route; /open has no guard at all.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	guard := map[string]any{"handler": "request_guard", "action": "block"}
	proxy := map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": up.srv.Listener.Addr().String()}}}
	cfg, _ := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{"http": map[string]any{
			"grace_period": 1,
			"servers": map[string]any{"test": map[string]any{
				"listen":          []string{addr},
				"automatic_https": map[string]any{"disable": true},
				"routes": []any{
					map[string]any{"match": []any{map[string]any{"path": []string{"/guarded"}}}, "handle": []any{guard, proxy}},
					map[string]any{"handle": []any{proxy}},
				},
			}},
		}},
	})
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	client := gatewayClient()
	defer client.CloseIdleConnections()

	// A payload on the unguarded route must pass through untouched.
	before, _, _ := up.snapshot()
	resp, err := client.Get("http://" + addr + "/open?q=" + "<script>")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unguarded route status = %d, want 200", resp.StatusCode)
	}
	after, _, _ := up.snapshot()
	if after != before+1 {
		t.Errorf("unguarded request did not reach upstream as before (%d -> %d)", before, after)
	}

	// The same payload on the guarded route must be blocked.
	resp, err = client.Get("http://" + addr + "/guarded?q=" + "%3Cscript%3E")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("guarded route status = %d, want 403", resp.StatusCode)
	}
}

// TestChunkedUploadNoContentLengthAcrossGuard proves a chunked upload with no
// declared length still arrives intact and is not forced into a buffered path
// that changes its framing.
func TestChunkedUploadNoContentLengthAcrossGuard(t *testing.T) {
	up := newFakeUpstream(t)
	addr := startGateway(t, up.srv.Listener.Addr().String(), map[string]any{
		"action":         "block",
		"max_body_size":  1 << 20,
		"oversized_body": "reject",
	})
	client := gatewayClient()
	defer client.CloseIdleConnections()

	body := strings.Repeat("0123456789", 5000)
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < len(body); i += 777 {
			end := min(i+777, len(body))
			pw.Write([]byte(body[i:end]))
		}
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/", pr)
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = -1
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	_, lastBody, _ := up.snapshot()
	if string(lastBody) != body {
		t.Errorf("chunked body changed: got %d bytes, want %d", len(lastBody), len(body))
	}
}
