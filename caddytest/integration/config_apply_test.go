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

package integration

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

type applyBlockHandler struct{}

var applyBlockHook struct {
	sync.Mutex
	entered  chan struct{}
	canceled chan struct{}
}

type applyWaitHandler struct{}

var applyWaitHook struct {
	sync.Mutex
	entered chan struct{}
	release chan struct{}
}

func (applyWaitHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apply_wait",
		New: func() caddy.Module { return new(applyWaitHandler) },
	}
}

func (applyWaitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	applyWaitHook.Lock()
	entered, release := applyWaitHook.entered, applyWaitHook.release
	applyWaitHook.Unlock()
	if entered != nil {
		select {
		case <-entered:
		default:
			close(entered)
		}
	}

	_, _ = io.WriteString(w, "before\n")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	if release != nil {
		select {
		case <-release:
		case <-r.Context().Done():
			return nil
		}
	}
	_, _ = io.WriteString(w, "after\n")
	return nil
}

func (applyBlockHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apply_block",
		New: func() caddy.Module { return new(applyBlockHandler) },
	}
}

func (applyBlockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	applyBlockHook.Lock()
	entered, canceled := applyBlockHook.entered, applyBlockHook.canceled
	applyBlockHook.Unlock()
	if entered != nil {
		select {
		case <-entered:
		default:
			close(entered)
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "before\n")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	<-r.Context().Done()
	if canceled != nil {
		select {
		case <-canceled:
		default:
			close(canceled)
		}
	}
	return nil
}

type applyFailApp struct{}

var applyFailHook struct {
	sync.Mutex
	reached chan struct{}
	release chan struct{}
}

func (applyFailApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tx_apply_fail",
		New: func() caddy.Module { return new(applyFailApp) },
	}
}

func (applyFailApp) Start() error {
	applyFailHook.Lock()
	reached, release := applyFailHook.reached, applyFailHook.release
	applyFailHook.Unlock()
	if reached != nil {
		select {
		case <-reached:
		default:
			close(reached)
		}
	}
	if release != nil {
		<-release
	}
	return fmt.Errorf("injected module start failure")
}

func (applyFailApp) Stop() error { return nil }

func init() {
	caddy.RegisterModule(applyBlockHandler{})
	caddy.RegisterModule(applyWaitHandler{})
	caddy.RegisterModule(applyFailApp{})
}

func TestConfigApplySuccessDrainsInFlightRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	applyWaitHook.Lock()
	applyWaitHook.entered = entered
	applyWaitHook.release = release
	applyWaitHook.Unlock()
	t.Cleanup(func() {
		_ = caddy.Stop()
		applyWaitHook.Lock()
		applyWaitHook.entered = nil
		applyWaitHook.release = nil
		applyWaitHook.Unlock()
	})

	const baseline = `{
		"admin":{"disabled":true,"config":{"apply":{"enabled":true,"drain_timeout":"2s"}}},
		"apps":{"http":{"servers":{"old":{
			"listen":[":9082"],
			"automatic_https":{"disable":true},
			"routes":[{"handle":[{"handler":"apply_wait"}]}]
		}}}}
	}`
	if err := caddy.Load([]byte(baseline), true); err != nil {
		t.Fatalf("loading baseline config: %v", err)
	}

	type requestResult struct {
		body string
		err  error
	}
	requestDone := make(chan requestResult, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://localhost:9082/")
		if err != nil {
			requestDone <- requestResult{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		requestDone <- requestResult{body: string(body), err: err}
	}()

	select {
	case <-entered:
	case result := <-requestDone:
		t.Fatalf("request ended before it became in-flight: %v", result.err)
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the old handler")
	}

	const candidate = `{
		"admin":{"disabled":true,"config":{"apply":{"enabled":true,"drain_timeout":"2s"}}},
		"apps":{"http":{"servers":{"new":{
			"listen":[":9082"],
			"automatic_https":{"disable":true},
			"routes":[{"handle":[{"handler":"static_response","body":"new"}]}]
		}}}}
	}`
	loadDone := make(chan error, 1)
	start := time.Now()
	go func() { loadDone <- caddy.Load([]byte(candidate), true) }()

	select {
	case err := <-loadDone:
		t.Fatalf("config apply returned before the old request drained: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)

	select {
	case result := <-requestDone:
		if result.err != nil {
			t.Fatalf("in-flight request failed during successful apply: %v", result.err)
		}
		if result.body != "before\nafter\n" {
			t.Fatalf("in-flight response body = %q", result.body)
		}
		t.Logf("old in-flight request completed after %s", time.Since(start))
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	select {
	case err := <-loadDone:
		if err != nil {
			t.Fatalf("config apply failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("config apply did not finish after the old request drained")
	}

	resp, err := http.Get("http://localhost:9082/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new" {
		t.Fatalf("new config body = %q, want new", body)
	}
}

func TestConfigApplyRollbackDrainsInFlightAndStopsAccepting(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	entered := make(chan struct{})
	canceled := make(chan struct{})
	reached := make(chan struct{})
	release := make(chan struct{})
	applyBlockHook.Lock()
	applyBlockHook.entered = entered
	applyBlockHook.canceled = canceled
	applyBlockHook.Unlock()
	applyFailHook.Lock()
	applyFailHook.reached = reached
	applyFailHook.release = release
	applyFailHook.Unlock()

	t.Cleanup(func() {
		_ = caddy.Stop()
		applyBlockHook.Lock()
		applyBlockHook.entered = nil
		applyBlockHook.canceled = nil
		applyBlockHook.Unlock()
		applyFailHook.Lock()
		applyFailHook.reached = nil
		applyFailHook.release = nil
		applyFailHook.Unlock()
	})

	const baseline = `{
		"admin":{"disabled":true,"config":{"apply":{"enabled":true,"drain_timeout":"500ms"}}},
		"apps":{"http":{"servers":{"old":{
			"listen":[":9080"],
			"automatic_https":{"disable":true},
			"routes":[{"handle":[{"handler":"static_response","body":"old"}]}]
		}}}}
	}`
	if err := caddy.Load([]byte(baseline), true); err != nil {
		t.Fatalf("loading baseline config: %v", err)
	}

	const candidate = `{
		"admin":{"disabled":true,"config":{"apply":{"enabled":true,"drain_timeout":"500ms"}}},
		"apps":{
			"http":{"servers":{
				"old":{
					"listen":[":9080"],
					"automatic_https":{"disable":true},
					"routes":[{"handle":[{"handler":"static_response","body":"old"}]}]
				},
				"candidate":{
					"listen":[":9081"],
					"automatic_https":{"disable":true},
					"routes":[{"handle":[{"handler":"apply_block"}]}]
				}
			}},
			"tx_apply_fail":{}
		}
	}`

	loadErr := make(chan error, 1)
	start := time.Now()
	go func() { loadErr <- caddy.Load([]byte(candidate), true) }()

	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("candidate did not reach the injected failing module")
	}

	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://localhost:9081/")
		if err != nil {
			requestDone <- err
			return
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		requestDone <- err
	}()

	select {
	case <-entered:
	case err := <-requestDone:
		t.Fatalf("in-flight request ended before it was established: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not reach the candidate HTTP app")
	}

	close(release)
	select {
	case err := <-loadErr:
		if err == nil {
			t.Fatal("candidate load unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("candidate load did not finish")
	}
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
		t.Fatalf("rollback returned after %s, before the drain timeout", elapsed)
	}

	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request was not force-closed after the drain timeout")
	}
	select {
	case err := <-requestDone:
		if err == nil {
			t.Fatal("in-flight request completed successfully instead of being force-closed")
		}
		t.Logf("in-flight request was forced closed after %s: %v", time.Since(start), err)
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not return after force-close")
	}

	status := caddy.CurrentConfigApplyStatus()
	if status.State != caddy.ConfigApplyStateRolledBack {
		t.Fatalf("state = %s, want rolled_back: %+v", status.State, status)
	}
	stageNames := make([]string, len(status.Stages))
	for i, stage := range status.Stages {
		stageNames[i] = fmt.Sprintf("%s=%s(%s)", stage.Name, stage.Status, stage.Duration)
	}
	t.Logf("config apply stages: %v", stageNames)

	waitForPortClosed(t, "127.0.0.1:9081", 2*time.Second)

	resp, err := http.Get("http://localhost:9080/")
	if err != nil {
		t.Fatalf("old config stopped serving: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "old" {
		t.Fatalf("old config body = %q, want old", body)
	}
}

func waitForPortClosed(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("port %s still accepts connections after rollback", addr)
}
