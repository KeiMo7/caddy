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

package reverseproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

func newActiveHealthTestHandler(t *testing.T, addresses []string, active *ActiveHealthChecks) (*Handler, UpstreamPool, context.CancelFunc) {
	t.Helper()
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	eventsApp := new(caddyevents.App)
	if err := eventsApp.Provision(caddyCtx); err != nil {
		t.Fatalf("provisioning events app: %v", err)
	}

	pool := make(UpstreamPool, 0, len(addresses))
	for _, address := range addresses {
		pool = append(pool, &Upstream{Dial: address})
	}
	h := &Handler{
		ctx:          caddyCtx,
		logger:       zap.NewNop(),
		events:       eventsApp,
		Upstreams:    pool,
		HealthChecks: &HealthChecks{Active: active},
	}
	for _, upstream := range pool {
		h.provisionUpstream(upstream, false)
	}
	if err := active.Provision(caddyCtx, h); err != nil {
		cancel()
		t.Fatalf("provisioning active health checks: %v", err)
	}
	t.Cleanup(func() {
		unregisterHealthStates(h)
		cancel()
		for _, upstream := range pool {
			_, _ = hosts.Delete(upstream.Dial)
		}
	})
	return h, pool, cancel
}

func TestActiveHealthCheckOverlappingProbeIsNotCountedTwice(t *testing.T) {
	var requests atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	address := strings.TrimPrefix(server.URL, "http://")
	h, u, cancel := newActiveHandler(t, address, "/health", 1)
	defer cancel()
	defer drainHostsPool()

	dialInfo, err := u.fillDialInfo(caddy.NewReplacer())
	if err != nil {
		t.Fatalf("filling dial info: %v", err)
	}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- h.doActiveHealthCheck(dialInfo, dialInfo.Address, u.Dial, u)
	}()
	<-entered

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- h.doActiveHealthCheck(dialInfo, dialInfo.Address, u.Dial, u)
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("overlapping probe returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("overlapping probe was not skipped")
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first probe returned error: %v", err)
	}

	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	if got := u.overlapSkipped.Load(); got != 1 {
		t.Fatalf("overlap skips = %d, want 1", got)
	}
	snapshot := u.healthState.Snapshot(time.Now())
	if len(snapshot.Results) != 1 {
		t.Fatalf("recorded results = %d, want 1", len(snapshot.Results))
	}
	if snapshot.Results[0].Outcome != HealthCheckPass {
		t.Fatalf("recorded outcome = %q, want %q", snapshot.Results[0].Outcome, HealthCheckPass)
	}
}

func TestActiveHealthCheckTimeoutIsRecordedSeparately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	address := strings.TrimPrefix(server.URL, "http://")
	h, pool, _ := newActiveHealthTestHandler(t, []string{address}, &ActiveHealthChecks{
		URI:     "/health",
		Fails:   2,
		Passes:  1,
		Timeout: caddy.Duration(25 * time.Millisecond),
	})

	runActiveHealthCheck(t, h, pool[0])
	snapshot := pool[0].healthState.Snapshot(time.Now())
	if len(snapshot.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(snapshot.Results))
	}
	if snapshot.Results[0].Outcome != HealthCheckTimeout {
		t.Fatalf("outcome = %q, want %q", snapshot.Results[0].Outcome, HealthCheckTimeout)
	}
	if snapshot.TotalTimeouts != 1 || snapshot.TotalBusinessFailures != 0 {
		t.Fatalf("timeout/business totals = %d/%d, want 1/0",
			snapshot.TotalTimeouts, snapshot.TotalBusinessFailures)
	}
	if snapshot.State != HealthStateHealthy {
		t.Fatalf("one timeout crossed threshold unexpectedly: state=%s", snapshot.State)
	}
}

func TestActiveHealthCheckGroupsOverrideThresholdsAndObservation(t *testing.T) {
	addresses := []string{"10.94.10.1:80", "10.94.10.2:80"}
	active := &ActiveHealthChecks{
		URI:    "/health",
		Fails:  2,
		Passes: 2,
		Groups: map[string]*ActiveHealthGroup{
			"critical": {
				Upstreams: []string{addresses[0]},
				Fails:     5,
				FlapDetection: &FlapDetection{
					Observation: caddy.Duration(45 * time.Second),
				},
			},
			"best-effort": {
				Upstreams: []string{addresses[1]},
				Fails:     1,
				Passes:    3,
				FlapDetection: &FlapDetection{
					Observation: caddy.Duration(10 * time.Second),
				},
			},
		},
	}
	_, pool, _ := newActiveHealthTestHandler(t, addresses, active)

	if pool[0].HealthGroup != "critical" {
		t.Fatalf("upstream 0 group = %q, want critical", pool[0].HealthGroup)
	}
	if pool[1].HealthGroup != "best-effort" {
		t.Fatalf("upstream 1 group = %q, want best-effort", pool[1].HealthGroup)
	}
	if got := pool[0].healthState.cfg.Fails; got != 5 {
		t.Errorf("critical fails = %d, want 5", got)
	}
	if got := pool[0].healthState.cfg.Observation; got != 45*time.Second {
		t.Errorf("critical observation = %s, want 45s", got)
	}
	if got := pool[1].healthState.cfg.Fails; got != 1 {
		t.Errorf("best-effort fails = %d, want 1", got)
	}
	if got := pool[1].healthState.cfg.Passes; got != 3 {
		t.Errorf("best-effort passes = %d, want 3", got)
	}
	if got := pool[1].healthState.cfg.Observation; got != 10*time.Second {
		t.Errorf("best-effort observation = %s, want 10s", got)
	}
}

func TestActiveHealthCheckAllUnhealthyFallbackSkipsManualRemoval(t *testing.T) {
	addresses := []string{"10.94.20.1:80", "10.94.20.2:80"}
	h, pool, _ := newActiveHealthTestHandler(t, addresses, &ActiveHealthChecks{
		URI:           "/health",
		Fails:         1,
		Passes:        1,
		FlapDetection: &FlapDetection{Observation: caddy.Duration(30 * time.Second)},
	})

	for _, upstream := range pool {
		upstream.setHealthy(false)
	}
	pool[0].SetManualUnhealthy(true, "maintenance")

	fallback := h.selectAllUnhealthyFallback(pool)
	if fallback == nil {
		t.Fatal("expected an all-unhealthy fallback")
	}
	if fallback != pool[1] {
		t.Fatalf("fallback = %s, want manually available upstream %s", fallback.Dial, pool[1].Dial)
	}

	pool[1].SetManualUnhealthy(true, "maintenance")
	if fallback := h.selectAllUnhealthyFallback(pool); fallback != nil {
		t.Fatalf("manual removals must not be bypassed; fallback = %s", fallback.Dial)
	}

	request := httptest.NewRequest(http.MethodPost, "/reverse_proxy/upstreams/manual",
		strings.NewReader(`{"address":"10.94.20.2:80","removed":false}`))
	response := httptest.NewRecorder()
	if err := (adminUpstreams{}).handleManualRemoval(response, request); err != nil {
		t.Fatalf("manual removal endpoint returned error: %v", err)
	}
	if response.Code != http.StatusNoContent {
		t.Fatalf("manual removal endpoint status = %d, want 204", response.Code)
	}
	if pool[1].ManualUnhealthy() {
		t.Fatal("manual removal endpoint did not clear the override")
	}
}

func TestActiveHealthAdminReadOnlyQueryDoesNotResetRecovery(t *testing.T) {
	address := "10.94.30.1:80"
	_, pool, _ := newActiveHealthTestHandler(t, []string{address}, &ActiveHealthChecks{
		URI:    "/health",
		Fails:  1,
		Passes: 1,
		FlapDetection: &FlapDetection{
			Observation: caddy.Duration(30 * time.Second),
			Ramp:        caddy.Duration(time.Minute),
		},
	})
	state := pool[0].healthState
	start := time.Unix(1_700_000_000, 0).UTC()
	observeHealthResult(state, start, HealthCheckBusinessFailure, 1)
	observeHealthResult(state, start.Add(time.Second), HealthCheckPass, 2)

	before := state.Snapshot(start.Add(2 * time.Second))
	request := httptest.NewRequest(http.MethodGet, "/reverse_proxy/health", nil)
	response := httptest.NewRecorder()
	if err := (adminUpstreams{}).handleHealth(response, request); err != nil {
		t.Fatalf("health endpoint returned error: %v", err)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("health endpoint status = %d, want 200", response.Code)
	}
	var snapshots []HealthStateSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshots); err != nil {
		t.Fatalf("decoding health endpoint: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].Address != address {
		t.Fatalf("unexpected health endpoint response: %+v", snapshots)
	}
	if len(snapshots[0].Results) != len(before.Results) {
		t.Fatalf("read-only query changed results: before=%d after=%d", len(before.Results), len(snapshots[0].Results))
	}

	transition, changed := observeHealthResult(state, start.Add(32*time.Second), HealthCheckPass, 3)
	if !changed || transition.To != HealthStateRamping {
		t.Fatalf("read-only query reset recovery timing: transition=%+v changed=%t", transition, changed)
	}

	upstreamRequest := httptest.NewRequest(http.MethodGet, "/reverse_proxy/upstreams", nil)
	upstreamResponse := httptest.NewRecorder()
	if err := (adminUpstreams{}).handleUpstreams(upstreamResponse, upstreamRequest); err != nil {
		t.Fatalf("upstreams endpoint returned error: %v", err)
	}
	if !strings.Contains(upstreamResponse.Body.String(), `"health"`) {
		t.Fatalf("upstreams response missing health summary: %s", upstreamResponse.Body.String())
	}
}

func TestActiveHealthFlapDetectionConfigValidation(t *testing.T) {
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &Handler{ctx: caddyCtx, logger: zap.NewNop()}

	var active ActiveHealthChecks
	if err := json.Unmarshal([]byte(`{"uri":"/health","flap_detection":{"observation":"0s"}}`), &active); err != nil {
		t.Fatalf("unmarshaling config: %v", err)
	}
	if err := active.Provision(caddyCtx, h); err == nil {
		t.Fatal("expected explicit zero observation to be rejected")
	}

	active = ActiveHealthChecks{}
	if err := json.Unmarshal([]byte(`{"uri":"/health","recovery_observation":"0s"}`), &active); err != nil {
		t.Fatalf("unmarshaling convenience config: %v", err)
	}
	if err := active.Provision(caddyCtx, h); err == nil {
		t.Fatal("expected explicit zero recovery_observation to be rejected")
	}

	d := caddyfile.NewTestDispenser(`
reverse_proxy 10.94.40.1:80 {
	health_uri /health
	health_flap_detection {
		observation 0s
	}
}`)
	var handler Handler
	if err := handler.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected Caddyfile zero observation to be rejected")
	}
}

func TestActiveHealthGroupCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
reverse_proxy 10.94.50.1:80 10.94.50.2:80 {
	health_uri /health
	health_flap_detection {
		observation 45s
		ramp 2m
		ramp_curve exponential
	}
	health_group critical 10.94.50.1:80 {
		fails 5
		passes 3
		observation 30s
	}
}`)

	var handler Handler
	if err := handler.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	active := handler.HealthChecks.Active
	if active.FlapDetection == nil || active.FlapDetection.Observation != caddy.Duration(45*time.Second) {
		t.Fatalf("unexpected top-level flap detection: %+v", active.FlapDetection)
	}
	group := active.Groups["critical"]
	if group == nil {
		t.Fatal("critical group was not parsed")
	}
	if len(group.Upstreams) != 1 || group.Upstreams[0] != "10.94.50.1:80" {
		t.Fatalf("critical group upstreams = %v", group.Upstreams)
	}
	if group.Fails != 5 || group.Passes != 3 {
		t.Fatalf("critical group thresholds = fails:%d passes:%d, want 5/3", group.Fails, group.Passes)
	}
	if group.FlapDetection == nil || group.FlapDetection.Observation != caddy.Duration(30*time.Second) {
		t.Fatalf("unexpected critical group flap detection: %+v", group.FlapDetection)
	}
}
