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

package caddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type txTestApp struct {
	Value     string `json:"value,omitempty"`
	FailStart bool   `json:"fail_start,omitempty"`
	StopError bool   `json:"stop_error,omitempty"`
	StopWait  bool   `json:"stop_wait,omitempty"`
}

type (
	txTestAppDrain struct{ txTestApp }
	txTestAppFail  struct{ txTestApp }
)

func (txTestApp) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "tx_test",
		New: func() Module { return new(txTestApp) },
	}
}

func (txTestAppDrain) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "tx_drain",
		New: func() Module { return new(txTestAppDrain) },
	}
}

func (txTestAppFail) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "tx_fail",
		New: func() Module { return new(txTestAppFail) },
	}
}

func (a *txTestApp) Start() error {
	txTestHooks.start(a.Value, "tx_test")
	if a.FailStart {
		return fmt.Errorf("injected start failure")
	}
	return nil
}

func (a *txTestApp) Stop() error {
	if a.StopError {
		return fmt.Errorf("injected stop failure")
	}
	return nil
}

func (a *txTestApp) StopContext(ctx context.Context) error {
	if a.StopWait {
		<-ctx.Done()
		txTestHooks.forcedStop(a.Value)
		return nil
	}
	return a.Stop()
}

func (a *txTestAppDrain) Start() error {
	txTestHooks.start(a.Value, "tx_drain")
	if a.FailStart {
		return fmt.Errorf("injected drain start failure")
	}
	return nil
}

func (a *txTestAppDrain) Stop() error {
	if a.StopError {
		return fmt.Errorf("injected drain stop failure")
	}
	return nil
}

func (a *txTestAppDrain) StopContext(ctx context.Context) error {
	if a.StopWait {
		<-ctx.Done()
		txTestHooks.forcedStop(a.Value)
		return nil
	}
	return a.Stop()
}

func (a *txTestAppFail) Start() error {
	txTestHooks.start(a.Value, "tx_fail")
	if a.FailStart {
		return fmt.Errorf("injected start failure")
	}
	return nil
}

func (a *txTestAppFail) Stop() error {
	if a.StopError {
		return fmt.Errorf("injected stop failure")
	}
	return nil
}

func init() {
	RegisterModule(txTestApp{})
	RegisterModule(txTestAppDrain{})
	RegisterModule(txTestAppFail{})
}

type txTestHooksState struct {
	sync.Mutex
	startOrder []string
	blocks     map[string]chan struct{}
	reached    map[string]chan struct{}
	forced     map[string]int
}

var txTestHooks = txTestHooksState{
	blocks:  make(map[string]chan struct{}),
	reached: make(map[string]chan struct{}),
	forced:  make(map[string]int),
}

func (h *txTestHooksState) reset() {
	h.Lock()
	defer h.Unlock()
	h.startOrder = nil
	h.blocks = make(map[string]chan struct{})
	h.reached = make(map[string]chan struct{})
	h.forced = make(map[string]int)
}

func (h *txTestHooksState) start(value, moduleID string) {
	h.Lock()
	h.startOrder = append(h.startOrder, moduleID+":"+value)
	block := h.blocks[value]
	reached := h.reached[value]
	h.Unlock()
	if reached != nil {
		select {
		case <-reached:
		default:
			close(reached)
		}
	}
	if block != nil {
		<-block
	}
}

func (h *txTestHooksState) forcedStop(value string) {
	h.Lock()
	h.forced[value]++
	h.Unlock()
}

func (h *txTestHooksState) order() []string {
	h.Lock()
	defer h.Unlock()
	return slices.Clone(h.startOrder)
}

func (h *txTestHooksState) forcedCount(value string) int {
	h.Lock()
	defer h.Unlock()
	return h.forced[value]
}

func TestConfigApplySuccess(t *testing.T) {
	resetConfigApplyTest(t)

	loadTransactionalConfig(t, `{"value":"old"}`)
	loadTransactionalConfig(t, `{"value":"new"}`)

	status := CurrentConfigApplyStatus()
	if status.State != ConfigApplyStateCommitted {
		t.Fatalf("state = %s, want %s: %+v", status.State, ConfigApplyStateCommitted, status)
	}
	if got := activeTxValue(t); got != "new" {
		t.Fatalf("active value = %q, want new", got)
	}
	assertStageOrder(t, status,
		"snapshot", "validate", "provision", "start", "finalize", "commit", "drain_old")
	for _, stage := range status.Stages {
		if stage.Status != "completed" {
			t.Errorf("stage %s status = %s, want completed", stage.Name, stage.Status)
		}
		if stage.Duration <= 0 {
			t.Errorf("stage %s duration = %s, want > 0", stage.Name, stage.Duration)
		}
	}
}

func TestConfigApplyStartFailureRollsBack(t *testing.T) {
	resetConfigApplyTest(t)

	loadTransactionalConfig(t, `{"value":"old"}`)
	err := Load(transactionalConfigJSONMulti(t, map[string]string{
		"tx_test": `{"value":"candidate"}`,
		"tx_fail": `{"fail_start":true}`,
	}), true)
	if err == nil {
		t.Fatal("expected start failure")
	}
	if !strings.Contains(err.Error(), "injected start failure") {
		t.Fatalf("unexpected error: %v", err)
	}

	status := CurrentConfigApplyStatus()
	if status.State != ConfigApplyStateRolledBack {
		t.Fatalf("state = %s, want rolled_back: %+v", status.State, status)
	}
	if status.Blocked {
		t.Fatal("rollback unexpectedly blocked config apply")
	}
	if got := activeTxValue(t); got != "old" {
		t.Fatalf("active value = %q, want old", got)
	}
	assertStageOrder(t, status,
		"snapshot", "validate", "provision", "start", "rollback")
	if status.Stages[3].Status != "failed" {
		t.Fatalf("start stage status = %s, want failed", status.Stages[3].Status)
	}
}

func TestConfigApplyPreflightRejectsUnknownModuleAndField(t *testing.T) {
	resetConfigApplyTest(t)
	loadTransactionalConfig(t, `{"value":"old"}`)

	for _, tc := range []struct {
		name string
		cfg  []byte
		want string
	}{
		{
			name: "unknown module",
			cfg: []byte(`{
				"admin":{"disabled":true,"config":{"apply":{"enabled":true,"drain_timeout":"50ms"}}},
				"apps":{"tx_test":{"value":"old"},"does_not_exist":{}}
			}`),
			want: "unknown module: does_not_exist",
		},
		{
			name: "unknown field",
			cfg: []byte(`{
				"admin":{"disabled":true,"config":{"apply":{"enabled":true,"drain_timeout":"50ms"}}},
				"apps":{"tx_test":{"value":"candidate","not_a_field":true}}
			}`),
			want: "unknown field",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Load(tc.cfg, true)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
			status := CurrentConfigApplyStatus()
			if status.State != ConfigApplyStateRolledBack {
				t.Fatalf("state = %s, want rolled_back", status.State)
			}
			if got := activeTxValue(t); got != "old" {
				t.Fatalf("active value = %q, want old", got)
			}
		})
	}
}

func TestConfigApplyTopLevelDecodeFailureIsObservable(t *testing.T) {
	resetConfigApplyTest(t)
	loadTransactionalConfig(t, `{"value":"old"}`)

	err := Load([]byte(`{
		"admin":{"disabled":true,"config":{"apply":{"enabled":true}}},
		"unknown_top_level":true,
		"apps":{"tx_test":{"value":"candidate"}}
	}`), true)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown field", err)
	}
	status := CurrentConfigApplyStatus()
	if status.State != ConfigApplyStateRolledBack {
		t.Fatalf("state = %s, want rolled_back", status.State)
	}
	if status.Stages[len(status.Stages)-2].Name != "validate" ||
		status.Stages[len(status.Stages)-2].Status != "failed" {
		t.Fatalf("unexpected stages: %+v", status.Stages)
	}
	if got := activeTxValue(t); got != "old" {
		t.Fatalf("active value = %q, want old", got)
	}
}

func TestConfigApplyRejectsNegativeDrainTimeout(t *testing.T) {
	resetConfigApplyTest(t)
	loadTransactionalConfig(t, `{"value":"old"}`)

	cfg := []byte(`{
		"admin":{"disabled":true,"config":{"apply":{"enabled":true,"drain_timeout":"-1s"}}},
		"apps":{"tx_test":{"value":"candidate"}}
	}`)
	err := Load(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("error = %v, want negative drain timeout", err)
	}
	status := CurrentConfigApplyStatus()
	if status.State != ConfigApplyStateRolledBack || status.FailedStage != "validate" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if got := activeTxValue(t); got != "old" {
		t.Fatalf("active value = %q, want old", got)
	}
}

func TestConfigApplyStatusAdminRoute(t *testing.T) {
	resetConfigApplyTest(t)
	loadTransactionalConfig(t, `{"value":"old"}`)

	addr, err := ParseNetworkAddress("localhost:2019")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := (&AdminConfig{}).newAdminHandler(addr, false, Context{})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/config/apply/status", nil)
	req.Host = "localhost:2019"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", rec.Code, rec.Body.String())
	}
	var status ConfigApplyStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.State != ConfigApplyStateCommitted || len(status.Stages) == 0 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestConfigApplyRollbackFailureBlocksUntilRecovery(t *testing.T) {
	resetConfigApplyTest(t)
	setAutosavePath(t)

	loadTransactionalConfig(t, `{"value":"old"}`)

	err := Load(transactionalConfigJSONMulti(t, map[string]string{
		"tx_drain": `{"value":"drain","stop_error":true}`,
		"tx_fail":  `{"value":"fail","fail_start":true}`,
	}), true)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failure, got %v", err)
	}

	status := CurrentConfigApplyStatus()
	if status.State != ConfigApplyStateRollbackFailed || !status.Blocked {
		t.Fatalf("state = %s blocked=%t, want rollback_failed/blocked: %+v", status.State, status.Blocked, status)
	}
	if status.FailedStage != "start" {
		t.Fatalf("failed stage = %q, want start", status.FailedStage)
	}
	if len(status.CandidateSnapshot) == 0 || len(status.PreviousSnapshot) == 0 {
		t.Fatal("rollback failure did not preserve config snapshots")
	}
	for _, name := range []string{"candidate.json", "previous.json", "status.json"} {
		if _, err := os.Stat(filepath.Join(status.SnapshotDir, name)); err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
		}
	}
	if got := activeTxValue(t); got != "old" {
		t.Fatalf("active value = %q, want old", got)
	}

	err = Load(transactionalConfigJSON(t, `{"value":"rejected"}`), true)
	var apiErr APIError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != 409 {
		t.Fatalf("blocked load error = %v, want HTTP 409 APIError", err)
	}

	if err := RecoverConfigApply(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(status.SnapshotDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot dir still exists after recovery: %v", err)
	}
	loadTransactionalConfig(t, `{"value":"after-recovery"}`)
	if got := activeTxValue(t); got != "after-recovery" {
		t.Fatalf("active value = %q, want after-recovery", got)
	}
}

func TestConfigApplyRollbackDrainForcesConvergence(t *testing.T) {
	resetConfigApplyTest(t)
	loadTransactionalConfig(t, `{"value":"old"}`)

	start := time.Now()
	err := Load(transactionalConfigJSONMulti(t, map[string]string{
		"tx_drain": `{"value":"draining","stop_wait":true}`,
		"tx_fail":  `{"value":"fail","fail_start":true}`,
	}), true)
	if err == nil {
		t.Fatal("expected candidate failure")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("rollback returned before the drain deadline: %s", elapsed)
	}
	if got := txTestHooks.forcedCount("draining"); got != 1 {
		t.Fatalf("forced stop count = %d, want 1", got)
	}
	status := CurrentConfigApplyStatus()
	if status.State != ConfigApplyStateRolledBack {
		t.Fatalf("state = %s, want rolled_back: %+v", status.State, status)
	}
	if got := activeTxValue(t); got != "old" {
		t.Fatalf("active value = %q, want old", got)
	}
}

func TestConfigApplyConcurrentPushesUseFinalState(t *testing.T) {
	resetConfigApplyTest(t)
	loadTransactionalConfig(t, `{"value":"old"}`)

	block := make(chan struct{})
	reached := make(chan struct{})
	txTestHooks.Lock()
	txTestHooks.blocks["first"] = block
	txTestHooks.reached["first"] = reached
	txTestHooks.Unlock()

	firstJSON := transactionalConfigJSON(t, `{"value":"first"}`)
	firstErr := make(chan error, 1)
	go func() { firstErr <- Load(firstJSON, true) }()

	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("first push did not reach app start")
	}

	secondJSON := transactionalConfigJSON(t, `{"value":"second"}`)
	secondErr := make(chan error, 1)
	go func() { secondErr <- Load(secondJSON, true) }()

	select {
	case <-secondErr:
		t.Fatal("second push completed while the first push was still in its start stage")
	case <-time.After(50 * time.Millisecond):
	}

	close(block)
	if err := <-firstErr; err != nil {
		t.Fatalf("first push: %v", err)
	}
	if err := <-secondErr; err != nil {
		t.Fatalf("second push: %v", err)
	}

	status := CurrentConfigApplyStatus()
	if status.State != ConfigApplyStateCommitted {
		t.Fatalf("state = %s, want committed", status.State)
	}
	if status.PreviousConfigSHA256 != configSHA256(firstJSON) {
		t.Fatalf("second push did not start from first push's final config")
	}
	if got := activeTxValue(t); got != "second" {
		t.Fatalf("active value = %q, want second", got)
	}
	if got := txTestHooks.order(); !slices.Equal(got, []string{"tx_test:old", "tx_test:first", "tx_test:second"}) {
		t.Fatalf("start order = %v", got)
	}
	t.Logf("second push generation=%d previous=%s order=%v",
		status.Generation, status.PreviousConfigSHA256[:12], txTestHooks.order())
}

func resetConfigApplyTest(t *testing.T) {
	t.Helper()
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	txTestHooks.reset()
	originalAutosavePath := ConfigAutosavePath
	ConfigAutosavePath = filepath.Join(t.TempDir(), "autosave.json")

	configApplyStatusMu.Lock()
	configApplyStatus = ConfigApplyStatus{State: ConfigApplyStateIdle}
	configApplyBlock = nil
	configApplyGen = 0
	configApplyStatusMu.Unlock()

	t.Cleanup(func() {
		_ = Stop()
		configApplyStatusMu.Lock()
		configApplyStatus = ConfigApplyStatus{State: ConfigApplyStateIdle}
		configApplyBlock = nil
		configApplyGen = 0
		configApplyStatusMu.Unlock()
		txTestHooks.reset()
		ConfigAutosavePath = originalAutosavePath
	})
}

func setAutosavePath(t *testing.T) {
	t.Helper()
	ConfigAutosavePath = filepath.Join(t.TempDir(), "autosave.json")
}

func loadTransactionalConfig(t *testing.T, appCfg string) {
	t.Helper()
	if err := Load(transactionalConfigJSON(t, appCfg), true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
}

func transactionalConfigJSON(t *testing.T, apps ...string) []byte {
	t.Helper()
	appMap := make(map[string]json.RawMessage, len(apps))
	for i, app := range apps {
		appMap[[]string{"tx_test", "tx_drain", "tx_fail"}[i]] = json.RawMessage(app)
	}
	return transactionalConfigJSONWithApps(t, appMap)
}

func transactionalConfigJSONMulti(t *testing.T, apps map[string]string) []byte {
	t.Helper()
	appMap := make(map[string]json.RawMessage, len(apps))
	for name, cfg := range apps {
		appMap[name] = json.RawMessage(cfg)
	}
	return transactionalConfigJSONWithApps(t, appMap)
}

func transactionalConfigJSONWithApps(t *testing.T, appMap map[string]json.RawMessage) []byte {
	t.Helper()
	cfg, err := json.Marshal(map[string]any{
		"admin": map[string]any{
			"disabled": true,
			"config": map[string]any{
				"apply": map[string]any{
					"enabled":       true,
					"drain_timeout": "50ms",
				},
			},
		},
		"apps": appMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func activeTxValue(t *testing.T) string {
	t.Helper()
	ctx := ActiveContext()
	if ctx.cfg == nil {
		t.Fatal("no active config")
	}
	app, ok := ctx.cfg.apps["tx_test"]
	if !ok {
		t.Fatal("tx_test app is not active")
	}
	return app.(*txTestApp).Value
}

func assertStageOrder(t *testing.T, status ConfigApplyStatus, want ...string) {
	t.Helper()
	got := make([]string, len(status.Stages))
	for i, stage := range status.Stages {
		got[i] = stage.Name
	}
	if !slices.Equal(got, want) {
		t.Fatalf("stage order = %v, want %v", got, want)
	}
}
