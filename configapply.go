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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// ConfigApplyState describes the result of a transactional config apply.
type ConfigApplyState string

const (
	ConfigApplyStateIdle           ConfigApplyState = "idle"
	ConfigApplyStateApplying       ConfigApplyState = "applying"
	ConfigApplyStateCommitted      ConfigApplyState = "committed"
	ConfigApplyStateRolledBack     ConfigApplyState = "rolled_back"
	ConfigApplyStateRollbackFailed ConfigApplyState = "rollback_failed"
	ConfigApplyStateRecovered      ConfigApplyState = "recovered"
)

// ConfigApplyStageStatus describes one observable stage of a config apply.
type ConfigApplyStageStatus struct {
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Started  time.Time     `json:"started"`
	Finished time.Time     `json:"finished"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

// ConfigApplyStatus is a snapshot of the most recent transactional config
// apply. It is safe to encode as JSON.
type ConfigApplyStatus struct {
	State         ConfigApplyState         `json:"state"`
	Enabled       bool                     `json:"enabled"`
	Generation    uint64                   `json:"generation"`
	CurrentStage  string                   `json:"current_stage,omitempty"`
	Started       time.Time                `json:"started,omitzero"`
	Finished      time.Time                `json:"finished,omitzero"`
	Duration      time.Duration            `json:"duration"`
	Stages        []ConfigApplyStageStatus `json:"stages,omitempty"`
	Error         string                   `json:"error,omitempty"`
	RollbackError string                   `json:"rollback_error,omitempty"`
	FailedStage   string                   `json:"failed_stage,omitempty"`

	CandidateConfigBytes  int    `json:"candidate_config_bytes,omitempty"`
	PreviousConfigBytes   int    `json:"previous_config_bytes,omitempty"`
	CandidateConfigSHA256 string `json:"candidate_config_sha256,omitempty"`
	PreviousConfigSHA256  string `json:"previous_config_sha256,omitempty"`

	// Snapshots are populated only when rollback fails so operators can
	// inspect exactly what was being applied when the transaction stopped.
	CandidateSnapshot json.RawMessage `json:"candidate_snapshot,omitempty"`
	PreviousSnapshot  json.RawMessage `json:"previous_snapshot,omitempty"`
	SnapshotDir       string          `json:"snapshot_dir,omitempty"`
	SnapshotError     string          `json:"snapshot_error,omitempty"`

	Blocked       bool      `json:"blocked"`
	BlockedReason string    `json:"blocked_reason,omitempty"`
	RecoveredAt   time.Time `json:"recovered_at,omitzero"`
}

// CurrentConfigApplyStatus returns the status of the most recent transactional
// config apply. The returned value is a deep copy.
func CurrentConfigApplyStatus() ConfigApplyStatus {
	configApplyStatusMu.RLock()
	defer configApplyStatusMu.RUnlock()
	return cloneConfigApplyStatus(configApplyStatus)
}

// RecoverConfigApply clears a rollback-failure block after an operator has
// inspected and cleaned up the preserved snapshots.
func RecoverConfigApply() error {
	configApplyStatusMu.Lock()
	defer configApplyStatusMu.Unlock()

	if configApplyBlock == nil {
		return fmt.Errorf("config apply is not blocked")
	}

	snapshotDir := configApplyStatus.SnapshotDir
	if snapshotDir != "" {
		if err := os.RemoveAll(snapshotDir); err != nil {
			return fmt.Errorf("removing failed apply snapshots: %v", err)
		}
	}

	configApplyStatus.State = ConfigApplyStateRecovered
	configApplyStatus.Blocked = false
	configApplyStatus.BlockedReason = ""
	configApplyStatus.RecoveredAt = time.Now()
	configApplyStatus.SnapshotDir = ""

	configApplyBlock = nil
	return nil
}

// ContextStopper is an optional interface implemented by apps that can stop
// using a caller-provided context. Transactional config application uses this
// to enforce a bounded drain and to force convergence when the deadline ends.
//
// EXPERIMENTAL: This API is subject to change.
type ContextStopper interface {
	StopContext(context.Context) error
}

type configApplyTransaction struct {
	currentStage string
}

type configApplyBlockInfo struct {
	stage       string
	rollbackErr error
}

var (
	configApplyStatusMu sync.RWMutex
	configApplyStatus   = ConfigApplyStatus{State: ConfigApplyStateIdle}
	configApplyBlock    *configApplyBlockInfo
	configApplyGen      uint64
)

func configApplyPolicyFor(previous, next *Config) ConfigApply {
	var policy ConfigApply
	if previous != nil {
		policy = previous.configApplyPolicy()
	}
	if next != nil {
		nextPolicy := next.configApplyPolicy()
		policy.Enabled = policy.Enabled || nextPolicy.Enabled
		if nextPolicy.DrainTimeout != 0 {
			policy.DrainTimeout = nextPolicy.DrainTimeout
		}
	}
	if policy.DrainTimeout == 0 {
		policy.DrainTimeout = Duration(DefaultConfigApplyDrainTimeout)
	}
	return policy
}

func (cfg *Config) configApplyPolicy() ConfigApply {
	if cfg == nil || cfg.Admin == nil || cfg.Admin.Config == nil || cfg.Admin.Config.Apply == nil {
		return ConfigApply{}
	}
	return *cfg.Admin.Config.Apply
}

func configApplyPolicyEnabled(cfg *Config) bool {
	return cfg.configApplyPolicy().Enabled
}

func configApplyBlockedError() error {
	configApplyStatusMu.RLock()
	defer configApplyStatusMu.RUnlock()
	if configApplyBlock == nil {
		return nil
	}
	return APIError{
		HTTPStatus: http.StatusConflict,
		Err: fmt.Errorf("config apply is blocked after rollback failure at stage %q: %v",
			configApplyBlock.stage, configApplyBlock.rollbackErr),
	}
}

func beginConfigApplyTransaction(candidate, previous []byte, policy ConfigApply) *configApplyTransaction {
	now := time.Now()
	configApplyStatusMu.Lock()
	configApplyGen++
	configApplyStatus = ConfigApplyStatus{
		State:                 ConfigApplyStateApplying,
		Enabled:               policy.Enabled,
		Generation:            configApplyGen,
		Started:               now,
		CandidateConfigBytes:  len(candidate),
		PreviousConfigBytes:   len(previous),
		CandidateConfigSHA256: configSHA256(candidate),
		PreviousConfigSHA256:  configSHA256(previous),
	}
	configApplyStatusMu.Unlock()

	return new(configApplyTransaction)
}

func (tx *configApplyTransaction) beginStage(name string) time.Time {
	now := time.Now()
	tx.currentStage = name

	configApplyStatusMu.Lock()
	configApplyStatus.Stages = append(configApplyStatus.Stages, ConfigApplyStageStatus{
		Name:    name,
		Status:  "running",
		Started: now,
	})
	configApplyStatus.CurrentStage = name
	configApplyStatusMu.Unlock()
	return now
}

func (tx *configApplyTransaction) finishStage(started time.Time, err error) {
	now := time.Now()
	status := "completed"
	errStr := ""
	if err != nil {
		status = "failed"
		errStr = err.Error()
	}
	updateStage := func(stages []ConfigApplyStageStatus) {
		for i := len(stages) - 1; i >= 0; i-- {
			if stages[i].Name == tx.currentStage && stages[i].Status == "running" {
				stages[i].Status = status
				stages[i].Finished = now
				stages[i].Duration = now.Sub(started)
				stages[i].Error = errStr
				return
			}
		}
	}

	configApplyStatusMu.Lock()
	updateStage(configApplyStatus.Stages)
	configApplyStatus.CurrentStage = ""
	configApplyStatusMu.Unlock()

	Log().Named("config_apply").Debug("config apply stage finished",
		zap.String("stage", tx.currentStage),
		zap.String("status", status),
		zap.Duration("duration", now.Sub(started)),
		zap.Error(err))
}

func (tx *configApplyTransaction) finish(state ConfigApplyState, failedStage string, err, rollbackErr error) {
	now := time.Now()
	configApplyStatusMu.Lock()
	configApplyStatus.State = state
	configApplyStatus.CurrentStage = ""
	configApplyStatus.FailedStage = failedStage
	configApplyStatus.Finished = now
	configApplyStatus.Duration = now.Sub(configApplyStatus.Started)
	if err != nil {
		configApplyStatus.Error = err.Error()
	}
	if rollbackErr != nil {
		configApplyStatus.RollbackError = rollbackErr.Error()
	}
	configApplyStatusMu.Unlock()
}

func (tx *configApplyTransaction) failRollback(stage string, stageErr, rollbackErr error, candidate, previous []byte) {
	snapshotDir, snapshotErr := writeConfigApplyFailureSnapshots(stage, stageErr, rollbackErr, candidate, previous)
	now := time.Now()

	configApplyStatusMu.Lock()
	configApplyStatus.State = ConfigApplyStateRollbackFailed
	configApplyStatus.CurrentStage = ""
	configApplyStatus.Finished = now
	configApplyStatus.Duration = now.Sub(configApplyStatus.Started)
	configApplyStatus.Error = stageErr.Error()
	configApplyStatus.RollbackError = rollbackErr.Error()
	configApplyStatus.FailedStage = stage
	configApplyStatus.CandidateSnapshot = cloneBytes(candidate)
	configApplyStatus.PreviousSnapshot = cloneBytes(previous)
	configApplyStatus.SnapshotDir = snapshotDir
	if snapshotErr != nil {
		configApplyStatus.SnapshotError = snapshotErr.Error()
	}
	configApplyStatus.Blocked = true
	configApplyStatus.BlockedReason = fmt.Sprintf("rollback failed at stage %q: %v", stage, rollbackErr)
	configApplyBlock = &configApplyBlockInfo{
		stage:       stage,
		rollbackErr: rollbackErr,
	}
	configApplyStatusMu.Unlock()

	logger := Log().Named("config_apply")
	logger.Error("CONFIG APPLY BLOCKED: rollback failed",
		zap.String("failed_stage", stage),
		zap.Error(stageErr),
		zap.Error(rollbackErr),
		zap.String("snapshot_dir", snapshotDir),
		zap.Error(snapshotErr))
}

func applyConfigTransaction(candidateJSON []byte, candidateCfg *Config, candidateErr error, previousJSON []byte, allowPersist bool) (err error) {
	previousCtx := ActiveContext()
	policy := configApplyPolicyFor(previousCtx.cfg, candidateCfg)
	tx := beginConfigApplyTransaction(candidateJSON, previousJSON, policy)

	var (
		ctx     Context
		started []string
		finish  *configFinishPlan
	)

	rollback := func(failedStage string, cause error) error {
		startedAt := tx.beginStage("rollback")
		var rollbackErrs []error

		if finish != nil {
			if rbErr := finish.Rollback(); rbErr != nil {
				rollbackErrs = append(rollbackErrs, rbErr)
			}
		}
		if ctx.cfg != nil {
			if rbErr := stopConfigApps(ctx, started, time.Duration(policy.DrainTimeout),
				fmt.Errorf("rolling back config apply after %s: %w", failedStage, cause)); rbErr != nil {
				rollbackErrs = append(rollbackErrs, rbErr)
			}
		}
		restoreCertMagicStorage(previousCtx)

		rollbackErr := errors.Join(rollbackErrs...)
		tx.finishStage(startedAt, rollbackErr)
		if rollbackErr != nil {
			tx.failRollback(failedStage, cause, rollbackErr, candidateJSON, previousJSON)
			return fmt.Errorf("%w (rollback failed: %v)", cause, rollbackErr)
		}

		tx.finish(ConfigApplyStateRolledBack, failedStage, cause, nil)
		Log().Named("config_apply").Warn("config apply rolled back",
			zap.String("failed_stage", failedStage),
			zap.Error(cause),
			zap.Duration("drain_timeout", time.Duration(policy.DrainTimeout)))
		return cause
	}

	stageStart := tx.beginStage("snapshot")
	tx.finishStage(stageStart, nil)

	stageStart = tx.beginStage("validate")
	var validateErr error
	switch {
	case candidateErr != nil:
		validateErr = candidateErr
	case policy.DrainTimeout < 0:
		validateErr = fmt.Errorf("apply drain_timeout must not be negative")
	default:
		validateErr = validateConfigLoadPolicy(candidateCfg, allowPersist)
	}
	tx.finishStage(stageStart, validateErr)
	if validateErr != nil {
		return rollback("validate", validateErr)
	}

	stageStart = tx.beginStage("provision")
	ctx, err = provisionContext(candidateCfg, false)
	tx.finishStage(stageStart, err)
	if err != nil {
		return rollback("provision", err)
	}

	stageStart = tx.beginStage("start")
	started, err = startAppsOrdered(ctx, true)
	tx.finishStage(stageStart, err)
	if err != nil {
		return rollback("start", err)
	}

	stageStart = tx.beginStage("finalize")
	finish, err = prepareConfigFinish(ctx, candidateCfg)
	tx.finishStage(stageStart, err)
	if err != nil {
		return rollback("finalize", err)
	}

	stageStart = tx.beginStage("commit")
	currentCtxMu.Lock()
	previousCtx = currentCtx
	currentCtx = ctx
	currentCtxMu.Unlock()
	finish.Commit()
	tx.finishStage(stageStart, nil)

	globalMetrics.configSuccess.Set(1)
	globalMetrics.configSuccessTime.SetToCurrentTime()
	ctx.emitEvent("started", nil)

	stageStart = tx.beginStage("drain_old")
	oldAppNames := make([]string, 0)
	if previousCtx.cfg != nil {
		oldAppNames = make([]string, 0, len(previousCtx.cfg.apps))
		for name := range previousCtx.cfg.apps {
			oldAppNames = append(oldAppNames, name)
		}
	}
	drainErr := stopConfigApps(previousCtx, oldAppNames, time.Duration(policy.DrainTimeout),
		fmt.Errorf("transactional config apply committed"))
	tx.finishStage(stageStart, drainErr)
	if drainErr != nil {
		Log().Named("config_apply").Error("previous configuration did not drain cleanly after commit",
			zap.Error(drainErr))
	}

	tx.finish(ConfigApplyStateCommitted, "", nil, nil)
	autosaveConfig(candidateJSON, candidateCfg, allowPersist)
	Log().Named("config_apply").Info("config apply committed",
		zap.Duration("duration", tx.statusDuration()),
		zap.Duration("drain_timeout", time.Duration(policy.DrainTimeout)))
	return nil
}

func (tx *configApplyTransaction) statusDuration() time.Duration {
	configApplyStatusMu.RLock()
	defer configApplyStatusMu.RUnlock()
	if configApplyStatus.Started.IsZero() {
		return 0
	}
	return time.Since(configApplyStatus.Started)
}

type configFinishPlan struct {
	identity *preparedIdentity
	remote   *preparedRemoteAdminServer
	local    *preparedLocalAdminServer
	loader   *preparedConfigLoader
}

func prepareConfigFinish(ctx Context, cfg *Config) (*configFinishPlan, error) {
	plan := new(configFinishPlan)

	identity, err := prepareIdentity(ctx, cfg)
	if err != nil {
		return nil, err
	}
	plan.identity = identity

	remote, err := prepareRemoteAdminServer(ctx, cfg)
	if err != nil {
		_ = plan.Rollback()
		return nil, err
	}
	plan.remote = remote

	local, err := prepareLocalAdminServer(cfg, ctx)
	if err != nil {
		_ = plan.Rollback()
		return nil, err
	}
	plan.local = local

	loader, err := prepareConfigLoader(ctx, cfg)
	if err != nil {
		_ = plan.Rollback()
		return nil, err
	}
	plan.loader = loader

	return plan, nil
}

func (p *configFinishPlan) Commit() {
	if p == nil {
		return
	}
	if p.identity != nil {
		p.identity.Commit()
	}
	if p.remote != nil {
		p.remote.Commit()
	}
	if p.local != nil {
		p.local.Commit()
	}
	if p.loader != nil {
		p.loader.Commit()
	}
}

func (p *configFinishPlan) Rollback() error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.loader != nil {
		if err := p.loader.Rollback(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.local != nil {
		if err := p.local.Rollback(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.remote != nil {
		if err := p.remote.Rollback(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.identity != nil {
		p.identity.Rollback()
	}
	return errors.Join(errs...)
}

type preparedConfigLoader struct {
	ctx     Context
	val     any
	logger  *zap.Logger
	delay   time.Duration
	loaded  []byte
	hasLoad bool
}

func prepareConfigLoader(ctx Context, cfg *Config) (*preparedConfigLoader, error) {
	if cfg == nil || cfg.Admin == nil || cfg.Admin.Config == nil || cfg.Admin.Config.LoadRaw == nil {
		return nil, nil
	}

	val, err := ctx.LoadModule(cfg.Admin.Config, "LoadRaw")
	if err != nil {
		return nil, fmt.Errorf("loading config loader module: %s", err)
	}

	prepared := &preparedConfigLoader{
		ctx:   ctx,
		val:   val,
		delay: time.Duration(cfg.Admin.Config.LoadDelay),
		logger: Log().Named("config_loader").With(
			zap.String("module", val.(Module).CaddyModule().ID.Name()),
			zap.Int("load_delay", int(cfg.Admin.Config.LoadDelay))),
	}

	if prepared.delay <= 0 {
		loaded, err := val.(ConfigLoader).LoadConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading dynamic config from %T: %v", val, err)
		}
		prepared.loaded = loaded
		prepared.hasLoad = true
	}
	return prepared, nil
}

func (p *preparedConfigLoader) Commit() {
	if p == nil {
		return
	}

	runLoadedConfig := func(config []byte) error {
		p.logger.Info("applying dynamically-loaded config")
		err := changeConfig(http.MethodPost, "/"+rawConfigKey, config, "", false)
		if errors.Is(err, errSameConfig) {
			return err
		}
		if err != nil {
			p.logger.Error("failed to run dynamically-loaded config", zap.Error(err))
			return err
		}
		p.logger.Info("successfully applied dynamically-loaded config")
		return nil
	}

	if p.delay > 0 {
		go func() {
			for {
				timer := time.NewTimer(p.delay)
				select {
				case <-timer.C:
					loadedConfig, err := p.val.(ConfigLoader).LoadConfig(p.ctx)
					if err != nil {
						p.logger.Error("failed loading dynamic config; will retry", zap.Error(err))
						continue
					}
					if loadedConfig == nil {
						p.logger.Info("dynamically-loaded config was nil; will retry")
						continue
					}
					err = runLoadedConfig(loadedConfig)
					if errors.Is(err, errSameConfig) {
						p.logger.Info("dynamically-loaded config was unchanged; will retry")
						continue
					}
				case <-p.ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					p.logger.Info("stopping dynamic config loading")
				}
				break
			}
		}()
		return
	}

	if p.hasLoad {
		go func() { _ = runLoadedConfig(p.loaded) }()
	}
}

func (p *preparedConfigLoader) Rollback() error {
	return nil
}

func writeConfigApplyFailureSnapshots(stage string, stageErr, rollbackErr error, candidate, previous []byte) (string, error) {
	baseDir := filepath.Dir(ConfigAutosavePath)
	if baseDir == "" || baseDir == "." {
		baseDir = os.TempDir()
	}
	snapshotDir := filepath.Join(baseDir, "apply-failed")
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		return "", err
	}

	status := CurrentConfigApplyStatus()
	status.State = ConfigApplyStateRollbackFailed
	status.CurrentStage = ""
	status.Error = stageErr.Error()
	status.RollbackError = rollbackErr.Error()
	status.Finished = time.Now()
	status.Duration = status.Finished.Sub(status.Started)
	status.FailedStage = stage
	status.SnapshotDir = snapshotDir
	status.Blocked = true
	status.BlockedReason = fmt.Sprintf("rollback failed at stage %q: %v", stage, rollbackErr)

	write := func(name string, data []byte) error {
		if data == nil {
			return nil
		}
		return os.WriteFile(filepath.Join(snapshotDir, name), data, 0o600)
	}
	if err := write("candidate.json", candidate); err != nil {
		return snapshotDir, err
	}
	if err := write("previous.json", previous); err != nil {
		return snapshotDir, err
	}
	statusBytes, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return snapshotDir, err
	}
	if err := write("status.json", statusBytes); err != nil {
		return snapshotDir, err
	}
	return snapshotDir, nil
}

func cloneConfigApplyStatus(status ConfigApplyStatus) ConfigApplyStatus {
	status.Stages = append([]ConfigApplyStageStatus(nil), status.Stages...)
	status.CandidateSnapshot = cloneBytes(status.CandidateSnapshot)
	status.PreviousSnapshot = cloneBytes(status.PreviousSnapshot)
	return status
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func configSHA256(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func stopAppContext(ctx context.Context, app App) error {
	if stopper, ok := app.(ContextStopper); ok {
		return stopper.StopContext(ctx)
	}

	done := make(chan error, 1)
	go func() {
		done <- app.Stop()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func stopConfigApps(ctx Context, names []string, timeout time.Duration, cause error) error {
	if ctx.cfg == nil {
		return nil
	}

	stopCtx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		stopCtx, cancel = context.WithTimeoutCause(stopCtx, timeout,
			fmt.Errorf("config apply drain timeout after %s", timeout))
		defer cancel()
	}

	type stopResult struct {
		name string
		err  error
	}
	results := make(chan stopResult, len(names))
	stopping := 0
	for _, name := range names {
		app, ok := ctx.cfg.apps[name]
		if !ok {
			continue
		}
		stopping++
		go func(name string, app App) {
			results <- stopResult{name: name, err: stopAppContext(stopCtx, app)}
		}(name, app)
	}

	var errs []error
	for range stopping {
		result := <-results
		if result.err != nil {
			errs = append(errs, fmt.Errorf("%s app module: stop: %w", result.name, result.err))
		}
	}

	if ctx.cfg.cancelFunc != nil {
		ctx.cfg.cancelFunc(cause)
	}
	return errors.Join(errs...)
}

func restoreCertMagicStorage(ctx Context) {
	if ctx.cfg != nil && ctx.cfg.storage != nil {
		certmagic.Default.Storage = ctx.cfg.storage
	}
}

func handleConfigApplyStatus(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}
	return writeConfigApplyStatus(w)
}

func handleConfigApplyRecover(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}
	if err := RecoverConfigApply(); err != nil {
		return APIError{
			HTTPStatus: http.StatusConflict,
			Err:        err,
		}
	}
	Log().Named("config_apply").Warn("config apply failure acknowledged; new configs accepted")
	return writeConfigApplyStatus(w)
}

func writeConfigApplyStatus(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(CurrentConfigApplyStatus())
}
