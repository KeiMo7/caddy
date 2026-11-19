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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// Active health states exposed by the state machine and the admin API.
const (
	HealthStateHealthy           = "healthy"
	HealthStateUnhealthy         = "unhealthy"
	HealthStateRecovering        = "recovering"
	HealthStateRamping           = "ramping"
	HealthStateManuallyRemoved   = "manually_removed"
	healthStateCheckInterrupted  = "interrupted"
	healthStateCheckPass         = "pass"
	healthStateCheckBusinessFail = "business_failure"
	healthStateCheckTimeout      = "timeout"
	healthStateCheckProbeFailure = "probe_failure"
)

// HealthCheckOutcome describes the result of one active health check.
type HealthCheckOutcome string

const (
	// HealthCheckPass means the probe completed and met all health criteria.
	HealthCheckPass HealthCheckOutcome = healthStateCheckPass

	// HealthCheckBusinessFailure means the probe completed, but the upstream
	// returned an unexpected status or body.
	HealthCheckBusinessFailure HealthCheckOutcome = healthStateCheckBusinessFail

	// HealthCheckTimeout means the probe did not complete before its timeout.
	HealthCheckTimeout HealthCheckOutcome = healthStateCheckTimeout

	// HealthCheckProbeFailure means the probe failed for a reason other than
	// a timeout or an application-level health response.
	HealthCheckProbeFailure HealthCheckOutcome = healthStateCheckProbeFailure

	// HealthCheckInterrupted means the probe was interrupted, for example
	// because the handler was shutting down. It does not count as a pass or
	// a failure.
	HealthCheckInterrupted HealthCheckOutcome = healthStateCheckInterrupted
)

// HealthCheckResult is one observed active health check result.
type HealthCheckResult struct {
	At       time.Time          `json:"at"`
	Outcome  HealthCheckOutcome `json:"outcome"`
	Success  bool               `json:"success"`
	Duration time.Duration      `json:"duration,omitempty"`
	Error    string             `json:"error,omitempty"`
	ProbeID  uint64             `json:"probe_id,omitempty"`
}

func (r HealthCheckResult) failed() bool {
	switch r.Outcome {
	case HealthCheckBusinessFailure, HealthCheckTimeout, HealthCheckProbeFailure:
		return true
	}
	return false
}

// HealthTransition is an immutable record of an automatic or manual health
// state transition. CheckResults is a bounded snapshot of the results known
// when the transition happened.
type HealthTransition struct {
	At                  time.Time           `json:"at"`
	From                string              `json:"from"`
	To                  string              `json:"to"`
	Reason              string              `json:"reason"`
	Automatic           bool                `json:"automatic"`
	FailureKind         HealthCheckOutcome  `json:"failure_kind,omitempty"`
	CheckResults        []HealthCheckResult `json:"check_results"`
	TransitionsInWindow int                 `json:"transitions_in_window"`
	Flapping            bool                `json:"flapping"`
	LoadFactor          float64             `json:"load_factor"`
}

// HealthStateSnapshot is a read-only snapshot suitable for monitoring and
// dashboards. Taking a snapshot never performs a health check and never
// changes state timers.
type HealthStateSnapshot struct {
	Address                     string              `json:"address,omitempty"`
	Group                       string              `json:"group,omitempty"`
	State                       string              `json:"state"`
	AutomaticState              string              `json:"automatic_state"`
	Reason                      string              `json:"reason,omitempty"`
	Since                       time.Time           `json:"since,omitempty"`
	Available                   bool                `json:"available"`
	LoadFactor                  float64             `json:"load_factor"`
	ManualRemoval               bool                `json:"manual_removal"`
	ManualReason                string              `json:"manual_reason,omitempty"`
	ManualSince                 time.Time           `json:"manual_since,omitempty"`
	ConsecutiveFailures         int                 `json:"consecutive_failures"`
	ConsecutiveTimeouts         int                 `json:"consecutive_timeouts"`
	ConsecutiveBusinessFailures int                 `json:"consecutive_business_failures"`
	ConsecutiveProbeFailures    int                 `json:"consecutive_probe_failures"`
	ConsecutivePasses           int                 `json:"consecutive_passes"`
	TotalTimeouts               int                 `json:"total_timeouts"`
	TotalBusinessFailures       int                 `json:"total_business_failures"`
	TotalProbeFailures          int                 `json:"total_probe_failures"`
	TransitionsInWindow         int                 `json:"transitions_in_window"`
	Flapping                    bool                `json:"flapping"`
	OverlapsSkipped             uint64              `json:"overlaps_skipped"`
	LastResult                  *HealthCheckResult  `json:"last_result,omitempty"`
	Results                     []HealthCheckResult `json:"results"`
	Transitions                 []HealthTransition  `json:"transitions"`
}

// HealthStateConfig configures a pure health state machine. Zero values for
// Observation and Ramp preserve the historical binary pass/fail behavior.
type HealthStateConfig struct {
	Fails                  int
	Passes                 int
	Observation            time.Duration
	Ramp                   time.Duration
	RampCurve              string
	FlapWindow             time.Duration
	FlapThreshold          int
	ResultHistoryLimit     int
	TransitionHistoryLimit int
}

func (c *HealthStateConfig) normalize() {
	if c.Fails < 1 {
		c.Fails = 1
	}
	if c.Passes < 1 {
		c.Passes = 1
	}
	if c.RampCurve == "" {
		c.RampCurve = "linear"
	}
	c.RampCurve = strings.ToLower(strings.TrimSpace(c.RampCurve))
	if c.ResultHistoryLimit < 1 {
		c.ResultHistoryLimit = 32
	}
	if c.TransitionHistoryLimit < 1 {
		c.TransitionHistoryLimit = 64
	}
}

// HealthStateMachine is a deterministic active health state machine. Feed it
// HealthCheckResult values with Observe; it never performs network I/O.
type HealthStateMachine struct {
	mu  sync.Mutex
	cfg HealthStateConfig

	address string
	group   string

	state  string
	reason string
	since  time.Time

	consecutiveFailures         int
	consecutiveTimeouts         int
	consecutiveBusinessFailures int
	consecutiveProbeFailures    int
	consecutivePasses           int

	totalTimeouts         int
	totalBusinessFailures int
	totalProbeFailures    int

	recoveryStarted time.Time
	rampStarted     time.Time

	manualRemoval bool
	manualReason  string
	manualSince   time.Time

	lastProbeID uint64
	lastResult  *HealthCheckResult
	results     []HealthCheckResult
	transitions []HealthTransition

	// transitionTimes is separate from the bounded transition history so a
	// capped history does not under-count flapping inside the rolling window.
	transitionTimes []time.Time
}

// NewHealthStateMachine returns a state machine initialized in the healthy
// state, matching the historical behavior before the first probe completes.
func NewHealthStateMachine(cfg HealthStateConfig) *HealthStateMachine {
	cfg.normalize()
	return &HealthStateMachine{
		cfg:   cfg,
		state: HealthStateHealthy,
	}
}

// SetIdentity attaches the upstream address and optional group to snapshots.
// It does not affect state transitions.
func (m *HealthStateMachine) SetIdentity(address, group string) {
	m.mu.Lock()
	m.address = address
	m.group = group
	m.mu.Unlock()
}

// Observe records one health check result. It returns true if an automatic
// transition occurred. Results with a duplicate nonzero ProbeID are ignored,
// which protects against overlapping probes being counted more than once.
func (m *HealthStateMachine) Observe(result HealthCheckResult) (HealthTransition, bool) {
	if result.At.IsZero() {
		result.At = time.Now()
	}
	if result.Outcome == "" {
		if result.Success {
			result.Outcome = HealthCheckPass
		} else {
			result.Outcome = HealthCheckProbeFailure
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if result.ProbeID != 0 {
		if result.ProbeID <= m.lastProbeID {
			return HealthTransition{}, false
		}
		m.lastProbeID = result.ProbeID
	}

	m.appendResultLocked(result)

	switch result.Outcome {
	case HealthCheckInterrupted:
		return HealthTransition{}, false

	case HealthCheckPass:
		m.recordPassLocked()
		switch m.state {
		case HealthStateUnhealthy:
			if m.consecutivePasses < m.cfg.Passes {
				return HealthTransition{}, false
			}
			return m.beginRecoveryLocked(result.At)

		case HealthStateRecovering:
			if m.cfg.Observation > 0 && result.At.Sub(m.recoveryStarted) < m.cfg.Observation {
				return HealthTransition{}, false
			}
			if m.cfg.Ramp > 0 {
				return m.transitionLocked(HealthStateRamping, "recovery observation completed; ramp started", result.At, "", true)
			}
			return m.transitionLocked(HealthStateHealthy, "recovery observation completed", result.At, "", true)

		case HealthStateRamping:
			if m.cfg.Ramp > 0 && result.At.Sub(m.rampStarted) < m.cfg.Ramp {
				return HealthTransition{}, false
			}
			return m.transitionLocked(HealthStateHealthy, "recovery ramp completed", result.At, "", true)
		}

	default:
		if !result.failed() {
			return HealthTransition{}, false
		}
		m.recordFailureLocked(result.Outcome)

		switch m.state {
		case HealthStateRecovering:
			return m.transitionLocked(HealthStateUnhealthy, "failure during recovery observation", result.At, result.Outcome, true)

		case HealthStateRamping:
			return m.transitionLocked(HealthStateUnhealthy, "failure during recovery ramp", result.At, result.Outcome, true)

		case HealthStateHealthy:
			if m.consecutiveFailures >= m.cfg.Fails {
				return m.transitionLocked(HealthStateUnhealthy, "failure threshold reached", result.At, result.Outcome, true)
			}
		}
	}

	return HealthTransition{}, false
}

// SetManualRemoval enables or disables a manual removal override. Automatic
// transitions continue to be recorded while manual removal is active, but the
// upstream remains unavailable until the override is cleared.
func (m *HealthStateMachine) SetManualRemoval(removed bool, reason string, at time.Time) (HealthTransition, bool) {
	if at.IsZero() {
		at = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.manualRemoval == removed {
		if removed && reason != "" {
			m.manualReason = reason
		}
		return HealthTransition{}, false
	}

	from := m.state
	to := HealthStateManuallyRemoved
	if removed {
		m.manualRemoval = true
		m.manualReason = reason
		m.manualSince = at
	} else {
		from = HealthStateManuallyRemoved
		to = m.state
		m.manualRemoval = false
		m.manualReason = ""
		m.manualSince = time.Time{}
	}

	transition := m.newTransitionLocked(from, to, reason, at, "", false)
	m.appendTransitionLocked(transition)
	return transition, true
}

// Snapshot returns a consistent, read-only view of the current state.
func (m *HealthStateMachine) Snapshot(now time.Time) HealthStateSnapshot {
	if now.IsZero() {
		now = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.state
	if m.manualRemoval {
		state = HealthStateManuallyRemoved
	}

	transitionsInWindow := m.transitionsInWindowLocked(now)
	loadFactor := m.loadFactorLocked(now)
	resultSnapshot := append([]HealthCheckResult(nil), m.results...)
	transitionSnapshot := append([]HealthTransition(nil), m.transitions...)
	if resultSnapshot == nil {
		resultSnapshot = []HealthCheckResult{}
	}
	if transitionSnapshot == nil {
		transitionSnapshot = []HealthTransition{}
	}
	for i := range transitionSnapshot {
		transitionSnapshot[i].CheckResults = append([]HealthCheckResult(nil), transitionSnapshot[i].CheckResults...)
	}

	var lastResult *HealthCheckResult
	if m.lastResult != nil {
		copied := *m.lastResult
		lastResult = &copied
	}

	return HealthStateSnapshot{
		Address:                     m.address,
		Group:                       m.group,
		State:                       state,
		AutomaticState:              m.state,
		Reason:                      m.reason,
		Since:                       m.since,
		Available:                   !m.manualRemoval && loadFactor > 0,
		LoadFactor:                  loadFactor,
		ManualRemoval:               m.manualRemoval,
		ManualReason:                m.manualReason,
		ManualSince:                 m.manualSince,
		ConsecutiveFailures:         m.consecutiveFailures,
		ConsecutiveTimeouts:         m.consecutiveTimeouts,
		ConsecutiveBusinessFailures: m.consecutiveBusinessFailures,
		ConsecutiveProbeFailures:    m.consecutiveProbeFailures,
		ConsecutivePasses:           m.consecutivePasses,
		TotalTimeouts:               m.totalTimeouts,
		TotalBusinessFailures:       m.totalBusinessFailures,
		TotalProbeFailures:          m.totalProbeFailures,
		TransitionsInWindow:         transitionsInWindow,
		Flapping:                    m.cfg.FlapWindow > 0 && m.cfg.FlapThreshold > 0 && transitionsInWindow >= m.cfg.FlapThreshold,
		LastResult:                  lastResult,
		Results:                     resultSnapshot,
		Transitions:                 transitionSnapshot,
	}
}

func (m *HealthStateMachine) beginRecoveryLocked(at time.Time) (HealthTransition, bool) {
	m.recoveryStarted = at
	if m.cfg.Observation <= 0 && m.cfg.Ramp <= 0 {
		return m.transitionLocked(HealthStateHealthy, "pass threshold reached", at, "", true)
	}
	return m.transitionLocked(HealthStateRecovering, "pass threshold reached; recovery observation started", at, "", true)
}

func (m *HealthStateMachine) recordPassLocked() {
	m.consecutivePasses++
	m.consecutiveFailures = 0
	m.consecutiveTimeouts = 0
	m.consecutiveBusinessFailures = 0
	m.consecutiveProbeFailures = 0
}

func (m *HealthStateMachine) recordFailureLocked(outcome HealthCheckOutcome) {
	m.consecutivePasses = 0
	m.consecutiveFailures++
	switch outcome {
	case HealthCheckTimeout:
		m.consecutiveTimeouts++
		m.consecutiveBusinessFailures = 0
		m.consecutiveProbeFailures = 0
		m.totalTimeouts++
	case HealthCheckBusinessFailure:
		m.consecutiveBusinessFailures++
		m.consecutiveTimeouts = 0
		m.consecutiveProbeFailures = 0
		m.totalBusinessFailures++
	case HealthCheckProbeFailure:
		m.consecutiveProbeFailures++
		m.consecutiveTimeouts = 0
		m.consecutiveBusinessFailures = 0
		m.totalProbeFailures++
	}
}

func (m *HealthStateMachine) appendResultLocked(result HealthCheckResult) {
	m.lastResult = &result
	m.results = append(m.results, result)
	if overflow := len(m.results) - m.cfg.ResultHistoryLimit; overflow > 0 {
		copy(m.results, m.results[overflow:])
		m.results = m.results[:len(m.results)-overflow]
	}
}

func (m *HealthStateMachine) transitionLocked(to, reason string, at time.Time, failureKind HealthCheckOutcome, automatic bool) (HealthTransition, bool) {
	if m.state == to {
		return HealthTransition{}, false
	}

	if to == HealthStateRamping {
		m.rampStarted = at
	}
	transition := m.newTransitionLocked(m.state, to, reason, at, failureKind, automatic)
	m.state = to
	m.reason = reason
	m.since = at
	switch to {
	case HealthStateHealthy:
		m.recoveryStarted = time.Time{}
		m.rampStarted = time.Time{}
		m.consecutiveFailures = 0
		m.consecutiveTimeouts = 0
		m.consecutiveBusinessFailures = 0
		m.consecutiveProbeFailures = 0
		m.consecutivePasses = 0
	case HealthStateUnhealthy:
		m.recoveryStarted = time.Time{}
		m.rampStarted = time.Time{}
	}

	m.appendTransitionLocked(transition)
	return transition, true
}

func (m *HealthStateMachine) newTransitionLocked(from, to, reason string, at time.Time, failureKind HealthCheckOutcome, automatic bool) HealthTransition {
	transitionsInWindow := m.transitionsInWindowLocked(at)
	if automatic {
		transitionsInWindow++
	}
	checkResults := append([]HealthCheckResult(nil), m.results...)
	if checkResults == nil {
		checkResults = []HealthCheckResult{}
	}
	loadFactor := m.loadFactorAtLocked(to, at)
	if m.manualRemoval {
		loadFactor = 0
	}
	return HealthTransition{
		At:                  at,
		From:                from,
		To:                  to,
		Reason:              reason,
		Automatic:           automatic,
		FailureKind:         failureKind,
		CheckResults:        checkResults,
		TransitionsInWindow: transitionsInWindow,
		Flapping:            m.cfg.FlapWindow > 0 && m.cfg.FlapThreshold > 0 && transitionsInWindow >= m.cfg.FlapThreshold,
		LoadFactor:          loadFactor,
	}
}

func (m *HealthStateMachine) appendTransitionLocked(transition HealthTransition) {
	m.transitions = append(m.transitions, transition)
	if overflow := len(m.transitions) - m.cfg.TransitionHistoryLimit; overflow > 0 {
		copy(m.transitions, m.transitions[overflow:])
		m.transitions = m.transitions[:len(m.transitions)-overflow]
	}
	if transition.Automatic {
		m.transitionTimes = append(m.transitionTimes, transition.At)
		m.pruneTransitionTimesLocked(transition.At)
	}
}

func (m *HealthStateMachine) transitionsInWindowLocked(now time.Time) int {
	if m.cfg.FlapWindow <= 0 {
		return 0
	}
	cutoff := now.Add(-m.cfg.FlapWindow)
	var count int
	for _, at := range m.transitionTimes {
		if !at.Before(cutoff) {
			count++
		}
	}
	return count
}

func (m *HealthStateMachine) pruneTransitionTimesLocked(now time.Time) {
	if m.cfg.FlapWindow <= 0 {
		m.transitionTimes = nil
		return
	}
	cutoff := now.Add(-m.cfg.FlapWindow)
	first := 0
	for first < len(m.transitionTimes) && m.transitionTimes[first].Before(cutoff) {
		first++
	}
	if first > 0 {
		copy(m.transitionTimes, m.transitionTimes[first:])
		m.transitionTimes = m.transitionTimes[:len(m.transitionTimes)-first]
	}

	// Keep a hard bound even under pathological configurations. This is far
	// above any realistic probe rate for a 10-minute window.
	const maxTransitionTimes = 8192
	if overflow := len(m.transitionTimes) - maxTransitionTimes; overflow > 0 {
		copy(m.transitionTimes, m.transitionTimes[overflow:])
		m.transitionTimes = m.transitionTimes[:len(m.transitionTimes)-overflow]
	}
}

func (m *HealthStateMachine) loadFactorLocked(now time.Time) float64 {
	if m.manualRemoval {
		return 0
	}
	return m.loadFactorAtLocked(m.state, now)
}

func (m *HealthStateMachine) loadFactorAtLocked(state string, now time.Time) float64 {
	switch state {
	case HealthStateHealthy:
		return 1
	case HealthStateRamping:
		if m.cfg.Ramp <= 0 {
			return 1
		}
		elapsed := now.Sub(m.rampStarted)
		if elapsed <= 0 {
			return recoveryRampFactor(m.cfg.RampCurve, 0)
		}
		if elapsed >= m.cfg.Ramp {
			return 1
		}
		return recoveryRampFactor(m.cfg.RampCurve, float64(elapsed)/float64(m.cfg.Ramp))
	default:
		return 0
	}
}

func recoveryRampFactor(curve string, progress float64) float64 {
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	switch curve {
	case "exponential":
		return 0.1 + 0.9*progress*progress
	case "step":
		switch {
		case progress < 1.0/3.0:
			return 0.25
		case progress < 2.0/3.0:
			return 0.5
		default:
			return 0.75
		}
	default:
		return 0.1 + 0.9*progress
	}
}

// FlapDetection configures flap suppression for active health checks. The
// presence of this object enables recovery observation and a gradual traffic
// ramp. If it is nil, active health checks retain their historical behavior.
type FlapDetection struct {
	// Window is the rolling window used to count state transitions. Default 10m.
	Window caddy.Duration `json:"window,omitempty"`

	// Threshold is the number of transitions within Window after which the
	// upstream is reported as flapping. Default 4.
	Threshold int `json:"threshold,omitempty"`

	// Observation is how long an upstream must keep passing before traffic is
	// admitted again. Must be greater than zero when explicitly configured.
	// Default 30s.
	Observation caddy.Duration `json:"observation,omitempty"`

	// Ramp is how long traffic is gradually increased after observation.
	// Default 1m. Set to zero explicitly to restore full traffic immediately
	// after observation.
	Ramp caddy.Duration `json:"ramp,omitempty"`

	// RampCurve controls gradual traffic admission after observation.
	// Supported values are "linear" (default), "exponential", and "step".
	RampCurve string `json:"ramp_curve,omitempty"`

	// ResultHistory is the maximum number of recent probe results retained.
	// Default 32.
	ResultHistory int `json:"result_history,omitempty"`

	// TransitionHistory is the maximum number of transition records retained.
	// Default 64.
	TransitionHistory int `json:"transition_history,omitempty"`

	windowSet            bool
	thresholdSet         bool
	observationSet       bool
	rampSet              bool
	resultHistorySet     bool
	transitionHistorySet bool
}

// UnmarshalJSON tracks which optional fields were explicitly configured so
// invalid explicit zero values can be rejected instead of silently defaulted.
func (f *FlapDetection) UnmarshalJSON(data []byte) error {
	type alias FlapDetection
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*f = FlapDetection(decoded)
	_, f.windowSet = raw["window"]
	_, f.thresholdSet = raw["threshold"]
	_, f.observationSet = raw["observation"]
	_, f.rampSet = raw["ramp"]
	_, f.resultHistorySet = raw["result_history"]
	_, f.transitionHistorySet = raw["transition_history"]
	return nil
}

func (f *FlapDetection) provision() error {
	if f == nil {
		return nil
	}
	if f.Window < 0 || (f.windowSet && f.Window <= 0) {
		return fmt.Errorf("flap_detection.window must be greater than zero")
	}
	if f.Window == 0 {
		f.Window = caddy.Duration(10 * time.Minute)
	}
	if f.Threshold < 0 || (f.thresholdSet && f.Threshold < 1) {
		return fmt.Errorf("flap_detection.threshold must be at least 1")
	}
	if f.Threshold == 0 {
		f.Threshold = 4
	}
	if f.Observation < 0 || (f.observationSet && f.Observation <= 0) {
		return fmt.Errorf("flap_detection.observation must be greater than zero")
	}
	if f.Observation == 0 {
		f.Observation = caddy.Duration(30 * time.Second)
	}
	if f.Ramp < 0 {
		return fmt.Errorf("flap_detection.ramp cannot be negative")
	}
	if !f.rampSet && f.Ramp == 0 {
		f.Ramp = caddy.Duration(time.Minute)
	}
	f.RampCurve = strings.ToLower(strings.TrimSpace(f.RampCurve))
	if f.RampCurve == "" {
		f.RampCurve = "linear"
	}
	switch f.RampCurve {
	case "linear", "exponential", "step":
	default:
		return fmt.Errorf("flap_detection.ramp_curve must be one of linear, exponential, or step")
	}
	if f.ResultHistory < 0 || (f.resultHistorySet && f.ResultHistory < 1) {
		return fmt.Errorf("flap_detection.result_history must be at least 1")
	}
	if f.ResultHistory == 0 {
		f.ResultHistory = 32
	}
	if f.TransitionHistory < 0 || (f.transitionHistorySet && f.TransitionHistory < 1) {
		return fmt.Errorf("flap_detection.transition_history must be at least 1")
	}
	if f.TransitionHistory == 0 {
		f.TransitionHistory = 64
	}
	return nil
}

func (f *FlapDetection) stateConfig(passes, fails int) HealthStateConfig {
	if f == nil {
		return HealthStateConfig{
			Fails:                  fails,
			Passes:                 passes,
			ResultHistoryLimit:     32,
			TransitionHistoryLimit: 64,
		}
	}
	return HealthStateConfig{
		Fails:                  fails,
		Passes:                 passes,
		Observation:            time.Duration(f.Observation),
		Ramp:                   time.Duration(f.Ramp),
		RampCurve:              f.RampCurve,
		FlapWindow:             time.Duration(f.Window),
		FlapThreshold:          f.Threshold,
		ResultHistoryLimit:     f.ResultHistory,
		TransitionHistoryLimit: f.TransitionHistory,
	}
}
