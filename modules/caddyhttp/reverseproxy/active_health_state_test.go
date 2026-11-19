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
	"testing"
	"time"
)

func testHealthStateConfig() HealthStateConfig {
	return HealthStateConfig{
		Fails:                  2,
		Passes:                 1,
		Observation:            30 * time.Second,
		Ramp:                   60 * time.Second,
		RampCurve:              "linear",
		FlapWindow:             10 * time.Minute,
		FlapThreshold:          4,
		ResultHistoryLimit:     8,
		TransitionHistoryLimit: 16,
	}
}

func observeHealthResult(state *HealthStateMachine, at time.Time, outcome HealthCheckOutcome, probeID uint64) (HealthTransition, bool) {
	return state.Observe(HealthCheckResult{
		At:      at,
		Outcome: outcome,
		Success: outcome == HealthCheckPass,
		ProbeID: probeID,
	})
}

func TestHealthStateMachineOccasionalFailuresDoNotTransition(t *testing.T) {
	state := NewHealthStateMachine(HealthStateConfig{
		Fails:  2,
		Passes: 1,
	})
	start := time.Unix(1_700_000_000, 0).UTC()

	for i, outcome := range []HealthCheckOutcome{
		HealthCheckBusinessFailure,
		HealthCheckPass,
		HealthCheckTimeout,
		HealthCheckPass,
	} {
		if transition, changed := observeHealthResult(state, start.Add(time.Duration(i)*time.Second), outcome, uint64(i+1)); changed {
			t.Fatalf("result %d (%s) changed state unexpectedly: %+v", i, outcome, transition)
		}
	}

	snapshot := state.Snapshot(start.Add(10 * time.Second))
	if snapshot.State != HealthStateHealthy {
		t.Fatalf("state = %q, want %q", snapshot.State, HealthStateHealthy)
	}
	if len(snapshot.Transitions) != 0 {
		t.Fatalf("expected no transitions, got %d", len(snapshot.Transitions))
	}
	if snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("consecutive failures = %d, want 0", snapshot.ConsecutiveFailures)
	}
}

func TestHealthStateMachinePersistentFailureAndRecoveryRamp(t *testing.T) {
	state := NewHealthStateMachine(testHealthStateConfig())
	start := time.Unix(1_700_000_000, 0).UTC()

	observeHealthResult(state, start, HealthCheckBusinessFailure, 1)
	if transition, changed := observeHealthResult(state, start.Add(time.Second), HealthCheckTimeout, 2); !changed {
		t.Fatal("expected unhealthy transition after failure threshold")
	} else if transition.To != HealthStateUnhealthy {
		t.Fatalf("transitioned to %q, want %q", transition.To, HealthStateUnhealthy)
	}

	if transition, changed := observeHealthResult(state, start.Add(2*time.Second), HealthCheckBusinessFailure, 3); changed {
		t.Fatalf("unhealthy node should keep probing without another transition: %+v", transition)
	}

	if transition, changed := observeHealthResult(state, start.Add(3*time.Second), HealthCheckPass, 4); !changed {
		t.Fatal("expected recovery observation transition")
	} else if transition.To != HealthStateRecovering {
		t.Fatalf("transitioned to %q, want %q", transition.To, HealthStateRecovering)
	}

	if transition, changed := observeHealthResult(state, start.Add(20*time.Second), HealthCheckPass, 5); changed {
		t.Fatalf("observation ended too early: %+v", transition)
	}

	if transition, changed := observeHealthResult(state, start.Add(34*time.Second), HealthCheckPass, 6); !changed {
		t.Fatal("expected recovery ramp transition after observation")
	} else if transition.To != HealthStateRamping {
		t.Fatalf("transitioned to %q, want %q", transition.To, HealthStateRamping)
	}

	rampMid := state.Snapshot(start.Add(64 * time.Second))
	if rampMid.State != HealthStateRamping {
		t.Fatalf("state = %q, want %q", rampMid.State, HealthStateRamping)
	}
	if rampMid.LoadFactor <= 0.1 || rampMid.LoadFactor >= 1 {
		t.Fatalf("mid-ramp load factor = %v, want between 0.1 and 1", rampMid.LoadFactor)
	}

	if transition, changed := observeHealthResult(state, start.Add(95*time.Second), HealthCheckPass, 7); !changed {
		t.Fatal("expected healthy transition after ramp")
	} else if transition.To != HealthStateHealthy {
		t.Fatalf("transitioned to %q, want %q", transition.To, HealthStateHealthy)
	}

	snapshot := state.Snapshot(start.Add(96 * time.Second))
	if snapshot.LoadFactor != 1 {
		t.Fatalf("final load factor = %v, want 1", snapshot.LoadFactor)
	}
	if len(snapshot.Transitions) != 4 {
		t.Fatalf("transitions = %d, want 4", len(snapshot.Transitions))
	}
	for i, transition := range snapshot.Transitions {
		if transition.Reason == "" {
			t.Errorf("transition %d has no reason", i)
		}
		if len(transition.CheckResults) == 0 {
			t.Errorf("transition %d has no check result snapshot", i)
		}
	}
}

func TestHealthStateMachineSeparatesTimeoutAndBusinessFailures(t *testing.T) {
	state := NewHealthStateMachine(HealthStateConfig{Fails: 5, Passes: 1})
	start := time.Unix(1_700_000_000, 0).UTC()

	observeHealthResult(state, start, HealthCheckTimeout, 1)
	observeHealthResult(state, start.Add(time.Second), HealthCheckBusinessFailure, 2)
	observeHealthResult(state, start.Add(2*time.Second), HealthCheckInterrupted, 3)

	snapshot := state.Snapshot(start.Add(3 * time.Second))
	if snapshot.State != HealthStateHealthy {
		t.Fatalf("interrupted probe changed state to %q", snapshot.State)
	}
	if snapshot.ConsecutiveTimeouts != 0 {
		t.Fatalf("consecutive timeouts = %d, want 0 after business failure", snapshot.ConsecutiveTimeouts)
	}
	if snapshot.ConsecutiveBusinessFailures != 1 {
		t.Fatalf("consecutive business failures = %d, want 1", snapshot.ConsecutiveBusinessFailures)
	}
	if snapshot.TotalTimeouts != 1 {
		t.Fatalf("total timeouts = %d, want 1", snapshot.TotalTimeouts)
	}
	if snapshot.TotalBusinessFailures != 1 {
		t.Fatalf("total business failures = %d, want 1", snapshot.TotalBusinessFailures)
	}
	if snapshot.ConsecutiveFailures != 2 {
		t.Fatalf("interrupted probe changed consecutive failures to %d", snapshot.ConsecutiveFailures)
	}
}

func TestHealthStateMachineManualRemovalBlocksAutomaticRecovery(t *testing.T) {
	state := NewHealthStateMachine(HealthStateConfig{Fails: 1, Passes: 1})
	start := time.Unix(1_700_000_000, 0).UTC()

	if _, changed := state.SetManualRemoval(true, "maintenance", start); !changed {
		t.Fatal("expected manual removal transition")
	}
	observeHealthResult(state, start.Add(time.Second), HealthCheckPass, 1)
	snapshot := state.Snapshot(start.Add(2 * time.Second))
	if !snapshot.ManualRemoval {
		t.Fatal("manual removal flag unexpectedly cleared")
	}
	if snapshot.Available {
		t.Fatal("manually removed upstream must not be available")
	}
	if snapshot.AutomaticState != HealthStateHealthy {
		t.Fatalf("automatic state = %q, want %q", snapshot.AutomaticState, HealthStateHealthy)
	}

	if _, changed := state.SetManualRemoval(false, "", start.Add(3*time.Second)); !changed {
		t.Fatal("expected manual removal clear transition")
	}
	snapshot = state.Snapshot(start.Add(4 * time.Second))
	if snapshot.ManualRemoval || !snapshot.Available {
		t.Fatalf("upstream should be available after clearing manual removal: %+v", snapshot)
	}
}

func TestHealthStateMachineFlapCountAndBoundedHistories(t *testing.T) {
	cfg := HealthStateConfig{
		Fails:                  1,
		Passes:                 1,
		FlapWindow:             10 * time.Minute,
		FlapThreshold:          4,
		ResultHistoryLimit:     3,
		TransitionHistoryLimit: 7,
	}
	state := NewHealthStateMachine(cfg)
	start := time.Unix(1_700_000_000, 0).UTC()

	var probeID uint64 = 1
	for i := 0; i < 17; i++ {
		at := start.Add(time.Duration(i) * 2 * time.Second)
		observeHealthResult(state, at, HealthCheckBusinessFailure, probeID)
		probeID++
		observeHealthResult(state, at.Add(time.Second), HealthCheckPass, probeID)
		probeID++
	}

	snapshot := state.Snapshot(start.Add(time.Minute))
	if !snapshot.Flapping {
		t.Fatalf("expected flapping to be reported, transitions=%d", snapshot.TransitionsInWindow)
	}
	if snapshot.TransitionsInWindow != 34 {
		t.Fatalf("transitions in window = %d, want 34", snapshot.TransitionsInWindow)
	}
	if len(snapshot.Results) > cfg.ResultHistoryLimit {
		t.Fatalf("result history = %d, exceeds limit %d", len(snapshot.Results), cfg.ResultHistoryLimit)
	}
	if len(snapshot.Transitions) > cfg.TransitionHistoryLimit {
		t.Fatalf("transition history = %d, exceeds limit %d", len(snapshot.Transitions), cfg.TransitionHistoryLimit)
	}
}

func TestHealthStateMachineSnapshotsDoNotResetRecoveryTiming(t *testing.T) {
	state := NewHealthStateMachine(HealthStateConfig{
		Fails:       1,
		Passes:      1,
		Observation: 30 * time.Second,
		Ramp:        30 * time.Second,
	})
	start := time.Unix(1_700_000_000, 0).UTC()

	observeHealthResult(state, start, HealthCheckBusinessFailure, 1)
	observeHealthResult(state, start.Add(time.Second), HealthCheckPass, 2)

	for i := 0; i < 5; i++ {
		snapshot := state.Snapshot(start.Add(time.Duration(i+1) * 5 * time.Second))
		if snapshot.State != HealthStateRecovering {
			t.Fatalf("snapshot %d state = %q, want %q", i, snapshot.State, HealthStateRecovering)
		}
	}

	if transition, changed := observeHealthResult(state, start.Add(32*time.Second), HealthCheckPass, 3); !changed {
		t.Fatal("read-only snapshots must not reset the observation timer")
	} else if transition.To != HealthStateRamping {
		t.Fatalf("transitioned to %q, want %q", transition.To, HealthStateRamping)
	}
}

func TestHealthStateMachineMultiNodeFlapping(t *testing.T) {
	states := []*HealthStateMachine{
		NewHealthStateMachine(HealthStateConfig{Fails: 1, Passes: 1, FlapWindow: 10 * time.Minute, FlapThreshold: 4}),
		NewHealthStateMachine(HealthStateConfig{Fails: 1, Passes: 1, FlapWindow: 10 * time.Minute, FlapThreshold: 4}),
		NewHealthStateMachine(HealthStateConfig{Fails: 1, Passes: 1, FlapWindow: 10 * time.Minute, FlapThreshold: 4}),
	}
	start := time.Unix(1_700_000_000, 0).UTC()

	for cycle := 0; cycle < 4; cycle++ {
		at := start.Add(time.Duration(cycle) * 2 * time.Second)
		for _, state := range states {
			observeHealthResult(state, at, HealthCheckTimeout, uint64(cycle*2+1))
			observeHealthResult(state, at.Add(time.Second), HealthCheckPass, uint64(cycle*2+2))
		}
	}

	for i, state := range states {
		snapshot := state.Snapshot(start.Add(20 * time.Second))
		if snapshot.TransitionsInWindow != 8 {
			t.Errorf("node %d transitions = %d, want 8", i, snapshot.TransitionsInWindow)
		}
		if !snapshot.Flapping {
			t.Errorf("node %d should be reported as flapping", i)
		}
	}
}

func TestHealthStateMachineDrillTimelineAndRamp(t *testing.T) {
	state := NewHealthStateMachine(HealthStateConfig{
		Fails:                  1,
		Passes:                 1,
		Observation:            5 * time.Second,
		Ramp:                   30 * time.Second,
		RampCurve:              "linear",
		FlapWindow:             10 * time.Minute,
		FlapThreshold:          4,
		ResultHistoryLimit:     64,
		TransitionHistoryLimit: 128,
	})
	start := time.Unix(1_700_000_000, 0).UTC()

	var probeID uint64
	next := func(at time.Time, outcome HealthCheckOutcome) {
		probeID++
		observeHealthResult(state, at, outcome, probeID)
	}

	var rampStart time.Time
	const cycleDuration = 40 * time.Second
	for cycle := 0; cycle < 17; cycle++ {
		at := start.Add(time.Duration(cycle) * cycleDuration)
		next(at, HealthCheckBusinessFailure)
		next(at.Add(time.Second), HealthCheckPass)
		next(at.Add(6*time.Second), HealthCheckPass)
		rampStart = at.Add(6 * time.Second)
		if cycle < 16 {
			next(at.Add(36*time.Second), HealthCheckPass)
		}
	}

	snapshot := state.Snapshot(rampStart.Add(30 * time.Second))
	if snapshot.State != HealthStateRamping {
		t.Fatalf("state = %q, want %q", snapshot.State, HealthStateRamping)
	}
	if !snapshot.Flapping {
		t.Fatalf("drill should report flapping, transitions=%d", snapshot.TransitionsInWindow)
	}

	t.Logf("observed %d transitions in %s; flapping=%t", snapshot.TransitionsInWindow, 10*time.Minute, snapshot.Flapping)
	first := len(snapshot.Transitions) - 8
	if first < 0 {
		first = 0
	}
	for _, transition := range snapshot.Transitions[first:] {
		t.Logf("%s %s -> %s: %s (transition #%d, flapping=%t)",
			transition.At.Format(time.RFC3339), transition.From, transition.To, transition.Reason,
			transition.TransitionsInWindow, transition.Flapping)
	}
	for _, progress := range []time.Duration{0, 6 * time.Second, 12 * time.Second, 18 * time.Second, 24 * time.Second, 30 * time.Second} {
		load := state.Snapshot(rampStart.Add(progress)).LoadFactor
		t.Logf("ramp +%s: load_factor=%.2f", progress, load)
	}

	next(rampStart.Add(30*time.Second), HealthCheckPass)
	if final := state.Snapshot(rampStart.Add(31 * time.Second)); final.State != HealthStateHealthy {
		t.Fatalf("final state = %q, want %q", final.State, HealthStateHealthy)
	}
}
