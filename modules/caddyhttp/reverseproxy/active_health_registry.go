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
	"sort"
	"sync"
	"time"
)

type healthStateRegistration struct {
	handler  *Handler
	address  string
	group    string
	state    *HealthStateMachine
	upstream *Upstream
}

var activeHealthStates sync.Map

func registerHealthState(h *Handler, upstream *Upstream, state *HealthStateMachine) {
	if h == nil || upstream == nil || state == nil {
		return
	}
	activeHealthStates.Store(
		struct {
			handler  *Handler
			upstream *Upstream
		}{h, upstream},
		&healthStateRegistration{
			handler:  h,
			address:  upstream.Dial,
			group:    upstream.HealthGroup,
			state:    state,
			upstream: upstream,
		},
	)
}

func unregisterHealthStates(h *Handler) {
	activeHealthStates.Range(func(key, value any) bool {
		registration, ok := value.(*healthStateRegistration)
		if ok && registration.handler == h {
			activeHealthStates.Delete(key)
		}
		return true
	})
}

func healthStateSnapshots(now time.Time) []HealthStateSnapshot {
	var snapshots []HealthStateSnapshot
	activeHealthStates.Range(func(_, value any) bool {
		registration, ok := value.(*healthStateRegistration)
		if !ok || registration.state == nil {
			return true
		}
		snapshot := registration.state.Snapshot(now)
		if snapshot.Address == "" {
			snapshot.Address = registration.address
		}
		if snapshot.Group == "" {
			snapshot.Group = registration.group
		}
		if registration.upstream != nil {
			snapshot.OverlapsSkipped = registration.upstream.overlapSkipped.Load()
		}
		snapshots = append(snapshots, snapshot)
		return true
	})
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].Address == snapshots[j].Address {
			return snapshots[i].Group < snapshots[j].Group
		}
		return snapshots[i].Address < snapshots[j].Address
	})
	return snapshots
}

func applyManualHealthRemoval(address string, removed bool, reason string) int {
	var changed int
	activeHealthStates.Range(func(_, value any) bool {
		registration, ok := value.(*healthStateRegistration)
		if !ok || registration.upstream == nil || registration.address != address {
			return true
		}
		if registration.upstream.SetManualUnhealthy(removed, reason) {
			changed++
		}
		return true
	})
	return changed
}

type healthStatusSummary struct {
	State               string    `json:"state"`
	AutomaticState      string    `json:"automatic_state"`
	Available           bool      `json:"available"`
	LoadFactor          float64   `json:"load_factor"`
	ManualRemoval       bool      `json:"manual_removal"`
	Flapping            bool      `json:"flapping"`
	TransitionsInWindow int       `json:"transitions_in_window"`
	OverlapsSkipped     uint64    `json:"overlaps_skipped,omitempty"`
	LastTransition      time.Time `json:"last_transition,omitempty"`
}

func healthStatusSummariesByAddress(now time.Time) map[string]*healthStatusSummary {
	summaries := make(map[string]*healthStatusSummary)
	selectedSince := make(map[string]time.Time)
	activeHealthStates.Range(func(_, value any) bool {
		registration, ok := value.(*healthStateRegistration)
		if !ok || registration.state == nil {
			return true
		}
		snapshot := registration.state.Snapshot(now)
		if snapshot.Address == "" {
			snapshot.Address = registration.address
		}
		if registration.upstream != nil {
			snapshot.OverlapsSkipped = registration.upstream.overlapSkipped.Load()
		}
		if _, ok := summaries[snapshot.Address]; !ok ||
			snapshot.Since.After(selectedSince[snapshot.Address]) {
			summaries[snapshot.Address] = summarizeHealthSnapshot(&snapshot)
			selectedSince[snapshot.Address] = snapshot.Since
		}
		return true
	})
	return summaries
}

func summarizeHealthSnapshot(snapshot *HealthStateSnapshot) *healthStatusSummary {
	summary := &healthStatusSummary{
		State:               snapshot.State,
		AutomaticState:      snapshot.AutomaticState,
		Available:           snapshot.Available,
		LoadFactor:          snapshot.LoadFactor,
		ManualRemoval:       snapshot.ManualRemoval,
		Flapping:            snapshot.Flapping,
		TransitionsInWindow: snapshot.TransitionsInWindow,
		OverlapsSkipped:     snapshot.OverlapsSkipped,
	}
	if len(snapshot.Transitions) > 0 {
		summary.LastTransition = snapshot.Transitions[len(snapshot.Transitions)-1].At
	}
	return summary
}
