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
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(adminUpstreams{})
}

// adminUpstreams is a module that provides the
// /reverse_proxy/upstreams endpoint for the Caddy admin
// API. This allows for checking the health of configured
// reverse proxy upstreams in the pool.
type adminUpstreams struct{}

// upstreamStatus holds the status of a particular upstream
type upstreamStatus struct {
	Address     string               `json:"address"`
	NumRequests int                  `json:"num_requests"`
	Fails       int                  `json:"fails"`
	Health      *healthStatusSummary `json:"health,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (adminUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.reverse_proxy",
		New: func() caddy.Module { return new(adminUpstreams) },
	}
}

// Routes returns a route for the /reverse_proxy/upstreams endpoint.
func (al adminUpstreams) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/reverse_proxy/upstreams",
			Handler: caddy.AdminHandlerFunc(al.handleUpstreams),
		},
		{
			Pattern: "/reverse_proxy/health",
			Handler: caddy.AdminHandlerFunc(al.handleHealth),
		},
		{
			Pattern: "/reverse_proxy/upstreams/manual",
			Handler: caddy.AdminHandlerFunc(al.handleManualRemoval),
		},
	}
}

// handleUpstreams reports the status of the reverse proxy
// upstream pool.
func (adminUpstreams) handleUpstreams(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	// Prep for a JSON response
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)

	// Collect the results to respond with
	results := []upstreamStatus{}
	knownHosts := make(map[string]struct{})
	now := time.Now()
	healthByAddress := healthStatusSummariesByAddress(now)

	// Iterate over the static upstream pool (needs to be fast)
	var rangeErr error
	hosts.Range(func(key, val any) bool {
		address, ok := key.(string)
		if !ok {
			rangeErr = caddy.APIError{
				HTTPStatus: http.StatusInternalServerError,
				Err:        fmt.Errorf("could not type assert upstream address"),
			}
			return false
		}

		upstream, ok := val.(*Host)
		if !ok {
			rangeErr = caddy.APIError{
				HTTPStatus: http.StatusInternalServerError,
				Err:        fmt.Errorf("could not type assert upstream struct"),
			}
			return false
		}

		knownHosts[address] = struct{}{}

		results = append(results, upstreamStatus{
			Address:     address,
			NumRequests: upstream.NumRequests(),
			Fails:       upstream.Fails(),
			Health:      healthByAddress[address],
		})
		return true
	})

	currentInFlight := getInFlightRequests()
	for address, count := range currentInFlight {
		if _, exists := knownHosts[address]; !exists && count > 0 {
			results = append(results, upstreamStatus{
				Address:     address,
				NumRequests: int(count),
				Fails:       0,
				Health:      healthByAddress[address],
			})
		}
	}

	if rangeErr != nil {
		return rangeErr
	}

	// Also include dynamic upstreams
	dynamicHostsMu.RLock()
	for address, entry := range dynamicHosts {
		results = append(results, upstreamStatus{
			Address:     address,
			NumRequests: entry.host.NumRequests(),
			Fails:       entry.host.Fails(),
			Health:      healthByAddress[address],
		})
	}
	dynamicHostsMu.RUnlock()

	err := enc.Encode(results)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        err,
		}
	}

	return nil
}

// handleHealth reports detailed active health state transitions and bounded
// check result history. It is strictly read-only: it never starts a probe or
// modifies any state machine timers.
func (adminUpstreams) handleHealth(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	snapshots := healthStateSnapshots(time.Now())
	if snapshots == nil {
		snapshots = []HealthStateSnapshot{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshots); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        err,
		}
	}
	return nil
}

type manualRemovalRequest struct {
	Address string `json:"address"`
	Removed bool   `json:"removed"`
	Reason  string `json:"reason,omitempty"`
}

// handleManualRemoval applies or clears a manual upstream removal override.
// Automatic health checks keep running, but cannot restore an upstream while
// a manual removal is active.
func (adminUpstreams) handleManualRemoval(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	var request manualRemovalRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("decoding request: %v", err),
		}
	}
	if request.Address == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("address is required"),
		}
	}

	if changed := applyManualHealthRemoval(request.Address, request.Removed, request.Reason); changed == 0 {
		return caddy.APIError{
			HTTPStatus: http.StatusNotFound,
			Err:        fmt.Errorf("no active health state for upstream %s", request.Address),
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
