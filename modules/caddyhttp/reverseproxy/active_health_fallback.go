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
	"time"

	"go.uber.org/zap"
)

// selectAllUnhealthyFallback returns a best-effort upstream when every
// upstream has been removed by active health checks. Manual removals are never
// bypassed. Flap suppression must be enabled for the fallback to apply, which
// preserves the historical 503 behavior for existing configurations.
func (h *Handler) selectAllUnhealthyFallback(upstreams UpstreamPool) *Upstream {
	if h.HealthChecks == nil || h.HealthChecks.Active == nil || !h.HealthChecks.Active.FlapsEnabled() {
		return nil
	}

	for _, upstream := range upstreams {
		if upstream != nil && upstream.Available() {
			return nil
		}
	}

	now := time.Now()
	var fallback *Upstream
	var fallbackFailures int
	var fallbackSince time.Time
	for _, upstream := range upstreams {
		if upstream == nil || upstream.ManualUnhealthy() || upstream.Full() {
			continue
		}

		failures := -1
		var since time.Time
		if upstream.healthState != nil {
			snapshot := upstream.healthState.Snapshot(now)
			failures = snapshot.ConsecutiveFailures
			since = snapshot.Since
		}
		if fallback == nil || failures < fallbackFailures ||
			(failures == fallbackFailures && since.Before(fallbackSince)) {
			fallback = upstream
			fallbackFailures = failures
			fallbackSince = since
		}
	}

	if fallback == nil {
		if len(upstreams) > 0 {
			if h.logger != nil {
				if c := h.logger.Check(zap.ErrorLevel, "all upstreams are unhealthy and no safe fallback is available"); c != nil {
					c.Write(zap.Int("upstreams", len(upstreams)))
				}
			}
			if h.events != nil {
				h.events.Emit(h.ctx, "all_unhealthy", map[string]any{
					"fallback":  "",
					"upstreams": len(upstreams),
				})
			}
		}
		return nil
	}

	if h.logger != nil {
		if c := h.logger.Check(zap.ErrorLevel, "all upstreams are unhealthy; using fallback upstream"); c != nil {
			c.Write(
				zap.String("fallback", fallback.Dial),
				zap.Int("upstreams", len(upstreams)),
			)
		}
	}
	if h.events != nil {
		h.events.Emit(h.ctx, "all_unhealthy", map[string]any{
			"fallback":  fallback.Dial,
			"upstreams": len(upstreams),
		})
	}
	return fallback
}
