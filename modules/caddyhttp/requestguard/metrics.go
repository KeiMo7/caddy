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

package requestguard

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Inspection outcomes. These are the only values used as metric labels, so
// the label set stays bounded and never contains request data.
const (
	outcomeBlocked            = "blocked"
	outcomeLogged             = "logged"
	outcomeBudget             = "budget_exceeded"
	outcomeOversized          = "oversized_allowed"
	outcomeRejected           = "rejected"
	outcomeDecompress         = "decompression_refused"
	outcomeUnsupported        = "unsupported_encoding"
	outcomeReadError          = "read_error"
	outcomeSkippedUpgrade     = "skipped_upgrade"
	outcomeSkippedIncremental = "skipped_incremental"
)

// guardMetrics holds the collectors for one handler. The collector is shared
// by every handler registered against the same registry, so counters
// aggregate across routes as intended.
type guardMetrics struct {
	inspections *prometheus.CounterVec
}

// initGuardMetrics creates and registers the inspection counter on reg.
//
// Registration is idempotent: a second handler provisioned against the same
// registry reuses the already-registered collector rather than failing.
func initGuardMetrics(reg *prometheus.Registry) *guardMetrics {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "caddy",
		Subsystem: "http_request_guard",
		Name:      "inspections_total",
		Help:      "Requests evaluated by the request guard, by outcome, target and rule. Never contains request data.",
	}, []string{"outcome", "target", "rule"})

	registered := c
	if err := reg.Register(c); err != nil {
		if are, ok := errors.AsType[prometheus.AlreadyRegisteredError](err); ok {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				registered = existing
			}
		}
	}

	return &guardMetrics{inspections: registered}
}

// observe records one inspection outcome. target and rule are "-" when they
// do not apply.
func (m *guardMetrics) observe(outcome, target, rule string) {
	if m == nil || m.inspections == nil {
		return
	}
	if target == "" {
		target = "-"
	}
	if rule == "" {
		rule = "-"
	}
	m.inspections.WithLabelValues(outcome, target, rule).Inc()
}
