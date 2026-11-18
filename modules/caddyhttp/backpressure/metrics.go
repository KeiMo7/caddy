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

package backpressure

import (
	"strconv"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

var handlerInstanceID atomic.Uint64

type metricsCollector struct {
	activeDesc          *prometheus.Desc
	queuedDesc          *prometheus.Desc
	admittedDesc        *prometheus.Desc
	completedDesc       *prometheus.Desc
	rejectedDesc        *prometheus.Desc
	healthDesc          *prometheus.Desc
	upstreamTimeoutDesc *prometheus.Desc
	queueCanceledDesc   *prometheus.Desc

	handler *Handler
}

func newMetricsCollector(handler *Handler) *metricsCollector {
	constLabels := prometheus.Labels{
		"instance": strconv.FormatUint(handlerInstanceID.Add(1), 10),
	}
	desc := func(name, help string, variableLabels ...string) *prometheus.Desc {
		return prometheus.NewDesc(
			prometheus.BuildFQName("caddy", "http", name),
			help,
			variableLabels,
			constLabels,
		)
	}
	return &metricsCollector{
		activeDesc: desc(
			"backpressure_active_requests",
			"Requests currently holding a backpressure admission slot.",
		),
		queuedDesc: desc(
			"backpressure_queued_requests",
			"Requests currently waiting for a backpressure admission slot.",
		),
		admittedDesc: desc(
			"backpressure_admitted_total",
			"Requests admitted by the backpressure limiter.",
		),
		completedDesc: desc(
			"backpressure_completed_total",
			"Requests which released a backpressure admission slot.",
		),
		rejectedDesc: desc(
			"backpressure_rejected_total",
			"Requests rejected by the backpressure limiter, by reason.",
			"reason",
		),
		healthDesc: desc(
			"backpressure_health_bypassed_total",
			"Health and readiness requests exempted from backpressure admission.",
		),
		upstreamTimeoutDesc: desc(
			"backpressure_upstream_timeouts_total",
			"Admitted requests that failed with an upstream timeout instead of backpressure rejection.",
		),
		queueCanceledDesc: desc(
			"backpressure_queue_canceled_total",
			"Queued requests canceled by their client before admission.",
		),
		handler: handler,
	}
}

func (m *metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.activeDesc
	ch <- m.queuedDesc
	ch <- m.admittedDesc
	ch <- m.completedDesc
	ch <- m.rejectedDesc
	ch <- m.healthDesc
	ch <- m.upstreamTimeoutDesc
	ch <- m.queueCanceledDesc
}

func (m *metricsCollector) Collect(ch chan<- prometheus.Metric) {
	stats := m.handler.Stats()

	ch <- prometheus.MustNewConstMetric(m.activeDesc, prometheus.GaugeValue, float64(stats.Active))
	ch <- prometheus.MustNewConstMetric(m.queuedDesc, prometheus.GaugeValue, float64(stats.Queued))
	ch <- prometheus.MustNewConstMetric(m.admittedDesc, prometheus.CounterValue, float64(stats.Admitted))
	ch <- prometheus.MustNewConstMetric(m.completedDesc, prometheus.CounterValue, float64(stats.Completed))
	ch <- prometheus.MustNewConstMetric(m.rejectedDesc, prometheus.CounterValue, float64(stats.RejectedOverload), rejectReasonOverloaded)
	ch <- prometheus.MustNewConstMetric(m.rejectedDesc, prometheus.CounterValue, float64(stats.RejectedQueueTimeout), rejectReasonQueueTimeout)
	ch <- prometheus.MustNewConstMetric(m.rejectedDesc, prometheus.CounterValue, float64(stats.RejectedShuttingDown), rejectReasonShuttingDown)
	ch <- prometheus.MustNewConstMetric(m.healthDesc, prometheus.CounterValue, float64(stats.HealthBypassed))
	ch <- prometheus.MustNewConstMetric(m.upstreamTimeoutDesc, prometheus.CounterValue, float64(stats.UpstreamTimeouts))
	ch <- prometheus.MustNewConstMetric(m.queueCanceledDesc, prometheus.CounterValue, float64(stats.QueueCanceled))
}
