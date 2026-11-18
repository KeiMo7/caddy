# Backpressure

`backpressure` is an HTTP middleware that limits how many requests may wait for
an upstream response before Caddy starts rejecting excess traffic. It is off
unless explicitly configured.

## Caddyfile

```caddyfile
example.com {
	backpressure {
		max_concurrency 64
		queue_size      16
		queue_timeout   250ms
		exempt          /health /internal/ready
	}

	reverse_proxy 10.0.0.10:8080 10.0.0.11:8080
}
```

- `max_concurrency` is required and must be greater than zero.
- `queue_size` defaults to zero, which rejects overflow immediately.
- `queue_timeout` defaults to one second when queuing is enabled.
- `exempt` adds path prefixes which bypass admission control.

Common health and readiness paths (`/health`, `/healthz`, `/healthcheck`,
`/live`, `/livez`, `/ready`, `/readyz`, `/_health`, `/_healthz`) are exempt by
default.

## Admission semantics

A request holds an admission slot until Caddy writes the first final response
header/body byte, or until the downstream handler returns without writing a
response. This makes the limiter measure time to first byte rather than total
response-body duration. Long-lived streaming responses release their slot as
soon as streaming begins and therefore do not consume ordinary request slots
for the whole connection lifetime.

When all slots are occupied:

1. A request enters the FIFO queue if `queue_size` is non-zero and space is
   available.
2. A full queue rejects immediately; it never blocks the request goroutine.
3. A queued request that waits longer than `queue_timeout` is removed and
   rejected.
4. Releases transfer a slot to exactly one waiter, so recovery cannot admit
   more than `max_concurrency` requests at once.

Rejections use HTTP 503 and include:

```text
X-Caddy-Backpressure: rejected
X-Caddy-Backpressure-Reason: overloaded|queue-timeout|shutting-down
Retry-After: 1
```

## Metrics

Prometheus metrics are registered per configured handler instance:

- `caddy_http_backpressure_active_requests`
- `caddy_http_backpressure_queued_requests`
- `caddy_http_backpressure_admitted_total`
- `caddy_http_backpressure_completed_total`
- `caddy_http_backpressure_rejected_total{reason=...}`
- `caddy_http_backpressure_health_bypassed_total`
- `caddy_http_backpressure_upstream_timeouts_total`
- `caddy_http_backpressure_queue_canceled_total`

Backpressure rejections and upstream timeouts are separate counters. The
upstream timeout counter is incremented only for admitted requests which return
an HTTP 504 error or a timeout implementing `net.Error`.

## Load comparison

Run the reproducible comparison:

```bash
CADDY_BACKPRESSURE_LOADTEST=1 \
CADDY_BACKPRESSURE_LOADTEST_OUT=/tmp/backpressure-load.json \
go test -count=1 -run '^TestLoadComparison$' -v ./modules/caddyhttp/backpressure
```

The harness uses one slow upstream implementation, the same request count, and
fixed concurrency levels of 16, 64, and 256. Each scenario runs in a fresh
process. The upstream holds a fixed 512 KiB working set while sleeping for
100 ms, making the cost of piled-up requests visible in memory. Backpressure
uses `max_concurrency=16`, `queue_size=32`, and `queue_timeout=50ms`.

Median of three runs on a 13th Gen Intel i9-13900HX Linux machine:

| Concurrency | Mode | Requests | Rejected | Reject % | Peak conns | Peak in-flight | Heap peak | RSS peak | Duration |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 16 | disabled | 64 | 0 | 0.00% | 16 | 16 | 19.56 MiB | 53.12 MiB | 411 ms |
| 16 | enabled | 64 | 0 | 0.00% | 16 | 16 | 19.51 MiB | 55.90 MiB | 411 ms |
| 64 | disabled | 256 | 0 | 0.00% | 64 | 64 | 69.37 MiB | 98.66 MiB | 440 ms |
| 64 | enabled | 256 | 192 | 75.00% | 64 | 50 | 22.85 MiB | 59.76 MiB | 422 ms |
| 256 | disabled | 1024 | 0 | 0.00% | 256 | 256 | 239.35 MiB | 240.96 MiB | 527 ms |
| 256 | enabled | 1024 | 960 | 93.75% | 211 | 52 | 29.85 MiB | 66.76 MiB | 538 ms |

The disabled path has no middleware in the route at all; there is no limiter
branch to execute. With the limiter enabled, the benchmark
`BenchmarkBackpressureAdmission` measures the admission path itself, while
`BenchmarkNoBackpressure` measures the direct handler chain.
