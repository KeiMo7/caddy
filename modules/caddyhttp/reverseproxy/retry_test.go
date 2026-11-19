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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func compileTestRetryPolicy(t *testing.T, lb *LoadBalancing, policy *RetryPolicy) *RetryPolicy {
	t.Helper()
	if lb == nil {
		lb = new(LoadBalancing)
	}
	if err := policy.compile(lb); err != nil {
		t.Fatalf("compiling retry policy: %v", err)
	}
	return policy
}

func testRetryPolicy(t *testing.T) *RetryPolicy {
	t.Helper()
	return compileTestRetryPolicy(t, nil, &RetryPolicy{
		RetryOn:          []string{"connection_refused", "connection_timeout", "tls_handshake"},
		RetryStatusCodes: []int{http.StatusBadGateway, http.StatusServiceUnavailable},
		MaxRetries:       2,
		TotalBudget:      caddy.Duration(2 * time.Second),
	})
}

func TestRetryPolicyDecide(t *testing.T) {
	base := func(method string) RetryRequestMeta {
		return RetryRequestMeta{
			Method:         method,
			BodyReplayable: true,
		}
	}

	for _, tc := range []struct {
		name      string
		failure   RetryFailure
		meta      RetryRequestMeta
		retries   int
		elapsed   time.Duration
		configure func(*RetryPolicy)
		wantRetry bool
		wantIn    string
	}{
		{
			name:      "idempotent connection refused",
			failure:   RetryFailure{Class: RetryFailureConnectionRefused},
			meta:      base(http.MethodGet),
			wantRetry: true,
			wantIn:    "retry_on.connection_refused",
		},
		{
			name:      "non-idempotent defaults to no retry",
			failure:   RetryFailure{Class: RetryFailureConnectionRefused},
			meta:      base(http.MethodPost),
			wantRetry: false,
			wantIn:    "non-idempotent",
		},
		{
			name:    "non-idempotent with idempotency key",
			failure: RetryFailure{Class: RetryFailureConnectionRefused},
			meta: func() RetryRequestMeta {
				meta := base(http.MethodPost)
				meta.IdempotencyKeyPresent = true
				return meta
			}(),
			configure: func(policy *RetryPolicy) {
				policy.RetryNonIdempotent = true
			},
			wantRetry: true,
			wantIn:    "retry_on.connection_refused",
		},
		{
			name:    "non-idempotent without idempotency key",
			failure: RetryFailure{Class: RetryFailureConnectionRefused},
			meta:    base(http.MethodPost),
			configure: func(policy *RetryPolicy) {
				policy.RetryNonIdempotent = true
			},
			wantRetry: false,
			wantIn:    "requires header Idempotency-Key",
		},
		{
			name:      "consumed request body is not replayed",
			failure:   RetryFailure{Class: RetryFailureConnectionRefused},
			meta:      RetryRequestMeta{Method: http.MethodPut, BodyPresent: true, BodyReplayable: false},
			wantRetry: false,
			wantIn:    "cannot be replayed",
		},
		{
			name:      "configured status",
			failure:   RetryFailure{Class: RetryFailureResponseStatus, StatusCode: http.StatusServiceUnavailable},
			meta:      base(http.MethodGet),
			wantRetry: true,
			wantIn:    "retry_status_codes.503",
		},
		{
			name:      "unlisted status",
			failure:   RetryFailure{Class: RetryFailureResponseStatus, StatusCode: http.StatusInternalServerError},
			meta:      base(http.MethodGet),
			wantRetry: false,
			wantIn:    "not listed",
		},
		{
			name:    "never retry status wins",
			failure: RetryFailure{Class: RetryFailureResponseStatus, StatusCode: http.StatusServiceUnavailable},
			meta:    base(http.MethodGet),
			configure: func(policy *RetryPolicy) {
				policy.NeverRetryStatusCodes = []int{http.StatusServiceUnavailable}
			},
			wantRetry: false,
			wantIn:    "never_retry_status_codes",
		},
		{
			name:      "unconfigured tls handshake",
			failure:   RetryFailure{Class: RetryFailureTLSHandshake},
			meta:      base(http.MethodGet),
			configure: func(policy *RetryPolicy) { policy.RetryOn = []string{"connection_refused"} },
			wantRetry: false,
			wantIn:    "not listed",
		},
		{
			name:      "response already started",
			failure:   RetryFailure{Class: RetryFailureResponseStatus, StatusCode: http.StatusServiceUnavailable},
			meta:      RetryRequestMeta{Method: http.MethodGet, ResponseStarted: true, BodyReplayable: true},
			wantRetry: false,
			wantIn:    "already been committed",
		},
		{
			name:      "client canceled",
			failure:   RetryFailure{Class: RetryFailureConnectionRefused},
			meta:      RetryRequestMeta{Method: http.MethodGet, ClientCanceled: true, BodyReplayable: true},
			wantRetry: false,
			wantIn:    "client disconnected",
		},
		{
			name:      "retry count cap",
			failure:   RetryFailure{Class: RetryFailureConnectionRefused},
			meta:      base(http.MethodGet),
			retries:   2,
			wantRetry: false,
			wantIn:    "maximum retries",
		},
		{
			name:      "total budget cap",
			failure:   RetryFailure{Class: RetryFailureConnectionRefused},
			meta:      base(http.MethodGet),
			elapsed:   2 * time.Second,
			wantRetry: false,
			wantIn:    "budget",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := testRetryPolicy(t)
			if tc.configure != nil {
				tc.configure(policy)
				compileTestRetryPolicy(t, nil, policy)
			}
			decision := policy.Decide(tc.failure, tc.meta, tc.retries, tc.elapsed)
			if decision.Retry != tc.wantRetry {
				t.Fatalf("Retry = %v, want %v (decision: %+v)", decision.Retry, tc.wantRetry, decision)
			}
			if !strings.Contains(decision.Reason+" "+decision.Policy, tc.wantIn) {
				t.Errorf("decision reason/policy = %q / %q, want to contain %q",
					decision.Reason, decision.Policy, tc.wantIn)
			}
		})
	}
}

func TestRetryPolicyDelayBounds(t *testing.T) {
	policy := compileTestRetryPolicy(t, nil, &RetryPolicy{
		RetryOn:          []string{"connection_refused"},
		MaxRetries:       10,
		TotalBudget:      caddy.Duration(time.Minute),
		InitialInterval:  caddy.Duration(100 * time.Millisecond),
		MaxInterval:      caddy.Duration(time.Second),
		Jitter:           0.2,
		RetryStatusCodes: nil,
	})

	for i, tc := range []struct {
		retries int
		min     time.Duration
		max     time.Duration
	}{
		{retries: 0, min: 80 * time.Millisecond, max: 120 * time.Millisecond},
		{retries: 2, min: 320 * time.Millisecond, max: 480 * time.Millisecond},
		{retries: 20, min: 800 * time.Millisecond, max: time.Second},
	} {
		delay := policy.delay(tc.retries)
		if delay < tc.min || delay > tc.max {
			t.Errorf("case %d: delay(%d) = %s, want [%s, %s]", i, tc.retries, delay, tc.min, tc.max)
		}
	}
}

func TestRetryPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy *RetryPolicy
		want   []string
	}{
		{
			name: "unknown failure class",
			policy: &RetryPolicy{
				RetryOn:     []string{"connection_reset"},
				MaxRetries:  1,
				TotalBudget: caddy.Duration(time.Second),
			},
			want: []string{"unknown failure class", "connection_refused", "tls_handshake"},
		},
		{
			name: "unknown status code",
			policy: &RetryPolicy{
				RetryStatusCodes: []int{999},
				MaxRetries:       1,
				TotalBudget:      caddy.Duration(time.Second),
			},
			want: []string{"unknown HTTP status code 999", "commonly retryable codes"},
		},
		{
			name: "retry count upper bound",
			policy: &RetryPolicy{
				MaxRetries:  maxRetryCount + 1,
				TotalBudget: caddy.Duration(time.Second),
			},
			want: []string{"exceeds the maximum"},
		},
		{
			name: "interval upper bound",
			policy: &RetryPolicy{
				MaxRetries:  1,
				TotalBudget: caddy.Duration(time.Second),
				MaxInterval: caddy.Duration(maxRetryInterval + time.Second),
			},
			want: []string{"max_interval", "exceeds the maximum"},
		},
		{
			name: "explicit total budget required",
			policy: &RetryPolicy{
				MaxRetries: 1,
			},
			want: []string{"total_budget", "explicit total budget"},
		},
		{
			name: "jitter range",
			policy: &RetryPolicy{
				MaxRetries:  1,
				TotalBudget: caddy.Duration(time.Second),
				Jitter:      1.1,
			},
			want: []string{"jitter", "range [0, 1]"},
		},
		{
			name: "invalid idempotency header",
			policy: &RetryPolicy{
				MaxRetries:           1,
				TotalBudget:          caddy.Duration(time.Second),
				RetryNonIdempotent:   true,
				IdempotencyKeyHeader: "bad header",
			},
			want: []string{"idempotency_key_header", "invalid header name"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.compile(nil)
			if err == nil {
				t.Fatal("expected validation error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestRetryPolicyCaddyfile(t *testing.T) {
	newHandler := func(input string) error {
		h := new(Handler)
		return h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	}

	if err := newHandler(`reverse_proxy localhost:9080 {
		lb_retry_policy {
			retry_on connection_refused connection_timeout tls_handshake
			retry_status_codes 502 503 504
			never_retry_status_codes 500
			max_retries 2
			total_budget 2s
			initial_interval 100ms
			max_interval 1s
			jitter 0.25
			idempotent_methods GET HEAD PUT DELETE
			retry_non_idempotent
			idempotency_key_header Idempotency-Key
		}
	}`); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	err := newHandler(`reverse_proxy localhost:9080 {
		lb_retry_policy {
			retry_status_codes 999
			max_retries 1
			total_budget 1s
		}
	}`)
	if err == nil || !strings.Contains(err.Error(), "unknown HTTP status code 999") {
		t.Fatalf("expected unknown status code error, got %v", err)
	}
	if !strings.Contains(err.Error(), "commonly retryable codes") {
		t.Errorf("error does not list valid options: %v", err)
	}
}

func TestHandlerValidateRetryPolicy(t *testing.T) {
	h := &Handler{
		LoadBalancing: &LoadBalancing{
			RetryPolicy: &RetryPolicy{
				RetryStatusCodes: []int{999},
				MaxRetries:       1,
				TotalBudget:      caddy.Duration(time.Second),
			},
		},
	}
	err := h.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "retry_policy.retry_status_codes") ||
		!strings.Contains(err.Error(), "unknown HTTP status code 999") {
		t.Errorf("validation error does not identify the invalid item: %v", err)
	}
}

func TestClassifyRetryFailure(t *testing.T) {
	refused := DialError{&net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
	}}
	timeout := DialError{&net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: timeoutError{},
	}}

	for _, tc := range []struct {
		name string
		err  error
		want RetryFailureClass
	}{
		{name: "connection refused", err: refused, want: RetryFailureConnectionRefused},
		{name: "connection timeout", err: timeout, want: RetryFailureConnectionTimeout},
		{name: "tls handshake", err: tlsHandshakeError{errors.New("handshake failure")}, want: RetryFailureTLSHandshake},
		{name: "transport", err: errors.New("connection reset by peer"), want: RetryFailureTransport},
		{name: "response status", err: retryableResponseError{statusCode: http.StatusServiceUnavailable}, want: RetryFailureResponseStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRetryFailure(tc.err).Class; got != tc.want {
				t.Errorf("classifyRetryFailure() = %q, want %q", got, tc.want)
			}
		})
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestRetryPolicyDecisionStringIsActionable(t *testing.T) {
	policy := testRetryPolicy(t)
	decision := policy.Decide(
		RetryFailure{Class: RetryFailureResponseStatus, StatusCode: http.StatusServiceUnavailable},
		RetryRequestMeta{Method: http.MethodGet, BodyReplayable: true},
		0,
		0,
	)
	if !decision.Retry {
		t.Fatalf("expected retry decision: %+v", decision)
	}
	if got := fmt.Sprintf("%s %s", decision.Policy, decision.Reason); !strings.Contains(got, "503") {
		t.Errorf("decision does not identify status policy: %s", got)
	}
}
