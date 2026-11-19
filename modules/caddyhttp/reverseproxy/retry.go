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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	defaultIdempotencyKeyHeader = "Idempotency-Key"
	defaultRetryJitter          = 0.2
	maxRetryCount               = 10
	maxRetryInterval            = 30 * time.Second
)

type tlsHandshakeError struct{ error }

func (e tlsHandshakeError) Unwrap() error { return e.error }

var defaultIdempotentMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPut,
	http.MethodDelete,
	http.MethodOptions,
	http.MethodTrace,
}

var retryFailureOptions = []string{
	string(RetryFailureConnectionRefused),
	string(RetryFailureConnectionTimeout),
	string(RetryFailureTLSHandshake),
	string(RetryFailureTransport),
}

var commonRetryStatusCodes = []int{
	http.StatusRequestTimeout,
	http.StatusTooEarly,
	http.StatusTooManyRequests,
	http.StatusInternalServerError,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
}

// RetryFailureClass is a transport- or response-level failure category used by
// RetryPolicy. It deliberately contains no HTTP status code list; status codes
// are supplied by configuration.
type RetryFailureClass string

const (
	// RetryFailureNone indicates that no retryable failure was classified.
	RetryFailureNone RetryFailureClass = ""
	// RetryFailureConnectionRefused is a connection attempt rejected by the upstream.
	RetryFailureConnectionRefused RetryFailureClass = "connection_refused"
	// RetryFailureConnectionTimeout is a timeout while establishing a connection.
	RetryFailureConnectionTimeout RetryFailureClass = "connection_timeout"
	// RetryFailureTLSHandshake is a TLS handshake or certificate verification failure.
	RetryFailureTLSHandshake RetryFailureClass = "tls_handshake"
	// RetryFailureTransport is any other transport-level failure.
	RetryFailureTransport RetryFailureClass = "transport_error"
	// RetryFailureResponseStatus is an upstream response with an HTTP status code.
	RetryFailureResponseStatus RetryFailureClass = "response_status"
	// RetryFailureUpstreamUnavailable means no upstream could be selected.
	RetryFailureUpstreamUnavailable RetryFailureClass = "upstream_unavailable"
)

// RetryFailure is the classified result of one proxy attempt.
type RetryFailure struct {
	Class      RetryFailureClass
	StatusCode int
}

// RetryRequestMeta describes request properties that affect whether an
// attempt may be safely repeated.
type RetryRequestMeta struct {
	Method                string
	IdempotencyKeyPresent bool
	BodyPresent           bool
	BodyReplayable        bool
	ResponseStarted       bool
	ClientCanceled        bool
}

// retryAttempt carries per-attempt state that is safe to inspect from both
// response handling and the retry decision.
type retryAttempt struct {
	retries        int
	start          time.Time
	bodyPresent    bool
	bodyReplayable func() bool
}

func (a *retryAttempt) bodyIsReplayable() bool {
	if a == nil || a.bodyReplayable == nil {
		return true
	}
	return a.bodyReplayable()
}

// RetryDecision is the policy's explainable decision for one failure.
type RetryDecision struct {
	Retry      bool
	Policy     string
	Reason     string
	Failure    RetryFailureClass
	StatusCode int
	Delay      time.Duration
}

// RetryPolicy controls when and how an upstream request is retried. A nil or
// disabled policy does not change the existing reverse proxy behavior.
type RetryPolicy struct {
	// Failure classes that are eligible for retry.
	RetryOn []string `json:"retry_on,omitempty"`

	// Failure classes that must never be retried. These take precedence over
	// RetryOn.
	NeverRetryOn []string `json:"never_retry_on,omitempty"`

	// HTTP response status codes that are eligible for retry.
	RetryStatusCodes []int `json:"retry_status_codes,omitempty"`

	// HTTP response status codes that must never be retried. These take
	// precedence over RetryStatusCodes.
	NeverRetryStatusCodes []int `json:"never_retry_status_codes,omitempty"`

	// Maximum number of retries after the initial attempt. If zero, the
	// load balancer's existing retries value is used. The maximum allowed
	// value is 10.
	MaxRetries int `json:"max_retries,omitempty"`

	// Total time budget for all attempts and retry delays. If zero, the load
	// balancer's existing try_duration is used. A budget is required whenever
	// retries are enabled by this policy.
	TotalBudget caddy.Duration `json:"total_budget,omitempty"`

	// Initial delay between attempts. If zero, the load balancer's existing
	// try_interval is used.
	InitialInterval caddy.Duration `json:"initial_interval,omitempty"`

	// Maximum delay between attempts after exponential backoff and jitter.
	// The maximum allowed value is 30s.
	MaxInterval caddy.Duration `json:"max_interval,omitempty"`

	// Jitter fraction applied to retry delays, in the range [0, 1]. The
	// default is 0.2, meaning a delay may vary by +/- 20%.
	Jitter float64 `json:"jitter,omitempty"`

	// Methods considered idempotent. Defaults to GET, HEAD, PUT, DELETE,
	// OPTIONS, and TRACE.
	IdempotentMethods []string `json:"idempotent_methods,omitempty"`

	// Allows retries for methods not listed in IdempotentMethods, but only when
	// the request carries IdempotencyKeyHeader.
	RetryNonIdempotent bool `json:"retry_non_idempotent,omitempty"`

	// Header carrying the idempotency key required for non-idempotent retries.
	// Defaults to Idempotency-Key.
	IdempotencyKeyHeader string `json:"idempotency_key_header,omitempty"`

	retryFailures      map[RetryFailureClass]struct{}
	neverRetryFailures map[RetryFailureClass]struct{}
	retryStatuses      map[int]struct{}
	neverRetryStatuses map[int]struct{}
	idempotentMethods  map[string]struct{}

	effectiveMaxRetries      int
	effectiveTotalBudget     time.Duration
	effectiveInitialInterval time.Duration
	effectiveMaxInterval     time.Duration
}

// compile validates p and prepares its lookup tables using lb for any values
// the policy inherits from the existing load-balancing configuration.
func (p *RetryPolicy) compile(lb *LoadBalancing) error {
	if p == nil {
		return nil
	}
	if lb == nil {
		lb = new(LoadBalancing)
	}

	p.retryFailures = make(map[RetryFailureClass]struct{}, len(p.RetryOn))
	for _, raw := range p.RetryOn {
		class := RetryFailureClass(strings.ToLower(strings.TrimSpace(raw)))
		if !slices.Contains(retryFailureOptions, string(class)) {
			return fmt.Errorf("retry_policy.retry_on: unknown failure class %q; valid options: %s",
				raw, strings.Join(retryFailureOptions, ", "))
		}
		p.retryFailures[class] = struct{}{}
	}

	p.neverRetryFailures = make(map[RetryFailureClass]struct{}, len(p.NeverRetryOn))
	for _, raw := range p.NeverRetryOn {
		class := RetryFailureClass(strings.ToLower(strings.TrimSpace(raw)))
		if !slices.Contains(retryFailureOptions, string(class)) {
			return fmt.Errorf("retry_policy.never_retry_on: unknown failure class %q; valid options: %s",
				raw, strings.Join(retryFailureOptions, ", "))
		}
		p.neverRetryFailures[class] = struct{}{}
	}

	var err error
	p.retryStatuses, err = compileRetryStatusCodes("retry_policy.retry_status_codes", p.RetryStatusCodes)
	if err != nil {
		return err
	}
	p.neverRetryStatuses, err = compileRetryStatusCodes("retry_policy.never_retry_status_codes", p.NeverRetryStatusCodes)
	if err != nil {
		return err
	}

	p.effectiveMaxRetries = p.MaxRetries
	if p.effectiveMaxRetries == 0 {
		p.effectiveMaxRetries = lb.Retries
	}
	if p.effectiveMaxRetries < 0 {
		return fmt.Errorf("retry_policy.max_retries: must not be negative")
	}
	if p.effectiveMaxRetries > maxRetryCount {
		return fmt.Errorf("retry_policy.max_retries: %d exceeds the maximum of %d", p.effectiveMaxRetries, maxRetryCount)
	}

	p.effectiveTotalBudget = time.Duration(p.TotalBudget)
	if p.effectiveTotalBudget == 0 {
		p.effectiveTotalBudget = time.Duration(lb.TryDuration)
	}
	if p.effectiveTotalBudget < 0 {
		return fmt.Errorf("retry_policy.total_budget: must not be negative")
	}
	if p.effectiveMaxRetries > 0 && p.effectiveTotalBudget == 0 {
		return fmt.Errorf("retry_policy.total_budget: an explicit total budget is required when retries are enabled")
	}

	p.effectiveInitialInterval = time.Duration(p.InitialInterval)
	if p.effectiveInitialInterval == 0 {
		p.effectiveInitialInterval = time.Duration(lb.TryInterval)
	}
	if p.effectiveInitialInterval < 0 {
		return fmt.Errorf("retry_policy.initial_interval: must not be negative")
	}

	p.effectiveMaxInterval = time.Duration(p.MaxInterval)
	if p.effectiveMaxInterval == 0 {
		p.effectiveMaxInterval = min(p.effectiveInitialInterval*8, maxRetryInterval)
		if p.effectiveMaxInterval < p.effectiveInitialInterval {
			p.effectiveMaxInterval = p.effectiveInitialInterval
		}
	}
	if p.effectiveMaxInterval < 0 {
		return fmt.Errorf("retry_policy.max_interval: must not be negative")
	}
	if p.effectiveMaxInterval > maxRetryInterval {
		return fmt.Errorf("retry_policy.max_interval: %s exceeds the maximum of %s", p.effectiveMaxInterval, maxRetryInterval)
	}
	if p.effectiveInitialInterval > p.effectiveMaxInterval {
		return fmt.Errorf("retry_policy.initial_interval: %s must not exceed max_interval %s",
			p.effectiveInitialInterval, p.effectiveMaxInterval)
	}

	if p.Jitter == 0 {
		p.Jitter = defaultRetryJitter
	}
	if math.IsNaN(p.Jitter) || p.Jitter < 0 || p.Jitter > 1 {
		return fmt.Errorf("retry_policy.jitter: %v must be in the range [0, 1]", p.Jitter)
	}

	methods := p.IdempotentMethods
	if len(methods) == 0 {
		methods = defaultIdempotentMethods
	}
	p.idempotentMethods = make(map[string]struct{}, len(methods))
	for _, method := range methods {
		method = strings.TrimSpace(method)
		if method == "" {
			return fmt.Errorf("retry_policy.idempotent_methods: method must not be empty")
		}
		p.idempotentMethods[strings.ToUpper(method)] = struct{}{}
	}

	if p.IdempotencyKeyHeader == "" {
		p.IdempotencyKeyHeader = defaultIdempotencyKeyHeader
	}
	if !httpguts.ValidHeaderFieldName(p.IdempotencyKeyHeader) {
		return fmt.Errorf("retry_policy.idempotency_key_header: invalid header name %q", p.IdempotencyKeyHeader)
	}

	return nil
}

func compileRetryStatusCodes(field string, statusCodes []int) (map[int]struct{}, error) {
	compiled := make(map[int]struct{}, len(statusCodes))
	for _, statusCode := range statusCodes {
		if statusCode < 100 || statusCode > 599 {
			return nil, fmt.Errorf("%s: unknown HTTP status code %d; valid options are 100-599; commonly retryable codes: %v",
				field, statusCode, commonRetryStatusCodes)
		}
		compiled[statusCode] = struct{}{}
	}
	return compiled, nil
}

// IsIdempotent reports whether method is configured as idempotent.
func (p *RetryPolicy) IsIdempotent(method string) bool {
	if p == nil {
		return false
	}
	if p.idempotentMethods == nil {
		return slices.Contains(defaultIdempotentMethods, strings.ToUpper(method))
	}
	_, ok := p.idempotentMethods[strings.ToUpper(method)]
	return ok
}

// Decide returns whether one classified failure may be retried. retries is the
// number of retries already performed, and elapsed is the total time spent on
// the request so far.
func (p *RetryPolicy) Decide(failure RetryFailure, meta RetryRequestMeta, retries int, elapsed time.Duration) RetryDecision {
	decision := RetryDecision{
		Failure:    failure.Class,
		StatusCode: failure.StatusCode,
	}
	if p == nil {
		decision.Reason = "retry policy is disabled"
		return decision
	}

	if meta.ClientCanceled {
		decision.Policy = "client.disconnected"
		decision.Reason = "client disconnected"
		return decision
	}
	if meta.ResponseStarted {
		decision.Policy = "response.committed"
		decision.Reason = "response has already been committed to the client"
		return decision
	}
	if meta.BodyPresent && !meta.BodyReplayable {
		decision.Policy = "request_body.not_replayable"
		decision.Reason = "request body was consumed and cannot be replayed"
		return decision
	}
	if !p.IsIdempotent(meta.Method) {
		if !p.RetryNonIdempotent {
			decision.Policy = "method.non_idempotent"
			decision.Reason = fmt.Sprintf("request method %s is non-idempotent", meta.Method)
			return decision
		}
		if !meta.IdempotencyKeyPresent {
			decision.Policy = "method.idempotency_key_required"
			decision.Reason = fmt.Sprintf("non-idempotent retry requires header %s", p.IdempotencyKeyHeader)
			return decision
		}
	}

	if failure.Class == RetryFailureResponseStatus {
		if _, ok := p.neverRetryStatuses[failure.StatusCode]; ok {
			decision.Policy = fmt.Sprintf("never_retry_status_codes.%d", failure.StatusCode)
			decision.Reason = fmt.Sprintf("HTTP status %d matched never_retry_status_codes", failure.StatusCode)
			return decision
		}
		if _, ok := p.retryStatuses[failure.StatusCode]; !ok {
			decision.Policy = "retry_status_codes"
			decision.Reason = fmt.Sprintf("HTTP status %d is not listed in retry_status_codes", failure.StatusCode)
			return decision
		}
		decision.Policy = fmt.Sprintf("retry_status_codes.%d", failure.StatusCode)
	} else {
		if _, ok := p.neverRetryFailures[failure.Class]; ok {
			decision.Policy = "never_retry_on." + string(failure.Class)
			decision.Reason = fmt.Sprintf("failure %s matched never_retry_on", failure.Class)
			return decision
		}
		if _, ok := p.retryFailures[failure.Class]; !ok {
			decision.Policy = "retry_on"
			decision.Reason = fmt.Sprintf("failure %s is not listed in retry_on", failure.Class)
			return decision
		}
		decision.Policy = "retry_on." + string(failure.Class)
	}

	if retries >= p.effectiveMaxRetries {
		decision.Policy = "max_retries"
		decision.Reason = fmt.Sprintf("maximum retries reached (%d)", p.effectiveMaxRetries)
		return decision
	}
	if p.effectiveTotalBudget > 0 && elapsed >= p.effectiveTotalBudget {
		decision.Policy = "total_budget"
		decision.Reason = fmt.Sprintf("retry budget exhausted (%s of %s)", elapsed, p.effectiveTotalBudget)
		return decision
	}

	delay := p.delay(retries)
	if p.effectiveTotalBudget > 0 && elapsed+delay >= p.effectiveTotalBudget {
		decision.Policy = "total_budget"
		decision.Reason = fmt.Sprintf("next attempt would exceed retry budget (%s + %s >= %s)",
			elapsed, delay, p.effectiveTotalBudget)
		return decision
	}

	decision.Retry = true
	decision.Delay = delay
	decision.Reason = fmt.Sprintf("failure %s matched %s", failure.Class, decision.Policy)
	if failure.Class == RetryFailureResponseStatus {
		decision.Reason = fmt.Sprintf("HTTP status %d matched %s", failure.StatusCode, decision.Policy)
	}
	return decision
}

func (p *RetryPolicy) delay(retries int) time.Duration {
	if p == nil || p.effectiveInitialInterval <= 0 {
		return 0
	}

	delay := p.effectiveInitialInterval
	for range retries {
		if delay >= p.effectiveMaxInterval/2 {
			delay = p.effectiveMaxInterval
			break
		}
		delay *= 2
	}
	if delay > p.effectiveMaxInterval {
		delay = p.effectiveMaxInterval
	}
	if p.Jitter > 0 {
		jitter := (rand.Float64()*2 - 1) * p.Jitter
		delay = time.Duration(float64(delay) * (1 + jitter))
	}
	if delay < 0 {
		return 0
	}
	if delay > p.effectiveMaxInterval {
		return p.effectiveMaxInterval
	}
	return delay
}

func (p *RetryPolicy) totalBudget() time.Duration {
	if p == nil {
		return 0
	}
	return p.effectiveTotalBudget
}

func retryRequestMeta(req *http.Request, bodyPresent, bodyReplayable bool) RetryRequestMeta {
	meta := RetryRequestMeta{
		Method:         req.Method,
		BodyPresent:    bodyPresent,
		BodyReplayable: bodyReplayable,
	}
	if req.Context() != nil {
		meta.ClientCanceled = req.Context().Err() != nil
	}
	return meta
}

func (m RetryRequestMeta) withIdempotencyKey(req *http.Request, header string) RetryRequestMeta {
	if req == nil {
		return m
	}
	if header == "" {
		header = defaultIdempotencyKeyHeader
	}
	m.IdempotencyKeyPresent = strings.TrimSpace(req.Header.Get(header)) != ""
	return m
}

func classifyRetryFailure(err error) RetryFailure {
	if err == nil {
		return RetryFailure{}
	}
	if errors.Is(err, context.Canceled) {
		return RetryFailure{}
	}
	if errors.Is(err, errWritingDownstream) {
		return RetryFailure{}
	}

	var responseErr retryableResponseError
	if errors.As(err, &responseErr) {
		return RetryFailure{
			Class:      RetryFailureResponseStatus,
			StatusCode: responseErr.statusCode,
		}
	}

	var herr caddyhttp.HandlerError
	if errors.As(err, &herr) && errors.Is(herr, errNoUpstream) {
		return RetryFailure{Class: RetryFailureUpstreamUnavailable}
	}

	if isTLSHandshakeFailure(err) {
		return RetryFailure{Class: RetryFailureTLSHandshake}
	}

	var dialErr DialError
	isDialError := errors.As(err, &dialErr)
	if isDialError {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return RetryFailure{Class: RetryFailureConnectionRefused}
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return RetryFailure{Class: RetryFailureConnectionTimeout}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return RetryFailure{Class: RetryFailureConnectionTimeout}
		}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return RetryFailure{Class: RetryFailureConnectionRefused}
	}

	return RetryFailure{Class: RetryFailureTransport}
}

func isTLSHandshakeFailure(err error) bool {
	var handshakeErr tlsHandshakeError
	if errors.As(err, &handshakeErr) {
		return true
	}
	var recordHeaderErr tls.RecordHeaderError
	if errors.As(err, &recordHeaderErr) {
		return true
	}
	var certificateErr *tls.CertificateVerificationError
	if errors.As(err, &certificateErr) {
		return true
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return true
	}
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var certificateInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certificateInvalidErr) {
		return true
	}

	// net/http does not expose typed errors for all handshake failures, and
	// some transports return plain errors. Keep this matching narrow so an
	// ordinary transport error is not misclassified.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls handshake timeout") ||
		strings.Contains(msg, "remote error: tls:") ||
		strings.Contains(msg, "tls: first record does not look like a tls handshake") ||
		strings.Contains(msg, "tls: failed to verify certificate") ||
		strings.Contains(msg, "server gave http response to https client") ||
		strings.Contains(msg, "x509:")
}

func logRetryDecision(logger *zap.Logger, decision RetryDecision, retries int, method string) {
	if logger == nil {
		return
	}
	if c := logger.Check(zap.DebugLevel, "retry decision"); c != nil {
		c.Write(
			zap.Bool("retry", decision.Retry),
			zap.String("policy", decision.Policy),
			zap.String("reason", decision.Reason),
			zap.String("failure", string(decision.Failure)),
			zap.Int("status_code", decision.StatusCode),
			zap.Int("retries", retries),
			zap.String("method", method),
			zap.Duration("delay", decision.Delay),
		)
	}
}

// UnmarshalCaddyfile parses the retry policy block. Syntax:
//
//	lb_retry_policy {
//	    retry_on <failure...>
//	    never_retry_on <failure...>
//	    retry_status_codes <code...>
//	    never_retry_status_codes <code...>
//	    max_retries <n>
//	    total_budget <duration>
//	    initial_interval <duration>
//	    max_interval <duration>
//	    jitter <fraction>
//	    idempotent_methods <method...>
//	    retry_non_idempotent
//	    idempotency_key_header <name>
//	}
func (p *RetryPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var sawBlock bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		sawBlock = true
		switch d.Val() {
		case "retry_on":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			p.RetryOn = append(p.RetryOn, args...)
		case "never_retry_on":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			p.NeverRetryOn = append(p.NeverRetryOn, args...)
		case "retry_status_codes", "retry_status_code":
			codes, err := parseRetryStatusCodes(d)
			if err != nil {
				return err
			}
			p.RetryStatusCodes = append(p.RetryStatusCodes, codes...)
		case "never_retry_status_codes", "never_retry_status_code":
			codes, err := parseRetryStatusCodes(d)
			if err != nil {
				return err
			}
			p.NeverRetryStatusCodes = append(p.NeverRetryStatusCodes, codes...)
		case "max_retries":
			if !d.NextArg() {
				return d.ArgErr()
			}
			retries, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("bad max_retries value %q: %v", d.Val(), err)
			}
			p.MaxRetries = retries
		case "total_budget":
			duration, err := parseRetryDuration(d)
			if err != nil {
				return err
			}
			p.TotalBudget = caddy.Duration(duration)
		case "initial_interval":
			duration, err := parseRetryDuration(d)
			if err != nil {
				return err
			}
			p.InitialInterval = caddy.Duration(duration)
		case "max_interval":
			duration, err := parseRetryDuration(d)
			if err != nil {
				return err
			}
			p.MaxInterval = caddy.Duration(duration)
		case "jitter":
			if !d.NextArg() {
				return d.ArgErr()
			}
			jitter, err := strconv.ParseFloat(d.Val(), 64)
			if err != nil {
				return d.Errf("bad jitter value %q: %v", d.Val(), err)
			}
			p.Jitter = jitter
		case "idempotent_methods":
			methods := d.RemainingArgs()
			if len(methods) == 0 {
				return d.ArgErr()
			}
			p.IdempotentMethods = append(p.IdempotentMethods, methods...)
		case "retry_non_idempotent":
			if d.NextArg() {
				enabled, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("bad retry_non_idempotent value %q: %v", d.Val(), err)
				}
				p.RetryNonIdempotent = enabled
			} else {
				p.RetryNonIdempotent = true
			}
		case "idempotency_key_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.IdempotencyKeyHeader = d.Val()
		default:
			return d.Errf("unrecognized retry policy subdirective: %s", d.Val())
		}
	}
	if !sawBlock {
		return d.Err("lb_retry_policy requires a block")
	}
	return p.compile(nil)
}

func parseRetryStatusCodes(d *caddyfile.Dispenser) ([]int, error) {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return nil, d.ArgErr()
	}
	codes := make([]int, 0, len(args))
	for _, arg := range args {
		code, err := strconv.Atoi(arg)
		if err != nil {
			return nil, d.Errf("bad HTTP status code %q: %v", arg, err)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

func parseRetryDuration(d *caddyfile.Dispenser) (time.Duration, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	duration, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return 0, d.Errf("bad duration value %q: %v", d.Val(), err)
	}
	return duration, nil
}
