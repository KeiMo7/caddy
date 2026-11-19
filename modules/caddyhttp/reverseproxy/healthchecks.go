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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// HealthChecks configures active and passive health checks.
type HealthChecks struct {
	// Active health checks run in the background on a timer. To
	// minimally enable active health checks, set either path or
	// port (or both). Note that active health check status
	// (healthy/unhealthy) is stored per-proxy-handler, not
	// globally; this allows different handlers to use different
	// criteria to decide what defines a healthy backend.
	//
	// Active health checks do not run for dynamic upstreams.
	Active *ActiveHealthChecks `json:"active,omitempty"`

	// Passive health checks monitor proxied requests for errors or timeouts.
	// To minimally enable passive health checks, specify at least an empty
	// config object with fail_duration > 0. Passive health check state is
	// shared (stored globally), so a failure from one handler will be counted
	// by all handlers; but the tolerances or standards for what defines
	// healthy/unhealthy backends is configured per-proxy-handler.
	//
	// Passive health checks technically do operate on dynamic upstreams,
	// but are only effective for very busy proxies where the list of
	// upstreams is mostly stable. This is because the shared/global
	// state of upstreams is cleaned up when the upstreams are no longer
	// used. Since dynamic upstreams are allocated dynamically at each
	// request (specifically, each iteration of the proxy loop per request),
	// they are also cleaned up after every request. Thus, if there is a
	// moment when no requests are actively referring to a particular
	// upstream host, the passive health check state will be reset because
	// it will be garbage-collected. It is usually better for the dynamic
	// upstream module to only return healthy, available backends instead.
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

// ActiveHealthChecks holds configuration related to active
// health checks (that is, health checks which occur in a
// background goroutine independently).
type ActiveHealthChecks struct {
	// Deprecated: Use 'uri' instead. This field will be removed. TODO: remove this field
	Path string `json:"path,omitempty"`

	// The URI (path and query) to use for health checks
	URI string `json:"uri,omitempty"`

	// The host:port to use (if different from the upstream's dial address)
	// for health checks. This should be used in tandem with `health_header` and
	// `{http.reverse_proxy.active.target_upstream}`. This can be helpful when
	// creating an intermediate service to do a more thorough health check.
	// If upstream is set, the active health check port is ignored.
	Upstream string `json:"upstream,omitempty"`

	// The port to use (if different from the upstream's dial
	// address) for health checks. If active upstream is set,
	// this value is ignored.
	Port int `json:"port,omitempty"`

	// HTTP headers to set on health check requests.
	Headers http.Header `json:"headers,omitempty"`

	// The HTTP method to use for health checks (default "GET").
	Method string `json:"method,omitempty"`

	// The body to send with the health check request.
	Body string `json:"body,omitempty"`

	// Whether to follow HTTP redirects in response to active health checks (default off).
	FollowRedirects bool `json:"follow_redirects,omitempty"`

	// How frequently to perform active health checks (default 30s).
	Interval caddy.Duration `json:"interval,omitempty"`

	// How long to wait for a response from a backend before
	// considering it unhealthy (default 5s).
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// Number of consecutive health check passes before marking
	// a previously unhealthy backend as healthy again (default 1).
	Passes int `json:"passes,omitempty"`

	// Number of consecutive health check failures before marking
	// a previously healthy backend as unhealthy (default 1).
	Fails int `json:"fails,omitempty"`

	// FlapDetection optionally enables state transition history, recovery
	// observation, and gradual traffic ramping. When omitted, active health
	// checks keep their historical binary pass/fail behavior.
	FlapDetection *FlapDetection `json:"flap_detection,omitempty"`

	// Convenience equivalents of the corresponding FlapDetection fields.
	// Setting any of these enables flap detection with defaults for the
	// remaining fields.
	RecoveryObservation caddy.Duration `json:"recovery_observation,omitempty"`
	RecoveryRamp        caddy.Duration `json:"recovery_ramp,omitempty"`
	RampCurve           string         `json:"ramp_curve,omitempty"`
	FlapWindow          caddy.Duration `json:"flap_window,omitempty"`
	FlapThreshold       int            `json:"flap_threshold,omitempty"`
	ResultHistory       int            `json:"result_history,omitempty"`
	TransitionHistory   int            `json:"transition_history,omitempty"`

	// Groups optionally overrides pass/fail thresholds and flap detection
	// settings for named groups of upstreams.
	Groups map[string]*ActiveHealthGroup `json:"groups,omitempty"`

	// The maximum response body to download from the backend
	// during a health check.
	MaxSize int64 `json:"max_size,omitempty"`

	// The HTTP status code to expect from a healthy backend.
	ExpectStatus int `json:"expect_status,omitempty"`

	// A regular expression against which to match the response
	// body of a healthy backend.
	ExpectBody string `json:"expect_body,omitempty"`

	uri        *url.URL
	httpClient *http.Client
	bodyRegexp *regexp.Regexp
	logger     *zap.Logger
	flap       *FlapDetection

	recoveryObservationSet bool
	recoveryRampSet        bool
	flapWindowSet          bool
	flapThresholdSet       bool
	resultHistorySet       bool
	transitionHistorySet   bool
}

// ActiveHealthGroup overrides active health check thresholds and flap
// suppression settings for a named group of upstreams.
type ActiveHealthGroup struct {
	// Upstreams lists the dial addresses in this group. The upstream's
	// health_group field may also assign it to a group directly.
	Upstreams []string `json:"upstreams,omitempty"`

	// Fails overrides ActiveHealthChecks.Fails for this group.
	Fails int `json:"fails,omitempty"`

	// Passes overrides ActiveHealthChecks.Passes for this group.
	Passes int `json:"passes,omitempty"`

	// FlapDetection overrides the top-level flap settings for this group.
	FlapDetection *FlapDetection `json:"flap_detection,omitempty"`
}

// UnmarshalJSON tracks explicitly configured convenience fields so invalid
// zero values can be rejected during provisioning.
func (a *ActiveHealthChecks) UnmarshalJSON(data []byte) error {
	type alias ActiveHealthChecks
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*a = ActiveHealthChecks(decoded)
	_, a.recoveryObservationSet = raw["recovery_observation"]
	_, a.recoveryRampSet = raw["recovery_ramp"]
	_, a.flapWindowSet = raw["flap_window"]
	_, a.flapThresholdSet = raw["flap_threshold"]
	_, a.resultHistorySet = raw["result_history"]
	_, a.transitionHistorySet = raw["transition_history"]
	return nil
}

// Provision ensures that a is set up properly before use.
func (a *ActiveHealthChecks) Provision(ctx caddy.Context, h *Handler) error {
	if h.logger != nil {
		a.logger = h.logger.Named("health_checker.active")
	} else {
		a.logger = zap.NewNop()
	}
	if err := a.provisionGroups(h); err != nil {
		return err
	}

	if !a.IsEnabled() {
		return nil
	}

	// Canonicalize the header keys ahead of time, since
	// JSON unmarshaled headers may be incorrect
	cleaned := http.Header{}
	for key, hdrs := range a.Headers {
		for _, val := range hdrs {
			cleaned.Add(key, val)
		}
	}
	a.Headers = cleaned

	// If Method is not set, default to GET
	if a.Method == "" {
		a.Method = http.MethodGet
	}

	timeout := time.Duration(a.Timeout)
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	if a.Path != "" {
		a.logger.Warn("the 'path' option is deprecated, please use 'uri' instead!")
	}

	// parse the URI string (supports path and query)
	if a.URI != "" {
		parsedURI, err := url.Parse(a.URI)
		if err != nil {
			return err
		}
		a.uri = parsedURI
	}

	a.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: h.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !a.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, upstream := range h.Upstreams {
		// if there's an alternative upstream for health-check provided in the config,
		// then use it, otherwise use the upstream's dial address. if upstream is used,
		// then the port is ignored.
		if a.Upstream != "" {
			upstream.activeHealthCheckUpstream = a.Upstream
		} else if a.Port != 0 {
			// if there's an alternative port for health-check provided in the config,
			// then use it, otherwise use the port of upstream.
			upstream.activeHealthCheckPort = a.Port
		}
	}

	if a.Interval == 0 {
		a.Interval = caddy.Duration(30 * time.Second)
	}

	if a.ExpectBody != "" {
		var err error
		a.bodyRegexp, err = regexp.Compile(a.ExpectBody)
		if err != nil {
			return fmt.Errorf("expect_body: compiling regular expression: %v", err)
		}
	}

	if a.Passes < 1 {
		a.Passes = 1
	}

	if a.Fails < 1 {
		a.Fails = 1
	}

	if a.FlapsEnabled() && time.Duration(a.Timeout) >= time.Duration(a.Interval) {
		a.logger.Warn("active health check timeout is greater than or equal to its interval; overlapping probes will be skipped",
			zap.Duration("interval", time.Duration(a.Interval)),
			zap.Duration("timeout", time.Duration(a.Timeout)),
		)
	}

	for _, upstream := range h.Upstreams {
		stateConfig := a.stateConfigForUpstream(upstream)
		state := upstream.ensureHealthState(stateConfig)
		state.SetIdentity(upstream.Dial, upstream.HealthGroup)
		registerHealthState(h, upstream, state)
	}
	if len(h.Upstreams) > 0 {
		go func() {
			<-ctx.Done()
			unregisterHealthStates(h)
		}()
	}

	return nil
}

// FlapsEnabled reports whether flap suppression is configured.
func (a *ActiveHealthChecks) FlapsEnabled() bool {
	if a == nil {
		return false
	}
	if a.flap != nil || a.FlapDetection != nil ||
		a.RecoveryObservation != 0 || a.RecoveryRamp != 0 || a.RampCurve != "" ||
		a.FlapWindow != 0 || a.FlapThreshold != 0 || a.ResultHistory != 0 || a.TransitionHistory != 0 ||
		a.recoveryObservationSet || a.recoveryRampSet || a.flapWindowSet ||
		a.flapThresholdSet || a.resultHistorySet || a.transitionHistorySet {
		return true
	}
	for _, group := range a.Groups {
		if group != nil && group.FlapDetection != nil {
			return true
		}
	}
	return false
}

func (a *ActiveHealthChecks) resolvedFlapDetection() *FlapDetection {
	if a == nil {
		return nil
	}
	if a.flap != nil {
		return a.flap
	}
	if a.FlapDetection != nil {
		a.flap = a.FlapDetection
		return a.flap
	}
	if a.RecoveryObservation == 0 && a.RecoveryRamp == 0 && a.RampCurve == "" &&
		a.FlapWindow == 0 && a.FlapThreshold == 0 && a.ResultHistory == 0 && a.TransitionHistory == 0 &&
		!a.recoveryObservationSet && !a.recoveryRampSet && !a.flapWindowSet && !a.flapThresholdSet &&
		!a.resultHistorySet && !a.transitionHistorySet {
		return nil
	}
	a.flap = &FlapDetection{
		Window:               a.FlapWindow,
		Threshold:            a.FlapThreshold,
		Observation:          a.RecoveryObservation,
		Ramp:                 a.RecoveryRamp,
		RampCurve:            a.RampCurve,
		ResultHistory:        a.ResultHistory,
		TransitionHistory:    a.TransitionHistory,
		windowSet:            a.flapWindowSet,
		thresholdSet:         a.flapThresholdSet,
		observationSet:       a.recoveryObservationSet,
		rampSet:              a.recoveryRampSet,
		resultHistorySet:     a.resultHistorySet,
		transitionHistorySet: a.transitionHistorySet,
	}
	return a.flap
}

func (a *ActiveHealthChecks) provisionGroups(h *Handler) error {
	flap := a.resolvedFlapDetection()
	if err := flap.provision(); err != nil {
		return err
	}
	a.flap = flap

	groupByName := make(map[string]*ActiveHealthGroup, len(a.Groups))
	for name, group := range a.Groups {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("active health check group name cannot be empty")
		}
		if group == nil {
			group = new(ActiveHealthGroup)
			a.Groups[name] = group
		}
		if group.Fails < 0 {
			return fmt.Errorf("active health check group %q fails cannot be negative", name)
		}
		if group.Passes < 0 {
			return fmt.Errorf("active health check group %q passes cannot be negative", name)
		}
		effectiveFlap := mergeFlapDetection(flap, group.FlapDetection)
		if err := effectiveFlap.provision(); err != nil {
			return fmt.Errorf("active health check group %q: %w", name, err)
		}
		group.FlapDetection = effectiveFlap
		groupByName[name] = group
	}

	for name, group := range a.Groups {
		for _, addr := range group.Upstreams {
			var matched bool
			for _, upstream := range h.Upstreams {
				if upstream.HealthGroup != "" && upstream.HealthGroup != name {
					if upstreamDialMatches(addr, upstream.Dial) {
						return fmt.Errorf("upstream %s is assigned to multiple active health check groups", upstream.Dial)
					}
					continue
				}
				if upstreamDialMatches(addr, upstream.Dial) {
					upstream.HealthGroup = name
					matched = true
				}
			}
			if !matched {
				a.logger.Warn("active health check group references an unknown upstream",
					zap.String("group", name),
					zap.String("upstream", addr),
				)
			}
		}
	}
	for _, upstream := range h.Upstreams {
		if upstream.HealthGroup == "" {
			continue
		}
		if _, ok := groupByName[upstream.HealthGroup]; !ok {
			return fmt.Errorf("upstream %s references unknown active health check group %q", upstream.Dial, upstream.HealthGroup)
		}
	}
	return nil
}

func (a *ActiveHealthChecks) stateConfigForUpstream(upstream *Upstream) HealthStateConfig {
	passes, fails := a.Passes, a.Fails
	flap := a.flap
	if group := a.groupForUpstream(upstream); group != nil {
		if group.Passes > 0 {
			passes = group.Passes
		}
		if group.Fails > 0 {
			fails = group.Fails
		}
		if group.FlapDetection != nil {
			flap = group.FlapDetection
		}
	}
	return flap.stateConfig(passes, fails)
}

func (a *ActiveHealthChecks) groupForUpstream(upstream *Upstream) *ActiveHealthGroup {
	if a == nil || upstream == nil || upstream.HealthGroup == "" {
		return nil
	}
	return a.Groups[upstream.HealthGroup]
}

func mergeFlapDetection(parent, child *FlapDetection) *FlapDetection {
	if child == nil {
		return parent
	}
	if parent == nil {
		return child
	}
	merged := *parent
	if child.windowSet || child.Window != 0 {
		merged.Window = child.Window
		merged.windowSet = child.windowSet
	}
	if child.thresholdSet || child.Threshold != 0 {
		merged.Threshold = child.Threshold
		merged.thresholdSet = child.thresholdSet
	}
	if child.observationSet || child.Observation != 0 {
		merged.Observation = child.Observation
		merged.observationSet = child.observationSet
	}
	if child.rampSet || child.Ramp != 0 {
		merged.Ramp = child.Ramp
		merged.rampSet = child.rampSet
	}
	if child.RampCurve != "" {
		merged.RampCurve = child.RampCurve
	}
	if child.resultHistorySet || child.ResultHistory != 0 {
		merged.ResultHistory = child.ResultHistory
		merged.resultHistorySet = child.resultHistorySet
	}
	if child.transitionHistorySet || child.TransitionHistory != 0 {
		merged.TransitionHistory = child.TransitionHistory
		merged.transitionHistorySet = child.transitionHistorySet
	}
	return &merged
}

func upstreamDialMatches(configAddr, dial string) bool {
	if configAddr == dial {
		return true
	}
	parsed, err := parseUpstreamDialAddress(configAddr)
	if err != nil {
		return false
	}
	return parsed.dialAddr() == dial
}

// IsEnabled checks if the active health checks have
// the minimum config necessary to be enabled.
func (a *ActiveHealthChecks) IsEnabled() bool {
	return a.Path != "" || a.URI != "" || a.Port != 0
}

// PassiveHealthChecks holds configuration related to passive
// health checks (that is, health checks which occur during
// the normal flow of request proxying).
type PassiveHealthChecks struct {
	// How long to remember a failed request to a backend. A duration > 0
	// enables passive health checking. Default is 0.
	FailDuration caddy.Duration `json:"fail_duration,omitempty"`

	// The number of failed requests within the FailDuration window to
	// consider a backend as "down". Must be >= 1; default is 1. Requires
	// that FailDuration be > 0.
	MaxFails int `json:"max_fails,omitempty"`

	// Limits the number of simultaneous requests to a backend by
	// marking the backend as "down" if it has this many concurrent
	// requests or more.
	UnhealthyRequestCount int `json:"unhealthy_request_count,omitempty"`

	// Count the request as failed if the response comes back with
	// one of these status codes.
	UnhealthyStatus []int `json:"unhealthy_status,omitempty"`

	// Count the request as failed if the response takes at least this
	// long to receive.
	UnhealthyLatency caddy.Duration `json:"unhealthy_latency,omitempty"`

	logger *zap.Logger
}

// CircuitBreaker is a type that can act as an early-warning
// system for the health checker when backends are getting
// overloaded. This interface is still experimental and is
// subject to change.
type CircuitBreaker interface {
	OK() bool
	RecordMetric(statusCode int, latency time.Duration)
}

// activeHealthChecker runs active health checks on a
// regular basis and blocks until
// h.HealthChecks.Active.stopChan is closed.
func (h *Handler) activeHealthChecker() {
	defer func() {
		if err := recover(); err != nil {
			if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "active health checker panicked"); c != nil {
				c.Write(
					zap.Any("error", err),
					zap.ByteString("stack", debug.Stack()),
				)
			}
		}
	}()
	ticker := time.NewTicker(time.Duration(h.HealthChecks.Active.Interval))
	h.doActiveHealthCheckForAllHosts()
	for {
		select {
		case <-ticker.C:
			h.doActiveHealthCheckForAllHosts()
		case <-h.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

// doActiveHealthCheckForAllHosts immediately performs a
// health checks for all upstream hosts configured by h.
func (h *Handler) doActiveHealthCheckForAllHosts() {
	for _, upstream := range h.Upstreams {
		go func(upstream *Upstream) {
			defer func() {
				if err := recover(); err != nil {
					if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "active health checker panicked"); c != nil {
						c.Write(
							zap.Any("error", err),
							zap.ByteString("stack", debug.Stack()),
						)
					}
				}
			}()

			repl := caddy.NewReplacer()

			networkAddr, err := repl.ReplaceOrErr(upstream.Dial, true, true)
			if err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "invalid use of placeholders in dial address for active health checks"); c != nil {
					c.Write(
						zap.String("address", networkAddr),
						zap.Error(err),
					)
				}
				return
			}
			addr, err := caddy.ParseNetworkAddress(networkAddr)
			if err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "bad network address"); c != nil {
					c.Write(
						zap.String("address", networkAddr),
						zap.Error(err),
					)
				}
				return
			}
			if hcp := uint(upstream.activeHealthCheckPort); hcp != 0 {
				if addr.IsUnixNetwork() || addr.IsFdNetwork() {
					addr.Network = "tcp" // I guess we just assume TCP since we are using a port??
				}
				addr.StartPort, addr.EndPort = hcp, hcp
			}
			if addr.PortRangeSize() != 1 {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "multiple addresses (upstream must map to only one address)"); c != nil {
					c.Write(
						zap.String("address", networkAddr),
					)
				}
				return
			}
			hostAddr := addr.JoinHostPort(0)
			if addr.IsUnixNetwork() || addr.IsFdNetwork() {
				// this will be used as the Host portion of a http.Request URL, and
				// paths to socket files would produce an error when creating URL,
				// so use a fake Host value instead; unix sockets are usually local
				hostAddr = "localhost"
			}

			// Fill in the dial info for the upstream
			// If the upstream is set, use that instead
			dialInfoUpstream := upstream
			if h.HealthChecks.Active.Upstream != "" {
				dialInfoUpstream = &Upstream{
					Dial: h.HealthChecks.Active.Upstream,
				}
			} else if upstream.activeHealthCheckPort != 0 {
				// health_port overrides the port; addr has already been updated
				// with the health port, so use its address for dialing
				dialInfoUpstream = &Upstream{
					Dial: addr.JoinHostPort(0),
				}
			}
			dialInfo, _ := dialInfoUpstream.fillDialInfo(repl)

			err = h.doActiveHealthCheck(dialInfo, hostAddr, networkAddr, upstream)
			if err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "active health check failed"); c != nil {
					c.Write(
						zap.String("address", hostAddr),
						zap.Error(err),
					)
				}
			}
		}(upstream)
	}
}

// doActiveHealthCheck performs a health check to upstream which
// can be reached at address hostAddr. The actual address for
// the request will be built according to active health checker
// config. The health status of the host will be updated
// according to whether it passes the health check. An error is
// returned only if the health check fails to occur or if marking
// the host's health status fails.
func (h *Handler) doActiveHealthCheck(dialInfo DialInfo, hostAddr string, networkAddr string, upstream *Upstream) error {
	if !upstream.probeInFlight.CompareAndSwap(false, true) {
		upstream.overlapSkipped.Add(1)
		return nil
	}
	defer upstream.probeInFlight.Store(false)

	probeStarted := time.Now()
	probeID := upstream.probeSeq.Add(1)

	// create the URL for the request that acts as a health check
	u := &url.URL{
		Scheme: "http",
		Host:   hostAddr,
	}

	// split the host and port if possible, override the port if configured
	host, port, err := net.SplitHostPort(hostAddr)
	if err != nil {
		host = hostAddr
	}

	// ignore active health check port if active upstream is provided as the
	// active upstream already contains the replacement port
	if h.HealthChecks.Active.Upstream != "" {
		u.Host = h.HealthChecks.Active.Upstream
	} else if h.HealthChecks.Active.Port != 0 {
		port := strconv.Itoa(h.HealthChecks.Active.Port)
		u.Host = net.JoinHostPort(host, port)
	}

	// override health check schemes if applicable, based on the port
	// the health check connects to (health_upstream may change it)
	if hcsot, ok := h.Transport.(HealthCheckSchemeOverriderTransport); ok {
		_, hcPort, err := net.SplitHostPort(u.Host)
		if err != nil {
			hcPort = port
		}
		hcsot.OverrideHealthCheckScheme(u, hcPort)
	}

	// if we have a provisioned uri, use that, otherwise use
	// the deprecated Path option
	if h.HealthChecks.Active.uri != nil {
		u.Path = h.HealthChecks.Active.uri.Path
		u.RawQuery = h.HealthChecks.Active.uri.RawQuery
	} else {
		u.Path = h.HealthChecks.Active.Path
	}

	// replacer used for both body and headers. Only globals (env vars, system info, etc.) are available
	repl := caddy.NewReplacer()

	// if body is provided, create a reader for it, otherwise nil
	var requestBody io.Reader
	if h.HealthChecks.Active.Body != "" {
		// Set body, using replacer. Only known placeholders are replaced: the
		// body is often JSON, whose braces would otherwise be read as
		// placeholders and blanked, sending an empty body instead.
		requestBody = strings.NewReader(repl.ReplaceKnown(h.HealthChecks.Active.Body, ""))
	}

	// attach dialing information to this request, as well as context values that
	// may be expected by handlers of this request
	ctx := h.ctx.Context
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, dialInfoCtxKey, dialInfo)
	req, err := http.NewRequestWithContext(ctx, h.HealthChecks.Active.Method, u.String(), requestBody)
	if err != nil {
		return fmt.Errorf("making request: %v", err)
	}
	ctx = context.WithValue(ctx, caddyhttp.OriginalRequestCtxKey, *req)
	req = req.WithContext(ctx)

	// set headers, using replacer
	repl.Set("http.reverse_proxy.active.target_upstream", networkAddr)
	for key, vals := range h.HealthChecks.Active.Headers {
		key = repl.ReplaceAll(key, "")
		if key == "Host" {
			req.Host = repl.ReplaceAll(h.HealthChecks.Active.Headers.Get(key), "")
			continue
		}
		for _, val := range vals {
			req.Header.Add(key, repl.ReplaceKnown(val, ""))
		}
	}

	markResult := func(outcome HealthCheckOutcome, checkErr error) {
		state := upstream.healthState
		if state == nil {
			state = upstream.ensureHealthState(h.HealthChecks.Active.stateConfigForUpstream(upstream))
		}

		var errorString string
		if checkErr != nil {
			errorString = checkErr.Error()
		}
		result := HealthCheckResult{
			At:       time.Now(),
			Outcome:  outcome,
			Success:  outcome == HealthCheckPass,
			Duration: time.Since(probeStarted),
			Error:    errorString,
			ProbeID:  probeID,
		}

		if outcome == HealthCheckPass {
			_ = upstream.countHealthPass(1)
			upstream.activeFails.Store(0)
		} else if outcome != HealthCheckInterrupted {
			_ = upstream.countHealthFail(1)
			upstream.activePasses.Store(0)
		}

		transition, changed := state.Observe(result)
		upstream.applyHealthState()
		if !changed {
			return
		}
		if transition.To == HealthStateUnhealthy || transition.To == HealthStateHealthy {
			upstream.resetHealth()
		}

		if transition.To == HealthStateUnhealthy && h.events != nil {
			h.events.Emit(h.ctx, "unhealthy", map[string]any{"host": hostAddr})
		}
		if transition.To == HealthStateHealthy && !upstream.ManualUnhealthy() && h.events != nil {
			h.events.Emit(h.ctx, "healthy", map[string]any{"host": hostAddr})
		}
		if h.events != nil {
			h.events.Emit(h.ctx, "health_state_change", map[string]any{
				"host":                  hostAddr,
				"from":                  transition.From,
				"to":                    transition.To,
				"reason":                transition.Reason,
				"automatic":             transition.Automatic,
				"failure_kind":          transition.FailureKind,
				"transitions_in_window": transition.TransitionsInWindow,
				"flapping":              transition.Flapping,
				"load_factor":           transition.LoadFactor,
			})
		}
		if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "active health state changed"); c != nil {
			c.Write(
				zap.String("host", hostAddr),
				zap.String("from", transition.From),
				zap.String("to", transition.To),
				zap.String("reason", transition.Reason),
				zap.Int("transitions_in_window", transition.TransitionsInWindow),
				zap.Bool("flapping", transition.Flapping),
				zap.Float64("load_factor", transition.LoadFactor),
			)
		}
	}

	markUnhealthy := func(outcome HealthCheckOutcome, checkErr error) {
		markResult(outcome, checkErr)
	}

	markHealthy := func() {
		markResult(HealthCheckPass, nil)
	}

	// do the request, being careful to tame the response body
	resp, err := h.HealthChecks.Active.httpClient.Do(req) //nolint:gosec // no SSRF
	if err != nil {
		if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "HTTP request failed"); c != nil {
			c.Write(
				zap.String("host", hostAddr),
				zap.Error(err),
			)
		}
		markUnhealthy(h.classifyActiveHealthError(err), err)
		return nil
	}
	var body io.Reader = resp.Body
	if h.HealthChecks.Active.MaxSize > 0 {
		body = io.LimitReader(body, h.HealthChecks.Active.MaxSize)
	}
	defer func() {
		// drain any remaining body so connection could be reused
		_, _ = io.Copy(io.Discard, body)
		resp.Body.Close()
	}()

	// if status code is outside criteria, mark down
	if h.HealthChecks.Active.ExpectStatus > 0 {
		if !caddyhttp.StatusCodeMatches(resp.StatusCode, h.HealthChecks.Active.ExpectStatus) {
			if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "unexpected status code"); c != nil {
				c.Write(
					zap.Int("status_code", resp.StatusCode),
					zap.String("host", hostAddr),
				)
			}
			markUnhealthy(HealthCheckBusinessFailure, fmt.Errorf("unexpected status code %d", resp.StatusCode))
			return nil
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "status code out of tolerances"); c != nil {
			c.Write(
				zap.Int("status_code", resp.StatusCode),
				zap.String("host", hostAddr),
			)
		}
		markUnhealthy(HealthCheckBusinessFailure, fmt.Errorf("status code out of tolerances: %d", resp.StatusCode))
		return nil
	}

	// if body does not match regex, mark down
	if h.HealthChecks.Active.bodyRegexp != nil {
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "failed to read response body"); c != nil {
				c.Write(
					zap.String("host", hostAddr),
					zap.Error(err),
				)
			}
			markUnhealthy(h.classifyActiveHealthError(err), err)
			return nil
		}
		if !h.HealthChecks.Active.bodyRegexp.Match(bodyBytes) {
			if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "response body failed expectations"); c != nil {
				c.Write(
					zap.String("host", hostAddr),
				)
			}
			markUnhealthy(HealthCheckBusinessFailure, fmt.Errorf("response body failed expectations"))
			return nil
		}
	}

	// passed health check parameters, so mark as healthy
	markHealthy()

	return nil
}

func (h *Handler) classifyActiveHealthError(err error) HealthCheckOutcome {
	if h.ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return HealthCheckInterrupted
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return HealthCheckTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return HealthCheckTimeout
	}
	return HealthCheckProbeFailure
}

// countFailure is used with passive health checks. It
// remembers 1 failure for upstream for the configured
// duration. If passive health checks are disabled or
// failure expiry is 0, this is a no-op.
func (h *Handler) countFailure(upstream *Upstream) {
	// only count failures if passive health checking is enabled
	// and if failures are configured have a non-zero expiry
	if h.HealthChecks == nil || h.HealthChecks.Passive == nil {
		return
	}
	failDuration := time.Duration(h.HealthChecks.Passive.FailDuration)
	if failDuration == 0 {
		return
	}

	// count failure immediately
	err := upstream.Host.countFail(1)
	if err != nil {
		if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "could not count failure"); c != nil {
			c.Write(
				zap.String("host", upstream.Dial),
				zap.Error(err),
			)
		}
		return
	}

	// forget it later
	go func(host *Host, failDuration time.Duration) {
		defer func() {
			if err := recover(); err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "passive health check failure forgetter panicked"); c != nil {
					c.Write(
						zap.Any("error", err),
						zap.ByteString("stack", debug.Stack()),
					)
				}
			}
		}()
		timer := time.NewTimer(failDuration)
		select {
		case <-h.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
		err := host.countFail(-1)
		if err != nil {
			if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "could not forget failure"); c != nil {
				c.Write(
					zap.String("host", upstream.Dial),
					zap.Error(err),
				)
			}
		}
	}(upstream.Host, failDuration)
}
