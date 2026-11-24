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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(RequestGuard{})
}

// Defaults applied when the corresponding option is zero.
const (
	defaultMaxBodySize     = 1 << 20 // 1 MiB
	defaultMaxDecodedSize  = 8 << 20 // 8 MiB
	defaultMaxDecodedRatio = 100
	defaultMaxConcurrent   = 64
	defaultConcurrencyWait = 100 * time.Millisecond
)

// Response headers the guard sets. They carry only fixed reason codes and a
// random request identifier, never request content.
const (
	requestIDHeader = "X-Request-Guard-Request-Id"
	reasonHeader    = "X-Request-Guard-Reason"
	budgetHeader    = "X-Request-Guard-Budget-Exceeded"
)

// requestIDVarKey is the per-request variable holding the guard's request
// identifier, so repeated lookups within one request stay stable.
const requestIDVarKey = "request_guard.request_id"

// RequestGuard inspects requests before later handlers see them and applies a
// route-scoped policy when a built-in or custom rule matches. It is an
// input-validation layer; it does not replace output encoding or
// parameterized queries on the upstream.
//
// EXPERIMENTAL: Subject to change or removal.
type RequestGuard struct {
	// How to respond when a rule matches: "block" (the default) rejects the
	// request before it reaches later handlers, "log" records the match and
	// forwards the request unchanged, and "off" evaluates the request without
	// recording or rejecting on a match.
	Action string `json:"action,omitempty"`

	// The maximum number of body bytes to buffer and inspect per request.
	// Larger bodies are handled according to OversizedBody. Default: 1 MiB.
	MaxBodySize int64 `json:"max_body_size,omitempty"`

	// What to do when a body exceeds MaxBodySize, the decompression limits,
	// or the scan budget: "reject" (the default) returns an error, and
	// "allow" forwards the request uninspected. Either way the event is
	// recorded in a response header and in the counters, so a pass-through is
	// never silent.
	OversizedBody string `json:"oversized_body,omitempty"`

	// The maximum decompressed size of a compressed body, in bytes. Default:
	// 8 MiB, clamped to MaxBodySize. A body that would exceed it is refused
	// with status 413 and reason "decompressed-size", without being expanded.
	MaxDecodedSize int64 `json:"max_decoded_size,omitempty"`

	// The maximum decompressed-to-compressed size ratio for bodies large
	// enough to matter. A body that would exceed it is refused with status
	// 413 and reason "decompression-ratio". Default: 100.
	MaxDecodedRatio int64 `json:"max_decoded_ratio,omitempty"`

	// The maximum number of bodies inspected concurrently. Requests over the
	// limit wait up to ConcurrencyWait for a slot, then are handled according
	// to OversizedBody. Default: 64.
	MaxConcurrent int `json:"max_concurrent,omitempty"`

	// How long a request may wait for a concurrency slot. Default: 100ms.
	ConcurrencyWait caddy.Duration `json:"concurrency_wait,omitempty"`

	// Rule IDs to disable. Built-in rules use the prefixes "xss-", "sqli-",
	// "path-", "cmd-", "jndi-", "xxe-" and "nosql-".
	DisabledRules []string `json:"disabled_rules,omitempty"`

	// Custom rules, evaluated in addition to the built-in ones.
	Rules []ruleConfig `json:"rules,omitempty"`

	// DisableBuiltinRules removes the shipped rule set, leaving only custom
	// rules. Use with care.
	DisableBuiltinRules bool `json:"disable_builtin_rules,omitempty"`

	logger    *zap.Logger
	rules     *compiledRules
	sem       chan struct{}
	semWait   time.Duration
	action    policyAction
	oversized oversizedPolicy
	metrics   *guardMetrics
}

// policyAction is the route policy applied to a match.
type policyAction uint8

const (
	actionBlock policyAction = iota
	actionLog
	actionOff
)

// oversizedPolicy is what to do when a body cannot be fully inspected.
type oversizedPolicy uint8

const (
	policyReject oversizedPolicy = iota
	policyAllow
)

// CaddyModule returns the Caddy module information.
func (RequestGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.request_guard",
		New: func() caddy.Module { return new(RequestGuard) },
	}
}

// Provision sets up the handler's rule set, limits and metrics.
func (g *RequestGuard) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()

	action, err := parseAction(g.Action)
	if err != nil {
		return err
	}
	oversized, err := parsePolicy("oversized_body", g.OversizedBody)
	if err != nil {
		return err
	}

	if g.MaxConcurrent < 0 {
		return errors.New("max_concurrent must not be negative")
	}

	if g.MaxBodySize <= 0 {
		g.MaxBodySize = defaultMaxBodySize
	}
	if g.MaxDecodedSize <= 0 {
		g.MaxDecodedSize = defaultMaxDecodedSize
	}
	if g.MaxDecodedRatio <= 0 {
		g.MaxDecodedRatio = defaultMaxDecodedRatio
	}
	if g.MaxConcurrent == 0 {
		g.MaxConcurrent = defaultMaxConcurrent
	}
	if g.ConcurrencyWait <= 0 {
		g.ConcurrencyWait = caddy.Duration(defaultConcurrencyWait)
	}
	if g.MaxDecodedSize > g.MaxBodySize {
		// A decoded body larger than the inspection budget could never be
		// inspected completely, so make the two limits agree.
		g.MaxDecodedSize = g.MaxBodySize
	}

	disabled := make(map[string]struct{}, len(g.DisabledRules))
	for _, id := range g.DisabledRules {
		disabled[id] = struct{}{}
	}

	custom := make([]ruleConfig, 0, len(g.Rules))
	for _, rc := range g.Rules {
		if _, skip := disabled[rc.ID]; skip {
			continue
		}
		custom = append(custom, rc)
	}

	// Filter the built-in table at provisioning time so a disabled rule costs
	// nothing at request time.
	activeBuiltin := make([]rule, 0, len(builtinRules))
	if !g.DisableBuiltinRules {
		for _, r := range builtinRules {
			if _, skip := disabled[r.id]; skip {
				continue
			}
			activeBuiltin = append(activeBuiltin, r)
		}
	}

	g.rules, err = compileRules(activeBuiltin, custom, g.DisableBuiltinRules)
	if err != nil {
		return err
	}

	g.action = action
	g.oversized = oversized
	g.semWait = time.Duration(g.ConcurrencyWait)
	g.sem = make(chan struct{}, g.MaxConcurrent)
	g.metrics = initGuardMetrics(ctx.GetMetricsRegistry())

	return nil
}

// Cleanup is a no-op beyond dropping the handler's own references. The
// concurrency channel is intentionally not cleared: requests already in flight
// may still be using it, and writing the field here would race with them.
func (g *RequestGuard) Cleanup() error {
	return nil
}

// ServeHTTP inspects the request and applies the route's policy.
func (g *RequestGuard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if g.rules == nil {
		return next.ServeHTTP(w, r)
	}

	// Connection upgrades are long-lived bidirectional streams: buffering a
	// request body would delay the handshake and there is no bounded body to
	// inspect, so leave them entirely alone.
	if isUpgrade(r) {
		g.metrics.observe(outcomeSkippedUpgrade, "-", "-")
		return next.ServeHTTP(w, r)
	}

	// Incremental forwarding promises the upstream bytes before the body is
	// complete. Buffering would break that contract, so such requests are
	// left alone and the skip is counted.
	if caddyhttp.IsIncremental(r.Header) {
		g.metrics.observe(outcomeSkippedIncremental, "-", "-")
		return next.ServeHTTP(w, r)
	}

	sc := &scanContext{rules: g.rules}

	if m, tgt, ok := sc.inspectMetadata(r); ok {
		return g.decide(w, r, next, m, tgt)
	}

	if !g.rules.wants(targetBody) || r.Body == nil || r.Body == http.NoBody {
		return next.ServeHTTP(w, r)
	}

	// Body inspection buffers bytes, so it needs a scan slot to keep the
	// per-instance memory bounded.
	if !g.acquire(r.Context()) {
		g.metrics.observe(outcomeBudget, "concurrency", "-")
		reqID := g.requestID(r)
		return g.overBudget(w, r, next, reqID, "concurrency-budget")
	}
	defer func() { <-g.sem }()

	body, err := g.readBody(r)
	if err != nil {
		// A body-size limit installed by an earlier handler must keep its
		// own status code and response; do not reinterpret it.
		if handlerErr, ok := errors.AsType[caddyhttp.HandlerError](err); ok {
			g.metrics.observe(outcomeReadError, "body", "-")
			return handlerErr
		}
		// A body that could not be read in full cannot be replayed faithfully
		// either, so it is never treated as inspected. "allow" cannot apply:
		// the data is already gone.
		g.metrics.observe(outcomeReadError, "body", "-")
		reqID := g.requestID(r)
		g.logWarn("could not read request body", reqID, "", "", "read-error")
		return g.reject(w, reqID, http.StatusBadRequest, "read-error")
	}
	if body.oversized {
		g.metrics.observe(outcomeOversized, "body", "-")
		reqID := g.requestID(r)
		return g.overBudget(w, r, next, reqID, body.reason)
	}

	decoded, decReason, decErr := decodeForInspection(
		r.Header.Get("Content-Encoding"), body.inspect,
		decodeLimits{maxDecoded: g.MaxDecodedSize, ratio: g.MaxDecodedRatio},
	)
	switch {
	case decErr == nil && decReason == decodeOK:
		if m, ok := sc.inspectBodyPayload(r, decoded); ok {
			return g.decide(w, r, next, m, targetBody)
		}
	case decReason == decodeUnsupported:
		// An encoding the guard cannot decode cannot be inspected. Treat it
		// as over budget rather than passing silently.
		g.metrics.observe(outcomeUnsupported, "body", "-")
		reqID := g.requestID(r)
		g.logWarn("body uses an unsupported content encoding", reqID, "", "body", string(decReason))
		return g.overBudget(w, r, next, reqID, string(decReason))
	case decReason == decodeRatio || decReason == decodeSize:
		// The decompressed body would exceed a hard limit. Refuse it without
		// expanding it, with a reason that distinguishes the two limits.
		g.metrics.observe(outcomeRejected, "body", "-")
		reqID := g.requestID(r)
		g.logWarn("rejected compressed body over the decompression limit", reqID, "", "body", string(decReason))
		return g.reject(w, reqID, http.StatusRequestEntityTooLarge, string(decReason))
	default:
		// The encoding was malformed rather than oversized; the body could
		// not be inspected, so it is not a clean request.
		g.metrics.observe(outcomeDecompress, "body", "-")
		reqID := g.requestID(r)
		g.logWarn("rejected unreadable compressed body", reqID, "", "body", string(decReason))
		return g.reject(w, reqID, http.StatusBadRequest, string(decReason))
	}

	return next.ServeHTTP(w, r)
}

// decide applies the route's action to a rule match. A match under "off" is
// not recorded; under "log" it is recorded and the request continues.
func (g *RequestGuard) decide(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, m match, tgt target) error {
	switch g.action {
	case actionBlock:
		g.metrics.observe(outcomeBlocked, tgt.String(), m.ruleID)
		reqID := g.requestID(r)
		g.logWarn("blocked request", reqID, m.ruleID, tgt.String(), "rule-match")
		return g.reject(w, reqID, http.StatusForbidden, "rule-match")
	case actionLog:
		g.metrics.observe(outcomeLogged, tgt.String(), m.ruleID)
		reqID := g.requestID(r)
		g.logWarn("request matched a rule; forwarding", reqID, m.ruleID, tgt.String(), "rule-match")
		return next.ServeHTTP(w, r)
	case actionOff:
		return next.ServeHTTP(w, r)
	}
	return next.ServeHTTP(w, r)
}

// overBudget handles a request whose body exceeded an inspection budget,
// following the route's oversized-body policy.
func (g *RequestGuard) overBudget(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, reqID, reason string) error {
	if g.oversized == policyReject {
		return g.reject(w, reqID, http.StatusRequestEntityTooLarge, reason)
	}
	g.markNotInspected(w, reqID, reason)
	return next.ServeHTTP(w, r)
}

// markNotInspected annotates the response so a pass-through is observable. The
// decision itself is counted by the caller; the header is what makes it
// visible to a client-side observer. Only fixed reason codes and a random
// identifier are written, never request content.
func (g *RequestGuard) markNotInspected(w http.ResponseWriter, reqID, reason string) {
	h := w.Header()
	h.Set(budgetHeader, reason)
	if reqID != "" {
		h.Set(requestIDHeader, reqID)
	}
}

// reject writes a privacy-safe error response. The message names only a fixed
// reason code; body bytes, cookie values and rule patterns never appear.
func (g *RequestGuard) reject(w http.ResponseWriter, reqID string, status int, reason string) error {
	if reqID != "" {
		w.Header().Set(requestIDHeader, reqID)
	}
	w.Header().Set(reasonHeader, reason)
	return caddyhttp.Error(status, errors.New("request rejected by security policy"))
}

// logWarn records a decision with only non-sensitive identifiers.
func (g *RequestGuard) logWarn(msg, reqID, ruleID, tgt, reason string) {
	if g.logger == nil {
		return
	}
	fields := make([]zap.Field, 0, 5)
	if reqID != "" {
		fields = append(fields, zap.String("request_id", reqID))
	}
	if ruleID != "" {
		fields = append(fields, zap.String("rule_id", ruleID))
	}
	if tgt != "" {
		fields = append(fields, zap.String("target", tgt))
	}
	if reason != "" {
		fields = append(fields, zap.String("reason", reason))
	}
	g.logger.Warn(msg, fields...)
}

// requestID returns a stable identifier for this request, generating and
// caching it in the request's variable table on first use, and attaching it to
// the access log.
func (g *RequestGuard) requestID(r *http.Request) string {
	if id, ok := caddyhttp.GetVar(r.Context(), requestIDVarKey).(string); ok && id != "" {
		return id
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	id := hex.EncodeToString(b[:])
	caddyhttp.SetVar(r.Context(), requestIDVarKey, id)
	if extra, ok := r.Context().Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields); ok && extra != nil {
		extra.Set(zap.String("request_id", id))
	}
	return id
}

// bodyResult is the outcome of reading and buffering a request body.
type bodyResult struct {
	// inspect holds the bytes that were inspected (uncompressed on the wire;
	// decompression happens afterwards on a copy).
	inspect []byte
	// size is the number of bytes read from the wire.
	size      int64
	oversized bool
	reason    string
}

// readBody buffers up to MaxBodySize bytes and installs a replaying body so
// the upstream receives exactly the original bytes.
//
// A body larger than the budget is not buffered in full: the buffered prefix
// is followed by the still-unread remainder through a streaming reader, so a
// large upload is not fully buffered and its Content-Length is untouched.
func (g *RequestGuard) readBody(r *http.Request) (bodyResult, error) {
	orig := r.Body
	limit := g.MaxBodySize

	// A declared length over the budget is known to be oversized without
	// reading anything. Leave the body untouched: this avoids buffering a
	// large upload at all and guarantees perfect byte and framing fidelity.
	if r.ContentLength > limit {
		return bodyResult{size: r.ContentLength, oversized: true, reason: "declared-size"}, nil
	}

	buf := make([]byte, 0, 32<<10)
	if limit > 0 && limit < 32<<10 {
		buf = make([]byte, 0, limit)
	}

	n, err := io.CopyN((*appendWriter)(&buf), orig, limit+1)
	switch {
	case err == nil:
		// budget+1 bytes read: there is definitely more body. Replay it all.
		r.Body = newReplayBody(buf, orig)
		return bodyResult{size: n, oversized: true, reason: "body-size"}, nil
	case errors.Is(err, io.EOF):
		// The whole body fit and was consumed.
		_ = orig.Close()
		r.Body = newReplayBody(buf, nil)
		return bodyResult{inspect: buf, size: n}, nil
	default:
		// A read failure is not a clean body. Close what remains so the
		// connection is not left half-read, and do not install a replay
		// body that would misrepresent the request.
		_ = orig.Close()
		return bodyResult{}, err
	}
}

// appendWriter appends written bytes to a slice, growing it as needed.
type appendWriter []byte

func (w *appendWriter) Write(p []byte) (int, error) {
	*w = append(*w, p...)
	return len(p), nil
}

// acquire takes a scan slot, waiting briefly. It reports false if none came
// free before the deadline or the request was canceled.
func (g *RequestGuard) acquire(parent context.Context) bool {
	select {
	case g.sem <- struct{}{}:
		return true
	default:
	}

	ctx, cancel := context.WithTimeout(parent, g.semWait)
	defer cancel()
	select {
	case g.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func parseAction(s string) (policyAction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "block":
		return actionBlock, nil
	case "log", "log_only":
		return actionLog, nil
	case "off", "allow":
		return actionOff, nil
	}
	return 0, fmt.Errorf("unknown action %q (want block, log, or off)", s)
}

func parsePolicy(field, s string) (oversizedPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "reject":
		return policyReject, nil
	case "allow", "pass":
		return policyAllow, nil
	}
	return 0, fmt.Errorf("unknown %s policy %q (want reject or allow)", field, s)
}

// isUpgrade reports whether r asks to switch protocols, which the guard must
// not interfere with.
func isUpgrade(r *http.Request) bool {
	if !httpguts.HeaderValuesContainsToken(r.Header["Connection"], "Upgrade") {
		return false
	}
	return r.Header.Get("Upgrade") != ""
}

// Interface guards
var (
	_ caddy.Provisioner           = (*RequestGuard)(nil)
	_ caddy.CleanerUpper          = (*RequestGuard)(nil)
	_ caddyhttp.MiddlewareHandler = (*RequestGuard)(nil)
)
