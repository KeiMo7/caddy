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

package caddyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
)

const (
	defaultRouteAuditMaxRoutes          = 500
	defaultRouteAuditMaxProbesPerRoute  = 64
	defaultRouteAuditMinCoverage        = 0.8
	routeAuditProbeMarker               = "audit-segment"
	routeAuditNoHost                    = "audit.invalid"
	routeAuditPath                      = "/"
	routeAuditMaxCandidatePathsPerRoute = 64
)

// RouteAudit configures static route-overlap analysis at config load time.
//
// The analysis is disabled by default. It never participates in request
// routing and writes its findings to a dedicated audit logger.
type RouteAudit struct {
	// Enabled turns on route-overlap analysis for this server.
	Enabled bool `json:"enabled,omitempty"`

	// MaxRoutes limits how many routes are analyzed. Routes beyond the
	// limit cause the report to be marked as truncated. Default: 500.
	MaxRoutes int `json:"max_routes,omitempty"`

	// MaxProbesPerRoute limits the number of synthetic requests generated
	// for each route. Default: 64.
	MaxProbesPerRoute int `json:"max_probes_per_route,omitempty"`

	// MinCoverage is the minimum fraction of routes that must be
	// statically analyzable for the report not to be marked as having
	// insufficient coverage. Default: 0.8.
	MinCoverage float64 `json:"min_coverage,omitempty"`

	// OutputFile is the file to which audit reports are appended. When
	// omitted, the audit logger is a named child of the regular logger.
	OutputFile string `json:"output_file,omitempty"`
}

// Conflict describes an overlap between two routes in the same server.
type Conflict struct {
	ServerName string   `json:"server_name,omitempty"`
	Earlier    int      `json:"earlier_route"`
	Later      int      `json:"later_route"`
	Kind       string   `json:"kind"`
	Direction  string   `json:"direction"`
	Hosts      []string `json:"hosts"`
	Paths      []string `json:"paths"`
	Partial    []string `json:"partial_dimensions,omitempty"`
	SameAction bool     `json:"same_action,omitempty"`
}

// AuditReport is the overall result of auditing one server's routes.
type AuditReport struct {
	ServerName          string            `json:"server_name,omitempty"`
	TotalRoutes         int               `json:"total_routes"`
	AnalyzedRoutes      int               `json:"analyzed_routes"`
	Unanalyzable        int               `json:"unanalyzable_routes"`
	Truncated           bool              `json:"truncated"`
	Conflicts           []Conflict        `json:"conflicts"`
	UnanalyzableList    []int             `json:"unanalyzable_route_indexes,omitempty"`
	UnanalyzableReasons map[string]string `json:"unanalyzable_reasons,omitempty"`
	Verdict             string            `json:"verdict"`
}

type analyzedRoute struct {
	index      int
	route      Route
	probes     []probeRequest
	analyzable bool
	reasons    []string
}

type probeRequest struct {
	req    *http.Request
	host   string
	path   string
	method string
}

type analyzedMatcherSet struct {
	hostPatterns []string
	pathPatterns []string
	methods      []string
	headers      http.Header

	hasHost bool
	hasPath bool

	impossible bool
}

// runRouteAudit performs the audit if it is enabled and returns the verdict
// and a human-readable summary. Analysis failures are reported to logger and
// degrade to SKIPPED; they never fail config loading.
func runRouteAudit(serverName string, routes RouteList, cfg *RouteAudit, logger *zap.Logger) (verdict, summary string) {
	if cfg == nil || !cfg.Enabled {
		return "", ""
	}

	verdict = "SKIPPED"
	defer func() {
		if recovered := recover(); recovered != nil {
			if logger != nil {
				logger.Error("route overlap analysis failed; skipping detection",
					zap.String("server", serverName),
					zap.Any("panic", recovered))
			}
			verdict = "SKIPPED"
			summary = ""
		}
	}()

	if logger == nil {
		logger = zap.NewNop()
	}

	auditLogger, closeFn, err := newAuditLogger(cfg, logger)
	if err != nil {
		logger.Error("route overlap analysis failed; skipping detection",
			zap.String("server", serverName),
			zap.Error(err))
		return "SKIPPED", ""
	}
	if closeFn != nil {
		defer closeFn()
	}

	start := time.Now()
	report := auditServerRoutes(serverName, routes, cfg, logger)
	elapsed := time.Since(start)
	emitAuditReport(auditLogger, report, elapsed)

	summary = fmt.Sprintf("%s: %d route(s), %d conflict(s), coverage %.1f%%",
		report.Verdict,
		report.TotalRoutes,
		len(report.Conflicts),
		auditCoverage(report)*100,
	)
	return report.Verdict, summary
}

// auditServerRoutes analyzes the routes for one server. The route matchers
// must already be provisioned; all overlap decisions are made by the same
// compiled MatcherSets used at request time.
func auditServerRoutes(serverName string, routes RouteList, cfg *RouteAudit, logger *zap.Logger) AuditReport {
	maxRoutes := defaultRouteAuditMaxRoutes
	maxProbes := defaultRouteAuditMaxProbesPerRoute
	minCoverage := defaultRouteAuditMinCoverage
	if cfg != nil {
		if cfg.MaxRoutes > 0 {
			maxRoutes = cfg.MaxRoutes
		}
		if cfg.MaxProbesPerRoute > 0 {
			maxProbes = cfg.MaxProbesPerRoute
		}
		if cfg.MinCoverage > 0 {
			minCoverage = cfg.MinCoverage
		}
	}

	report := AuditReport{
		ServerName:          serverName,
		TotalRoutes:         len(routes),
		Conflicts:           make([]Conflict, 0),
		UnanalyzableReasons: make(map[string]string),
	}

	limit := len(routes)
	if limit > maxRoutes {
		limit = maxRoutes
		report.Truncated = true
	}

	analyzed := make([]analyzedRoute, 0, limit)
	for i := 0; i < limit; i++ {
		result := analyzeRoute(i, routes[i], maxProbes)
		analyzed = append(analyzed, result)
		if result.analyzable {
			report.AnalyzedRoutes++
			continue
		}

		report.Unanalyzable++
		report.UnanalyzableList = append(report.UnanalyzableList, i)
		reason := "route contains matchers that cannot be analyzed statically"
		if len(result.reasons) > 0 {
			reason = strings.Join(uniqueStrings(result.reasons), "; ")
		}
		report.UnanalyzableReasons[fmt.Sprintf("route_%d", i)] = reason
	}

	for i := 0; i < len(analyzed); i++ {
		if !analyzed[i].analyzable {
			continue
		}
		for j := i + 1; j < len(analyzed); j++ {
			if !analyzed[j].analyzable {
				continue
			}
			if !hostsMayOverlap(analyzed[i], analyzed[j]) {
				continue
			}
			if conflict, ok := detectPairOverlap(serverName, analyzed[i], analyzed[j]); ok {
				report.Conflicts = append(report.Conflicts, conflict)
			}
		}
	}

	sort.SliceStable(report.Conflicts, func(i, j int) bool {
		iHost := conflictGroup(report.Conflicts[i])
		jHost := conflictGroup(report.Conflicts[j])
		if iHost != jHost {
			return iHost < jHost
		}
		if report.Conflicts[i].Earlier != report.Conflicts[j].Earlier {
			return report.Conflicts[i].Earlier < report.Conflicts[j].Earlier
		}
		return report.Conflicts[i].Later < report.Conflicts[j].Later
	})

	coverage := auditCoverage(report)
	switch {
	case report.Truncated, report.AnalyzedRoutes == 0, coverage < minCoverage:
		report.Verdict = "INSUFFICIENT_COVERAGE"
	case len(report.Conflicts) > 0:
		report.Verdict = "FAIL"
	default:
		report.Verdict = "PASS"
	}

	if logger != nil && report.Truncated {
		logger.Debug("route audit truncated",
			zap.String("server", serverName),
			zap.Int("max_routes", maxRoutes),
			zap.Int("total_routes", report.TotalRoutes))
	}

	return report
}

func auditCoverage(report AuditReport) float64 {
	if report.TotalRoutes == 0 {
		return 0
	}
	return float64(report.AnalyzedRoutes) / float64(report.TotalRoutes)
}

func conflictGroup(conflict Conflict) string {
	if len(conflict.Hosts) == 0 {
		return "*"
	}
	return conflict.Hosts[0]
}

// analyzeRoute builds a bounded set of representative requests for a route.
// A route is analyzable only when every matcher in every matcher set can be
// modeled statically.
func analyzeRoute(index int, route Route, maxProbes int) analyzedRoute {
	result := analyzedRoute{
		index:      index,
		route:      route,
		analyzable: true,
	}
	if maxProbes <= 0 {
		maxProbes = defaultRouteAuditMaxProbesPerRoute
	}

	if len(route.MatcherSetsRaw) > 0 && len(route.MatcherSets) == 0 {
		result.analyzable = false
		result.reasons = append(result.reasons, "route matchers have not been provisioned")
		return result
	}

	if len(route.MatcherSets) == 0 {
		result.probes = append(result.probes,
			newProbe(routeAuditNoHost, routeAuditPath, http.MethodGet, nil))
		return result
	}

	for setIndex, matcherSet := range route.MatcherSets {
		info, reason := inspectMatcherSet(matcherSet)
		if reason != "" {
			result.analyzable = false
			result.reasons = append(result.reasons,
				fmt.Sprintf("matcher set %d contains a matcher that cannot be analyzed statically", setIndex))
			continue
		}
		if info.impossible {
			continue
		}

		remaining := maxProbes - len(result.probes)
		if remaining <= 0 {
			break
		}
		probes := buildProbesForMatcherSet(info, remaining)
		for _, probe := range probes {
			if countRouteMatches(route.MatcherSets, probe.req) == 0 {
				continue
			}
			if !containsProbe(result.probes, probe) {
				result.probes = append(result.probes, probe)
			}
			if len(result.probes) >= maxProbes {
				break
			}
		}
	}

	if result.analyzable && len(result.probes) == 0 {
		result.reasons = append(result.reasons, "no representative requests could be generated")
	}

	return result
}

func inspectMatcherSet(matcherSet MatcherSet) (analyzedMatcherSet, string) {
	var info analyzedMatcherSet

	for _, matcher := range matcherSet {
		switch m := matcher.(type) {
		case MatchHost:
			info.hasHost = true
			info.hostPatterns = append(info.hostPatterns, m...)
			if hasDynamicPattern(m) {
				return info, "dynamic host matcher"
			}
			if len(m) == 0 {
				info.impossible = true
			}
		case *MatchHost:
			if m == nil {
				return info, "nil host matcher"
			}
			info.hasHost = true
			info.hostPatterns = append(info.hostPatterns, (*m)...)
			if hasDynamicPattern(*m) {
				return info, "dynamic host matcher"
			}
			if len(*m) == 0 {
				info.impossible = true
			}
		case MatchPath:
			info.hasPath = true
			info.pathPatterns = append(info.pathPatterns, m...)
			if hasDynamicPattern(m) || hasUnsupportedPathSyntax(m) {
				return info, "dynamic path matcher"
			}
			if len(m) == 0 {
				info.impossible = true
			}
		case *MatchPath:
			if m == nil {
				return info, "nil path matcher"
			}
			info.hasPath = true
			info.pathPatterns = append(info.pathPatterns, (*m)...)
			if hasDynamicPattern(*m) || hasUnsupportedPathSyntax(*m) {
				return info, "dynamic path matcher"
			}
			if len(*m) == 0 {
				info.impossible = true
			}
		case MatchMethod:
			info.methods = append(info.methods, m...)
			if len(m) == 0 {
				info.impossible = true
			}
		case *MatchMethod:
			if m == nil {
				return info, "nil method matcher"
			}
			info.methods = append(info.methods, (*m)...)
			if len(*m) == 0 {
				info.impossible = true
			}
		case MatchHeader:
			info.headers = mergeHeaders(info.headers, http.Header(m))
			if headersHaveDynamicValues(http.Header(m)) {
				return info, "dynamic header matcher"
			}
		case *MatchHeader:
			if m == nil {
				return info, "nil header matcher"
			}
			info.headers = mergeHeaders(info.headers, http.Header(*m))
			if headersHaveDynamicValues(http.Header(*m)) {
				return info, "dynamic header matcher"
			}
		default:
			return info, "unsupported matcher"
		}
	}

	for i := range info.methods {
		info.methods[i] = strings.ToUpper(info.methods[i])
	}
	info.methods = uniqueStrings(info.methods)
	sort.Strings(info.methods)
	return info, ""
}

func hasDynamicPattern(patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(pattern, "{") || strings.Contains(pattern, "}") {
			return true
		}
	}
	return false
}

func hasUnsupportedPathSyntax(patterns []string) bool {
	for _, pattern := range patterns {
		// MatchPath treats these as glob or escaped-path syntax. They are
		// statically analyzable in principle, but generating intersection
		// witnesses for character classes and escaped paths is deliberately
		// left out to avoid false negatives.
		if strings.ContainsAny(pattern, `?[]%\`) {
			return true
		}
	}
	return false
}

func headersHaveDynamicValues(headers http.Header) bool {
	for field, values := range headers {
		if strings.Contains(field, "{") {
			return true
		}
		for _, value := range values {
			if strings.Contains(value, "{") {
				return true
			}
		}
	}
	return false
}

func mergeHeaders(dst, src http.Header) http.Header {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(http.Header, len(src))
	}
	for field, values := range src {
		dst[field] = append(dst[field], values...)
	}
	return dst
}

func buildProbesForMatcherSet(info analyzedMatcherSet, maxProbes int) []probeRequest {
	if maxProbes <= 0 || info.impossible {
		return nil
	}

	hosts := hostCandidates(info.hostPatterns)
	if !info.hasHost {
		hosts = []string{routeAuditNoHost, "other.invalid"}
	}
	paths := pathCandidates(info.pathPatterns)
	if !info.hasPath {
		paths = []string{routeAuditPath, "/audit-other"}
	}
	methods := info.methods
	if len(methods) == 0 {
		// A second method reveals whether an unrestricted route is truly
		// covered by an earlier method-restricted route.
		methods = []string{http.MethodGet, http.MethodPost}
	}
	headerVariants := headerVariants(info.headers)

	probes := make([]probeRequest, 0, min(maxProbes, len(hosts)*len(paths)*len(methods)*len(headerVariants)))
	for _, host := range hosts {
		for _, path := range paths {
			for _, method := range methods {
				for _, headers := range headerVariants {
					probe := newProbe(host, path, method, headers)
					if containsProbe(probes, probe) {
						continue
					}
					probes = append(probes, probe)
					if len(probes) >= maxProbes {
						return probes
					}
				}
			}
		}
	}
	return probes
}

func headerVariants(headers http.Header) []http.Header {
	variants := []http.Header{nil}
	if len(headers) == 0 {
		return variants
	}

	fields := make([]string, 0, len(headers))
	for field := range headers {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	for _, field := range fields {
		values := headers[field]
		next := make([]http.Header, 0, len(variants)*max(1, len(values)))
		for _, variant := range variants {
			if values == nil {
				copied := cloneHeader(variant)
				if copied != nil {
					copied.Del(field)
				}
				next = append(next, copied)
				continue
			}

			candidates := values
			if len(candidates) == 0 {
				candidates = []string{routeAuditProbeMarker}
			}
			for _, value := range candidates {
				copied := cloneHeader(variant)
				if copied == nil {
					copied = make(http.Header)
				}
				copied.Set(field, value)
				next = append(next, copied)
			}
		}
		variants = next
		if len(variants) > defaultRouteAuditMaxProbesPerRoute {
			variants = variants[:defaultRouteAuditMaxProbesPerRoute]
		}
	}
	return variants
}

func cloneHeader(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	return headers.Clone()
}

func hostCandidates(patterns []string) []string {
	if len(patterns) == 0 {
		return []string{routeAuditNoHost}
	}

	candidates := make([]string, 0, len(patterns)*2)
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		candidates = append(candidates, pattern)
		if strings.Contains(pattern, "*") {
			candidates = append(candidates, strings.ReplaceAll(pattern, "*", "audit"))
		}
	}
	candidates = uniqueStrings(candidates)
	sort.Strings(candidates)
	return candidates
}

func pathCandidates(patterns []string) []string {
	if len(patterns) == 0 {
		return []string{routeAuditPath}
	}

	candidates := make([]string, 0, len(patterns)*4)
	for _, pattern := range patterns {
		candidates = append(candidates, pathWitness(pattern, routeAuditProbeMarker))
		candidates = append(candidates, pathWitness(pattern, ""))
		if !strings.Contains(pattern, "*") {
			candidates = append(candidates, pattern)
		} else {
			for _, chunk := range pathLiteralChunks(pattern) {
				if chunk != "" {
					candidates = append(candidates, ensurePath(chunk))
				}
			}
		}
	}
	candidates = cleanPathCandidates(candidates)
	if len(candidates) > routeAuditMaxCandidatePathsPerRoute {
		candidates = candidates[:routeAuditMaxCandidatePathsPerRoute]
	}
	return candidates
}

func pathCandidatesPair(earlier, later []string) []string {
	candidates := append(pathCandidates(earlier), pathCandidates(later)...)
	if len(earlier) == 0 && len(later) == 0 {
		return []string{routeAuditPath, "/audit-wildcard"}
	}
	for _, a := range earlier {
		for _, b := range later {
			candidates = append(candidates, crossPathCandidates(a, b)...)
		}
	}
	candidates = cleanPathCandidates(candidates)
	if len(candidates) > routeAuditMaxCandidatePathsPerRoute {
		candidates = candidates[:routeAuditMaxCandidatePathsPerRoute]
	}
	return candidates
}

func pathWitness(pattern, marker string) string {
	if pattern == "*" {
		if marker == "" {
			return routeAuditPath
		}
		return ensurePath(marker)
	}

	replaced := strings.ReplaceAll(pattern, "*", marker)
	replaced = ensurePath(replaced)
	return collapseRepeatedSlashes(replaced)
}

func crossPathCandidates(a, b string) []string {
	candidates := make([]string, 0, 16)

	aChunks := pathLiteralChunks(a)
	bChunks := pathLiteralChunks(b)

	for i := 0; i < strings.Count(a, "*"); i++ {
		for _, value := range append(append([]string{}, bChunks...), routeAuditProbeMarker, "") {
			candidates = append(candidates,
				pathWitness(replaceNthWildcard(a, i, value), routeAuditProbeMarker))
		}
	}
	for i := 0; i < strings.Count(b, "*"); i++ {
		for _, value := range append(append([]string{}, aChunks...), routeAuditProbeMarker, "") {
			candidates = append(candidates,
				pathWitness(replaceNthWildcard(b, i, value), routeAuditProbeMarker))
		}
	}

	aPrefix, aSuffix := pathPrefixSuffix(a)
	bPrefix, bSuffix := pathPrefixSuffix(b)
	candidates = append(candidates,
		collapseRepeatedSlashes(ensurePath(aPrefix+bSuffix)),
		collapseRepeatedSlashes(ensurePath(bPrefix+aSuffix)),
	)

	combined := make([]string, 0, len(aChunks)+len(bChunks))
	for _, chunk := range append(aChunks, bChunks...) {
		chunk = strings.Trim(chunk, "/")
		if chunk != "" {
			combined = append(combined, chunk)
		}
	}
	if len(combined) > 0 {
		candidates = append(candidates, "/"+strings.Join(combined, "/"))
	}

	return candidates
}

func pathLiteralChunks(pattern string) []string {
	parts := strings.Split(pattern, "*")
	chunks := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			chunks = append(chunks, part)
		}
	}
	return chunks
}

func pathPrefixSuffix(pattern string) (prefix, suffix string) {
	first := strings.IndexByte(pattern, '*')
	last := strings.LastIndexByte(pattern, '*')
	if first < 0 {
		return pattern, ""
	}
	prefix = pattern[:first]
	if last >= 0 && last+1 <= len(pattern) {
		suffix = pattern[last+1:]
	}
	return prefix, suffix
}

func replaceNthWildcard(pattern string, n int, value string) string {
	if n < 0 {
		return pattern
	}
	var builder strings.Builder
	seen := 0
	for _, char := range pattern {
		if char == '*' {
			if seen == n {
				builder.WriteString(value)
			} else {
				builder.WriteRune(char)
			}
			seen++
			continue
		}
		builder.WriteRune(char)
	}
	return builder.String()
}

func ensurePath(path string) string {
	if path == "" {
		return routeAuditPath
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func collapseRepeatedSlashes(path string) string {
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}

func cleanPathCandidates(candidates []string) []string {
	cleaned := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if !strings.HasPrefix(candidate, "/") {
			candidate = "/" + candidate
		}
		candidate = collapseRepeatedSlashes(candidate)
		cleaned = append(cleaned, candidate)
	}
	cleaned = uniqueStrings(cleaned)
	sort.Strings(cleaned)
	return cleaned
}

// detectPairOverlap returns a conflict when the two compiled match sets have
// at least one request in common and their actions differ.
func detectPairOverlap(serverName string, earlier, later analyzedRoute) (Conflict, bool) {
	if !earlier.analyzable || !later.analyzable {
		return Conflict{}, false
	}
	if sameAction(earlier, later) {
		return Conflict{}, false
	}
	if !hostsMayOverlap(earlier, later) {
		return Conflict{}, false
	}

	var sharedHosts []string
	var sharedPaths []string
	overlap := false

	earlierSets := routeMatcherSetInfos(earlier.route)
	laterSets := routeMatcherSetInfos(later.route)

	maxEvaluations := max(earlierMaxProbes(earlier), laterMaxProbes(later))
	maxEvaluations *= 4
	if maxEvaluations < defaultRouteAuditMaxProbesPerRoute {
		maxEvaluations = defaultRouteAuditMaxProbesPerRoute
	}
	evaluations := 0

	for _, earlierSet := range earlierSets {
		if earlierSet.impossible {
			continue
		}
		for _, laterSet := range laterSets {
			if laterSet.impossible {
				continue
			}
			if !matcherSetsMayShareHost(earlierSet, laterSet) {
				continue
			}

			hosts := pairHostCandidates(earlierSet, laterSet)
			paths := pairPathCandidates(earlierSet, laterSet)
			methods := pairMethodCandidates(earlierSet, laterSet)
			headers := pairHeaderVariants(earlierSet, laterSet)

			for _, host := range hosts {
				for _, path := range paths {
					for _, method := range methods {
						for _, header := range headers {
							probe := newProbe(host, path, method, header)
							evaluations++
							if countRouteMatches(earlier.route.MatcherSets, probe.req) == 0 ||
								countRouteMatches(later.route.MatcherSets, probe.req) == 0 {
								if evaluations >= maxEvaluations {
									goto done
								}
								continue
							}
							overlap = true
							sharedHosts = append(sharedHosts, probe.host)
							sharedPaths = append(sharedPaths, probe.path)
							if evaluations >= maxEvaluations {
								goto done
							}
						}
					}
				}
			}
		}
	}

done:
	if !overlap {
		return Conflict{}, false
	}

	laterCovered := len(later.probes) > 0
	for _, probe := range later.probes {
		if countRouteMatches(later.route.MatcherSets, probe.req) == 0 {
			continue
		}
		if countRouteMatches(earlier.route.MatcherSets, probe.req) == 0 {
			laterCovered = false
			break
		}
	}

	kind := "order_dependent"
	direction := fmt.Sprintf("route %d wins on shared requests; route %d still serves requests the earlier one does not match",
		earlier.index, later.index)
	if laterCovered {
		kind = "shadowed"
		direction = fmt.Sprintf("route %d shadows route %d", earlier.index, later.index)
	}

	conflict := Conflict{
		ServerName: serverName,
		Earlier:    earlier.index,
		Later:      later.index,
		Kind:       kind,
		Direction:  direction,
		Hosts:      normalizeSharedHosts(sharedHosts, earlier.route, later.route),
		Paths:      normalizeSharedPaths(sharedPaths),
		Partial:    make([]string, 0),
	}
	if kind == "order_dependent" {
		conflict.Partial = partialDimensions(earlier, later)
	}
	return conflict, true
}

func routeMatcherSetInfos(route Route) []analyzedMatcherSet {
	if len(route.MatcherSets) == 0 {
		return []analyzedMatcherSet{{}}
	}
	infos := make([]analyzedMatcherSet, 0, len(route.MatcherSets))
	for _, matcherSet := range route.MatcherSets {
		info, reason := inspectMatcherSet(matcherSet)
		if reason != "" {
			continue
		}
		infos = append(infos, info)
	}
	return infos
}

func earlierMaxProbes(route analyzedRoute) int {
	return max(1, len(route.probes))
}

func laterMaxProbes(route analyzedRoute) int {
	return max(1, len(route.probes))
}

func matcherSetsMayShareHost(earlier, later analyzedMatcherSet) bool {
	if !earlier.hasHost || !later.hasHost {
		return true
	}
	for _, a := range earlier.hostPatterns {
		for _, b := range later.hostPatterns {
			if hostPatternsMayOverlap(a, b) {
				return true
			}
		}
	}
	return false
}

func pairHostCandidates(earlier, later analyzedMatcherSet) []string {
	switch {
	case earlier.hasHost && later.hasHost:
		return hostCandidates(append(append([]string{}, earlier.hostPatterns...), later.hostPatterns...))
	case earlier.hasHost:
		return hostCandidates(earlier.hostPatterns)
	case later.hasHost:
		return hostCandidates(later.hostPatterns)
	default:
		return []string{routeAuditNoHost}
	}
}

func pairPathCandidates(earlier, later analyzedMatcherSet) []string {
	switch {
	case earlier.hasPath && later.hasPath:
		return pathCandidatesPair(earlier.pathPatterns, later.pathPatterns)
	case earlier.hasPath:
		return pathCandidates(earlier.pathPatterns)
	case later.hasPath:
		return pathCandidates(later.pathPatterns)
	default:
		return []string{routeAuditPath}
	}
}

func pairMethodCandidates(earlier, later analyzedMatcherSet) []string {
	methods := append(append([]string{}, earlier.methods...), later.methods...)
	if len(methods) == 0 {
		return []string{http.MethodGet}
	}
	methods = uniqueStrings(methods)
	sort.Strings(methods)
	return methods
}

func pairHeaderVariants(earlier, later analyzedMatcherSet) []http.Header {
	if len(earlier.headers) == 0 && len(later.headers) == 0 {
		return []http.Header{nil}
	}

	combined := mergeHeaders(cloneHeader(earlier.headers), later.headers)
	if combined == nil {
		return []http.Header{nil}
	}

	variants := headerVariants(combined)
	if len(variants) == 0 {
		return []http.Header{nil}
	}
	return variants
}

func hostsMayOverlap(earlier, later analyzedRoute) bool {
	earlierPatterns, earlierHas, earlierImpossible := routeHostMatcher(earlier.route)
	laterPatterns, laterHas, laterImpossible := routeHostMatcher(later.route)
	if earlierImpossible || laterImpossible {
		return false
	}
	if !earlierHas || !laterHas {
		return true
	}
	for _, a := range earlierPatterns {
		for _, b := range laterPatterns {
			if hostPatternsMayOverlap(a, b) {
				return true
			}
		}
	}
	return false
}

func routeHostMatcher(route Route) (patterns []string, hasHost, impossible bool) {
	if len(route.MatcherSets) == 0 {
		return nil, false, false
	}
	for _, matcherSet := range route.MatcherSets {
		info, reason := inspectMatcherSet(matcherSet)
		if reason != "" {
			continue
		}
		if info.impossible {
			impossible = true
			continue
		}
		if !info.hasHost {
			return nil, false, false
		}
		patterns = append(patterns, info.hostPatterns...)
		hasHost = true
	}
	return patterns, hasHost, impossible
}

func hostPatternsMayOverlap(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if !strings.Contains(a, "*") && !strings.Contains(b, "*") {
		return a == b
	}

	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	if len(aParts) != len(bParts) {
		return false
	}
	for i := range aParts {
		if aParts[i] == "*" || bParts[i] == "*" {
			continue
		}
		if aParts[i] != bParts[i] {
			return false
		}
	}
	return true
}

func partialDimensions(earlier, later analyzedRoute) []string {
	var dimensions []string

	earlierMethods := routeMethods(earlier.route)
	laterMethods := routeMethods(later.route)
	if !reflect.DeepEqual(earlierMethods, laterMethods) {
		dimensions = append(dimensions, "method")
	}

	earlierHeaders := routeHeaderMatchers(earlier.route)
	laterHeaders := routeHeaderMatchers(later.route)
	if !headersEqual(earlierHeaders, laterHeaders) {
		dimensions = append(dimensions, "header")
	}

	return dimensions
}

func routeMethods(route Route) []string {
	methods := make([]string, 0)
	for _, matcherSet := range route.MatcherSets {
		for _, matcher := range matcherSet {
			switch m := matcher.(type) {
			case MatchMethod:
				methods = append(methods, m...)
			case *MatchMethod:
				if m != nil {
					methods = append(methods, (*m)...)
				}
			}
		}
	}
	methods = uniqueStrings(methods)
	sort.Strings(methods)
	return methods
}

func routeHeaderMatchers(route Route) []http.Header {
	headers := make([]http.Header, 0)
	for _, matcherSet := range route.MatcherSets {
		for _, matcher := range matcherSet {
			switch m := matcher.(type) {
			case MatchHeader:
				headers = append(headers, cloneHeader(http.Header(m)))
			case *MatchHeader:
				if m != nil {
					headers = append(headers, cloneHeader(http.Header(*m)))
				}
			}
		}
	}
	return headers
}

func headersEqual(earlier, later []http.Header) bool {
	if len(earlier) != len(later) {
		return false
	}
	for i := range earlier {
		if !reflect.DeepEqual(earlier[i], later[i]) {
			return false
		}
	}
	return true
}

func normalizeSharedHosts(hosts []string, routes ...Route) []string {
	hosts = uniqueStrings(hosts)
	if len(hosts) == 0 {
		for _, route := range routes {
			patterns, hasHost, _ := routeHostMatcher(route)
			if hasHost {
				hosts = append(hosts, patterns...)
			}
		}
	}
	if len(hosts) == 0 {
		hosts = []string{"*"}
	}
	sort.Strings(hosts)
	if len(hosts) > 8 {
		hosts = hosts[:8]
	}
	return hosts
}

func normalizeSharedPaths(paths []string) []string {
	paths = uniqueStrings(paths)
	if len(paths) == 0 {
		paths = []string{"*"}
	}
	sort.Strings(paths)
	if len(paths) > 8 {
		paths = paths[:8]
	}
	return paths
}

func sameAction(earlier, later analyzedRoute) bool {
	if earlier.route.Terminal != later.route.Terminal {
		return false
	}

	if len(earlier.route.HandlersRaw) > 0 || len(later.route.HandlersRaw) > 0 {
		if len(earlier.route.HandlersRaw) != len(later.route.HandlersRaw) {
			return false
		}
		for i := range earlier.route.HandlersRaw {
			if !canonicalJSONEqual(earlier.route.HandlersRaw[i], later.route.HandlersRaw[i]) {
				return false
			}
		}
		return true
	}

	if len(earlier.route.Handlers) != len(later.route.Handlers) {
		return false
	}
	for i := range earlier.route.Handlers {
		earlierJSON, earlierErr := json.Marshal(earlier.route.Handlers[i])
		laterJSON, laterErr := json.Marshal(later.route.Handlers[i])
		if earlierErr != nil || laterErr != nil {
			if !reflect.DeepEqual(earlier.route.Handlers[i], later.route.Handlers[i]) {
				return false
			}
			continue
		}
		if !canonicalJSONEqual(earlierJSON, laterJSON) {
			return false
		}
	}
	return true
}

func canonicalJSONEqual(a, b json.RawMessage) bool {
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return bytes.Equal(a, b)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return bytes.Equal(a, b)
	}
	ac, err := json.Marshal(av)
	if err != nil {
		return bytes.Equal(a, b)
	}
	bc, err := json.Marshal(bv)
	if err != nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(ac, bc)
}

// newProbe creates a request with the request-time replacer expected by the
// built-in matchers.
func newProbe(host, path, method string, headers http.Header) probeRequest {
	if method == "" {
		method = http.MethodGet
	}
	if path == "" {
		path = routeAuditPath
	}

	req := &http.Request{
		Method:     method,
		Host:       host,
		URL:        &url.URL{Path: path},
		Header:     cloneHeader(headers),
		RequestURI: path,
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req = req.WithContext(context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	return probeRequest{
		req:    req,
		host:   host,
		path:   path,
		method: method,
	}
}

func countRouteMatches(sets MatcherSets, req *http.Request) int {
	matches, err := sets.AnyMatchWithError(req)
	if err != nil || !matches {
		return 0
	}
	return 1
}

func containsProbe(probes []probeRequest, candidate probeRequest) bool {
	key := probeKey(candidate.req)
	for _, probe := range probes {
		if probeKey(probe.req) == key {
			return true
		}
	}
	return false
}

func probeKey(req *http.Request) string {
	fields := make([]string, 0, len(req.Header))
	for field, values := range req.Header {
		fields = append(fields, field+"="+strings.Join(values, ","))
	}
	sort.Strings(fields)
	return req.Host + "\x00" + req.URL.Path + "\x00" + req.Method + "\x00" + strings.Join(fields, "&")
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// newAuditLogger returns a dedicated JSON logger for audit output.
func newAuditLogger(cfg *RouteAudit, base *zap.Logger) (*zap.Logger, func(), error) {
	if cfg == nil || strings.TrimSpace(cfg.OutputFile) == "" {
		if base == nil {
			base = zap.NewNop()
		}
		return base.Named("route_audit"), func() {}, nil
	}

	file, err := os.OpenFile(cfg.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "ts"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(file),
		zapcore.InfoLevel,
	)
	return zap.New(core), func() { _ = file.Close() }, nil
}

func emitAuditReport(logger *zap.Logger, report AuditReport, elapsed time.Duration) {
	if logger == nil {
		logger = zap.NewNop()
	}

	for _, conflict := range report.Conflicts {
		logger.Info("route overlap detected",
			zap.String("server", conflict.ServerName),
			zap.Int("earlier_route", conflict.Earlier),
			zap.Int("later_route", conflict.Later),
			zap.String("kind", conflict.Kind),
			zap.String("direction", conflict.Direction),
			zap.Strings("hosts", conflict.Hosts),
			zap.Strings("paths", conflict.Paths),
			zap.Strings("partial_dimensions", conflict.Partial))
	}

	fields := []zap.Field{
		zap.String("server", report.ServerName),
		zap.Int("total_routes", report.TotalRoutes),
		zap.Int("analyzed_routes", report.AnalyzedRoutes),
		zap.Int("unanalyzable_routes", report.Unanalyzable),
		zap.Bool("truncated", report.Truncated),
		zap.Int("conflict_count", len(report.Conflicts)),
		zap.Duration("analysis_duration", elapsed),
		zap.Float64("coverage", auditCoverage(report)),
		zap.Any("conflict_groups", conflictGroups(report.Conflicts)),
	}
	if len(report.UnanalyzableList) > 0 {
		fields = append(fields,
			zap.Ints("unanalyzable_indexes", report.UnanalyzableList),
			zap.Any("unanalyzable_reasons", report.UnanalyzableReasons))
	}

	message := "route audit verdict: " + report.Verdict
	if report.Verdict == "PASS" {
		logger.Info(message, fields...)
	} else {
		logger.Warn(message, fields...)
	}
}

func conflictGroups(conflicts []Conflict) map[string]int {
	groups := make(map[string]int)
	for _, conflict := range conflicts {
		groups[conflictGroup(conflict)]++
	}
	return groups
}
