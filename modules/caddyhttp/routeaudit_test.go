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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestRouteAuditOverlapKinds(t *testing.T) {
	tests := []struct {
		name           string
		routes         RouteList
		wantConflicts  int
		wantKind       string
		wantPartial    []string
		wantNoConflict bool
	}{
		{
			name: "exact path covered by earlier wildcard",
			routes: RouteList{
				testAuditRoute("/internal/*", "api.example.com", nil, nil, "public"),
				testAuditRoute("/internal/admin", "api.example.com", nil, nil, "admin"),
			},
			wantConflicts: 1,
			wantKind:      "shadowed",
		},
		{
			name: "same priority routes compete by order",
			routes: RouteList{
				testAuditRoute("/internal/*", "api.example.com", nil, nil, "internal"),
				testAuditRoute("*/health", "api.example.com", nil, nil, "health"),
			},
			wantConflicts: 1,
			wantKind:      "order_dependent",
		},
		{
			name: "same path on different hosts does not conflict",
			routes: RouteList{
				testAuditRoute("/internal/admin", "api.example.com", nil, nil, "api"),
				testAuditRoute("/internal/admin", "intranet.example.com", nil, nil, "intranet"),
			},
			wantNoConflict: true,
		},
		{
			name: "method and header restrictions partially overlap",
			routes: RouteList{
				testAuditRoute("/events", "api.example.com", []string{http.MethodPost}, nil, "ingest"),
				testAuditRoute("/events", "api.example.com", nil, http.Header{"X-Internal": {"true"}}, "internal"),
			},
			wantConflicts: 1,
			wantKind:      "order_dependent",
			wantPartial:   []string{"method", "header"},
		},
		{
			name: "wildcard and fixed path differ semantically",
			routes: RouteList{
				testAuditRoute("/assets/*", "cdn.example.com", nil, nil, "assets"),
				testAuditRoute("/assets", "cdn.example.com", nil, nil, "root"),
			},
			wantNoConflict: true,
		},
		{
			name: "wildcard segment is not a string prefix",
			routes: RouteList{
				testAuditRoute("/accounts/*/info", "api.example.com", nil, nil, "account info"),
				testAuditRoute("/accounts/42/info", "api.example.com", nil, nil, "fixed"),
			},
			wantConflicts: 1,
			wantKind:      "shadowed",
		},
		{
			name: "different exact paths do not conflict",
			routes: RouteList{
				testAuditRoute("/one", "api.example.com", nil, nil, "one"),
				testAuditRoute("/two", "api.example.com", nil, nil, "two"),
			},
			wantNoConflict: true,
		},
		{
			name: "identical actions are not noise",
			routes: RouteList{
				testAuditRoute("/assets/*", "cdn.example.com", nil, nil, "cache"),
				testAuditRoute("/assets/logo.png", "cdn.example.com", nil, nil, "cache"),
			},
			wantNoConflict: true,
		},
		{
			name: "same path with incompatible methods does not conflict",
			routes: RouteList{
				testAuditRoute("/events", "api.example.com", []string{http.MethodGet}, nil, "read"),
				testAuditRoute("/events", "api.example.com", []string{http.MethodPost}, nil, "write"),
			},
			wantNoConflict: true,
		},
		{
			name: "same path with incompatible headers does not conflict",
			routes: RouteList{
				testAuditRoute("/events", "api.example.com", nil, http.Header{"X-Internal": {"true"}}, "internal"),
				testAuditRoute("/events", "api.example.com", nil, http.Header{"X-Internal": {"false"}}, "public"),
			},
			wantNoConflict: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := auditServerRoutes("test", tc.routes, &RouteAudit{Enabled: true}, nil)

			if tc.wantNoConflict {
				if len(report.Conflicts) != 0 {
					t.Fatalf("expected no conflicts, got %+v", report.Conflicts)
				}
				return
			}

			if len(report.Conflicts) != tc.wantConflicts {
				t.Fatalf("expected %d conflicts, got %d: %+v", tc.wantConflicts, len(report.Conflicts), report.Conflicts)
			}
			conflict := report.Conflicts[0]
			if conflict.Kind != tc.wantKind {
				t.Errorf("expected kind %q, got %q", tc.wantKind, conflict.Kind)
			}
			if len(tc.wantPartial) > 0 && !sameStringSet(conflict.Partial, tc.wantPartial) {
				t.Errorf("expected partial dimensions %v, got %v", tc.wantPartial, conflict.Partial)
			}
			if len(conflict.Hosts) == 0 {
				t.Error("expected affected hosts to be reported")
			}
			if len(conflict.Paths) == 0 {
				t.Error("expected affected paths to be reported")
			}
		})
	}
}

func TestRouteAuditUnanalyzableAndTruncation(t *testing.T) {
	t.Run("unsupported matcher is unanalyzable", func(t *testing.T) {
		routes := RouteList{
			{
				MatcherSets: MatcherSets{{
					MatchPathRE{MatchRegexp: MatchRegexp{Pattern: `^/internal/.*`}},
				}},
				HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"static_response","body":"dynamic"}`)},
			},
			testAuditRoute("/internal/admin", "api.example.com", nil, nil, "admin"),
		}

		report := auditServerRoutes("test", routes, &RouteAudit{Enabled: true, MinCoverage: 0.75}, nil)
		if report.Unanalyzable != 1 {
			t.Fatalf("expected one unanalyzable route, got %d", report.Unanalyzable)
		}
		if len(report.UnanalyzableList) != 1 || report.UnanalyzableList[0] != 0 {
			t.Fatalf("expected route 0 to be unanalyzable, got %v", report.UnanalyzableList)
		}
		if report.Verdict != "INSUFFICIENT_COVERAGE" {
			t.Errorf("expected insufficient coverage verdict, got %q", report.Verdict)
		}
		if report.UnanalyzableReasons["route_0"] == "" {
			t.Error("expected an unanalyzable reason for route 0")
		}
	})

	t.Run("route limit truncates analysis", func(t *testing.T) {
		routes := RouteList{
			testAuditRoute("/one", "api.example.com", nil, nil, "one"),
			testAuditRoute("/two", "api.example.com", nil, nil, "two"),
		}

		report := auditServerRoutes("test", routes, &RouteAudit{
			Enabled:   true,
			MaxRoutes: 1,
		}, nil)
		if !report.Truncated {
			t.Fatal("expected report to be marked as truncated")
		}
		if report.TotalRoutes != 2 || report.AnalyzedRoutes != 1 {
			t.Fatalf("unexpected route counts: total=%d analyzed=%d", report.TotalRoutes, report.AnalyzedRoutes)
		}
		if report.Verdict != "INSUFFICIENT_COVERAGE" {
			t.Errorf("expected insufficient coverage verdict, got %q", report.Verdict)
		}
	})
}

func TestRunRouteAuditDisabled(t *testing.T) {
	verdict, summary := runRouteAudit("test", RouteList{
		testAuditRoute("/a", "example.com", nil, nil, "a"),
	}, &RouteAudit{Enabled: false}, nil)
	if verdict != "" || summary != "" {
		t.Fatalf("disabled audit should not produce a verdict, got %q %q", verdict, summary)
	}
}

func TestRunRouteAuditWritesToDedicatedFile(t *testing.T) {
	output := filepath.Join(t.TempDir(), "route-audit.log")
	verdict, _ := runRouteAudit("test", RouteList{
		testAuditRoute("/internal/*", "api.example.com", nil, nil, "public"),
		testAuditRoute("/internal/admin", "api.example.com", nil, nil, "admin"),
	}, &RouteAudit{
		Enabled:    true,
		OutputFile: output,
	}, nil)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL verdict, got %q", verdict)
	}

	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("reading audit output: %v", err)
	}
	if len(content) == 0 {
		t.Fatal("expected audit output file to contain findings")
	}
}

func testAuditRoute(path, host string, methods []string, headers http.Header, body string) Route {
	matcherSet := make(MatcherSet, 0, 4)
	if host != "" {
		matcherSet = append(matcherSet, &MatchHost{host})
	}
	if path != "" {
		matcherSet = append(matcherSet, &MatchPath{path})
	}
	if len(methods) > 0 {
		methodMatcher := MatchMethod(methods)
		matcherSet = append(matcherSet, &methodMatcher)
	}
	if headers != nil {
		headerMatcher := MatchHeader(headers)
		matcherSet = append(matcherSet, &headerMatcher)
	}

	return Route{
		MatcherSets: MatcherSets{matcherSet},
		HandlersRaw: []json.RawMessage{
			json.RawMessage(fmt.Sprintf(`{"handler":"static_response","body":%q}`, body)),
		},
	}
}

func sameStringSet(actual, expected []string) bool {
	actualCopy := append([]string(nil), actual...)
	expectedCopy := append([]string(nil), expected...)
	sort.Strings(actualCopy)
	sort.Strings(expectedCopy)
	if len(actualCopy) != len(expectedCopy) {
		return false
	}
	for i := range actualCopy {
		if actualCopy[i] != expectedCopy[i] {
			return false
		}
	}
	return true
}

func TestRouteAuditWithProvisionedHandlers(t *testing.T) {
	output := filepath.Join(t.TempDir(), "route-audit.log")
	config := []byte(fmt.Sprintf(`{
		"apps": {"http": {"servers": {"gateway": {
			"listen": ["127.0.0.1:9080"],
			"route_audit": {"enabled": true, "output_file": %q},
			"routes": [
				{"match": [{"host": ["api.example.com"], "path": ["/internal/*"]}], "handle": [{"handler": "static_response", "body": "public"}]},
				{"match": [{"host": ["api.example.com"], "path": ["/internal/admin"]}], "handle": [{"handler": "static_response", "body": "admin"}]}
			]
		}}}}
	}`, output))
	var cfg caddy.Config
	if err := json.Unmarshal(config, &cfg); err != nil {
		t.Fatal(err)
	}
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	appIface, err := ctx.App("http")
	if err != nil {
		t.Fatal(err)
	}
	app := appIface.(*App)
	srv := app.Servers["gateway"]

	report := auditServerRoutes("gateway", srv.Routes, srv.RouteAudit, nil)
	if len(report.Conflicts) != 1 {
		t.Fatalf("expected one conflict after provisioning, got %+v", report)
	}
	if report.Conflicts[0].Kind != "shadowed" {
		t.Errorf("expected shadowed conflict, got %q", report.Conflicts[0].Kind)
	}
}

func TestRouteAuditProvisionedSameActionSuppressed(t *testing.T) {
	output := filepath.Join(t.TempDir(), "route-audit.log")
	config := []byte(fmt.Sprintf(`{
		"apps": {"http": {"servers": {"gateway": {
			"listen": ["127.0.0.1:9080"],
			"route_audit": {"enabled": true, "output_file": %q},
			"routes": [
				{"match": [{"path": ["/assets/*"]}], "handle": [{"handler": "static_response", "body": "cache"}]},
				{"match": [{"path": ["/assets/logo.png"]}], "handle": [{"handler": "static_response", "body": "cache"}]}
			]
		}}}}
	}`, output))
	var cfg caddy.Config
	if err := json.Unmarshal(config, &cfg); err != nil {
		t.Fatal(err)
	}
	ctx, err := caddy.ProvisionContext(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	appIface, err := ctx.App("http")
	if err != nil {
		t.Fatal(err)
	}
	app := appIface.(*App)
	srv := app.Servers["gateway"]

	report := auditServerRoutes("gateway", srv.Routes, srv.RouteAudit, nil)
	if len(report.Conflicts) != 0 {
		t.Fatalf("expected identical actions to be suppressed, got %+v", report.Conflicts)
	}
}
