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
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		name    string
		input   string
		wantErr bool
		check   func(*testing.T, *RequestGuard)
	}{
		{
			name:  "inline action",
			input: `request_guard log`,
			check: func(t *testing.T, g *RequestGuard) {
				if g.Action != "log" {
					t.Errorf("action = %q, want log", g.Action)
				}
			},
		},
		{
			name: "full block",
			input: `request_guard {
				action block
				max_body_size 2MB
				oversized_body allow
				max_decoded_size 4MB
				max_decoded_ratio 50
				max_concurrent 8
				concurrency_wait 250ms
			}`,
			check: func(t *testing.T, g *RequestGuard) {
				if g.MaxBodySize != 2_000_000 {
					t.Errorf("max_body_size = %d, want 2000000", g.MaxBodySize)
				}
				if g.OversizedBody != "allow" {
					t.Errorf("oversized_body = %q, want allow", g.OversizedBody)
				}
				if g.MaxDecodedSize != 4_000_000 {
					t.Errorf("max_decoded_size = %d, want 4000000", g.MaxDecodedSize)
				}
				if g.MaxDecodedRatio != 50 {
					t.Errorf("max_decoded_ratio = %d, want 50", g.MaxDecodedRatio)
				}
				if g.MaxConcurrent != 8 {
					t.Errorf("max_concurrent = %d, want 8", g.MaxConcurrent)
				}
			},
		},
		{
			name: "disabled and custom rules",
			input: `request_guard {
				disable_rule xss-tag sqli-union
				rule my-rule "secret[a-z]+" targets=query,body compact description=my_rule
			}`,
			check: func(t *testing.T, g *RequestGuard) {
				if len(g.DisabledRules) != 2 {
					t.Fatalf("disabled rules = %v, want 2 entries", g.DisabledRules)
				}
				if len(g.Rules) != 1 {
					t.Fatalf("custom rules = %v, want 1 entry", g.Rules)
				}
				r := g.Rules[0]
				if r.ID != "my-rule" || r.Pattern != `secret[a-z]+` {
					t.Errorf("rule = %+v", r)
				}
				if !r.Compact {
					t.Error("compact flag not parsed")
				}
				if r.Description != "my_rule" {
					t.Errorf("description = %q", r.Description)
				}
				if len(r.Targets) != 2 || r.Targets[0] != "query" || r.Targets[1] != "body" {
					t.Errorf("targets = %v", r.Targets)
				}
			},
		},
		{
			name: "unknown subdirective",
			input: `request_guard {
				nonsense
			}`,
			wantErr: true,
		},
		{
			name: "regexp rule with comma is one token",
			input: `request_guard {
				rule my-rule "a{1,3}"
			}`,
			check: func(t *testing.T, g *RequestGuard) {
				if len(g.Rules) != 1 || g.Rules[0].Pattern != "a{1,3}" {
					t.Errorf("rules = %+v", g.Rules)
				}
			},
		},
		{
			name: "invalid size",
			input: `request_guard {
				max_body_size not-a-size
			}`,
			wantErr: true,
		},
	} {
		d := caddyfile.NewTestDispenser(tc.input)
		g := new(RequestGuard)
		err := g.UnmarshalCaddyfile(d)
		if tc.wantErr && err == nil {
			t.Errorf("Test %d (%s): expected error, got none", i, tc.name)
			continue
		}
		if !tc.wantErr && err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
			continue
		}
		if tc.check != nil && err == nil {
			tc.check(t, g)
		}
	}
}

func TestUnmarshalCaddyfileInvalidRule(t *testing.T) {
	for i, tc := range []struct {
		name  string
		input string
	}{
		{"missing pattern", "request_guard {\nrule only-id\n}"},
		{"unknown option", "request_guard {\nrule id pat nope=1\n}"},
	} {
		err := new(RequestGuard).UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if err == nil {
			t.Errorf("Test %d (%s): expected error, got none", i, tc.name)
		}
	}
}
