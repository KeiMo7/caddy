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
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestProvisionDefaults proves a zero-value guard provisions to a usable,
// bounded configuration.
func TestProvisionDefaults(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	g := new(RequestGuard)
	if err := g.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	defer g.Cleanup()

	if g.MaxBodySize <= 0 {
		t.Errorf("max body size not defaulted: %d", g.MaxBodySize)
	}
	if g.MaxDecodedSize <= 0 || g.MaxDecodedSize > g.MaxBodySize {
		t.Errorf("max decoded size not defaulted/clamped: %d (body %d)", g.MaxDecodedSize, g.MaxBodySize)
	}
	if g.MaxDecodedRatio <= 0 {
		t.Errorf("max decoded ratio not defaulted: %d", g.MaxDecodedRatio)
	}
	if g.MaxConcurrent <= 0 {
		t.Errorf("max concurrent not defaulted: %d", g.MaxConcurrent)
	}
	if cap(g.sem) != g.MaxConcurrent {
		t.Errorf("semaphore capacity = %d, want %d", cap(g.sem), g.MaxConcurrent)
	}
	if g.rules == nil {
		t.Error("rules not compiled")
	}
	if g.metrics == nil {
		t.Error("metrics not initialized")
	}
}

// TestProvisionSharedRegistry proves two handlers provisioned against the
// same metrics registry do not fail on duplicate collector registration.
func TestProvisionSharedRegistry(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i := 0; i < 3; i++ {
		g := new(RequestGuard)
		if err := g.Provision(ctx); err != nil {
			t.Fatalf("provisioning handler %d: %v", i, err)
		}
		_ = g.Cleanup()
	}
}

// TestProvisionRejectsBadConfig proves invalid configuration fails at
// provision time rather than at request time.
func TestProvisionRejectsBadConfig(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range []struct {
		name string
		g    *RequestGuard
	}{
		{"bad action", &RequestGuard{Action: "nonsense"}},
		{"bad oversized policy", &RequestGuard{OversizedBody: "maybe"}},
		{"negative concurrency", &RequestGuard{MaxConcurrent: -1}},
		{"bad custom rule", &RequestGuard{Rules: []ruleConfig{{ID: "x", Pattern: "("}}}},
	} {
		if err := tc.g.Provision(ctx); err == nil {
			t.Errorf("Test %d (%s): expected an error, got none", i, tc.name)
		}
	}
}
