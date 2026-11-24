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
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("request_guard", parseCaddyfile)
}

// parseCaddyfile parses the request_guard directive. Syntax:
//
//	request_guard [<action>] {
//	    action            <block|log|off>
//	    max_body_size     <size>
//	    oversized_body    <reject|allow>
//	    max_decoded_size  <size>
//	    max_decoded_ratio <n>
//	    max_concurrent    <n>
//	    concurrency_wait  <duration>
//	    disable_rule      <id>...
//	    disable_builtin_rules
//	    rule <id> <pattern> [targets=<list>] [compact] [description=<text>]
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	g := new(RequestGuard)
	if err := parseGuard(h, g); err != nil {
		return nil, err
	}
	return g, nil
}

// parseGuard parses request_guard tokens into g. It is shared by the adapter
// and by UnmarshalCaddyfile so the two can never diverge.
func parseGuard(h httpcaddyfile.Helper, g *RequestGuard) error {
	h.Next() // consume directive name

	// an action may be given inline
	for h.NextArg() {
		g.Action = h.Val()
	}

	for h.NextBlock(0) {
		switch h.Val() {
		case "action":
			if !h.AllArgs(&g.Action) {
				return h.ArgErr()
			}

		case "max_body_size":
			size, err := parseSizeArg(h, "max_body_size")
			if err != nil {
				return err
			}
			g.MaxBodySize = size

		case "max_decoded_size":
			size, err := parseSizeArg(h, "max_decoded_size")
			if err != nil {
				return err
			}
			g.MaxDecodedSize = size

		case "oversized_body":
			if !h.AllArgs(&g.OversizedBody) {
				return h.ArgErr()
			}

		case "max_decoded_ratio":
			n, err := parseIntArg(h, "max_decoded_ratio")
			if err != nil {
				return err
			}
			g.MaxDecodedRatio = n

		case "max_concurrent":
			n, err := parseIntArg(h, "max_concurrent")
			if err != nil {
				return err
			}
			g.MaxConcurrent = int(n)

		case "concurrency_wait":
			var s string
			if !h.AllArgs(&s) {
				return h.ArgErr()
			}
			d, err := caddy.ParseDuration(s)
			if err != nil {
				return h.Errf("parsing concurrency_wait: %v", err)
			}
			g.ConcurrencyWait = caddy.Duration(d)

		case "disable_rule":
			args := h.RemainingArgs()
			if len(args) == 0 {
				return h.ArgErr()
			}
			g.DisabledRules = append(g.DisabledRules, args...)

		case "disable_builtin_rules":
			if h.NextArg() {
				return h.ArgErr()
			}
			g.DisableBuiltinRules = true

		case "rule":
			rc, err := parseRule(h)
			if err != nil {
				return err
			}
			g.Rules = append(g.Rules, rc)

		default:
			return h.Errf("unrecognized request_guard subdirective %q", h.Val())
		}
	}

	return nil
}

// parseRule parses:
//
//	rule <id> <pattern> [targets=<list>] [compact] [description=<text>]
func parseRule(h httpcaddyfile.Helper) (ruleConfig, error) {
	var rc ruleConfig

	args := h.RemainingArgs()
	if len(args) < 2 {
		return rc, h.Errf("rule requires an id and a pattern")
	}
	rc.ID = args[0]
	rc.Pattern = args[1]

	for _, arg := range args[2:] {
		key, value, hasValue := splitOption(arg)
		switch {
		case hasValue && key == "targets":
			rc.Targets = splitList(value)
		case hasValue && key == "description":
			rc.Description = value
		case !hasValue && arg == "compact":
			rc.Compact = true
		default:
			return rc, h.Errf("unrecognized rule option %q", arg)
		}
	}

	return rc, nil
}

// splitOption splits "key=value" into its parts.
func splitOption(s string) (key, value string, hasValue bool) {
	if key, value, ok := strings.Cut(s, "="); ok {
		return key, value, true
	}
	return s, "", false
}

// splitList splits a comma-separated list, dropping empty elements.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseSizeArg parses a single human-readable size argument.
func parseSizeArg(h httpcaddyfile.Helper, field string) (int64, error) {
	var s string
	if !h.AllArgs(&s) {
		return 0, h.ArgErr()
	}
	size, err := humanize.ParseBytes(s)
	if err != nil {
		return 0, h.Errf("parsing %s: %v", field, err)
	}
	return int64(size), nil
}

// parseIntArg parses a single positive integer argument.
func parseIntArg(h httpcaddyfile.Helper, field string) (int64, error) {
	var s string
	if !h.AllArgs(&s) {
		return 0, h.ArgErr()
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, h.Errf("parsing %s: %v", field, err)
	}
	if n <= 0 {
		return 0, h.Errf("parsing %s: must be positive", field)
	}
	return n, nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (g *RequestGuard) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return parseGuard(httpcaddyfile.Helper{Dispenser: d}, g)
}

// Interface guard
var _ caddyfile.Unmarshaler = (*RequestGuard)(nil)
