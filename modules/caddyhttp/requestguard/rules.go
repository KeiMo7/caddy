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
	"fmt"
	"html"
	"regexp"
	"strings"
)

// maxDecodeDepth bounds how many times a percent-encoded string is decoded
// while normalizing it. Two levels cover double encoding; the third catches
// triple-encoded evasions without letting crafted input force unbounded work.
const maxDecodeDepth = 3

// target identifies the part of a request a rule applies to.
type target uint8

const (
	targetQuery target = 1 << iota
	targetPath
	targetHeaders
	targetCookies
	targetBody

	targetAll = targetQuery | targetPath | targetHeaders | targetCookies | targetBody
)

func (t target) String() string {
	switch t {
	case targetQuery:
		return "query"
	case targetPath:
		return "path"
	case targetHeaders:
		return "headers"
	case targetCookies:
		return "cookies"
	case targetBody:
		return "body"
	case targetAll:
		return "all"
	default:
		return "all"
	}
}

// parseTarget parses one target name.
func parseTarget(s string) (target, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "query", "query_string":
		return targetQuery, nil
	case "path", "uri":
		return targetPath, nil
	case "headers", "header":
		return targetHeaders, nil
	case "cookies", "cookie":
		return targetCookies, nil
	case "body":
		return targetBody, nil
	case "all", "":
		return targetAll, nil
	}
	return 0, fmt.Errorf("unknown target %q (want query, path, headers, cookies, body, or all)", s)
}

func parseTargets(names []string) (target, error) {
	if len(names) == 0 {
		return targetAll, nil
	}
	var t target
	for _, name := range names {
		nt, err := parseTarget(name)
		if err != nil {
			return 0, err
		}
		t |= nt
	}
	return t, nil
}

// rule is a compiled detection rule.
type rule struct {
	id          string
	description string
	re          *regexp.Regexp
	targets     target
	// compact selects the normalized form the rule is matched against:
	// fully compacted text (all whitespace and comments removed) for
	// structural markers that inserted separators must not split, or
	// space-squashed text for rules that rely on token boundaries.
	compact bool
	// needles are lowercase substrings, at least one of which must appear in
	// the normalized text for the rule to be able to match. They are a
	// substring prefilter that lets most rules be skipped with a fast linear
	// scan instead of running a backtracking-prone regex over the whole
	// input. An empty list disables the prefilter for that rule.
	needles []string
	// requireAll makes every needle mandatory (logical AND) rather than
	// any-of (logical OR). It is used where the regex itself needs each
	// literal to be present.
	requireAll bool
}

// mayMatch reports whether v satisfies the rule's needle prefilter.
func (r rule) mayMatch(v string) bool {
	if len(r.needles) == 0 {
		return true
	}
	if r.requireAll {
		for _, n := range r.needles {
			if !strings.Contains(v, n) {
				return false
			}
		}
		return true
	}
	for _, n := range r.needles {
		if strings.Contains(v, n) {
			return true
		}
	}
	return false
}

// ruleConfig is the user-facing configuration of a rule.
type ruleConfig struct {
	// ID is a stable identifier reported in logs and metrics.
	ID string `json:"id,omitempty"`

	// Pattern is a Go regular expression.
	Pattern string `json:"pattern,omitempty"`

	// Targets restricts the rule to certain request parts. Default: all.
	Targets []string `json:"targets,omitempty"`

	// Description is a human-readable explanation. It is logged with
	// matches, so it must not contain request data.
	Description string `json:"description,omitempty"`

	// Compact matches the fully compacted form instead of squashed text.
	Compact bool `json:"compact,omitempty"`
}

// builtinRules is the default rule set. Each carries lowercase needles that
// must be present, in the normalized text, for its regex to be able to match;
// they let find skip the regex for the vast majority of inputs.
var builtinRules = []rule{
	{id: "xss-tag", description: "script-capable HTML tag", re: regexp.MustCompile(`<script|<iframe|<svg|<object|<embed|<math|<base|<form`), targets: targetAll, compact: true, needles: []string{"<"}},
	{id: "xss-js-uri", description: "script pseudo-protocol", re: regexp.MustCompile(`javascript:|vbscript:`), targets: targetAll, compact: true, needles: []string{"javascript:", "vbscript:"}},
	{id: "xss-event", description: "inline event handler", re: regexp.MustCompile(`\bon(?:error|load|click|mouseover|focus|submit|toggle)\s*=`), targets: targetAll, needles: []string{"on"}},
	{id: "xss-dom", description: "DOM access", re: regexp.MustCompile(`document\.cookie|document\.domain|window\.location`), targets: targetAll, compact: true, needles: []string{"document.", "window."}},

	{id: "sqli-union", description: "UNION SELECT", re: regexp.MustCompile(`\bunion\s+(?:all\s+)?select\b`), targets: targetAll, needles: []string{"union"}},
	{id: "sqli-boolean", description: "boolean SQL injection", re: regexp.MustCompile(`\b(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`), targets: targetAll, needles: []string{"or", "and"}},
	{id: "sqli-quoted", description: "quoted SQL tautology", re: regexp.MustCompile(`['"]\s*(?:or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+`), targets: targetAll, needles: []string{"="}},
	{id: "sqli-time", description: "time-based SQL injection", re: regexp.MustCompile(`\b(?:sleep|benchmark|pg_sleep)\s*\(`), targets: targetAll, needles: []string{"sleep", "benchmark"}},
	{id: "sqli-schema", description: "SQL metadata or file access", re: regexp.MustCompile(`\binformation_schema\b|\binto\s+outfile\b|\bload_file\s*\(`), targets: targetAll, needles: []string{"information_schema", "outfile", "load_file"}},
	{id: "sqli-stacked", description: "stacked SQL statement", re: regexp.MustCompile(`;\s*(?:drop|truncate|alter|create)\s+(?:table|database|user)\b`), targets: targetAll, needles: []string{";"}},

	{id: "path-traversal", description: "path traversal", re: regexp.MustCompile(`(?:^|[\\/])\.\.(?:[\\/]|$)`), targets: targetAll, compact: true, needles: []string{".."}},
	{id: "path-sensitive-file", description: "sensitive filesystem path", re: regexp.MustCompile(`/etc/passwd|/proc/self/environ|/proc/self/cmdline`), targets: targetAll, compact: true, needles: []string{"/etc/passwd", "/proc/self/"}},

	{id: "cmd-inject", description: "shell command injection", re: regexp.MustCompile(`(?:;|\|\||&&|\|)\s*(?:cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|ncat|python|perl)\b`), targets: targetAll, needles: []string{";", "|", "&&"}},
	{id: "cmd-substitution", description: "shell command substitution", re: regexp.MustCompile("\\$\\(|`(?:cat|ls|id|whoami|uname|wget|curl|bash|sh|nc)\\b"), targets: targetAll, compact: true, needles: []string{"$(", "`"}},

	{id: "jndi-lookup", description: "JNDI lookup", re: regexp.MustCompile(`\$\{jndi:`), targets: targetAll, compact: true, needles: []string{"${jndi:"}},
	{id: "xxe", description: "XML external entity", re: regexp.MustCompile(`<!entity\b|<!doctype[^>]*\[`), targets: targetAll, needles: []string{"<!entity", "<!doctype"}},
	{id: "nosql-operator", description: "NoSQL operator injection", re: regexp.MustCompile(`\$(?:where|ne|gt|lt|regex)\b`), targets: targetAll, needles: []string{"$"}},
}

// combined is the set of rules that share a matching mode, with the union of
// their targets so a whole set can be skipped when none apply.
type combined struct {
	rules   []rule
	targets target
}

func combine(rules []rule) *combined {
	if len(rules) == 0 {
		return nil
	}
	var tgts target
	for _, r := range rules {
		tgts |= r.targets
	}
	return &combined{rules: rules, targets: tgts}
}

// compiledRules is the rule set for one handler.
type compiledRules struct {
	text    *combined
	compact *combined
}

// compileRules merges built-in rules with custom ones. Each matching mode
// gets one alternation built from all rules that use it.
func compileRules(builtin []rule, custom []ruleConfig, disableBuiltin bool) (*compiledRules, error) {
	var textRules, compactRules []rule
	if !disableBuiltin {
		for _, r := range builtin {
			if r.compact {
				compactRules = append(compactRules, r)
			} else {
				textRules = append(textRules, r)
			}
		}
	}

	seen := make(map[string]struct{}, len(custom))
	for i, rc := range custom {
		if rc.ID == "" {
			return nil, fmt.Errorf("rule %d: id is required", i)
		}
		if _, ok := seen[rc.ID]; ok {
			return nil, fmt.Errorf("rule %d: duplicate id %q", i, rc.ID)
		}
		seen[rc.ID] = struct{}{}
		if rc.Pattern == "" {
			return nil, fmt.Errorf("rule %q: pattern is required", rc.ID)
		}
		re, err := regexp.Compile(rc.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %v", rc.ID, err)
		}
		tgts, err := parseTargets(rc.Targets)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %v", rc.ID, err)
		}
		r := rule{id: rc.ID, description: rc.Description, re: re, targets: tgts, compact: rc.Compact}
		if r.compact {
			compactRules = append(compactRules, r)
		} else {
			textRules = append(textRules, r)
		}
	}

	if len(textRules) == 0 && len(compactRules) == 0 {
		return nil, fmt.Errorf("no rules configured")
	}
	return &compiledRules{text: combine(textRules), compact: combine(compactRules)}, nil
}

// match describes a rule hit. It carries no request data.
type match struct {
	ruleID      string
	description string
}

// wants reports whether any rule targets t.
func (c *compiledRules) wants(t target) bool {
	if c == nil {
		return false
	}
	if c.text != nil && c.text.targets&t != 0 {
		return true
	}
	if c.compact != nil && c.compact.targets&t != 0 {
		return true
	}
	return false
}

// find reports the first rule that matches any normalized form of s for the
// given target.
func (c *compiledRules) find(s string, tgt target) (match, bool) {
	if c == nil || s == "" || !c.wants(tgt) {
		return match{}, false
	}
	forms := normalize(s)
	if c.text != nil {
		for _, v := range forms.squashed {
			if m, ok := findIn(c.text, v, tgt); ok {
				return m, true
			}
		}
	}
	if c.compact != nil {
		for _, v := range forms.compact {
			if m, ok := findIn(c.compact, v, tgt); ok {
				return m, true
			}
		}
	}
	return match{}, false
}

func findIn(c *combined, v string, tgt target) (match, bool) {
	if c.targets&tgt == 0 {
		return match{}, false
	}
	// Prefer the rules whose needles are present. Most inputs fail every
	// needle check, so no regex runs at all.
	var candidates []rule
	for _, r := range c.rules {
		if r.targets&tgt == 0 || !r.mayMatch(v) {
			continue
		}
		candidates = append(candidates, r)
	}
	if len(candidates) == 0 {
		return match{}, false
	}
	for _, r := range candidates {
		if r.re.MatchString(v) {
			return match{ruleID: r.id, description: r.description}, true
		}
	}
	return match{}, false
}

// normalized holds the forms of a string that rules are matched against.
type normalized struct {
	squashed []string
	compact  []string
}

// normalize produces decoded and de-obfuscated forms of s: percent decoding
// over several levels, HTML entity decoding where those characters appear,
// control-character and comment removal, whitespace squashing, and ASCII
// lowercasing. Duplicate forms are dropped so each regex runs once per form.
func normalize(s string) normalized {
	var forms normalized

	// Fast path: if the input contains nothing normalization would change
	// (no uppercase, no whitespace or control bytes to squash, no comments
	// or percent/entity escapes to decode), the squashed form is the input
	// itself and there is nothing else to try. This keeps large clean bodies
	// from paying for copies of themselves on the hot path.
	if isAlreadyNormal(s) {
		forms.squashed = []string{s}
		forms.compact = []string{s}
		return forms
	}

	seenSquash := make(map[string]struct{}, maxDecodeDepth+2)
	seenCompact := make(map[string]struct{}, maxDecodeDepth+2)

	add := func(v string) {
		if sq := squash(v, true); sq != "" {
			if _, ok := seenSquash[sq]; !ok {
				seenSquash[sq] = struct{}{}
				forms.squashed = append(forms.squashed, sq)
			}
		}
		if cp := squash(v, false); cp != "" {
			if _, ok := seenCompact[cp]; !ok {
				seenCompact[cp] = struct{}{}
				forms.compact = append(forms.compact, cp)
			}
		}
	}

	add(s)

	// In query strings and form bodies, "+" stands for a space. Rules match
	// against a form-decoded variant as well so token boundaries survive.
	bases := []string{s}
	if strings.ContainsRune(s, '+') {
		bases = append(bases, strings.ReplaceAll(s, "+", " "))
	}

	for _, base := range bases {
		if base != s {
			add(base)
		}
		// percent decoding, applied repeatedly to unwrap multiple layers
		cur := base
		for range maxDecodeDepth {
			dec, changed := percentDecode(cur)
			if !changed {
				break
			}
			cur = dec
			add(cur)
		}

		// HTML entities hide angle brackets and quotes
		if strings.ContainsRune(base, '&') {
			if un := html.UnescapeString(base); un != base {
				add(un)
				if dec, changed := percentDecode(un); changed {
					add(dec)
				}
			}
		}
	}

	return forms
}

// percentDecode decodes every valid %XX escape and leaves malformed ones
// alone, so hostile input cannot make normalization fail.
func percentDecode(s string) (string, bool) {
	if !strings.ContainsRune(s, '%') {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := fromHex(s[i+1])
			lo, ok2 := fromHex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), changed
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// squash lowercases ASCII, removes control characters, strips /* */ comments,
// and either collapses whitespace to single spaces (keepSpace) or removes it
// entirely. A removed comment becomes one space in keepSpace mode so that
// "union/**/select" still separates into tokens.
func squash(s string, keepSpace bool) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := true // also trims leading whitespace
	inBlockComment := false
	for i := 0; i < len(s); {
		if inBlockComment {
			if i+1 < len(s) && s[i] == '*' && s[i+1] == '/' {
				inBlockComment = false
				i += 2
				if keepSpace && !prevSpace {
					b.WriteByte(' ')
					prevSpace = true
				}
			} else {
				i++
			}
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			inBlockComment = true
			i += 2
			continue
		}
		c := s[i]
		if c < 0x20 || c == 0x7f || c == ' ' {
			if keepSpace && !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			i++
			continue
		}
		if c >= 0x80 {
			b.WriteByte(c)
		} else {
			b.WriteByte(asciiLower(c))
		}
		prevSpace = false
		i++
	}
	if keepSpace {
		return strings.TrimSpace(b.String())
	}
	return b.String()
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// isAlreadyNormal reports whether squashing s with and without spaces would
// both return s unchanged, and whether no decoding (percent, HTML entity, or
// form "+"-as-space) could produce a different string. When true, normalize
// can skip building the extra forms entirely.
func isAlreadyNormal(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			return false
		case c <= 0x20 || c == 0x7f:
			// any whitespace or control byte would be squashed away or
			// collapsed, changing the string
			return false
		case c == '%' || c == '&' || c == '+':
			return false
		case c == '/':
			if i+1 < len(s) && s[i+1] == '*' {
				return false
			}
		}
	}
	return true
}
