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
	"math/rand"
	"testing"
)

// withoutNeedles returns the same rule set with every needle prefilter
// removed, so find runs every regex. Comparing against it proves the
// prefilter never changes which rule matches.
func withoutNeedles(c *compiledRules) *compiledRules {
	strip := func(cb *combined) *combined {
		if cb == nil {
			return nil
		}
		rules := make([]rule, len(cb.rules))
		for i, r := range cb.rules {
			r.needles = nil
			rules[i] = r
		}
		return combine(rules)
	}
	return &compiledRules{text: strip(c.text), compact: strip(c.compact)}
}

// TestPrefilterNeverMissesMatch compares find() with and without the needle
// prefilter over targeted payloads and random mutations. A difference means
// the prefilter dropped a rule that would otherwise have matched.
func TestPrefilterNeverMissesMatch(t *testing.T) {
	full, err := compileRules(builtinRules, nil, false)
	if err != nil {
		t.Fatalf("compiling: %v", err)
	}
	ref := withoutNeedles(full)

	seeds := []string{
		"<script>alert(1)</script>",
		"<svg/onload=alert(1)>",
		"javascript:alert(1)",
		"document.cookie",
		"window.location='x'",
		"1 union select 2",
		"1 union all select password from users",
		"' or 1=1 --",
		"'x' or 'a'='a",
		"1 and 2=2",
		"sleep(5)",
		"benchmark(1000000,x)",
		"information_schema.tables",
		"1 into outfile '/tmp/x'",
		"load_file('/etc/passwd')",
		";drop table users",
		"../../etc/passwd",
		"/etc/passwd",
		"/proc/self/environ",
		"; cat /etc/passwd",
		"| whoami",
		"$(id)",
		"`uname -a`",
		"${jndi:ldap://x/a}",
		`<!ENTITY xxe SYSTEM "file:///etc/passwd">`,
		`<!DOCTYPE foo [<!ENTITY x SYSTEM "x">]>`,
		`{"$where":"1==1"}`,
		"%3Cscript%3E",
		"%253Cscript%253E",
	}

	// every seed with and without surrounding benign text
	cases := make([]string, 0, len(seeds)*3)
	for _, s := range seeds {
		cases = append(cases,
			s,
			"prefix "+s+" suffix",
			"%"+s,
		)
	}

	// random mutations of the seeds to probe normalization interactions
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("<>%&'+;$()/\\=|#-* abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\x00\x01")
	for i := 0; i < 5000; i++ {
		base := []byte(seeds[rng.Intn(len(seeds))])
		for j := 0; j < 1+rng.Intn(6); j++ {
			switch rng.Intn(3) {
			case 0:
				base[rng.Intn(len(base))] = alphabet[rng.Intn(len(alphabet))]
			case 1:
				pos := rng.Intn(len(base))
				base = append(base[:pos], append([]byte{alphabet[rng.Intn(len(alphabet))]}, base[pos:]...)...)
			case 2:
				if len(base) > 1 {
					pos := rng.Intn(len(base))
					base = append(base[:pos], base[pos+1:]...)
				}
			}
		}
		cases = append(cases, string(base))
	}

	for i, in := range cases {
		gotM, gotOK := full.find(in, targetBody)
		wantM, wantOK := ref.find(in, targetBody)
		if gotOK != wantOK {
			t.Fatalf("case %d %q: prefilter changed match presence: got %v (%q), want %v (%q)",
				i, in, gotOK, gotM.ruleID, wantOK, wantM.ruleID)
		}
	}
}
