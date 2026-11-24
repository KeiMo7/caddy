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
	"strings"
	"testing"
)

var benchRules = func() *compiledRules {
	r, err := compileRules(builtinRules, nil, false)
	if err != nil {
		panic(err)
	}
	return r
}()

func BenchmarkFindCleanShort(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := benchRules.find("hello world", targetBody); ok {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkFindCleanLargeJSON(b *testing.B) {
	body := `{"name":"Alice","items":[` + strings.Repeat(`"item",`, 2000) + `"last"]}`
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := benchRules.find(body, targetBody); ok {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkFindEncodedPayload(b *testing.B) {
	// double-encoded payload forces the full normalization pipeline
	in := "%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E"
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := benchRules.find(in, targetBody); !ok {
			b.Fatal("expected a match")
		}
	}
}
