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
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// maxFieldScan bounds how much of a single header or cookie value is scanned.
// Bodies are bounded by the scan budget instead.
const maxFieldScan = 64 << 10

// maxJSONDepth bounds recursion into a JSON document. Documents deeper than
// this are scanned as raw text rather than walked.
const maxJSONDepth = 256

// scanContext holds per-request inspection state. It is never shared between
// requests, so one request's verdict cannot leak into another.
type scanContext struct {
	rules *compiledRules
}

// inspectMetadata checks the request line, headers and cookies. It does not
// read the body.
func (sc *scanContext) inspectMetadata(r *http.Request) (match, target, bool) {
	if sc == nil || sc.rules == nil {
		return match{}, 0, false
	}

	if sc.rules.wants(targetPath) {
		escaped := r.URL.EscapedPath()
		if m, ok := sc.rules.find(escaped, targetPath); ok {
			return m, targetPath, true
		}
		if dec, err := url.PathUnescape(escaped); err == nil && dec != escaped {
			if m, ok := sc.rules.find(dec, targetPath); ok {
				return m, targetPath, true
			}
		}
	}

	if sc.rules.wants(targetQuery) && r.URL.RawQuery != "" {
		if m, ok := sc.rules.find(r.URL.RawQuery, targetQuery); ok {
			return m, targetQuery, true
		}
	}

	if sc.rules.wants(targetHeaders) {
		if r.Host != "" {
			if m, ok := sc.rules.find(limit(r.Host, maxFieldScan), targetHeaders); ok {
				return m, targetHeaders, true
			}
		}
		for name, values := range r.Header {
			if skipHeader(name) {
				continue
			}
			if m, ok := sc.rules.find(name, targetHeaders); ok {
				return m, targetHeaders, true
			}
			for _, v := range values {
				if m, ok := sc.rules.find(v, targetHeaders); ok {
					return m, targetHeaders, true
				}
			}
		}
	}

	if sc.rules.wants(targetCookies) {
		if raw := r.Header["Cookie"]; len(raw) > 0 {
			// Scan the raw header first so malformed cookies that the parser
			// rejects cannot hide a payload between pairs.
			for _, line := range raw {
				if m, ok := sc.rules.find(limit(line, maxFieldScan), targetCookies); ok {
					return m, targetCookies, true
				}
			}
			for _, c := range r.Cookies() {
				if m, ok := sc.rules.find(c.Name, targetCookies); ok {
					return m, targetCookies, true
				}
				if m, ok := sc.rules.find(c.Value, targetCookies); ok {
					return m, targetCookies, true
				}
			}
		}
	}

	return match{}, 0, false
}

// inspectBodyPayload checks a decoded body. Structured content is split into
// its fields; if that is not possible the whole payload is scanned as text,
// so payloads cannot escape by using a shape the parser does not understand.
func (sc *scanContext) inspectBodyPayload(r *http.Request, payload []byte) (match, bool) {
	if sc == nil || sc.rules == nil || len(payload) == 0 {
		return match{}, false
	}

	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return sc.scanRaw(payload)
	}

	switch {
	case mediaType == "multipart/form-data":
		if m, ok, complete := sc.inspectMultipart(payload, params["boundary"]); complete {
			return m, ok
		}
	case mediaType == "application/x-www-form-urlencoded":
		if m, ok, complete := sc.inspectURLValues(payload); complete {
			return m, ok
		}
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		if m, ok, complete := sc.inspectJSON(payload); complete {
			return m, ok
		}
	}
	return sc.scanRaw(payload)
}

// scanRaw scans the entire payload as text.
func (sc *scanContext) scanRaw(payload []byte) (match, bool) {
	return sc.rules.find(string(payload), targetBody)
}

func (sc *scanContext) inspectURLValues(payload []byte) (match, bool, bool) {
	values, err := url.ParseQuery(string(payload))
	if err != nil {
		// ParseQuery drops pairs it cannot decode. Rather than inspect a
		// partial view, report the body as not fully understood so the
		// caller scans it raw; a payload must not hide in a malformed pair.
		return match{}, false, false
	}
	for name, vals := range values {
		if m, ok := sc.rules.find(name, targetBody); ok {
			return m, true, true
		}
		for _, v := range vals {
			if m, ok := sc.rules.find(v, targetBody); ok {
				return m, true, true
			}
		}
	}
	return match{}, false, true
}

// inspectJSON walks a JSON document with the streaming decoder, so a deeply
// nested or large document is never fully materialized as a tree. The third
// return value reports whether the whole document was understood.
func (sc *scanContext) inspectJSON(payload []byte) (match, bool, bool) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()

	var walk func(depth int) (match, bool, bool)
	walk = func(depth int) (match, bool, bool) {
		if depth > maxJSONDepth {
			return match{}, false, false
		}
		tok, err := dec.Token()
		if err != nil {
			return match{}, false, false
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				for dec.More() {
					keyTok, err := dec.Token()
					if err != nil {
						return match{}, false, false
					}
					if key, ok := keyTok.(string); ok {
						if m, ok := sc.rules.find(key, targetBody); ok {
							return m, true, true
						}
					}
					if m, ok, complete := walk(depth + 1); !complete || ok {
						return m, ok, complete
					}
				}
				if _, err := dec.Token(); err != nil { // closing brace
					return match{}, false, false
				}
			case '[':
				for dec.More() {
					if m, ok, complete := walk(depth + 1); !complete || ok {
						return m, ok, complete
					}
				}
				if _, err := dec.Token(); err != nil { // closing bracket
					return match{}, false, false
				}
			}
		case string:
			if m, ok := sc.rules.find(v, targetBody); ok {
				return m, true, true
			}
		case json.Number:
			if m, ok := sc.rules.find(v.String(), targetBody); ok {
				return m, true, true
			}
		}
		return match{}, false, true
	}

	return walk(0)
}

// inspectMultipart parses a multipart body and scans part names, filenames and
// contents. The third return value reports whether the body was parsed to a
// natural end.
func (sc *scanContext) inspectMultipart(payload []byte, boundary string) (match, bool, bool) {
	if boundary == "" {
		return match{}, false, false
	}
	mr := multipart.NewReader(bytes.NewReader(payload), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			// io.EOF means a clean end; any other error means the body was
			// not fully understood, so the caller falls back to a raw scan.
			return match{}, false, err == io.EOF
		}
		if m, ok := sc.rules.find(part.FormName(), targetBody); ok {
			return m, true, true
		}
		if m, ok := sc.rules.find(part.FileName(), targetBody); ok {
			return m, true, true
		}
		data, err := io.ReadAll(part)
		if err == nil {
			if m, ok := sc.rules.find(string(data), targetBody); ok {
				return m, true, true
			}
		}
	}
}

// limit truncates s to n bytes. It only applies to single values; bodies are
// bounded by the scan budget instead.
func limit(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}

// skipHeader reports whether name carries no client payload worth scanning.
// Framing headers are consumed by the HTTP server and never reach the upstream
// as data; Cookie is scanned under its own target instead.
func skipHeader(name string) bool {
	switch strings.ToLower(name) {
	case "cookie", "content-length", "transfer-encoding", "connection",
		"keep-alive", "proxy-connection", "te", "trailer", "upgrade", "expect":
		return true
	}
	return false
}
