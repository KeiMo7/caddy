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
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"slices"

	"github.com/klauspost/compress/zstd"
)

// decodeReason classifies why a body could not be inspected. The values are
// fixed identifiers safe to put in headers and metric labels.
type decodeReason string

const (
	decodeOK          decodeReason = ""
	decodeSize        decodeReason = "decompressed-size"
	decodeRatio       decodeReason = "decompression-ratio"
	decodeUnsupported decodeReason = "unsupported-encoding"
	decodeCorrupt     decodeReason = "corrupt-encoding"
)

// decodeLimits bounds decompression.
type decodeLimits struct {
	// maxDecoded is the absolute cap on decoded bytes.
	maxDecoded int64
	// ratio caps decoded bytes per compressed byte for inputs large enough
	// for a compression bomb to matter.
	ratio int64
}

// minRatioInput is the compressed size below which the ratio limit is not
// applied. Small inputs decode to small outputs anyway and are already bounded
// by maxDecoded; applying the ratio there would reject legitimate highly
// compressible bodies such as short repetitive forms.
const minRatioInput = 1024

// decodeForInspection decodes body according to its Content-Encoding so it can
// be inspected. The result is never forwarded; the caller keeps and replays
// the original bytes. The returned reason names which limit was hit, so the
// caller can refuse with a distinguishable cause.
func decodeForInspection(encoding string, body []byte, lim decodeLimits) ([]byte, decodeReason, error) {
	codings := parseCodings(encoding)
	// An empty body carries nothing to inspect, whatever its declared
	// encoding; decoding it would only fail on a truncated stream.
	if len(codings) == 0 || len(body) == 0 {
		return body, decodeOK, nil
	}

	// Content-Encoding lists codings in the order they were applied, so
	// decode in reverse.
	cur := body
	for _, coding := range slices.Backward(codings) {
		cap := lim.maxDecoded
		ratioBounded := false
		if lim.ratio > 0 && int64(len(cur)) >= minRatioInput {
			if r := int64(len(cur)) * lim.ratio; r < cap {
				cap = r
				ratioBounded = true
			}
		}
		dec, reason, err := decodeOne(coding, cur, cap)
		if reason == decodeSize && ratioBounded {
			// The cap that was hit was the ratio-derived one.
			reason = decodeRatio
		}
		if reason != decodeOK || err != nil {
			return nil, reason, err
		}
		cur = dec
	}
	return cur, decodeOK, nil
}

func parseCodings(encoding string) []string {
	var out []string
	for _, part := range splitComma(encoding) {
		part = lowerTrim(part)
		if part == "" || part == "identity" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func decodeOne(coding string, in []byte, cap int64) ([]byte, decodeReason, error) {
	switch coding {
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, decodeCorrupt, err
		}
		defer r.Close()
		return readCapped(r, cap)
	case "deflate":
		// RFC 7230 specifies zlib framing, but raw deflate is common in
		// the wild, so fall back to it.
		if r, err := zlib.NewReader(bytes.NewReader(in)); err == nil {
			defer r.Close()
			return readCapped(r, cap)
		}
		return readCapped(flate.NewReader(bytes.NewReader(in)), cap)
	case "zstd":
		// Decode as a stream into a capped buffer. DecodeAll would build the
		// whole output in memory before the cap could be checked, which is
		// exactly what a decompression bomb wants.
		dec, err := zstd.NewReader(bytes.NewReader(in),
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(uint64(cap)),
			zstd.WithDecoderLowmem(true),
		)
		if err != nil {
			return nil, decodeCorrupt, err
		}
		defer dec.Close()
		return readCapped(dec.IOReadCloser(), cap)
	default:
		return nil, decodeUnsupported, nil
	}
}

// readCapped reads r to EOF or cap+1 bytes, whichever comes first, so an
// oversized decode is detected without materializing it.
func readCapped(r io.Reader, cap int64) ([]byte, decodeReason, error) {
	buf, err := io.ReadAll(io.LimitReader(r, cap+1))
	if err != nil {
		return nil, decodeCorrupt, err
	}
	if int64(len(buf)) > cap {
		return nil, decodeSize, nil
	}
	return buf, decodeOK, nil
}

// replayBody serves the buffered prefix followed by whatever remains of the
// original body. It never changes the bytes, and Close releases both.
type replayBody struct {
	reader    io.Reader
	remainder io.ReadCloser
	closed    bool
}

func newReplayBody(buf []byte, remainder io.ReadCloser) *replayBody {
	var r io.Reader = bytes.NewReader(buf)
	if remainder != nil {
		r = io.MultiReader(r, remainder)
	}
	return &replayBody{reader: r, remainder: remainder}
}

func (b *replayBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, errors.New("request guard: read on closed body")
	}
	return b.reader.Read(p)
}

func (b *replayBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	if b.remainder != nil {
		err := b.remainder.Close()
		b.remainder = nil
		return err
	}
	return nil
}

// splitComma splits on commas without trimming, so callers can decide.
func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func lowerTrim(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	b := make([]byte, 0, end-start)
	for i := start; i < end; i++ {
		b = append(b, asciiLower(s[i]))
	}
	return string(b)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
