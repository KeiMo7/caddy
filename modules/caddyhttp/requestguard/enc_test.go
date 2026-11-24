package requestguard

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"testing"
)

func TestDecodeMultipleCodings(t *testing.T) {
	// gzip then zlib, with Content-Encoding listing application order.
	inner := []byte("hello world payload")
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	gw.Write(inner)
	gw.Close()

	// Wrap the gzip stream in zlib to simulate two stacked codings.
	// (zlib of gzip bytes.) Content-Encoding: gzip, zlib -> apply gzip then zlib.
	// decodeForInspection reverses: zlib first, then gzip.
	var zl bytes.Buffer
	zw := zlib.NewWriter(&zl)
	zw.Write(gz.Bytes())
	zw.Close()

	out, reason, err := decodeForInspection("gzip, deflate", zl.Bytes(), decodeLimits{maxDecoded: 1 << 20, ratio: 100})
	if reason != decodeOK || err != nil {
		t.Fatalf("decode failed: %v %v", reason, err)
	}
	if !bytes.Equal(out, inner) {
		t.Errorf("decoded = %q, want %q", out, inner)
	}
}
