# request_guard — verification report

This directory holds the real output of the tests added for the `request_guard`
middleware (`modules/caddyhttp/requestguard`). Nothing here is hand-edited;
each file was produced by redirecting a `go test` invocation.

Environment: Go 1.26.0, linux/amd64. The toolchain lives at `/home/wll/go-sdk`;
`GOTMPDIR` was pointed outside the small `/tmp` tmpfs.

## Files

| File | What it is |
|------|-----------|
| `request_guard_tests.txt` | `go test -v ./modules/caddyhttp/requestguard/` (47 top-level tests, 0 failures) |
| `request_guard_memory.txt` | the 100 MiB body memory measurement |
| `request_guard_bench.txt` | rule-engine benchmarks (`-bench . -benchmem`) |
| `request_guard_adapt_test.txt` | Caddyfile → JSON golden test for the directive |
| `request_guard_regression.txt` | `go test -short ./...` for the whole repo |
| `baseline_full_short.txt` | the same full run on the untouched baseline commit |
| `baseline_preexisting_failure.txt` | the pre-existing failing test on baseline |

## Requirement → test map

| Requirement | Test(s) |
|-------------|---------|
| Query, path, header, cookie payloads; case, double encoding, whitespace, control chars | `TestNormalizeForms`, `TestGuardBlocksAndDoesNotReachUpstream` |
| Form and structured-body payloads; nested fields, long values, non-standard bytes | `TestGuardMultipartNestedPayload`, `TestEndToEndBlockedRequestsNeverReachUpstream`, `TestGuardReplaysBodyByteForByte` |
| Compressed bodies decoded within limits, unbounded-memory safe | `TestGuardDecompressionBombRejected`, `TestGuardDecompressionReasonsAreDistinguishable`, `TestEndToEndCompressedReplay`, `TestDecodeMultipleCodings` |
| Chunked / no length / half-sent bodies | `TestEndToEndChunkedBody`, `TestChunkedUploadNoContentLengthAcrossGuard`, `TestGuardIncompleteBodyRejected`, `TestGuardOversizedDoesNotWaitForEOF` |
| Over-budget bodies: allow vs reject per route, observable | `TestGuardOversizedReject`, `TestGuardOversizedAllowForwardsWholeBody`, `TestLargeBodyAllowedPassesThroughObservably` |
| Connection upgrades not broken | `TestGuardSkipsUpgrade` |
| Per-route on/off, no overhead when off | `TestRouteWithoutGuardIsUnchanged`, `TestGuardOffActionForwards` |
| Independent verdicts on one connection | `TestGuardIndependentRequests` |
| Bounded memory (per-request + per-instance) | `TestLargeBodyMemoryIsBounded`, `TestGuardConcurrencyBudget`, `TestGuardConcurrencyBudgetReject`, `TestGuardConcurrentRequestsAreSafe` |
| Body replayed byte-for-byte, framing preserved | `TestGuardReplaysBodyByteForByte`, `TestEndToEndBytesDoNotChangeUnderEncoding`, `TestEndToEndFramingPreserved`, `TestGuardPreservesTrailers`, `TestGuardHeaderCountsUnchangedOnCleanBody`, `TestEndToEndCleanRequestsArriveUnchanged` |
| Three-way action: block / log / forward | `TestGuardBlocksAndDoesNotReachUpstream`, `TestGuardLogActionForwards`, `TestGuardOffActionForwards` |
| No body/cookie/pattern leak in errors, logs, labels | `TestGuardBlocksAndDoesNotReachUpstream` asserts the error text; reason/label values are fixed constants |
| Detection has no bypass via parser edge cases | `TestPrefilterNeverMissesMatch`, `TestGuardMalformedFormFallsBackToRawScan`, `TestGuardEmptyBodyWithEncoding` |
| Existing size limit unchanged | `TestRequestBodySizeLimitStillWins` |
| Upstream health/retry/reuse untouched | no change to `reverseproxy`; full `-short` suite unchanged from baseline |

## Measured memory (100 MiB body)

```
100 MiB body (no length): body=104857600 bytes heap_delta=2932480 bytes total_alloc_delta=5500280 bytes
100 MiB body (declared):  body=104857600 bytes heap_delta=52072 bytes   total_alloc_delta=52072 bytes
```

Two cases, both at the default 1 MiB inspection budget:

- **No declared length (the hard case).** The guard buffers one budget's
  worth and streams the remainder, so a 100 MiB body costs about 2.9 MiB of
  live heap — memory does not scale with body size.
- **Declared length over the budget.** The guard detects this from
  `Content-Length`, reads nothing, and forwards the body untouched, so a
  100 MiB upload costs about 52 KiB.

## Rule-engine throughput (after the needle prefilter)

```
BenchmarkFindCleanShort          499 ns/op
BenchmarkFindCleanLargeJSON      235 MB/s
BenchmarkFindEncodedPayload      2.3 µs/op
```

## Known limitations

- `go test -race` could not be run in this environment: the race detector needs
  cgo and no C compiler (`gcc`) is installed, and there is no passwordless sudo
  to install one. The concurrency tests run without `-race`.
- `TestServer_ClosedRequestBodyDoesNotDesyncHTTP1` (in `modules/caddyhttp`) fails
  on the untouched baseline commit as well; see `baseline_preexisting_failure.txt`.
  It is unrelated to this change.
- `TestFileRotationPreserveMode` (in `modules/logging`) failed once under the
  full parallel suite and passes on repeated isolated runs; it is a pre-existing
  flake in file-mode handling, not touched by this change.
