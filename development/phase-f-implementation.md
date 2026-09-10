# Phase F: Measured CPU, RAM, and Capacity Work

## Scope and Result

Phase F resolves R13 for the local pure-Go scope on 2026-09-10. It adds permanent parser, formatter, capture, GSS, framing, and command-lifecycle benchmarks; profiles a representative concurrent workload; removes the measured formatter allocation hot path; caches immutable XPath selectors; and bounds asynchronous capture storage and delivery.

This is not a live Windows/KDC capacity certification. The command benchmark uses a local HTTP fixture and the GSS benchmarks use local AES contexts. No production throughput, safe deployment concurrency, or host RSS ceiling is inferred from these values.

## Implemented Changes

- `formatDebugBodyUnsafe` uses a single builder and fixed hexadecimal lookup. A regression test permits at most two allocations for 64 KiB of binary input.
- Response parsing reuses immutable compiled XPath executors and the namespace mapping. The XML DOM remains in place because profiles did not justify a higher-risk parser replacement.
- Capture production is nonblocking through a 64-record queue. New records are dropped when full and counted by `WinRMCaptureDroppedRecords`.
- `FlushWinRMCapture` provides context-bounded delivery of previously accepted records. It neither retries dropped records nor converts prior asynchronous sink errors into a flush error.
- Payload capture is limited to 64 KiB; headers to 64 fields and 8 KiB; each method, URL, and content-type value to 8 KiB; and encoded records to 256 KiB.
- Unsafe records retain either UTF-8 text or base64, never both. Safe records retain counts and protocol metadata without payload copies.
- Capture files rotate at 16 MiB with one `.1` generation. Active, existing, and rotated files are forced to mode `0600` where Unix permissions are supported.

## Permanent Benchmarks

The permanent benchmark set is:

- `BenchmarkFormatDebugBodyUnsafeBinary64KiB`
- `BenchmarkParseOutputResponse`, for 1 KiB and 64 KiB decoded output
- `BenchmarkCaptureFile64KiB`, in safe and unsafe modes
- `BenchmarkCaptureSaturatedQueue`
- `BenchmarkKerberosGSSWrapUnwrap64KiB`
- `BenchmarkKerberosGSSFramer64KiB`
- `BenchmarkCommandCapacity`, for 1 KiB and 64 KiB output, concurrency 1/8/32, and debug off/on

Five final samples used Linux/amd64, a QEMU virtual CPU, `GOMAXPROCS=8`, `CGO_ENABLED=0`, and a 500 ms benchmark target. Timing was noisy on the shared virtual CPU; allocation counts were stable and are the stronger comparison.

| Workload | Time/op range | Bytes/op range | Allocs/op |
| --- | ---: | ---: | ---: |
| Binary formatter, 64 KiB | 2.01-3.06 ms | 262,146-262,152 | 1 |
| Capture safe, 64 KiB | 15.0-23.3 us | 1,208-1,215 | 6 |
| Capture unsafe, 64 KiB | 0.72-1.21 ms | 215,520-218,239 | 12 |
| Saturated capture enqueue | 119-207 ns | 8 | 1 |
| Parse decoded 1 KiB output | 0.23-0.71 ms | 51,120-51,121 | 709 |
| Parse decoded 64 KiB output | 2.69-7.16 ms | 559,159-559,168 | 715 |
| Direct GSS wrap/unwrap, 64 KiB | 3.77-7.21 ms | 1,496,800-1,496,820 | 204 |
| Full GSS framing, 64 KiB | 3.54-8.70 ms | 1,573,320-1,573,450 | 232 |

The same-machine committed Phase E formatter baseline, measured in a detached worktree with five samples, was 5.48-9.67 ms, 2,195,465-2,195,623 bytes, and 131,079 allocations per operation. The final implementation uses one allocation: a 99.999% reduction, exceeding the 90% target without changing escaping semantics.

XPath caching reduced the parser benchmark from 807/813 allocations for 1 KiB/64 KiB to 709/715, a reduction of 98 allocations in each case. Total allocated bytes remain dominated by DOM construction, base64 decoding, and response copies.

## Capacity Characterization

`BenchmarkCommandCapacity` runs complete local Create, Command, Receive, Signal, and Delete lifecycles. Each concurrent command owns its own shell lifecycle while sharing the client HTTP transport. It records batch p50/p95, bytes and allocations, connection count, peak goroutines, final live heap, heap growth, and reserved heap.

Across the five short adaptive samples:

| Output / concurrency | Debug | Batch time range | Bytes/op range | Allocs/op range | Peak goroutine delta |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 KiB / 1 | off | 2.08-5.46 ms | 381,237-389,575 | 4,115-4,120 | 5 |
| 1 KiB / 1 | on | 2.74-4.22 ms | 405,578-411,561 | 4,400-4,429 | 5 |
| 1 KiB / 8 | off | 17.8-27.7 ms | 3,469,304-3,555,033 | 33,759-33,872 | 14-18 |
| 1 KiB / 8 | on | 21.2-37.3 ms | 3,661,622-3,722,370 | 36,246-36,404 | 14-18 |
| 1 KiB / 32 | off | 163-263 ms | 13,810,936-14,177,008 | 136,433-137,464 | 32-76 |
| 1 KiB / 32 | on | 150-320 ms | 14,788,600-15,310,032 | 146,797-148,423 | 32-37 |
| 64 KiB / 1 | off | 7.04-30.4 ms | 1,606,710-1,628,830 | 4,199-4,210 | 4-5 |
| 64 KiB / 1 | on | 14.4-19.5 ms | 1,620,786-1,653,323 | 4,512-4,522 | 4-5 |
| 64 KiB / 8 | off | 139-212 ms | 13,094,080-13,403,312 | 34,439-34,996 | 8 |
| 64 KiB / 8 | on | 88.7-207 ms | 13,323,832-13,588,216 | 36,971-37,379 | 8-14 |
| 64 KiB / 32 | off | 224-634 ms | 52,484,984-53,135,488 | 139,350-140,267 | 32 |
| 64 KiB / 32 | on | 414-733 ms | 53,018,840-53,664,608 | 148,736-149,714 | 32 |

The 100 ms adaptive target sometimes produced only one batch at concurrency 32, so those p50/p95 values are emitted by the benchmark but are not statistically meaningful. Use a longer target on the deployment hardware before making a latency SLO or admission decision. The repeatable result is that debug mode increases allocations, and 64 KiB output scales memory approximately with concurrent command count.

No session pool was added. The local fixture does not model KDC, Windows service, network, or encrypted connection costs well enough to justify the shell-affinity API and independent GSS-session ownership a pool requires. A future pool must use separate authenticated connections and contexts; it must never share one GSS sequence space across connections.

## Profiles and Memory

The profiled case was 64 KiB output, concurrency 32, safe HTTP debug enabled, with a two-second target:

```sh
CGO_ENABLED=0 go test -run '^$' \
  -bench '^BenchmarkCommandCapacity/output-65536/concurrency-32/debug-true$' \
  -benchtime=2s -count=1 \
  -cpuprofile=/tmp/winrm-phasef-cpu.pprof \
  -memprofile=/tmp/winrm-phasef-heap.pprof \
  -blockprofile=/tmp/winrm-phasef-block.pprof .
```

CPU samples were led by syscall work (13.90%), runtime preemption (6.95%), XML text scanning (5.14%), XML byte input (4.83%), and runtime locking/unlocking (4.83%/4.23%). Allocation space was led by slice growth (36.98%), `io.ReadAll` (15.08%), SOAP reads (5.96%), base64 decode (5.73%), cloning (4.61%), and XPath tree work (4.08%). Block delay was principally `runtime.selectgo` (78.61%) and channel receive (16.83%), consistent with HTTP and lifecycle synchronization in this synthetic concurrent workload.

RSS was measured separately by running a prebuilt pure-Go test binary under Python `resource.getrusage`, excluding Go compilation. The same two-second case completed 24 batches at 117.6 ms/op and reached 49,942,528 bytes maximum RSS. This process peak is distinct from allocations/op, final live heap, and reserved heap. It is a local characterization, not an application memory limit.

## Budgets and Decisions

- Binary unsafe formatting: at most two allocations for 64 KiB, enforced by test.
- Capture producer: never waits for sink I/O; queue capacity is 64 and saturation drops the new record.
- Capture retention: 64 KiB payload, bounded headers/metadata, 256 KiB record, 16 MiB active file, and one rotated generation.
- Encrypted response and envelope limits remain protocol budgets, not aggregate process heap limits.
- String-returning helpers still grow with total command output. Streaming APIs remain the required choice for unbounded output.
- No live throughput, latency, RSS, or maximum-concurrency budget is set without a Windows/KDC workload on representative deployment hardware.

## Validation

The implementation gate includes five-sample before/after formatter measurements, five-sample permanent microbenchmarks and capacity sweep, focused capture/formatter tests, the complete pure-Go suite, vet, shuffled race tests, vulnerability scanning, and whitespace checks. Live Windows/KDC capacity and hosted CI remain outside Phase F and must not be inferred from this local fixture.
