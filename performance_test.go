package winrm

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkCommandCapacity(b *testing.B) {
	for _, outputSize := range []int{1 << 10, 64 << 10} {
		for _, concurrency := range []int{1, 8, 32} {
			for _, debug := range []bool{false, true} {
				name := fmt.Sprintf("output-%d/concurrency-%d/debug-%t", outputSize, concurrency, debug)
				b.Run(name, func(b *testing.B) {
					benchmarkCommandCapacity(b, outputSize, concurrency, debug)
				})
			}
		}
	}
}

func benchmarkCommandCapacity(b *testing.B, outputSize, concurrency int, debug bool) {
	response := kerberosPhase4Receive([]byte(strings.Repeat("x", outputSize)), nil, true, 0)
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			b.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", soapXML)
		switch message := string(body); {
		case strings.Contains(message, "transfer/Create"):
			_, _ = io.WriteString(writer, createShellResponse)
		case strings.Contains(message, "shell/Command"):
			_, _ = io.WriteString(writer, executeCommandResponse)
		case strings.Contains(message, "shell/Receive"):
			_, _ = io.WriteString(writer, response)
		default:
			_, _ = io.WriteString(writer, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`)
		}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	b.Cleanup(server.Close)

	host, port, err := FindHostAndPortFromURL(server.URL)
	if err != nil {
		b.Fatal(err)
	}
	client, err := NewClient(NewEndpoint(host, port, false, false, nil, nil, nil, 0), "user", "password")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = client.Close() })

	previousDebug := HTTPDebugEnabled()
	previousUnsafe := httpDebugUnsafe.Load()
	SetHTTPDebug(debug)
	SetHTTPDebugUnsafe(false)
	b.Cleanup(func() {
		SetHTTPDebug(previousDebug)
		SetHTTPDebugUnsafe(previousUnsafe)
	})
	if debug {
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			b.Fatal(err)
		}
		previousStderr := os.Stderr
		os.Stderr = devNull
		b.Cleanup(func() {
			os.Stderr = previousStderr
			_ = devNull.Close()
		})
	}

	latencies := make([]time.Duration, b.N)
	baselineGoroutines := runtime.NumGoroutine()
	peakGoroutines := baselineGoroutines
	var beforeMemory runtime.MemStats
	runtime.ReadMemStats(&beforeMemory)
	b.SetBytes(int64(outputSize * concurrency))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		started := time.Now()
		var wait sync.WaitGroup
		errorsSeen := make(chan error, concurrency)
		for index := 0; index < concurrency; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				stdout, stderr, exitCode, err := client.RunCmdWithContext(context.Background(), "hostname")
				if err != nil || len(stdout) != outputSize || stderr != "" || exitCode != 0 {
					errorsSeen <- fmt.Errorf("result: stdout=%d stderr=%q exit=%d err=%w", len(stdout), stderr, exitCode, err)
				}
			}()
		}
		peakGoroutines = max(peakGoroutines, runtime.NumGoroutine())
		wait.Wait()
		latencies[iteration] = time.Since(started)
		close(errorsSeen)
		for err := range errorsSeen {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	var afterMemory runtime.MemStats
	runtime.ReadMemStats(&afterMemory)
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	if len(latencies) > 0 {
		b.ReportMetric(float64(latencies[len(latencies)/2].Nanoseconds()), "batch-p50-ns")
		b.ReportMetric(float64(latencies[(len(latencies)-1)*95/100].Nanoseconds()), "batch-p95-ns")
	}
	operations := int64(b.N * concurrency)
	if operations > 0 {
		b.ReportMetric(float64(connections.Load())/float64(operations), "connections/command")
	}
	b.ReportMetric(float64(peakGoroutines), "peak-goroutines")
	b.ReportMetric(float64(peakGoroutines-baselineGoroutines), "peak-goroutine-delta")
	b.ReportMetric(float64(afterMemory.HeapAlloc), "final-heap-bytes")
	b.ReportMetric(float64(afterMemory.HeapSys), "heap-reserved-bytes")
	if afterMemory.HeapAlloc >= beforeMemory.HeapAlloc {
		b.ReportMetric(float64(afterMemory.HeapAlloc-beforeMemory.HeapAlloc), "heap-growth-bytes")
	}
}
