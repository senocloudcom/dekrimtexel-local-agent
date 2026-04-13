// Package ping checks liveness of configured targets via ICMP or TCP.
package ping

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

type Poller struct {
	Client  *api.Client
	mu      sync.Mutex
	targets []api.PingTarget
}

func NewPoller(client *api.Client) *Poller {
	return &Poller{Client: client}
}

func (p *Poller) UpdateTargets(targets []api.PingTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = targets
	slog.Info("ping targets loaded", "count", len(targets))
}

// Run starts the poll loop. Each tick: check all targets and POST results.
func (p *Poller) Run(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	slog.Info("ping poller started")
	p.pollAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.pollAll(ctx)
		}
	}
}

func (p *Poller) pollAll(ctx context.Context) {
	p.mu.Lock()
	targets := make([]api.PingTarget, len(p.targets))
	copy(targets, p.targets)
	p.mu.Unlock()

	if len(targets) == 0 {
		return
	}

	type result struct {
		TargetID  int     `json:"target_id"`
		Reachable bool    `json:"reachable"`
		LatencyMS float64 `json:"latency_ms"`
		Error     string  `json:"error,omitempty"`
	}

	results := make([]result, 0, len(targets))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, t := range targets {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := checkTarget(t)
			mu.Lock()
			results = append(results, result{
				TargetID:  t.ID,
				Reachable: r.ok,
				LatencyMS: r.latencyMS,
				Error:     r.err,
			})
			mu.Unlock()
		}()
	}
	wg.Wait()

	if err := p.Client.IngestPing(results); err != nil {
		slog.Warn("ping ingest failed", "err", err)
		return
	}
	reachable := 0
	for _, r := range results {
		if r.Reachable {
			reachable++
		}
	}
	slog.Info("ping poll", "total", len(results), "reachable", reachable)
}

type checkResult struct {
	ok        bool
	latencyMS float64
	err       string
}

func checkTarget(t api.PingTarget) checkResult {
	checkType := strings.ToLower(t.CheckType)
	if checkType == "tcp" && t.TCPPort != nil {
		return checkTCP(t.Host, *t.TCPPort)
	}
	// Default = ICMP
	return checkICMP(t.Host)
}

func checkTCP(host string, port int) checkResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		return checkResult{ok: false, err: err.Error()}
	}
	conn.Close()
	return checkResult{ok: true, latencyMS: float64(time.Since(start).Microseconds()) / 1000}
}

// checkICMP uses the OS ping command. Works on Windows (unprivileged) and Linux.
func checkICMP(host string) checkResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// -n 1 (1 echo) -w 2000 (2 sec timeout)
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", host)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", host)
	}
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := float64(time.Since(start).Microseconds()) / 1000
	output := string(out)

	if err != nil {
		return checkResult{ok: false, err: firstLine(output)}
	}

	// Probeer RTT uit output te halen
	latency := parsePingLatency(output)
	if latency == 0 {
		latency = elapsed
	}
	// Windows ping geeft ook "100% loss" zonder errexit, check op 'unreachable' / 'time out'
	lower := strings.ToLower(output)
	if strings.Contains(lower, "100% loss") ||
		strings.Contains(lower, "onbereikbaar") ||
		strings.Contains(lower, "unreachable") ||
		strings.Contains(lower, "time out") ||
		strings.Contains(lower, "time-out") ||
		strings.Contains(lower, "request timed out") {
		return checkResult{ok: false, err: "unreachable"}
	}
	return checkResult{ok: true, latencyMS: latency}
}

func parsePingLatency(output string) float64 {
	// Windows: "time=X ms" or "tijd=X ms"
	// Linux: "time=X ms"
	for _, needle := range []string{"time=", "tijd=", "time<"} {
		idx := strings.Index(output, needle)
		if idx < 0 {
			continue
		}
		rest := output[idx+len(needle):]
		end := strings.IndexAny(rest, " m")
		if end < 0 {
			continue
		}
		val := strings.TrimSpace(rest[:end])
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return 0
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
