package syslog

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

const (
	flushInterval  = 10 * time.Second
	flushThreshold = 100
	maxBufferSize  = 500
	udpReadBuffer  = 8192
)

// Listener is a UDP syslog listener that batches parsed events and POSTs
// them to the dashboard. Fase C-epsilon — listener only, no write actions.
type Listener struct {
	cfg    api.SyslogConfig
	client *api.Client

	mu        sync.Mutex
	buffer    []api.SyslogEvent
	switchMap map[string]int // source IP → switch_id

	dropped atomic.Uint64
	flushCh chan struct{}
}

// NewListener creates a listener. Call Run to start it.
func NewListener(cfg api.SyslogConfig, client *api.Client, switches []api.SwitchConfig) *Listener {
	l := &Listener{
		cfg:     cfg,
		client:  client,
		flushCh: make(chan struct{}, 1),
	}
	l.UpdateSwitches(switches)
	return l
}

// UpdateSwitches rebuilds the source_ip → switch_id lookup table.
// Called by the scheduler on config refetch.
func (l *Listener) UpdateSwitches(switches []api.SwitchConfig) {
	m := make(map[string]int, len(switches))
	for _, sw := range switches {
		if sw.Host != "" {
			m[sw.Host] = sw.ID
		}
	}
	l.mu.Lock()
	l.switchMap = m
	l.mu.Unlock()
}

// Run starts the listener and blocks until ctx is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	addr := l.cfg.ListenAddress
	if addr == "" {
		addr = "0.0.0.0"
	}
	port := l.cfg.Port
	if port == 0 {
		port = 1514
	}

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	slog.Info("syslog listener started", "addr", conn.LocalAddr().String())

	// Close connection when context is done to unblock ReadFromUDP.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.flushLoop(ctx)
	}()

	buf := make([]byte, udpReadBuffer)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			slog.Warn("syslog read failed", "err", err)
			continue
		}
		l.handleMessage(string(buf[:n]), remote.IP.String())
	}

	// Drain buffer with one final flush.
	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	l.flush(flushCtx)
	cancel()
	wg.Wait()
	slog.Info("syslog listener stopped", "dropped_total", l.dropped.Load())
	return nil
}

func (l *Listener) handleMessage(raw, sourceIP string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("syslog parse panic", "panic", r, "raw", raw)
		}
	}()

	parsed := ParseMessage(raw)
	ev := api.SyslogEvent{
		SourceIP:      sourceIP,
		SwitchName:    parsed.SwitchName,
		Facility:      parsed.Facility,
		Severity:      parsed.Severity,
		SeverityLevel: parsed.SeverityLevel,
		Mnemonic:      parsed.Mnemonic,
		Interface:     parsed.Interface,
		Message:       parsed.Message,
		RawMessage:    parsed.RawMessage,
		Timestamp:     parsed.Timestamp,
	}

	l.mu.Lock()
	if id, ok := l.switchMap[sourceIP]; ok {
		ev.SwitchID = &id
	}
	l.buffer = append(l.buffer, ev)

	// Drop oldest if over max (prevents unbounded growth during POST failures).
	if len(l.buffer) > maxBufferSize {
		overflow := len(l.buffer) - maxBufferSize
		l.buffer = l.buffer[overflow:]
		l.dropped.Add(uint64(overflow))
	}

	shouldFlush := len(l.buffer) >= flushThreshold
	l.mu.Unlock()

	if shouldFlush {
		select {
		case l.flushCh <- struct{}{}:
		default:
		}
	}
}

func (l *Listener) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.flush(ctx)
		case <-l.flushCh:
			l.flush(ctx)
		}
	}
}

func (l *Listener) flush(ctx context.Context) {
	_ = ctx // reserved for future per-flush deadlines

	l.mu.Lock()
	if len(l.buffer) == 0 {
		l.mu.Unlock()
		return
	}
	events := l.buffer
	l.buffer = nil
	l.mu.Unlock()

	if err := l.client.IngestSyslog(events); err != nil {
		slog.Warn("syslog flush failed, requeueing", "count", len(events), "err", err)
		// Put failed batch back at the front. If requeue overflows maxBufferSize
		// we drop newest (simpler than FIFO on failure and the listener is not
		// critical path — losing a few new events during an outage is fine).
		l.mu.Lock()
		combined := append(events, l.buffer...)
		if len(combined) > maxBufferSize {
			overflow := len(combined) - maxBufferSize
			combined = combined[:maxBufferSize]
			l.dropped.Add(uint64(overflow))
		}
		l.buffer = combined
		l.mu.Unlock()
		return
	}
	slog.Debug("syslog flush ok", "count", len(events))
}
