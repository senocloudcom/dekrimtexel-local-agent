package syslog

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// TestListenerEndToEnd starts a listener on a random UDP port, a fake
// dashboard HTTP server, sends one CBS350 syslog packet, and asserts the
// listener posts a correctly parsed event to the fake server.
func TestListenerEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var received []api.SyslogEvent
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.SyslogIngestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		received = append(received, req.Events...)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(api.IngestResponse{Status: "ok", Processed: len(req.Events)})
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	client := api.NewClient(srv.URL, "test-key", "test-tenant", "test")

	cfg := api.SyslogConfig{
		Enabled:       true,
		Port:          0, // random
		ListenAddress: "127.0.0.1",
	}
	switches := []api.SwitchConfig{
		{ID: 42, Host: "127.0.0.1", Name: "test-switch"},
	}
	l := NewListener(cfg, client, switches)

	// Bind a UDP socket manually so we know the port, then inject it
	// into the listener by setting cfg.Port. Simpler approach: listen
	// on port 0, then call Run — but Run picks its own conn. We need
	// the port upfront to send the packet. Workaround: pre-bind here,
	// close, reuse the number.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	l.cfg.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := l.Run(ctx); err != nil {
			t.Errorf("listener run: %v", err)
		}
	}()

	// Give the listener a moment to bind.
	time.Sleep(200 * time.Millisecond)

	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	raw := "<warning> Feb 19 15:23:01 test-switch: %STP-W-PORTSTATUS: gi1/0/15: STP status Forwarding"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()

	// Force a flush by cancelling the context after a brief delay.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for dashboard POST")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("received %d events, want 1", len(received))
	}
	ev := received[0]
	if ev.SourceIP != "127.0.0.1" {
		t.Errorf("source_ip = %q, want 127.0.0.1", ev.SourceIP)
	}
	if ev.SwitchID == nil || *ev.SwitchID != 42 {
		t.Errorf("switch_id = %v, want 42", ev.SwitchID)
	}
	if ev.Severity != "warning" {
		t.Errorf("severity = %q, want warning", ev.Severity)
	}
	if ev.Mnemonic != "PORTSTATUS" {
		t.Errorf("mnemonic = %q, want PORTSTATUS", ev.Mnemonic)
	}
	if ev.Interface != "gi1/0/15" {
		t.Errorf("interface = %q, want gi1/0/15", ev.Interface)
	}
	if !strings.Contains(ev.Message, "STP status Forwarding") {
		t.Errorf("message = %q, want to contain STP status Forwarding", ev.Message)
	}
}

