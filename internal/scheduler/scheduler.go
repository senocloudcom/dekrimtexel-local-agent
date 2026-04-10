// Package scheduler runs the main agent loop: heartbeat, trigger polling,
// periodic scans, config refetch.
package scheduler

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/switches"
)

// Scheduler orchestrates the runtime loops.
type Scheduler struct {
	Client    *api.Client
	Hostname  string
	AgentType string
	Version   string
	SecretKey string

	config         *api.RemoteConfig
	scanInProgress atomic.Bool // true while a scan is running, prevents duplicate triggers
}

// NewScheduler creates a new scheduler. Call Run to start it.
func NewScheduler(client *api.Client, hostname, agentType, version, secretKey string) *Scheduler {
	return &Scheduler{
		Client:    client,
		Hostname:  hostname,
		AgentType: agentType,
		Version:   version,
		SecretKey: secretKey,
	}
}

// Run starts the main loop and blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) error {
	// Initial config fetch (blocking — can't start without config)
	if err := s.refetchConfig(); err != nil {
		return err
	}

	intervals := s.config.Agent.Intervals

	heartbeatTick := time.NewTicker(time.Duration(intervals.HeartbeatSeconds) * time.Second)
	defer heartbeatTick.Stop()

	triggerTick := time.NewTicker(time.Duration(intervals.TriggerPollSeconds) * time.Second)
	defer triggerTick.Stop()

	configTick := time.NewTicker(time.Duration(intervals.ConfigRefetchSeconds) * time.Second)
	defer configTick.Stop()

	// Send initial heartbeat immediately
	s.sendHeartbeat()

	slog.Info("scheduler started",
		"heartbeat_s", intervals.HeartbeatSeconds,
		"trigger_poll_s", intervals.TriggerPollSeconds,
		"config_refetch_s", intervals.ConfigRefetchSeconds,
	)

	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler stopping")
			return nil
		case <-heartbeatTick.C:
			go s.sendHeartbeat()
		case <-triggerTick.C:
			go s.pollTriggers()
		case <-configTick.C:
			go func() {
				if err := s.refetchConfig(); err != nil {
					slog.Error("config refetch failed", "err", err)
				}
			}()
		}
	}
}

func (s *Scheduler) refetchConfig() error {
	cfg, err := s.Client.GetConfig()
	if err != nil {
		return err
	}
	s.config = cfg
	slog.Info("config loaded",
		"switches", len(cfg.Switches),
		"ping_targets", len(cfg.PingTargets),
		"modules", cfg.Agent.Modules,
	)
	return nil
}

func (s *Scheduler) sendHeartbeat() {
	if err := s.Client.Heartbeat(s.Hostname, s.AgentType, s.Version); err != nil {
		slog.Error("heartbeat failed", "err", err)
		return
	}
	slog.Debug("heartbeat sent")
}

func (s *Scheduler) pollTriggers() {
	triggers, err := s.Client.GetTriggers()
	if err != nil {
		slog.Error("trigger poll failed", "err", err)
		return
	}
	for _, t := range triggers {
		switch t.Type {
		case "scan":
			// Skip if a scan is already in progress (prevents duplicate work
			// because triggers are seen on every poll until acked, and a scan
			// can take minutes for many switches).
			if !s.scanInProgress.CompareAndSwap(false, true) {
				slog.Debug("scan already in progress, skipping duplicate trigger", "scan_id", t.ScanID)
				continue
			}
			slog.Info("trigger received", "type", t.Type, "scan_id", t.ScanID, "switch_id", t.SwitchID)
			// Run the scan in a goroutine so pollTriggers returns quickly
			// (heartbeats and other triggers can keep flowing during the scan)
			go func(trigger api.Trigger) {
				defer s.scanInProgress.Store(false)
				s.handleScanTrigger(trigger)
			}(t)
		case "configure":
			slog.Info("trigger received", "type", t.Type, "scan_id", t.ScanID)
			// Fase C-zeta
			slog.Warn("configure triggers not yet implemented (fase C-zeta)", "scan_id", t.ScanID)
			_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "configure actions not implemented in this version")
		}
	}
}

func (s *Scheduler) handleScanTrigger(t api.Trigger) {
	if s.config == nil {
		slog.Error("cannot run scan: no config loaded")
		_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "no config loaded")
		return
	}

	// Determine which switches to scan
	var targets []api.SwitchConfig
	if t.SwitchID != nil {
		for _, sw := range s.config.Switches {
			if sw.ID == *t.SwitchID {
				targets = append(targets, sw)
				break
			}
		}
		if len(targets) == 0 {
			slog.Error("switch_id not found in config", "id", *t.SwitchID)
			_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "switch not found in config")
			return
		}
	} else {
		targets = s.config.Switches
	}

	// Scan each in a goroutine, but wait for all to complete before ack
	errors := 0
	for _, sw := range targets {
		if err := s.scanOneSwitch(sw, t.ScanID); err != nil {
			slog.Error("scan failed", "switch", sw.Name, "err", err)
			errors++
		}
	}

	result := "success"
	errMsg := ""
	if errors > 0 {
		result = "failure"
		errMsg = "one or more switches failed to scan"
	}
	if err := s.Client.AckTrigger(t.ScanID, t.Type, result, errMsg); err != nil {
		slog.Error("ack failed", "err", err)
	}
}

func (s *Scheduler) scanOneSwitch(sw api.SwitchConfig, scanID string) error {
	creds, err := switches.DecryptCredentials(s.SecretKey, sw.SSHCredentialsEncrypted)
	if err != nil {
		return err
	}

	// Progress callback pushes updates live to the dashboard
	progress := func(step api.ScanProgressStep) {
		go func() {
			if err := s.Client.IngestScanProgress(sw.ID, sw.Name, []api.ScanProgressStep{step}); err != nil {
				slog.Warn("scan progress push failed", "err", err)
			}
		}()
	}

	result, err := switches.ScanSwitch(sw, creds, scanID, progress)
	if err != nil {
		return err
	}

	if err := s.Client.IngestNetwork(result); err != nil {
		return err
	}
	return nil
}
