// Package scheduler runs the main agent loop: heartbeat, trigger polling,
// periodic background scans, and config refetch.
//
// Concurrency model (alpha10):
//   - There is NO global "scan in progress" lock.
//   - Multiple scan triggers can run in parallel (manual + periodic + per-switch).
//   - Per-switch concurrency is guarded by a sync.Map-based SwitchLocker so the
//     same switch is never SSH'd by two goroutines at the same time.
//   - A shared semaphore (chan struct{} cap=5) caps the total number of
//     simultaneous SSH sessions across all scans, to avoid DDoS'ing the VPN
//     tunnel.
//   - A separate atomic.Bool guards the periodic background scan so we never
//     start a second periodic scan while the previous one is still running.
//     Manual triggers are unaffected.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/switches"
)

// Maximum aantal parallelle SSH sessies (voorkomt DDoS van agent + VPN tunnel).
// Geldt over alle scans samen, niet per scan.
const maxParallelSSH = 5

// Scheduler orchestrates the runtime loops.
type Scheduler struct {
	Client    *api.Client
	Hostname  string
	AgentType string
	Version   string
	SecretKey string

	config *api.RemoteConfig

	// Per-switch lock — voorkomt dat dezelfde switch tegelijk door twee
	// scans wordt aangeraakt. Verschillende switches scannen vrolijk parallel.
	locker SwitchLocker

	// Globale SSH semaphore over alle scans — rate limit op de VPN tunnel.
	scanSem chan struct{}

	// Voorkomt dat we een tweede periodieke background scan starten terwijl
	// de vorige nog loopt. Manual scans hebben geen guard nodig.
	periodicInProgress atomic.Bool
}

// NewScheduler creates a new scheduler. Call Run to start it.
func NewScheduler(client *api.Client, hostname, agentType, version, secretKey string) *Scheduler {
	return &Scheduler{
		Client:    client,
		Hostname:  hostname,
		AgentType: agentType,
		Version:   version,
		SecretKey: secretKey,
		scanSem:   make(chan struct{}, maxParallelSSH),
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

	// Periodic background scan ticker. Default 900s (15 min) uit dashboard config.
	scanFullSeconds := intervals.ScanFullSeconds
	if scanFullSeconds <= 0 {
		scanFullSeconds = 900
	}
	scanFullTick := time.NewTicker(time.Duration(scanFullSeconds) * time.Second)
	defer scanFullTick.Stop()

	// Send initial heartbeat immediately
	s.sendHeartbeat()

	slog.Info("scheduler started",
		"heartbeat_s", intervals.HeartbeatSeconds,
		"trigger_poll_s", intervals.TriggerPollSeconds,
		"config_refetch_s", intervals.ConfigRefetchSeconds,
		"scan_full_s", scanFullSeconds,
		"max_parallel_ssh", maxParallelSSH,
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
		case <-scanFullTick.C:
			go s.runPeriodicScan()
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

// runPeriodicScan starts a full-fleet scan as if it came from the dashboard.
// Guarded by periodicInProgress to avoid stacking up if a previous periodic
// scan hasn't finished. Manual triggers are not affected by this guard.
func (s *Scheduler) runPeriodicScan() {
	if !s.periodicInProgress.CompareAndSwap(false, true) {
		slog.Info("periodic scan skipped: previous run still in progress")
		return
	}
	defer s.periodicInProgress.Store(false)

	scanID := "periodic-" + uuid.NewString()
	slog.Info("periodic scan starting", "scan_id", scanID)
	s.handleScanTrigger(api.Trigger{
		Type:   "scan",
		ScanID: scanID,
	})
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
			slog.Info("trigger received", "type", t.Type, "scan_id", t.ScanID, "switch_id", t.SwitchID)
			// Run elke scan in z'n eigen goroutine. Geen globale lock meer:
			// per-switch concurrency wordt bewaakt door de SwitchLocker
			// in handleScanTrigger.
			go func(trigger api.Trigger) {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("scan goroutine panic", "scan_id", trigger.ScanID, "panic", r)
					}
				}()
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
	if s.config == nil || len(s.config.Switches) == 0 {
		slog.Error("cannot run scan: no config or no switches")
		_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "no config or no switches in config")
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
			placeholderID := s.config.Switches[0].ID
			s.pushStep(t.ScanID, &placeholderID, "scan_complete",
				fmt.Sprintf("Switch ID %d niet gevonden in agent config", *t.SwitchID), "error")
			_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "switch not found in config")
			return
		}
	} else {
		targets = s.config.Switches
	}

	// Push initial start step zodat de modal direct iets ziet.
	// We gebruiken de eerste switch_id als plaatshouder omdat het ingest endpoint
	// een geldige switch_id vereist (de modal toont alleen step+detail).
	placeholderID := targets[0].ID
	s.pushStep(t.ScanID, &placeholderID, "scan_start",
		fmt.Sprintf("Scan gestart voor %d switch(es) (parallel, max %d SSH tegelijk)", len(targets), maxParallelSSH),
		"running")

	// Parallelle scan met:
	// - per-switch lock (skip als al bezig door andere scan)
	// - shared semaphore (cap maxParallelSSH over alle scans)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	failures := 0
	skipped := 0
	var failedSwitches []string
	var skippedSwitches []string

	for _, sw := range targets {
		sw := sw // capture loop variable
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("scanOneSwitch panic", "switch", sw.Name, "panic", r)
				}
			}()

			// Probeer per-switch lock te krijgen
			if !s.locker.TryLock(sw.ID) {
				slog.Info("switch already being scanned, skipping", "switch", sw.Name, "scan_id", t.ScanID)
				swID := sw.ID
				s.pushStep(t.ScanID, &swID, "skipped",
					fmt.Sprintf("%s wordt al gescand door een andere taak — overslaan", sw.Name),
					"warning")
				mu.Lock()
				skipped++
				skippedSwitches = append(skippedSwitches, sw.Name)
				mu.Unlock()
				return
			}
			defer s.locker.Unlock(sw.ID)

			// Acquire global SSH semaphore (rate limit on VPN)
			s.scanSem <- struct{}{}
			defer func() { <-s.scanSem }()

			err := s.scanOneSwitch(sw, t.ScanID)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				slog.Error("scan failed", "switch", sw.Name, "err", err)
				failures++
				failedSwitches = append(failedSwitches, sw.Name)
			} else {
				successes++
			}
		}()
	}
	wg.Wait()

	// Final summary step
	var summary string
	var status string
	switch {
	case failures == 0 && skipped == 0:
		summary = fmt.Sprintf("Scan voltooid: %d/%d switches geslaagd", successes, len(targets))
		status = "done"
	case failures == 0 && skipped > 0:
		skippedList := strings.Join(skippedSwitches, ", ")
		summary = fmt.Sprintf("Scan voltooid: %d OK, %d overgeslagen (%s)",
			successes, skipped, skippedList)
		status = "warning"
	case successes == 0 && skipped == 0:
		summary = fmt.Sprintf("Scan MISLUKT: 0/%d switches geslaagd", len(targets))
		status = "error"
	default:
		parts := []string{fmt.Sprintf("%d OK", successes)}
		if failures > 0 {
			parts = append(parts, fmt.Sprintf("%d gefaald (%s)", failures, strings.Join(failedSwitches, ", ")))
		}
		if skipped > 0 {
			parts = append(parts, fmt.Sprintf("%d overgeslagen (%s)", skipped, strings.Join(skippedSwitches, ", ")))
		}
		summary = "Scan deels gelukt: " + strings.Join(parts, ", ")
		status = "error"
	}
	s.pushStep(t.ScanID, &placeholderID, "scan_complete", summary, status)
	slog.Info("scan finished",
		"scan_id", t.ScanID, "ok", successes, "failed", failures, "skipped", skipped)

	result := "success"
	errMsg := ""
	if failures > 0 && successes == 0 {
		result = "failure"
		errMsg = summary
	}
	if err := s.Client.AckTrigger(t.ScanID, t.Type, result, errMsg); err != nil {
		slog.Error("ack failed", "err", err)
	}
}

// pushStep stuurt een enkele scan progress step naar het dashboard.
func (s *Scheduler) pushStep(scanID string, switchID *int, step, detail, status string) {
	swID := 0
	if switchID != nil {
		swID = *switchID
	}
	go func() {
		err := s.Client.IngestScanProgress(swID, "", []api.ScanProgressStep{{
			ScanID:   scanID,
			SwitchID: switchID,
			Step:     step,
			Detail:   detail,
			Status:   status,
		}})
		if err != nil {
			slog.Warn("scan summary push failed", "err", err)
		}
	}()
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
