// Package scheduler runs the main agent loop: heartbeat, jobs polling,
// legacy trigger polling, periodic background scans, and config refetch.
//
// Concurrency model:
//   - Per-switch lock guards individual switches (SwitchLocker)
//   - Shared SSH semaphore caps total parallel SSH sessions
//   - activeScans dedupliceert lopende scan_id's (legacy triggers nodig dit,
//     jobs pollen via FOR UPDATE SKIP LOCKED zodat de server het al doet)
//   - periodicInProgress voorkomt stacked periodic scans
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
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/syslog"
)

// Maximum aantal parallelle SSH sessies (voorkomt DDoS van agent + VPN tunnel).
const maxParallelSSH = 5

// Scheduler orchestrates the runtime loops.
type Scheduler struct {
	Client    *api.Client
	Hostname  string
	AgentType string
	Version   string
	SecretKey string

	config *api.RemoteConfig

	locker             SwitchLocker
	scanSem            chan struct{}
	periodicInProgress atomic.Bool
	activeScans        sync.Map // dedupe voor legacy triggers

	syslogListener *syslog.Listener
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
	if err := s.refetchConfig(); err != nil {
		return err
	}

	intervals := s.config.Agent.Intervals

	heartbeatTick := time.NewTicker(time.Duration(intervals.HeartbeatSeconds) * time.Second)
	defer heartbeatTick.Stop()

	// Eén ticker voor BOTH triggers (legacy) en jobs (nieuw). Pollt elk interval beide.
	pollTick := time.NewTicker(time.Duration(intervals.TriggerPollSeconds) * time.Second)
	defer pollTick.Stop()

	configTick := time.NewTicker(time.Duration(intervals.ConfigRefetchSeconds) * time.Second)
	defer configTick.Stop()

	scanFullSeconds := intervals.ScanFullSeconds
	if scanFullSeconds <= 0 {
		scanFullSeconds = 900
	}
	scanFullTick := time.NewTicker(time.Duration(scanFullSeconds) * time.Second)
	defer scanFullTick.Stop()

	s.sendHeartbeat()

	// Start syslog listener if enabled for this agent.
	if s.config.Agent.Modules.Syslog && s.config.Syslog.Enabled {
		s.syslogListener = syslog.NewListener(s.config.Syslog, s.Client, s.config.Switches)
		go func() {
			if err := s.syslogListener.Run(ctx); err != nil {
				slog.Error("syslog listener failed", "err", err)
			}
		}()
	}

	slog.Info("scheduler started",
		"heartbeat_s", intervals.HeartbeatSeconds,
		"poll_s", intervals.TriggerPollSeconds,
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
		case <-pollTick.C:
			go s.pollJobs()
			// Legacy pollTriggers UIT in alpha11+ — de dashboard schrijft
			// nu via scan_jobs queue. Zonder dit zou elke klik dubbel
			// uitgevoerd worden (één keer als legacy trigger, één keer
			// als job) en zou de race tussen beide flows tot rare modal
			// states leiden. De legacy code blijft staan zodat we 'm
			// later terug kunnen aanzetten als blijkt dat een specifieke
			// agent versie het nodig heeft.
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
	// Keep the syslog listener's IP→switch map in sync with the latest config.
	if s.syslogListener != nil {
		s.syslogListener.UpdateSwitches(cfg.Switches)
	}
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
// Note: deze gebruikt nog de legacy executeScan path met een eigen scan_id,
// niet de scan_jobs queue. Dat is bewust — periodic runs hoeven niet in de
// admin scan-jobs lijst te verschijnen totdat we daar reden voor hebben.
func (s *Scheduler) runPeriodicScan() {
	if !s.periodicInProgress.CompareAndSwap(false, true) {
		slog.Info("periodic scan skipped: previous run still in progress")
		return
	}
	defer s.periodicInProgress.Store(false)

	scanID := "periodic-" + uuid.NewString()
	slog.Info("periodic scan starting", "scan_id", scanID)
	s.executeScan(scanID, nil)
}

// scanResult is what executeScan returns to the caller (either pollJobs or
// the legacy trigger handler) so they can compose the right finish/ack call.
type scanResult struct {
	successes       int
	failures        int
	skipped         int
	failedSwitches  []string
	skippedSwitches []string
	summary         string
	status          string // 'done' | 'warning' | 'error'
	totalTargets    int
}

// executeScan voert een scan uit voor één scan_id en optionele target switch.
// Stuurt progress steps naar de dashboard tijdens het werk en returned
// een scanResult die de caller gebruikt voor de uiteindelijke ack/finish call.
//
// Geen ack/finish hier — dat doet de caller (pollJobs of pollTriggers handler)
// zodat we hetzelfde scan-werk kunnen hergebruiken voor zowel jobs als legacy.
func (s *Scheduler) executeScan(scanID string, targetSwitchID *int) scanResult {
	if s.config == nil || len(s.config.Switches) == 0 {
		slog.Error("cannot run scan: no config or no switches", "scan_id", scanID)
		return scanResult{
			summary: "Geen config of geen switches geconfigureerd",
			status:  "error",
		}
	}

	// Determine which switches to scan
	var targets []api.SwitchConfig
	if targetSwitchID != nil {
		for _, sw := range s.config.Switches {
			if sw.ID == *targetSwitchID {
				targets = append(targets, sw)
				break
			}
		}
		if len(targets) == 0 {
			slog.Error("switch_id not found in config", "id", *targetSwitchID, "scan_id", scanID)
			placeholderID := s.config.Switches[0].ID
			s.pushStep(scanID, &placeholderID, "scan_complete",
				fmt.Sprintf("Switch ID %d niet gevonden in agent config", *targetSwitchID), "error")
			return scanResult{
				summary: fmt.Sprintf("Switch ID %d niet gevonden in agent config", *targetSwitchID),
				status:  "error",
			}
		}
	} else {
		targets = s.config.Switches
	}

	placeholderID := targets[0].ID
	s.pushStep(scanID, &placeholderID, "scan_start",
		fmt.Sprintf("Scan gestart voor %d switch(es) (parallel, max %d SSH tegelijk)", len(targets), maxParallelSSH),
		"running")

	// Parallelle scan met:
	// - per-switch lock (skip als al bezig door andere scan)
	// - shared semaphore (cap maxParallelSSH over alle scans)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var result scanResult
	result.totalTargets = len(targets)

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

			if !s.locker.TryLock(sw.ID) {
				slog.Info("switch already being scanned, skipping", "switch", sw.Name, "scan_id", scanID)
				swID := sw.ID
				s.pushStep(scanID, &swID, "skipped",
					fmt.Sprintf("%s wordt al gescand door een andere taak — overslaan", sw.Name),
					"warning")
				mu.Lock()
				result.skipped++
				result.skippedSwitches = append(result.skippedSwitches, sw.Name)
				mu.Unlock()
				return
			}
			defer s.locker.Unlock(sw.ID)

			s.scanSem <- struct{}{}
			defer func() { <-s.scanSem }()

			err := s.scanOneSwitch(sw, scanID)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				slog.Error("scan failed", "switch", sw.Name, "err", err)
				result.failures++
				result.failedSwitches = append(result.failedSwitches, sw.Name)
			} else {
				result.successes++
			}
		}()
	}
	wg.Wait()

	// Compose summary
	switch {
	case result.failures == 0 && result.skipped == 0:
		result.summary = fmt.Sprintf("Scan voltooid: %d/%d switches geslaagd", result.successes, result.totalTargets)
		result.status = "done"
	case result.failures == 0 && result.skipped > 0:
		result.summary = fmt.Sprintf("Scan voltooid: %d OK, %d overgeslagen (%s)",
			result.successes, result.skipped, strings.Join(result.skippedSwitches, ", "))
		result.status = "warning"
	case result.successes == 0 && result.skipped == 0:
		result.summary = fmt.Sprintf("Scan MISLUKT: 0/%d switches geslaagd", result.totalTargets)
		result.status = "error"
	default:
		parts := []string{fmt.Sprintf("%d OK", result.successes)}
		if result.failures > 0 {
			parts = append(parts, fmt.Sprintf("%d gefaald (%s)", result.failures, strings.Join(result.failedSwitches, ", ")))
		}
		if result.skipped > 0 {
			parts = append(parts, fmt.Sprintf("%d overgeslagen (%s)", result.skipped, strings.Join(result.skippedSwitches, ", ")))
		}
		result.summary = "Scan deels gelukt: " + strings.Join(parts, ", ")
		result.status = "error"
	}
	s.pushStep(scanID, &placeholderID, "scan_complete", result.summary, result.status)
	slog.Info("scan finished",
		"scan_id", scanID, "ok", result.successes, "failed", result.failures, "skipped", result.skipped)

	return result
}

// pollJobs is de NIEUWE flow: pollt /v1/agent/jobs, claimt jobs atomair,
// voert ze uit, rapporteert finish.
func (s *Scheduler) pollJobs() {
	jobs, err := s.Client.GetJobs()
	if err != nil {
		slog.Error("jobs poll failed", "err", err)
		return
	}
	for _, j := range jobs {
		j := j
		slog.Info("job claimed", "scan_id", j.ScanID, "scope", j.Scope, "switch_id", j.TargetSwitchID, "switch", j.TargetSwitchName)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("job goroutine panic", "scan_id", j.ScanID, "panic", r)
				}
			}()
			s.handleJob(j)
		}()
	}
}

// handleJob verwerkt één claimed job en stuurt de finish-call naar het dashboard.
func (s *Scheduler) handleJob(j api.Job) {
	res := s.executeScan(j.ScanID, j.TargetSwitchID)

	// Map naar finish API
	var finishResult string
	switch {
	case res.failures == 0 && res.successes > 0:
		finishResult = "success"
	case res.successes > 0 && res.failures > 0:
		finishResult = "partial"
	default:
		finishResult = "failure"
	}

	counts := map[string]int{
		"ok":      res.successes,
		"failed":  res.failures,
		"skipped": res.skipped,
		"total":   res.totalTargets,
	}

	errMsg := ""
	if res.status == "error" {
		errMsg = res.summary
	}

	if err := s.Client.FinishJob(j.ScanID, finishResult, counts, res.summary, errMsg); err != nil {
		slog.Error("finish job failed", "scan_id", j.ScanID, "err", err)
	}
}

// pollTriggers is de LEGACY flow voor pre-alpha11 dashboards. Kan na 1-2
// weken weg als alle dashboards via scan_jobs werken.
func (s *Scheduler) pollTriggers() {
	triggers, err := s.Client.GetTriggers()
	if err != nil {
		slog.Debug("legacy trigger poll failed", "err", err)
		return
	}
	for _, t := range triggers {
		switch t.Type {
		case "scan":
			if _, alreadyRunning := s.activeScans.LoadOrStore(t.ScanID, struct{}{}); alreadyRunning {
				slog.Debug("legacy scan already running, skipping duplicate poll", "scan_id", t.ScanID)
				continue
			}
			slog.Info("legacy trigger received", "type", t.Type, "scan_id", t.ScanID, "switch_id", t.SwitchID)
			go func(trigger api.Trigger) {
				defer s.activeScans.Delete(trigger.ScanID)
				defer func() {
					if r := recover(); r != nil {
						slog.Error("legacy scan goroutine panic", "scan_id", trigger.ScanID, "panic", r)
					}
				}()
				s.handleLegacyTrigger(trigger)
			}(t)
		case "configure":
			slog.Info("legacy trigger received", "type", t.Type, "scan_id", t.ScanID)
			slog.Warn("configure triggers not yet implemented (fase C-zeta)", "scan_id", t.ScanID)
			_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "configure actions not implemented in this version")
		}
	}
}

// handleLegacyTrigger verwerkt een oude-stijl trigger uit agent_config.
// Komt vooral nog voor zolang dashboards dual-write doen.
func (s *Scheduler) handleLegacyTrigger(t api.Trigger) {
	res := s.executeScan(t.ScanID, t.SwitchID)

	result := "success"
	errMsg := ""
	if res.failures > 0 && res.successes == 0 {
		result = "failure"
		errMsg = res.summary
	}
	if err := s.Client.AckTrigger(t.ScanID, t.Type, result, errMsg); err != nil {
		slog.Error("legacy ack failed", "err", err)
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
