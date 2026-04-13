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
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/sonicwall"
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
	periodicStartedAt  atomic.Value // time.Time
	lastPeriodicAt     atomic.Value // time.Time
	activeScans        sync.Map // dedupe voor legacy triggers

	syslogListener  *syslog.Listener
	sonicwallPoller *sonicwall.Poller
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

	// Start SonicWall poller if devices are configured
	if len(s.config.SonicwallDevices) > 0 {
		s.sonicwallPoller = sonicwall.NewPoller(s.Client, s.SecretKey)
		if err := s.sonicwallPoller.UpdateDevices(s.config.SonicwallDevices); err == nil {
			go func() {
				if err := s.sonicwallPoller.Run(ctx); err != nil {
					slog.Error("sonicwall poller failed", "err", err)
				}
			}()
		}
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
			// Legacy pollTriggers alleen voor configure actions — scan
			// triggers gaan via scan_jobs queue (alpha11+). Configure
			// triggers hebben (nog) geen eigen queue en gebruiken het
			// legacy agent_config systeem.
			go s.pollConfigureTriggers()
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
	// Keep sonicwall poller in sync
	if s.sonicwallPoller != nil {
		_ = s.sonicwallPoller.UpdateDevices(cfg.SonicwallDevices)
	}
	return nil
}

func (s *Scheduler) sendHeartbeat() {
	req := api.HeartbeatRequest{
		Hostname:  s.Hostname,
		AgentType: s.AgentType,
		Version:   s.Version,
	}
	if last := s.lastPeriodicAt.Load(); last != nil {
		if t, ok := last.(time.Time); ok && !t.IsZero() {
			req.LastPeriodicScanAt = t.UTC().Format(time.RFC3339)
		}
	}
	if started := s.periodicStartedAt.Load(); started != nil {
		if t, ok := started.(time.Time); ok && !t.IsZero() {
			req.PeriodicScanRunningSince = t.UTC().Format(time.RFC3339)
		}
	}
	if s.syslogListener != nil {
		req.SyslogListenerActive = true
		req.SyslogEventsReceived = s.syslogListener.EventsReceived()
	}

	if err := s.Client.HeartbeatWithHealth(req); err != nil {
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
	// Detect hung previous scan: reset if it's been running > 15 min
	if started := s.periodicStartedAt.Load(); started != nil {
		if startTime, ok := started.(time.Time); ok {
			if time.Since(startTime) > 15*time.Minute {
				slog.Warn("previous periodic scan appears hung, force-resetting",
					"started_at", startTime, "duration", time.Since(startTime))
				s.periodicInProgress.Store(false)
			}
		}
	}

	if !s.periodicInProgress.CompareAndSwap(false, true) {
		slog.Info("periodic scan skipped: previous run still in progress")
		return
	}
	now := time.Now()
	s.periodicStartedAt.Store(now)
	defer func() {
		s.periodicInProgress.Store(false)
		s.periodicStartedAt.Store(time.Time{})
		s.lastPeriodicAt.Store(time.Now())
	}()

	scanID := "periodic-" + uuid.NewString()
	slog.Info("periodic scan starting", "scan_id", scanID)

	// Run scan in goroutine with 10 min timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("periodic scan panic", "recover", r)
			}
		}()
		s.executeScan(scanID, nil)
	}()

	select {
	case <-done:
		slog.Info("periodic scan finished", "scan_id", scanID, "duration", time.Since(now))
	case <-time.After(10 * time.Minute):
		slog.Error("periodic scan timeout (10 min), continuing", "scan_id", scanID)
		// Don't block — scan goroutine will finish eventually or be abandoned
	}
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

// pollConfigureTriggers polls legacy triggers but only handles configure
// actions. Scan triggers are handled by the jobs system (pollJobs).
func (s *Scheduler) pollConfigureTriggers() {
	triggers, err := s.Client.GetTriggers()
	if err != nil {
		slog.Debug("configure trigger poll failed", "err", err)
		return
	}
	for _, t := range triggers {
		switch t.Type {
		case "scan":
			// Scan triggers worden afgehandeld door pollJobs — skip hier.
			// ACK zodat de trigger niet blijft hangen.
			_ = s.Client.AckTrigger(t.ScanID, t.Type, "success", "handled by jobs system")
		case "configure":
			if _, alreadyRunning := s.activeScans.LoadOrStore(t.ScanID, struct{}{}); alreadyRunning {
				continue
			}
			slog.Info("configure trigger received", "action", t.Action, "scan_id", t.ScanID, "switches", len(t.SwitchIDs))
			go func(trigger api.Trigger) {
				defer s.activeScans.Delete(trigger.ScanID)
				defer func() {
					if r := recover(); r != nil {
						slog.Error("configure goroutine panic", "scan_id", trigger.ScanID, "panic", r)
					}
				}()
				s.handleConfigureTrigger(trigger)
			}(t)
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

// handleConfigureTrigger verwerkt een configure action (syslog, PNP, show, VLAN).
func (s *Scheduler) handleConfigureTrigger(t api.Trigger) {
	if s.config == nil {
		_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "no config loaded")
		return
	}

	// Decrypt SSH credentials from the trigger
	var creds switches.Credentials
	if t.SSHCredentialsEncrypted != nil {
		var err error
		creds, err = switches.DecryptCredentials(s.SecretKey, *t.SSHCredentialsEncrypted)
		if err != nil {
			slog.Error("decrypt configure credentials failed", "err", err)
			s.pushStep(t.ScanID, nil, "error", fmt.Sprintf("Credentials decryptie mislukt: %s", err), "error")
			_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "credential decryption failed")
			return
		}
	} else {
		// Fallback: use credentials from config (for run_show_command)
		if len(s.config.Switches) > 0 {
			var err error
			creds, err = switches.DecryptCredentials(s.SecretKey, s.config.Switches[0].SSHCredentialsEncrypted)
			if err != nil {
				_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "no credentials available")
				return
			}
		}
	}

	// Find target switches
	switchMap := make(map[int]api.SwitchConfig)
	for _, sw := range s.config.Switches {
		switchMap[sw.ID] = sw
	}

	var targets []api.SwitchConfig
	for _, id := range t.SwitchIDs {
		if sw, ok := switchMap[id]; ok {
			targets = append(targets, sw)
		}
	}

	if len(targets) == 0 {
		slog.Error("no valid target switches found", "ids", t.SwitchIDs)
		_ = s.Client.AckTrigger(t.ScanID, t.Type, "failure", "no valid target switches")
		return
	}

	placeholderID := targets[0].ID
	s.pushStep(t.ScanID, &placeholderID, "configure_start",
		fmt.Sprintf("Configuratie gestart: %s op %d switch(es)", t.Action, len(targets)),
		"running")

	progress := func(step api.ScanProgressStep) {
		swID := 0
		if step.SwitchID != nil {
			swID = *step.SwitchID
		}
		go func() {
			if err := s.Client.IngestScanProgress(swID, "", []api.ScanProgressStep{step}); err != nil {
				slog.Warn("configure progress push failed", "err", err)
			}
		}()
	}

	// Execute on each switch (sequentially for write safety)
	var successes, failures int
	var failedNames []string

	for _, sw := range targets {
		// Acquire SSH semaphore
		s.scanSem <- struct{}{}

		result := switches.ExecuteConfigureAction(t.Action, sw, creds, t.Params, t.ScanID, progress)

		<-s.scanSem

		if result.Success {
			successes++
		} else {
			failures++
			failedNames = append(failedNames, sw.Name)
		}
	}

	// Summary
	var ackResult, ackError string
	if failures == 0 {
		ackResult = "success"
		s.pushStep(t.ScanID, &placeholderID, "configure_complete",
			fmt.Sprintf("Configuratie voltooid: %d/%d switches geslaagd", successes, len(targets)),
			"done")
	} else if successes == 0 {
		ackResult = "failure"
		ackError = fmt.Sprintf("Alle %d switches mislukt: %s", failures, strings.Join(failedNames, ", "))
		s.pushStep(t.ScanID, &placeholderID, "configure_complete", ackError, "error")
	} else {
		ackResult = "success"
		ackError = fmt.Sprintf("%d OK, %d mislukt (%s)", successes, failures, strings.Join(failedNames, ", "))
		s.pushStep(t.ScanID, &placeholderID, "configure_complete",
			fmt.Sprintf("Configuratie deels geslaagd: %s", ackError), "warning")
	}

	if err := s.Client.AckTrigger(t.ScanID, t.Type, ackResult, ackError); err != nil {
		slog.Error("configure ack failed", "err", err)
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

	var macLookup switches.MACLookup
	if s.sonicwallPoller != nil {
		macLookup = s.sonicwallPoller.LookupMAC
	}

	result, err := switches.ScanSwitch(sw, creds, scanID, progress, macLookup)
	if err != nil {
		return err
	}

	if err := s.Client.IngestNetwork(result); err != nil {
		return err
	}
	return nil
}
