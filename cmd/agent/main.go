// local-agent — Go-based monitoring agent for the Ping platform.
//
// Commands:
//
//	local-agent pair --code <code> --tenant <id> --server <url> [--hostname <name>]
//	local-agent set-secret --key <64-hex-chars>
//	local-agent scan [--switch-id <id>]
//	local-agent run
//	local-agent version
//	local-agent help
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/config"
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/scheduler"
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/switches"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	// Setup logging — write to BOTH stdout (visible when run interactively)
	// AND a file (essential when running as a Windows Scheduled Task / Service
	// where stdout is discarded). Best-effort: if the log file can't be created
	// we still get stdout-only logging.
	var logWriter io.Writer = os.Stdout
	if err := config.EnsureDir(); err == nil {
		if f, err := os.OpenFile(config.LogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			logWriter = io.MultiWriter(os.Stdout, f)
			// Don't close f — it lives for the lifetime of the process
		}
	}
	h := slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(h))

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "pair":
		cmdPair(args)
	case "set-secret":
		cmdSetSecret(args)
	case "scan":
		cmdScan(args)
	case "run":
		cmdRun(args)
	case "version", "-v", "--version":
		fmt.Printf("local-agent %s\n", version)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Print(`local-agent — Ping platform local monitoring agent

Usage:
  local-agent <command> [flags]

Commands:
  pair         Pair with a dashboard using a one-time pairing code
  set-secret   Set the agent secret key (64 hex chars, from dashboard admin UI)
  scan         Run a one-off scan and exit
  run          Run the agent in the foreground (use this or 'install' as service)
  version      Print version
  help         Print this help

Examples:
  local-agent pair --code ABCD-EF12 --tenant dekrim --server https://ping.senocloud.com
  local-agent set-secret --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  local-agent run

Config is stored in:
  Windows: %PROGRAMDATA%\dekrimtexel-agent\config.json
  Linux:   /etc/dekrimtexel-agent/config.json
`)
}

func cmdPair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	code := fs.String("code", "", "pairing code (from dashboard Admin → Agents)")
	tenant := fs.String("tenant", "", "tenant id (e.g. 'dekrim')")
	server := fs.String("server", "", "dashboard URL (e.g. https://ping.senocloud.com)")
	hostname := fs.String("hostname", "", "override hostname (defaults to os.Hostname())")
	fs.Parse(args)

	if *code == "" || *tenant == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "Error: --code, --tenant and --server are required")
		fs.Usage()
		os.Exit(1)
	}

	hn := *hostname
	if hn == "" {
		h, err := os.Hostname()
		if err != nil {
			fmt.Fprintf(os.Stderr, "os.Hostname: %v\n", err)
			os.Exit(1)
		}
		hn = h
	}

	client := api.NewClient(*server, "", "", version)
	fmt.Printf("Pairing with %s (tenant: %s) as %s...\n", *server, *tenant, hn)

	resp, err := client.Pair(*code, hn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pair failed: %v\n", err)
		os.Exit(1)
	}
	if resp.Status != "ok" || resp.APIKey == "" {
		fmt.Fprintf(os.Stderr, "pair failed: %s %s\n", resp.Status, resp.Message)
		os.Exit(1)
	}

	cfg := &config.Config{
		ServerURL: *server,
		TenantID:  resp.TenantID,
		APIKey:    resp.APIKey,
		Hostname:  hn,
		AgentType: resp.AgentType,
	}
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully paired as '%s'\n", hn)
	fmt.Printf("✓ API key saved to %s\n", config.ConfigFile())
	fmt.Println("")
	fmt.Println("⚠ Agent secret key is NOT set yet. Switch SSH credentials cannot be decrypted.")
	fmt.Println("  1. In dashboard: go to Admin → Agents → 'Agent secret key tonen'")
	fmt.Println("  2. Copy the 64-character hex string")
	fmt.Println("  3. Run: local-agent set-secret --key <the-key>")
}

func cmdSetSecret(args []string) {
	fs := flag.NewFlagSet("set-secret", flag.ExitOnError)
	key := fs.String("key", "", "agent secret key (64 hex chars)")
	fs.Parse(args)

	if *key == "" {
		fmt.Fprintln(os.Stderr, "Error: --key is required")
		fs.Usage()
		os.Exit(1)
	}

	if err := config.StoreSecret(*key); err != nil {
		fmt.Fprintf(os.Stderr, "store secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Secret key saved (stored encrypted with OS-level secret store)")
	fmt.Println("✓ Ready to start. Run 'local-agent run' to start the agent.")
}

func cmdRun(_ []string) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	secret, err := config.LoadSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load secret: %v\n", err)
		os.Exit(1)
	}

	client := api.NewClient(cfg.ServerURL, cfg.APIKey, cfg.TenantID, version)
	sched := scheduler.NewScheduler(client, cfg.Hostname, cfg.AgentType, version, secret)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("signal received, shutting down")
		cancel()
	}()

	slog.Info("local-agent starting",
		"version", version,
		"server", cfg.ServerURL,
		"tenant", cfg.TenantID,
		"hostname", cfg.Hostname,
	)

	if err := sched.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "scheduler: %v\n", err)
		os.Exit(1)
	}
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	switchID := fs.String("switch-id", "", "scan only this switch id (optional)")
	fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	secret, err := config.LoadSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load secret: %v\n", err)
		os.Exit(1)
	}

	client := api.NewClient(cfg.ServerURL, cfg.APIKey, cfg.TenantID, version)
	remote, err := client.GetConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch remote config: %v\n", err)
		os.Exit(1)
	}

	targets := remote.Switches
	if *switchID != "" {
		var filtered []api.SwitchConfig
		for _, sw := range targets {
			if strconv.Itoa(sw.ID) == *switchID {
				filtered = append(filtered, sw)
				break
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(os.Stderr, "switch id %s not found\n", *switchID)
			os.Exit(1)
		}
		targets = filtered
	}

	fmt.Printf("Scanning %d switch(es)...\n", len(targets))
	scanID := "manual-" + strconv.FormatInt(int64(os.Getpid()), 10)

	for _, sw := range targets {
		fmt.Printf("\n--- %s (%s) ---\n", sw.Name, sw.Host)
		creds, err := switches.DecryptCredentials(secret, sw.SSHCredentialsEncrypted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  decrypt creds: %v\n", err)
			continue
		}
		result, err := switches.ScanSwitch(sw, creds, scanID, func(step api.ScanProgressStep) {
			fmt.Printf("  [%s] %s\n", step.Step, step.Detail)
		}, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  scan failed: %v\n", err)
			continue
		}
		if err := client.IngestNetwork(result); err != nil {
			fmt.Fprintf(os.Stderr, "  ingest failed: %v\n", err)
			continue
		}
		fmt.Printf("  ✓ %d ports, %d neighbors → sent to dashboard\n", len(result.PortStates), len(result.Topology))
	}
	fmt.Println("\nDone.")
}
