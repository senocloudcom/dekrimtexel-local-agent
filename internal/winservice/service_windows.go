//go:build windows

// Package winservice registreert en runt de agent als native Windows service
// via de golang.org/x/sys/windows/svc API. Geen externe dependency (NSSM,
// WinSW) nodig — 1 binary doet zowel foreground run als service entry point.
package winservice

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	ServiceName        = "DekrimLocalAgent"
	ServiceDisplayName = "Dekrim Local Agent"
	ServiceDescription = "Ping monitoring agent — switch scans, syslog listener, SonicWall polling, ping & scanner"
)

// Install registreert de service bij de Windows SCM. Moet als admin draaien.
// De service start automatisch bij boot en wordt herstart na 5s bij een crash.
func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w (admin vereist?)", err)
	}
	defer m.Disconnect()

	// Bestaat al? Dan niet opnieuw aanmaken.
	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %q bestaat al — eerst 'uninstall' draaien", ServiceName)
	}

	s, err = m.CreateService(ServiceName, exe, mgr.Config{
		DisplayName:  ServiceDisplayName,
		Description:  ServiceDescription,
		StartType:    mgr.StartAutomatic,
		ServiceType:  svc.ServiceType(0x10), // SERVICE_WIN32_OWN_PROCESS
		ErrorControl: mgr.ErrorNormal,
	}, "service")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Recovery: restart 5s na crash, 3 keer binnen 24u, daarna stoppen
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, uint32(86400)); err != nil {
		// Niet fataal; de service werkt wel, alleen zonder auto-restart bij crash
		slog.Warn("set recovery actions failed", "err", err)
	}

	return nil
}

// Uninstall verwijdert de service. Draai deze nadat je de service hebt
// gestopt (anders blijft hij pending-delete tot reboot).
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w (admin vereist?)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service %q: %w (bestaat hij wel?)", ServiceName, err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}

// Runner is de functie die de scheduler loop runt. Moet blokkeren tot ctx
// geannuleerd is en dan schoon returnen.
type Runner func(ctx context.Context) error

// Run is het entry point voor de SCM — wordt aangeroepen wanneer de service
// start. Verbindt de SCM control handler met een context die de runner
// cancelt bij Stop/Shutdown.
func Run(runner Runner) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("determine if running as service: %w", err)
	}
	if !isSvc {
		return fmt.Errorf("not running as Windows service — gebruik 'run' voor foreground mode")
	}
	return svc.Run(ServiceName, &handler{runner: runner})
}

type handler struct {
	runner Runner
}

func (h *handler) Execute(_ []string, changeReq <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- h.runner(ctx)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepts}
	slog.Info("service running")

	for {
		select {
		case req := <-changeReq:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				slog.Info("service stop requested")
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// Wacht op graceful shutdown, max 25 sec
				select {
				case err := <-runErr:
					if err != nil && err != context.Canceled {
						slog.Error("runner exited with error", "err", err)
					}
				case <-time.After(25 * time.Second):
					slog.Warn("runner did not exit within 25s, forcing stop")
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-runErr:
			// Runner exited vóór een stop-signaal — rapporteer als service-stop
			if err != nil && err != context.Canceled {
				slog.Error("runner exited unexpectedly", "err", err)
				status <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}
