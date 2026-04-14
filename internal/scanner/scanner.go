// Package scanner implementeert subnet discovery met een betrouwbare
// "TCP wake + ARP read" aanpak (zelfde techniek als nmap -Pn): we triggeren
// ARP resolutie per host door parallel TCP te connecten op bekende poorten,
// lezen daarna de ARP tabel en beschouwen alleen IPs met een verse MAC als
// live. Dit voorkomt false positives (oude ARP cache, gateway-artefacten)
// die een pure `arp -a` read gaf.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

type ProgressFn func(step, detail, status string)

type RunResult struct {
	HostsScanned int
	HostsFound   int
	Devices      []api.ScannerDevice
}

// Run voert een volledige scan uit op subnet.
// scanType = "quick" (wake + ARP, ~20s/24) of "full" (+ port scan + DNS, ~90s/24).
func Run(ctx context.Context, subnet, scanType string, progress ProgressFn) (*RunResult, error) {
	emit := func(step, detail, status string) {
		if progress != nil {
			progress(step, detail, status)
		}
		slog.Info("scanner progress", "step", step, "detail", detail, "status", status)
	}

	emit("expand", fmt.Sprintf("Subnet %s uitklappen...", subnet), "running")
	ips, err := CIDRHosts(subnet)
	if err != nil {
		emit("expand", err.Error(), "error")
		return nil, err
	}
	emit("expand", fmt.Sprintf("%d hosts te testen", len(ips)), "done")

	emit("discover", "TCP wake + ARP resolve...", "running")
	t0 := time.Now()
	ipToMAC := DiscoverHosts(ctx, ips, func(done, total int) {
		emit("discover", fmt.Sprintf("%d/%d hosts getest", done, total), "running")
	})
	emit("discover", fmt.Sprintf("%d hosts gevonden in %s", len(ipToMAC), time.Since(t0).Round(time.Second)), "done")

	result := &RunResult{
		HostsScanned: len(ips),
		HostsFound:   len(ipToMAC),
	}

	full := scanType == "full"

	// Per host: enrich met vendor (altijd) + DNS + ports (alleen full)
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	i := 0
	for ip, mac := range ipToMAC {
		select {
		case <-ctx.Done():
			wg.Wait()
			return result, ctx.Err()
		default:
		}
		ip := ip
		mac := mac
		i++
		idx := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			dev := api.ScannerDevice{
				IPAddress:  ip,
				MACAddress: mac,
				Vendor:     OUILookup(mac),
			}
			if full {
				dev.Hostname = ReverseDNS(ctx, ip)
				dev.OpenPorts = ScanPorts(ctx, ip)
			}
			mu.Lock()
			result.Devices = append(result.Devices, dev)
			mu.Unlock()
			if idx%10 == 0 {
				emit("enrich", fmt.Sprintf("%d/%d hosts verrijkt", idx, len(ipToMAC)), "running")
			}
		}()
	}
	wg.Wait()
	emit("enrich", fmt.Sprintf("%d hosts verrijkt", len(result.Devices)), "done")
	emit("complete", fmt.Sprintf("Scan klaar: %d/%d hosts gevonden", result.HostsFound, result.HostsScanned), "done")
	return result, nil
}
