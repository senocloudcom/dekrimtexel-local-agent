// Package scanner implementeert subnet discovery: ICMP ping sweep +
// ARP tabel parse + optioneel TCP port scan + reverse DNS + vendor lookup.
// Resultaten worden per batch naar het dashboard gestuurd.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ProgressFn wordt aangeroepen tijdens de scan om status terug te melden.
// step, detail zijn vrij; status is running|done|error.
type ProgressFn func(step, detail, status string)

// RunResult bevat het eindresultaat van een scan-run.
type RunResult struct {
	HostsScanned int
	HostsFound   int
	Devices      []api.ScannerDevice
}

// Run voert een volledige scan uit op subnet.
// scanType = "quick" (ICMP+ARP, ~30s/24) of "full" (+ port scan + vendor + DNS, ~2m/24).
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

	emit("sweep", "ICMP ping sweep...", "running")
	t0 := time.Now()
	responded := PingSweep(ctx, ips, func(done, total int) {
		emit("sweep", fmt.Sprintf("%d/%d", done, total), "running")
	})
	emit("sweep", fmt.Sprintf("%d/%d responded in %s", len(responded), len(ips), time.Since(t0).Round(time.Second)), "done")

	emit("arp", "ARP tabel inlezen...", "running")
	arp := ArpTable(ctx)
	// Combineer ARP-hits die níét responded hebben (ICMP blocked) alsnog in de set
	for ip := range arp {
		if _, ok := responded[ip]; !ok {
			// Alleen opnemen als binnen de subnet range
			if inSubnet(ip, subnet) {
				responded[ip] = true
			}
		}
	}
	emit("arp", fmt.Sprintf("%d ARP entries (%d hosts totaal)", len(arp), len(responded)), "done")

	result := &RunResult{
		HostsScanned: len(ips),
		HostsFound:   len(responded),
	}

	// Parallel enrich per gevonden host: DNS + port scan (full) + vendor lookup
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	full := scanType == "full"

	i := 0
	for ip := range responded {
		select {
		case <-ctx.Done():
			wg.Wait()
			return result, ctx.Err()
		default:
		}
		ip := ip
		i++
		idx := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			dev := api.ScannerDevice{IPAddress: ip}
			if mac, ok := arp[ip]; ok {
				dev.MACAddress = mac
				dev.Vendor = OUILookup(mac)
			}
			if full {
				dev.Hostname = ReverseDNS(ctx, ip)
				dev.OpenPorts = ScanPorts(ctx, ip)
			}
			mu.Lock()
			result.Devices = append(result.Devices, dev)
			mu.Unlock()
			if idx%10 == 0 {
				emit("enrich", fmt.Sprintf("%d/%d hosts verrijkt", idx, len(responded)), "running")
			}
		}()
	}
	wg.Wait()
	emit("enrich", fmt.Sprintf("%d hosts verrijkt", len(result.Devices)), "done")
	emit("complete", fmt.Sprintf("Scan klaar: %d/%d hosts gevonden", result.HostsFound, result.HostsScanned), "done")
	return result, nil
}

func inSubnet(ip, cidr string) bool {
	ips, err := CIDRHosts(cidr)
	if err != nil {
		return false
	}
	for _, h := range ips {
		if h == ip {
			return true
		}
	}
	return false
}
