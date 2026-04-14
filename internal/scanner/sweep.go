package scanner

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CIDRHosts retourneert alle host-IPs in een CIDR (excl. network + broadcast).
func CIDRHosts(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr: %w", err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("alleen IPv4 /x ondersteund")
	}
	// Voorzichtig bij grote subnets — limiet op /16
	if ones < 16 {
		return nil, fmt.Errorf("subnet te groot (max /16)")
	}

	var ips []string
	ip := ipnet.IP.Mask(ipnet.Mask)
	for ; ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) <= 2 {
		return ips, nil
	}
	// Strip network + broadcast (eerste + laatste)
	return ips[1 : len(ips)-1], nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// PingSweep verstuurt een ICMP echo naar elke host in ips en retourneert de
// set van responders. Parallel (cap 100) via OS ping cmd.
func PingSweep(ctx context.Context, ips []string, progress func(done, total int)) map[string]bool {
	const concurrency = 100
	responded := make(map[string]bool)
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var done int

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return responded
		default:
		}
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if pingOne(ctx, ip) {
				mu.Lock()
				responded[ip] = true
				mu.Unlock()
			}
			mu.Lock()
			done++
			d := done
			mu.Unlock()
			if progress != nil && d%25 == 0 {
				progress(d, len(ips))
			}
		}()
	}
	wg.Wait()
	if progress != nil {
		progress(len(ips), len(ips))
	}
	return responded
}

// pingOne voert 1 ICMP ping uit via de OS ping cmd. Returns true bij response.
func pingOne(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "800", ip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	s := strings.ToLower(string(out))
	// Windows print "Reply from", Unix print "bytes from" bij succes.
	return strings.Contains(s, "reply from") || strings.Contains(s, "bytes from")
}
