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

// ArpWakePorts zijn poorten die we parallel TCP-connecten om het OS te
// dwingen ARP te doen naar het target IP. Het maakt niet uit of de poort
// open of dicht is — de SYN moet weg, en dat kan alleen als het MAC bekend
// is, dus het OS stuurt een ARP-request. Na de sweep staat het IP→MAC in
// de ARP tabel en lezen we die uit.
//
// Uitgebreid genoeg om ~elk device te triggeren: Windows (135/139/445/3389),
// Linux/server (22/80/443), printers (9100/631/80), IoT (23/80/443/554).
var ArpWakePorts = []int{22, 23, 80, 135, 139, 443, 445, 554, 631, 3389, 8080, 9100}

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

// DiscoverHosts doet een betrouwbare discovery in 3 fases:
//  1. Parallelle TCP connect op een set bekende poorten per host (triggert
//     ARP in het OS, ongeacht of de poort open is of timeout geeft).
//  2. Parallelle ICMP ping als aanvulling (zie hosts die wel pingbaar maar
//     geen open poort hebben, zeldzaam maar gratis).
//  3. Lees `arp -a` en filter op IPs uit dit subnet — dat is de ground truth.
//
// Resultaat: set van IPs die bewezen bestaan EN met hun vers opgehaalde MAC.
// Hosts zonder MAC in de ARP tabel (gateway-routed of niet geantwoord) komen
// er niet in.
func DiscoverHosts(ctx context.Context, ips []string, progress func(done, total int)) map[string]string {
	// Fase 1+2 parallel per host
	const concurrency = 100
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var done int
	var mu sync.Mutex

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// TCP wake eerst (triggert ARP). ICMP erna (goedkoop).
			tcpWake(ctx, ip)
			pingOne(ctx, ip)
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

	// Fase 3: lees ARP tabel; alleen IPs uit ons subnet-set behouden
	ipSet := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ipSet[ip] = true
	}
	out := make(map[string]string)
	arp := ArpTable(ctx)
	for ip, mac := range arp {
		if ipSet[ip] {
			out[ip] = mac
		}
	}
	return out
}

// tcpWake opent parallel TCP connects naar de wake-poorten. We gooien alle
// errors weg — het enige doel is dat het OS een ARP-request verstuurt.
func tcpWake(ctx context.Context, ip string) {
	var wg sync.WaitGroup
	for _, port := range ArpWakePorts {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: 300 * time.Millisecond}
			c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
			if err == nil {
				_ = c.Close()
			}
		}()
	}
	wg.Wait()
}

// pingOne voert 1 ICMP ping uit via de OS ping cmd.
func pingOne(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "600", ip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	s := strings.ToLower(string(out))
	return strings.Contains(s, "reply from") || strings.Contains(s, "bytes from")
}
