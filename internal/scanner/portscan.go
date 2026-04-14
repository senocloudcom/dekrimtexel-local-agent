package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ScanPorts test een hardcoded lijst poorten op host met parallelle TCP
// connects. Timeout per poort: 500ms. Max 50 concurrent binnen dezelfde host.
func ScanPorts(ctx context.Context, host string) []api.ScannerOpenPort {
	const concurrency = 50
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var out []api.ScannerOpenPort
	var wg sync.WaitGroup

	for _, port := range CommonPorts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return out
		default:
		}
		port := port
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			addr := fmt.Sprintf("%s:%d", host, port)
			c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err != nil {
				return
			}
			_ = c.Close()
			mu.Lock()
			out = append(out, api.ScannerOpenPort{Port: port, Service: ServiceName[port]})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}
