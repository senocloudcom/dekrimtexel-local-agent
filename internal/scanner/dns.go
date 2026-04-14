package scanner

import (
	"context"
	"net"
	"strings"
	"time"
)

// ReverseDNS probeert een hostname te vinden voor ip. Stil falen (return "")
// bij timeout of NXDOMAIN.
func ReverseDNS(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	r := net.Resolver{}
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Strip trailing dot en lowercase voor consistentie
	return strings.TrimSuffix(strings.ToLower(names[0]), ".")
}
