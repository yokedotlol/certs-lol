package probe

import (
	"fmt"
	"net"
)

// privateRanges lists all CIDR blocks considered private/reserved.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",     // IPv4 loopback
		"10.0.0.0/8",      // RFC1918
		"172.16.0.0/12",   // RFC1918
		"192.168.0.0/16",  // RFC1918
		"169.254.0.0/16",  // link-local
		"224.0.0.0/4",     // multicast
		"0.0.0.0/8",       // unspecified
		"100.64.0.0/10",   // carrier-grade NAT
		"192.0.0.0/24",    // IETF protocol
		"192.0.2.0/24",    // documentation (TEST-NET-1)
		"198.51.100.0/24", // documentation (TEST-NET-2)
		"203.0.113.0/24",  // documentation (TEST-NET-3)
		"198.18.0.0/15",   // benchmarking
		"240.0.0.0/4",     // reserved
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 unique local
		"fe80::/10",       // IPv6 link-local
		"ff00::/8",        // IPv6 multicast
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateRanges = append(privateRanges, network)
		}
	}
}

// IsPrivateIP checks if an IP is in a private or reserved range.
func IsPrivateIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckSSRF resolves a hostname and validates that none of the resulting
// IPs are private. Returns the resolved IPs or an error. When allowPrivate
// is true, the check is skipped.
func CheckSSRF(host string, allowPrivate bool) ([]net.IP, error) {
	// If it's a raw IP, validate directly
	if parsed := net.ParseIP(host); parsed != nil {
		if !allowPrivate && IsPrivateIP(parsed) {
			return nil, fmt.Errorf("connection to private/reserved IP %s blocked (SSRF protection)", parsed)
		}
		return []net.IP{parsed}, nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs resolved for %s", host)
	}

	if !allowPrivate {
		for _, ip := range ips {
			if IsPrivateIP(ip) {
				return nil, fmt.Errorf("connection to private/reserved IP %s blocked (SSRF protection)", ip)
			}
		}
	}

	// Sort IPs: prefer IPv4 over IPv6 for compatibility.
	// Many Go CLI binaries are built with CGO_ENABLED=0, which uses
	// Go's pure-Go resolver that may return IPv6 first. Unlike curl,
	// we don't implement Happy Eyeballs, so prefer the more reliable
	// address family.
	sortIPv4First(ips)

	return ips, nil
}

// sortIPv4First re-orders a slice of IPs so IPv4 addresses come first.
func sortIPv4First(ips []net.IP) {
	j := 0
	for i, ip := range ips {
		if ip.To4() != nil {
			if i != j {
				ips[i], ips[j] = ips[j], ips[i]
			}
			j++
		}
	}
}
