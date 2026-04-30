package reputation

import (
	"fmt"
	"net"
	"strings"
)

// subnetKey returns the canonical /24 (IPv4) or /48 (IPv6) prefix string
// for ip, suitable for use as a map key.
//
// Examples:
//
//	"1.2.3.4"          → "1.2.3.0/24"
//	"2001:db8::1"      → "2001:db8::/48"
//	"::ffff:1.2.3.4"   → "1.2.3.0/24"   (IPv4-mapped unwrapped)
func subnetKey(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	// Unwrap IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if ip.To4() != nil {
		// IPv4: mask to /24
		masked := ip.Mask(net.CIDRMask(24, 32))
		return fmt.Sprintf("%s/24", masked)
	}
	// IPv6: mask to /48
	masked := ip.Mask(net.CIDRMask(48, 128))
	return fmt.Sprintf("%s/48", masked)
}

// asnKey returns a normalised "AS<number>" string for use as a map key.
func asnKey(asn uint32) string {
	return fmt.Sprintf("AS%d", asn)
}

// fpKey returns a prefixed fingerprint key for use as a map key.
func fpKey(fp string) string {
	if fp == "" {
		return ""
	}
	return "fp:" + fp
}

// stripPort removes the port suffix from addr strings like "1.2.3.4:5678"
// or "[::1]:5678". Used when r.RemoteAddr contains a port.
func stripPort(addr string) string {
	if strings.HasPrefix(addr, "[") {
		// IPv6 with port: [::1]:port
		end := strings.LastIndex(addr, "]")
		if end > 0 {
			return addr[1:end]
		}
	}
	if colon := strings.LastIndex(addr, ":"); colon > 0 {
		// Only strip if what remains looks like an IP (has a dot or colon)
		candidate := addr[:colon]
		if strings.ContainsAny(candidate, ".:") {
			return candidate
		}
	}
	return addr
}
