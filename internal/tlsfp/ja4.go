package tlsfp

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// JA4 computes the JA4 TLS fingerprint for a parsed ClientHello.
//
// JA4 format:
//
//	[proto][version][d/i][cipher_count][ext_count][alpn]_[cipher_hash]_[ext_hash]
//
//	proto        = "t" (TLS) — QUIC ("q") and DTLS ("d") not implemented here
//	version      = two-digit TLS version (13, 12, 11, 10)
//	d/i          = "d" if SNI present (domain), "i" if absent (IP / unknown)
//	cipher_count = zero-padded count of cipher suites (GREASE excluded), max 99
//	ext_count    = zero-padded count of extensions   (GREASE excluded), max 99
//	alpn         = first 2 chars of first ALPN value, or "00" if none
//	cipher_hash  = SHA-256[:12] of comma-separated sorted cipher decimal values
//	ext_hash     = SHA-256[:12] of sorted ext decimals (ex SNI, ALPN) + "_" +
//	               sorted signature-algorithm decimals
//
// Sorting ciphers and extensions before hashing makes JA4 immune to the
// order-randomisation attacks that defeated JA3.
func JA4(h *Hello) string {
	a := ja4a(h)
	b := ja4b(h)
	c := ja4c(h)
	return a + "_" + b + "_" + c
}

// JA4Raw returns the JA4_r variant: the raw (unsorted, unhashed) string,
// useful for debugging and building custom blocklists.
func JA4Raw(h *Hello) string {
	var b strings.Builder

	// Part A (same as JA4)
	b.WriteString(ja4a(h))
	b.WriteByte('_')

	// Part B raw: ciphers in wire order, comma-separated decimal
	for i, c := range h.CipherSuites {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", c)
	}
	b.WriteByte('_')

	// Part C raw: extensions in wire order (ex SNI, ALPN), then sig algs
	first := true
	for _, e := range h.Extensions {
		if e == extSNI || e == extALPN {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", e)
		first = false
	}
	b.WriteByte('_')
	for i, s := range h.SignatureAlgorithms {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", s)
	}

	return b.String()
}

// HashRaw is a convenience wrapper: parse + JA4 in one call.
// Returns ("", err) on parse failure.
func HashRaw(data []byte) (string, error) {
	h, err := ParseClientHello(data)
	if err != nil {
		return "", err
	}
	return JA4(h), nil
}

// ── JA4 components ────────────────────────────────────────────────────────────

// ja4a builds the undelimited first component:
// proto + tls_version + sni_flag + cipher_count + ext_count + alpn_prefix
func ja4a(h *Hello) string {
	ver := tlsVersionString(h.MaxSupportedVersion())
	sni := "i"
	if h.SNIPresent {
		sni = "d"
	}
	cc := len(h.CipherSuites)
	if cc > 99 {
		cc = 99
	}
	ec := len(h.Extensions)
	if ec > 99 {
		ec = 99
	}
	alpn := alpnPrefix(h.FirstALPN)
	return fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, cc, ec, alpn)
}

// ja4b hashes sorted cipher suites.
func ja4b(h *Hello) string {
	sorted := make([]uint16, len(h.CipherSuites))
	copy(sorted, h.CipherSuites)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var b strings.Builder
	for i, c := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", c)
	}
	return sha256Prefix(b.String())
}

// ja4c hashes sorted extensions (excluding SNI and ALPN) + "_" + sorted sig algs.
func ja4c(h *Hello) string {
	// Collect extensions, excluding SNI (0x0000) and ALPN (0x0010).
	var exts []uint16
	for _, e := range h.Extensions {
		if e != extSNI && e != extALPN {
			exts = append(exts, e)
		}
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })

	// Signature algorithms, sorted.
	sigs := make([]uint16, len(h.SignatureAlgorithms))
	copy(sigs, h.SignatureAlgorithms)
	sort.Slice(sigs, func(i, j int) bool { return sigs[i] < sigs[j] })

	var b strings.Builder
	for i, e := range exts {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", e)
	}
	b.WriteByte('_')
	for i, s := range sigs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", s)
	}
	return sha256Prefix(b.String())
}

// ── helpers ───────────────────────────────────────────────────────────────────

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

// alpnPrefix returns the first two characters of the ALPN value, padded with
// "0" if shorter, or "00" if empty. This matches the JA4 spec.
func alpnPrefix(alpn string) string {
	switch len(alpn) {
	case 0:
		return "00"
	case 1:
		return string(alpn[0]) + "0"
	default:
		return alpn[:2]
	}
}

// sha256Prefix returns the first 12 hex characters of the SHA-256 hash of s.
func sha256Prefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}

// KnownBadFingerprints maps JA4 fingerprints to descriptive labels.
//
// Unlike JA3, JA4 hashes are stable across minor library updates because
// they sort before hashing.  This list is intentionally conservative — only
// fingerprints with high confidence are included.
//
// Operators should build their own list from observed traffic and add entries
// via the tls_fingerprint.blocklist_file config option.  The ja4db project
// (https://github.com/FoxIO-LLC/ja4) publishes a community database.
var KnownBadFingerprints = map[string]string{
	// ── Python ────────────────────────────────────────────────────────────
	// python-requests 2.x / urllib3 — very common scraper stack
	"t13d1516h2_002f,0035,009c": "python-requests",  // illustrative; verify from traffic

	// ── curl / libcurl ────────────────────────────────────────────────────
	// curl with OpenSSL backend
	"t13d2009h2_aebd44fc6246": "curl-openssl",

	// ── Go standard library ───────────────────────────────────────────────
	"t13d0900_00": "go-http-client",

	// ── Headless Chrome / Puppeteer ───────────────────────────────────────
	// Headless Chrome omits many extensions that real Chrome sends.
	// Populate from your own traffic; headless fingerprints vary by version.

	// ── Note ──────────────────────────────────────────────────────────────
	// The above entries are illustrative starting points. Real JA4 values
	// depend on the exact TLS library version and configuration. Use the
	// ja4db community database or capture traffic from known bots to build
	// an accurate production blocklist.
}
