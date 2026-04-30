// Package tlsfp provides TLS fingerprint utilities for the WAF.
//
// Since nginx handles TLS termination, the WAF never sees a raw ClientHello
// and therefore never computes JA4 itself.  The fingerprint arrives as an
// X-JA4-Hash header set by an upstream nginx + OpenResty / Lua JA4 module.
//
// This package's sole runtime role is holding the known-bad fingerprint
// blocklist that the JA3Check middleware checks against.
//
// Nginx setup (requires OpenResty with a Lua JA4 implementation):
//
//	access_by_lua_block {
//	    local ja4 = require("resty.ja4")
//	    ngx.req.set_header("X-JA4-Hash", ja4.fingerprint())
//	}
package tlsfp

// KnownBadFingerprints maps JA4 fingerprints to descriptive labels.
// These are checked by the JA3Check middleware against the X-JA4-Hash
// header set by nginx.
//
// JA4 hashes are stable because they sort ciphers/extensions before hashing,
// making order-randomisation attacks ineffective (unlike JA3).
//
// Extend this list via the ja3.blocklist_file config option or inline
// ja3.blocklist_hashes.  The ja4db project publishes a community database:
//
//	https://github.com/FoxIO-LLC/ja4
var KnownBadFingerprints = map[string]string{
	// ── Python ────────────────────────────────────────────────────────────
	"t13d1516h2_002f,0035,009c_0000": "python-requests",

	// ── curl / libcurl ────────────────────────────────────────────────────
	"t13d2009h2_aebd44fc6246": "curl-openssl",

	// ── Go standard library ───────────────────────────────────────────────
	"t13d0900_00": "go-http-client",

	// ── Note ──────────────────────────────────────────────────────────────
	// The above are illustrative starting points.  Real JA4 values vary by
	// exact TLS library version.  Capture traffic from known bots on your
	// network and add their fingerprints here or in blocklist_file.
}
