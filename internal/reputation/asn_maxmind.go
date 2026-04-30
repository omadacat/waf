//go:build maxmind

package reputation

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// ASNLookup resolves IP addresses to ASNs using a MaxMind GeoLite2-ASN
// or GeoIP2-ASN MMDB file.
type ASNLookup struct {
	db *maxminddb.Reader
}

// NewASNLookup opens the MMDB at dbPath. If dbPath is empty, returns a
// no-op lookup (same behaviour as the stub build).
func NewASNLookup(dbPath string) (*ASNLookup, error) {
	if dbPath == "" {
		return &ASNLookup{}, nil
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &ASNLookup{db: db}, nil
}

// Lookup returns the ASN for ip, or 0 on any error or if no DB is loaded.
func (a *ASNLookup) Lookup(ipStr string) uint32 {
	if a.db == nil {
		return 0
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	var record struct {
		AutonomousSystemNumber uint32 `maxminddb:"autonomous_system_number"`
	}
	if err := a.db.Lookup(ip, &record); err != nil {
		return 0
	}
	return record.AutonomousSystemNumber
}

// Close releases the MMDB file handle.
func (a *ASNLookup) Close() {
	if a.db != nil {
		a.db.Close()
	}
}
