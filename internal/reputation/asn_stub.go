//go:build !maxmind

package reputation

// ASNLookup resolves an IP address to its Autonomous System Number.
// This stub always returns 0 (unknown). Build with -tags maxmind and
// provide a GeoLite2-ASN.mmdb path to enable real ASN lookup.
//
// Download GeoLite2-ASN from:
//   https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
//
// Build with MaxMind support:
//   go build -tags maxmind ./...
//
// The maxmind build requires:
//   go get github.com/oschwald/maxminddb-golang
type ASNLookup struct{}

// NewASNLookup returns a no-op ASN lookup. dbPath is ignored in stub mode.
func NewASNLookup(dbPath string) (*ASNLookup, error) {
	return &ASNLookup{}, nil
}

// Lookup always returns 0 in stub mode.
func (a *ASNLookup) Lookup(ip string) uint32 { return 0 }

// Close is a no-op in stub mode.
func (a *ASNLookup) Close() {}
