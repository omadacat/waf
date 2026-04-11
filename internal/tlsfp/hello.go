// Package tlsfp implements TLS ClientHello fingerprinting using the JA4
// algorithm (John Althouse / FoxIO, 2023).
//
// JA4 supersedes JA3 because it sorts cipher suites and extensions before
// hashing, making order-randomisation attacks ineffective.
//
// Two operational modes are supported:
//
//  1. Header mode (nginx in front): nginx computes the JA4 hash and sets
//     X-JA4-Hash; the middleware reads that header.
//     Nginx config (requires ngx_http_ssl_ja4 or equivalent):
//       proxy_set_header X-JA4-Hash $ssl_ja4_hash;
//
//  2. Native mode (WAF terminates TLS): wrap net.Listener with NewListener;
//     it peeks each raw TCP connection before handing it to crypto/tls,
//     computing the full JA4 hash from the ClientHello bytes.
package tlsfp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// greaseTable lists all GREASE values (RFC 8701) that must be filtered.
var greaseTable = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

const (
	extSNI               = 0x0000
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
	extSupportedGroups   = 0x000a
	extECPointFormats    = 0x000b
	extSigAlgs           = 0x000d
)

// Hello holds all ClientHello fields needed for JA4 computation.
type Hello struct {
	// LegacyVersion is the version field in the ClientHello body.
	// For TLS 1.3 this is always 0x0303 (TLS 1.2 compat); the real
	// negotiated version is in SupportedVersions.
	LegacyVersion uint16

	// SupportedVersions lists versions from the supported_versions extension,
	// GREASE removed.  Empty on TLS ≤ 1.2 clients.
	SupportedVersions []uint16

	// CipherSuites lists offered suites in wire order, GREASE removed.
	CipherSuites []uint16

	// Extensions lists extension type codes in wire order, GREASE removed.
	Extensions []uint16

	// SupportedGroups lists named groups from the supported_groups extension,
	// GREASE removed.
	SupportedGroups []uint16

	// ECPointFormats lists point format codes.
	ECPointFormats []uint8

	// SignatureAlgorithms lists signature schemes from the
	// signature_algorithms extension.
	SignatureAlgorithms []uint16

	// SNIPresent is true when a server_name extension was present.
	SNIPresent bool

	// FirstALPN is the first protocol name from the ALPN extension
	// (e.g. "h2", "http/1.1").  Empty if the extension is absent.
	FirstALPN string
}

// MaxSupportedVersion returns the highest TLS version the client advertised,
// preferring the supported_versions extension over the legacy version field.
func (h *Hello) MaxSupportedVersion() uint16 {
	var max uint16
	for _, v := range h.SupportedVersions {
		if v > max {
			max = v
		}
	}
	if max != 0 {
		return max
	}
	return h.LegacyVersion
}

// ErrNotTLS is returned when data does not start with a TLS handshake record.
var ErrNotTLS = errors.New("tlsfp: not a TLS handshake record")

// reader is a position-tracked byte-slice view that errors instead of panicking.
type reader struct {
	data []byte
	pos  int
}

func (r *reader) remaining() int { return len(r.data) - r.pos }

func (r *reader) read(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, fmt.Errorf("tlsfp: need %d bytes, %d remain", n, r.remaining())
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *reader) uint8() (uint8, error) {
	b, err := r.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) uint16() (uint16, error) {
	b, err := r.read(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *reader) uint24() (uint32, error) {
	b, err := r.read(3)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}

func (r *reader) sub(n int) (*reader, error) {
	b, err := r.read(n)
	if err != nil {
		return nil, err
	}
	return &reader{data: b}, nil
}

// ParseClientHello parses a raw TLS record starting at data[0] and returns
// the fields needed for JA4 computation.
//
// data must begin with the TLS record header (content-type byte 0x16).
// Truncated or malformed records return an error; callers should treat this
// as "unable to fingerprint" rather than fatal.
func ParseClientHello(data []byte) (*Hello, error) {
	r := &reader{data: data}

	// ── TLS record header (5 bytes) ──────────────────────────────────────
	ct, err := r.uint8()
	if err != nil {
		return nil, ErrNotTLS
	}
	if ct != 0x16 {
		return nil, ErrNotTLS
	}
	if _, err = r.read(2); err != nil { // record-layer version (ignored)
		return nil, err
	}
	recLen, err := r.uint16()
	if err != nil {
		return nil, err
	}
	rec, err := r.sub(int(recLen))
	if err != nil {
		return nil, err
	}

	// ── Handshake header (4 bytes) ───────────────────────────────────────
	msgType, err := rec.uint8()
	if err != nil {
		return nil, err
	}
	if msgType != 0x01 {
		return nil, fmt.Errorf("tlsfp: not a ClientHello (type 0x%02x)", msgType)
	}
	hsLen, err := rec.uint24()
	if err != nil {
		return nil, err
	}
	hs, err := rec.sub(int(hsLen))
	if err != nil {
		return nil, err
	}

	// ── ClientHello body ─────────────────────────────────────────────────
	hello := &Hello{}

	hello.LegacyVersion, err = hs.uint16()
	if err != nil {
		return nil, err
	}
	if _, err = hs.read(32); err != nil { // random
		return nil, err
	}
	sidLen, err := hs.uint8() // session_id
	if err != nil {
		return nil, err
	}
	if _, err = hs.read(int(sidLen)); err != nil {
		return nil, err
	}

	// cipher_suites
	csLen, err := hs.uint16()
	if err != nil {
		return nil, err
	}
	csr, err := hs.sub(int(csLen))
	if err != nil {
		return nil, err
	}
	for csr.remaining() >= 2 {
		cs, _ := csr.uint16()
		if !greaseTable[cs] {
			hello.CipherSuites = append(hello.CipherSuites, cs)
		}
	}

	// compression_methods
	cmLen, err := hs.uint8()
	if err != nil {
		return nil, err
	}
	if _, err = hs.read(int(cmLen)); err != nil {
		return nil, err
	}

	// extensions (optional)
	if hs.remaining() < 2 {
		return hello, nil
	}
	extTotalLen, err := hs.uint16()
	if err != nil {
		return nil, err
	}
	extr, err := hs.sub(int(extTotalLen))
	if err != nil {
		return nil, err
	}

	for extr.remaining() >= 4 {
		extType, err := extr.uint16()
		if err != nil {
			break
		}
		extLen, err := extr.uint16()
		if err != nil {
			break
		}
		extData, err := extr.sub(int(extLen))
		if err != nil {
			break
		}

		if !greaseTable[extType] {
			hello.Extensions = append(hello.Extensions, extType)
		}

		switch extType {
		case extSNI:
			hello.SNIPresent = true
			// We only need presence for JA4, not the actual name.

		case extALPN:
			// ALPN: list_length(2) + protocol_length(1) + protocol_bytes
			if extData.remaining() >= 2 {
				listLen, _ := extData.uint16()
				alpnList, _ := extData.sub(int(listLen))
				if alpnList.remaining() >= 1 {
					nameLen, _ := alpnList.uint8()
					if nameBytes, err := alpnList.read(int(nameLen)); err == nil {
						hello.FirstALPN = string(nameBytes)
					}
				}
			}

		case extSupportedVersions:
			if extData.remaining() >= 1 {
				listLen, _ := extData.uint8()
				svr, _ := extData.sub(int(listLen))
				for svr.remaining() >= 2 {
					v, _ := svr.uint16()
					if !greaseTable[v] {
						hello.SupportedVersions = append(hello.SupportedVersions, v)
					}
				}
			}

		case extSupportedGroups:
			if extData.remaining() >= 2 {
				glLen, _ := extData.uint16()
				gr, _ := extData.sub(int(glLen))
				for gr.remaining() >= 2 {
					g, _ := gr.uint16()
					if !greaseTable[g] {
						hello.SupportedGroups = append(hello.SupportedGroups, g)
					}
				}
			}

		case extECPointFormats:
			if extData.remaining() >= 1 {
				pfLen, _ := extData.uint8()
				pfr, _ := extData.sub(int(pfLen))
				for pfr.remaining() >= 1 {
					pf, _ := pfr.uint8()
					hello.ECPointFormats = append(hello.ECPointFormats, pf)
				}
			}

		case extSigAlgs:
			if extData.remaining() >= 2 {
				listLen, _ := extData.uint16()
				sar, _ := extData.sub(int(listLen))
				for sar.remaining() >= 2 {
					sa, _ := sar.uint16()
					if !greaseTable[sa] {
						hello.SignatureAlgorithms = append(hello.SignatureAlgorithms, sa)
					}
				}
			}
		}
	}

	return hello, nil
}
