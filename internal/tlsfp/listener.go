package tlsfp

import (
	"io"
	"net"
	"sync"
	"time"
)

// Listener wraps a net.Listener.  For each accepted connection it peeks
// at the first bytes, attempts to parse a TLS ClientHello, and stores the
// resulting JA4 fingerprint keyed by the connection's remote address string.
//
// The underlying connection is unaffected: all peeked bytes are replayed
// to crypto/tls transparently via a peekConn.
//
// When the WAF sits behind nginx and nginx terminates TLS, this listener
// is never activated — use the X-JA4-Hash header path instead (see
// middleware/ja3.go for the middleware side).  Activate this listener when the WAF should
// terminate TLS directly:
//
//	l, err := tls.Listen("tcp", addr, tlsCfg)
//	tlsfpL := tlsfp.NewListener(l)
//	srv.Serve(ja3l)
//
// Nginx configuration for the header path (requires a JA4-capable nginx
// module, e.g. nginx-ssl-ja4, or an OpenResty Lua implementation):
//
//	# In the server block that proxies to the WAF:
//	proxy_set_header X-JA4-Hash $ssl_ja4_hash;  # nginx-ssl-ja4 module
//
// Without that module, use the Lua alternative:
//
//	# lua_package_path "/usr/local/share/lua/5.1/?.lua;;";
//	# access_by_lua_block {
//	#     local ja4 = require("ja4")
//	#     ngx.req.set_header("X-JA4-Hash", ja4.hash())
//	# }
//
// The middleware reads whichever of the two sources is available and falls
// back gracefully when neither is present.
type Listener struct {
	net.Listener
	mu     sync.Mutex
	hashes map[string]string // remote addr → JA4 fingerprint
}

// NewListener wraps inner.  inner may already be a tls.Listener — in that
// case native JA4 peeking is impossible (TLS is handled internally by
// crypto/tls before our Read() is ever called).  Pass the raw TCP listener
// and apply TLS afterwards via tls.Server for native mode.
func NewListener(inner net.Listener) *Listener {
	return &Listener{
		Listener: inner,
		hashes:   make(map[string]string),
	}
}

// Accept wraps the inner Accept, peeks the first 4 KB of each connection,
// and attempts to compute a JA4 fingerprint.  If parsing fails (non-TLS
// connection, truncated record, etc.) the connection is still served
// normally — the fingerprint simply won't be available for that request.
func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Peek with a short deadline so we don't block indefinitely on a
	// client that connects but sends nothing.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{}) // clear deadline

	peeked := buf[:n]

	if n > 0 {
		if hash, parseErr := HashRaw(peeked); parseErr == nil {
			l.mu.Lock()
			l.hashes[conn.RemoteAddr().String()] = hash
			l.mu.Unlock()
		}
	}

	// If Read returned an error AND yielded no bytes, the connection is
	// unusable; surface the error so the caller can handle it.
	if readErr != nil && n == 0 {
		_ = conn.Close()
		return nil, readErr
	}

	return &peekConn{
		Conn:    conn,
		pending: peeked,
	}, nil
}

// Get returns the JA4 fingerprint for the given remote address (as returned by
// r.RemoteAddr or conn.RemoteAddr().String()).  The second return value
// is false when no hash was recorded.
func (l *Listener) Get(remoteAddr string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h, ok := l.hashes[remoteAddr]
	return h, ok
}

// Delete removes the stored hash for remoteAddr.  Call this from
// middleware after consuming the hash to keep the map from growing.
func (l *Listener) Delete(remoteAddr string) {
	l.mu.Lock()
	delete(l.hashes, remoteAddr)
	l.mu.Unlock()
}

// ── peekConn ─────────────────────────────────────────────────────────────────

// peekConn replays the bytes that were already read during the ClientHello
// peek before delegating further reads to the underlying connection.
type peekConn struct {
	net.Conn
	pending []byte
}

func (c *peekConn) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		return c.Conn.Read(b)
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	// If all pending bytes fit in b, read any remainder from the real conn
	// to fill b completely only if the caller is still hungry.
	// Do NOT do an extra real read here: return what we have; the caller
	// will call Read again if it needs more. This matches io.Reader contract.
	return n, nil
}

// WriteTo is implemented so that io.Copy fast-paths work correctly even
// though we have buffered bytes.
func (c *peekConn) WriteTo(w io.Writer) (int64, error) {
	var total int64
	if len(c.pending) > 0 {
		n, err := w.Write(c.pending)
		total += int64(n)
		c.pending = c.pending[n:]
		if err != nil {
			return total, err
		}
	}
	// Delegate remaining data directly; avoid an extra interface conversion
	// that would bypass the underlying conn's own WriteTo optimisation.
	if wt, ok := c.Conn.(io.WriterTo); ok {
		n, err := wt.WriteTo(w)
		return total + n, err
	}
	n, err := io.Copy(w, c.Conn)
	return total + n, err
}
