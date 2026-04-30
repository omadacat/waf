package tlsfp

import (
	"io"
	"net"
	"sync"
	"time"
)

type Listener struct {
	net.Listener
	mu     sync.Mutex
	hashes map[string]string // remote addr → JA4 fingerprint
}

func NewListener(inner net.Listener) *Listener {
	return &Listener{
		Listener: inner,
		hashes:   make(map[string]string),
	}
}

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
