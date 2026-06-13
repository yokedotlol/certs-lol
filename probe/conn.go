package probe

import "crypto/tls"

// scanConn abstracts a TLS connection for the scanner.
// Both *tls.Conn (stdlib) and uTLS connections implement this.
type scanConn interface {
	Close() error
	StdConnectionState() tls.ConnectionState
}

// stdConn wraps *tls.Conn to implement scanConn.
type stdConn struct {
	*tls.Conn
}

func (c *stdConn) StdConnectionState() tls.ConnectionState {
	return c.Conn.ConnectionState()
}
