package probe

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// utlsConn wraps a uTLS UConn to implement scanConn.
type utlsConn struct {
	*utls.UConn
}

// StdConnectionState converts the uTLS ConnectionState to a standard
// crypto/tls ConnectionState. uTLS uses standard crypto/x509 certs,
// so PeerCertificates transfer directly.
func (c *utlsConn) StdConnectionState() tls.ConnectionState {
	us := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     us.Version,
		HandshakeComplete:           us.HandshakeComplete,
		CipherSuite:                 us.CipherSuite,
		NegotiatedProtocol:          us.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  us.NegotiatedProtocolIsMutual,
		ServerName:                  us.ServerName,
		PeerCertificates:            us.PeerCertificates,
		VerifiedChains:              us.VerifiedChains,
		SignedCertificateTimestamps: us.SignedCertificateTimestamps,
		OCSPResponse:                us.OCSPResponse,
	}
}

// dialUTLS connects using a Chrome-mimicking TLS client hello fingerprint.
// This defeats bot-detection systems that reject Go's default fingerprint.
func dialUTLS(addr, serverName string, timeout time.Duration, insecure bool) (scanConn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp connect: %w", err)
	}

	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}

	uc := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
	if err := uc.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	return &utlsConn{uc}, nil
}
