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

// fingerprint pairs a display name with a uTLS ClientHelloID.
type fingerprint struct {
	name string
	id   utls.ClientHelloID
}

// browserFingerprints lists the uTLS fingerprints to try, in order.
var browserFingerprints = []fingerprint{
	{"Chrome", utls.HelloChrome_Auto},
	{"Firefox", utls.HelloFirefox_Auto},
	{"Safari", utls.HelloSafari_Auto},
	{"Randomized", utls.HelloRandomized},
}

// dialUTLSWithFingerprints tries multiple browser fingerprints, each
// with verify then insecure, returning on the first success.
func dialUTLSWithFingerprints(addr, serverName string, timeout time.Duration, verbose func(string)) (scanConn, error) {
	var lastErr error
	for _, fp := range browserFingerprints {
		if verbose != nil {
			verbose(fmt.Sprintf("  uTLS %s → %s (verify)", fp.name, addr))
		}
		sc, err := dialUTLS(addr, serverName, timeout, false, fp.id)
		if err == nil {
			if verbose != nil {
				verbose(fmt.Sprintf("  uTLS %s connected ✓", fp.name))
			}
			return sc, nil
		}
		if verbose != nil {
			verbose(fmt.Sprintf("  uTLS %s verify failed: %v", fp.name, err))
		}

		if isEOFLike(err) {
			if verbose != nil {
				verbose(fmt.Sprintf("  uTLS %s → %s (insecure)", fp.name, addr))
			}
			sc, err = dialUTLS(addr, serverName, timeout, true, fp.id)
			if err == nil {
				if verbose != nil {
					verbose(fmt.Sprintf("  uTLS %s insecure connected ✓", fp.name))
				}
				return sc, nil
			}
			if verbose != nil {
				verbose(fmt.Sprintf("  uTLS %s insecure failed: %v", fp.name, err))
			}
		}
		lastErr = err
	}
	return nil, lastErr
}

// dialUTLS connects using a specific uTLS browser fingerprint.
func dialUTLS(addr, serverName string, timeout time.Duration, insecure bool, helloID utls.ClientHelloID) (scanConn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp connect: %w", err)
	}

	// Set deadline so the TLS handshake can't hang forever
	tcpConn.SetDeadline(time.Now().Add(timeout))

	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}

	uc := utls.UClient(tcpConn, config, helloID)
	if err := uc.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	// Clear deadline for subsequent reads
	tcpConn.SetDeadline(time.Time{})

	return &utlsConn{uc}, nil
}
