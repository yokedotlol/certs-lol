package probe

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"
)

// Scan probes a target's TLS configuration and returns a full result.
// Target is a domain name or IP address.
func Scan(target string, opts Options) SSLResult {
	start := time.Now()

	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.TimeoutSec == 0 {
		opts.TimeoutSec = 8
	}
	timeout := time.Duration(opts.TimeoutSec) * time.Second

	// Determine STARTTLS protocol from port if not explicitly set
	proto := opts.StartTLSProto
	if proto == "" {
		proto = DetectProtocol(opts.Port)
	}

	// Resolve and SSRF-check the target
	verbose := opts.Verbose
	ips, err := CheckSSRF(target, opts.AllowPrivate)
	if err != nil {
		elapsed := int(time.Since(start).Milliseconds())
		errStr := err.Error()
		return SSLResult{Grade: "T", ProbeMs: elapsed, Error: &errStr}
	}
	if verbose != nil {
		ipStrs := make([]string, len(ips))
		for i, ip := range ips {
			ipStrs[i] = ip.String()
		}
		verbose(fmt.Sprintf("resolved %s → %s", target, strings.Join(ipStrs, ", ")))
	}

	// Dial TLS (direct or via STARTTLS)
	serverName := target
	if net.ParseIP(target) != nil {
		serverName = "" // IP target — no SNI
	}

	var sc scanConn
	var connState *tls.ConnectionState
	var connectErr error
	var connectedAddr string // the IP:port that actually connected

	port := fmt.Sprintf("%d", opts.Port)

	if proto != "" {
		// STARTTLS: negotiate on plaintext, then upgrade
		// Try each resolved IP until one connects.
		for _, ip := range ips {
			addr := net.JoinHostPort(ip.String(), port)
			var conn *tls.Conn
			conn, connectErr = DialSTARTTLS(addr, serverName, proto, timeout)
			if connectErr != nil {
				conn, connectErr = dialSTARTTLSInsecure(addr, serverName, proto, timeout)
			}
			if conn != nil {
				sc = &stdConn{conn}
				connectedAddr = addr
				break
			}
		}
	} else {
		// Direct TLS — try each resolved IP, with uTLS fallback on EOF.
		for _, ip := range ips {
			addr := net.JoinHostPort(ip.String(), port)
			sc, connectErr = dialWithFallback(addr, serverName, timeout, verbose)
			if connectErr == nil {
				connectedAddr = addr
				break
			}
		}
	}

	if connectErr != nil {
		elapsed := int(time.Since(start).Milliseconds())
		errStr := connectErr.Error()
		return SSLResult{Grade: "T", ProbeMs: elapsed, Error: &errStr}
	}
	defer sc.Close()

	state := sc.StdConnectionState()
	connState = &state

	// Detect supported protocols
	protocols := detectProtocols(connState, connectedAddr, serverName, proto, timeout)

	if len(connState.PeerCertificates) == 0 {
		elapsed := int(time.Since(start).Milliseconds())
		errStr := "no peer certificates returned"
		return SSLResult{Grade: "T", Protocols: protocols, ProbeMs: elapsed, Error: &errStr}
	}

	leaf := connState.PeerCertificates[0]

	// Extract key info
	keyAlg, keySize := extractKeyInfo(leaf)
	fingerprint := fmt.Sprintf("%X", sha256.Sum256(leaf.Raw))

	// Validate chain
	chainValid := validateChain(connState, target, serverName)

	// SANs (limit to 20)
	sans := leaf.DNSNames
	if len(sans) > 20 {
		sans = sans[:20]
	}

	// Days remaining
	daysRemaining := int(math.Floor(time.Until(leaf.NotAfter).Hours() / 24))

	// Serial
	serial := ""
	if leaf.SerialNumber != nil {
		serial = fmt.Sprintf("%X", leaf.SerialNumber)
	}

	// OCSP, SCTs, Forward Secrecy
	ocspStapling := len(connState.OCSPResponse) > 0
	sctCount := len(connState.SignedCertificateTimestamps)
	hasSCTs := sctCount > 0
	forwardSecrecy, keyExchange := extractForwardSecrecy(connState)

	// Cipher enumeration
	var ciphers []CipherInfo
	if !opts.SkipCipherEnum {
		ciphers = enumerateCiphers(connectedAddr, serverName, proto, timeout, opts.AllowPrivate)
	}

	// Full certificate chain
	chainCerts := extractChainCerts(connState, leaf)

	// X.509 extensions
	certType := ExtractCertType(leaf)
	extKeyUsage := ExtractExtKeyUsage(leaf.ExtKeyUsage)
	keyUsage := ExtractKeyUsage(leaf.KeyUsage)
	ocspMustStaple := ExtractOCSPMustStaple(leaf)
	policyOIDs := ExtractPolicyOIDs(leaf.PolicyIdentifiers)
	ipAddresses := ExtractIPAddresses(leaf)

	// Compute grade
	grade := ComputeGrade(connState, leaf, chainValid, protocols, ciphers)

	return SSLResult{
		Grade:          grade,
		Issuer:         leaf.Issuer.String(),
		Subject:        leaf.Subject.String(),
		ValidFrom:      leaf.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:        leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining:  daysRemaining,
		KeyAlg:         keyAlg,
		KeySize:        keySize,
		Fingerprint:    fingerprint,
		Protocols:      protocols,
		ChainDepth:     len(connState.PeerCertificates),
		ChainValid:     chainValid,
		ChainCerts:     chainCerts,
		SANs:           sans,
		Serial:         serial,
		ProbeMs:        int(time.Since(start).Milliseconds()),
		Ciphers:        ciphers,
		OCSPStapling:   ocspStapling,
		SCTCount:       sctCount,
		HasSCTs:        hasSCTs,
		ForwardSecrecy: forwardSecrecy,
		KeyExchange:    keyExchange,
		SignatureAlg:   leaf.SignatureAlgorithm.String(),
		CertType:       certType,
		ExtKeyUsage:    extKeyUsage,
		KeyUsage:       keyUsage,
		OCSPMustStaple: ocspMustStaple,
		OCSPServers:    leaf.OCSPServer,
		IssuingCertURL: leaf.IssuingCertificateURL,
		CRLEndpoints:   leaf.CRLDistributionPoints,
		IsCA:           leaf.IsCA,
		PolicyOIDs:     policyOIDs,
		IPAddresses:    ipAddresses,
		StartTLS:       proto != "",
		StartTLSProto:  proto,
	}
}

// dialTLS connects to addr and performs a TLS handshake.
func dialTLS(addr, serverName string, timeout time.Duration, tlsConf *tls.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	return conn, err
}

// dialWithFallback tries stdlib TLS, then multiple uTLS fingerprints on EOF-like errors.
func dialWithFallback(addr, serverName string, timeout time.Duration, verbose func(string)) (scanConn, error) {
	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	if verbose != nil {
		verbose(fmt.Sprintf("  stdlib TLS → %s (verify)", addr))
	}
	conn, err := dialTLS(addr, serverName, timeout, tlsConf)
	if err != nil {
		if verbose != nil {
			verbose(fmt.Sprintf("  stdlib TLS verify failed: %v", err))
			verbose(fmt.Sprintf("  stdlib TLS → %s (insecure)", addr))
		}
		tlsConf.InsecureSkipVerify = true
		conn, err = dialTLS(addr, serverName, timeout, tlsConf)
	}
	if err != nil && isEOFLike(err) {
		if verbose != nil {
			verbose(fmt.Sprintf("  stdlib TLS insecure failed (EOF-like): %v", err))
			verbose("  falling back to uTLS fingerprints...")
		}
		// Server rejected Go's default ClientHello — try browser fingerprints.
		sc, uErr := dialUTLSWithFingerprints(addr, serverName, timeout, verbose)
		return sc, uErr
	}
	if err != nil {
		if verbose != nil {
			verbose(fmt.Sprintf("  stdlib TLS failed (non-EOF): %v", err))
		}
		return nil, err
	}
	if verbose != nil {
		verbose("  stdlib TLS connected ✓")
	}
	return &stdConn{conn}, nil
}

// detectProtocols determines which TLS versions the target supports.
func detectProtocols(state *tls.ConnectionState, addr, serverName, startTLSProto string, timeout time.Duration) []string {
	protocols := []string{}

	switch state.Version {
	case tls.VersionTLS13:
		protocols = append(protocols, "TLS 1.3")
		// Also test TLS 1.2
		if conn12 := probeVersion(addr, serverName, startTLSProto, timeout, tls.VersionTLS12); conn12 != nil {
			if conn12.ConnectionState().Version == tls.VersionTLS12 {
				protocols = append(protocols, "TLS 1.2")
			}
			conn12.Close()
		}
	case tls.VersionTLS12:
		protocols = append(protocols, "TLS 1.2")
	case tls.VersionTLS11:
		protocols = append(protocols, "TLS 1.1")
	case tls.VersionTLS10:
		protocols = append(protocols, "TLS 1.0")
	}

	return protocols
}

// probeVersion tries to connect with a specific max TLS version.
func probeVersion(addr, serverName, startTLSProto string, timeout time.Duration, maxVersion uint16) *tls.Conn {
	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MaxVersion:         maxVersion,
	}

	if startTLSProto != "" {
		conn, err := dialSTARTTLSWithConfig(addr, serverName, startTLSProto, timeout, tlsConf)
		if err != nil {
			return nil
		}
		return conn
	}

	conn, err := dialTLS(addr, serverName, timeout, tlsConf)
	if err != nil {
		return nil
	}
	return conn
}

// extractKeyInfo returns the algorithm name and key size for a certificate.
func extractKeyInfo(cert *x509.Certificate) (string, int) {
	keyAlg := ""
	keySize := 0

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			if params := pub.Curve.Params(); params != nil && params.BitSize > 0 {
				keySize = params.BitSize
			}
		}
		if keySize == 0 && pub.X != nil {
			switch byteLen := len(pub.X.Bytes()); {
			case byteLen <= 32:
				keySize = 256
			case byteLen <= 48:
				keySize = 384
			default:
				keySize = 521
			}
		}
	case *ed25519.PublicKey:
		keySize = 256
	case interface{ Size() int }:
		keySize = pub.Size() * 8
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyAlg = "RSA"
	case x509.ECDSA:
		keyAlg = "ECDSA"
	case x509.Ed25519:
		keyAlg = "Ed25519"
	default:
		keyAlg = cert.PublicKeyAlgorithm.String()
	}

	return keyAlg, keySize
}

// validateChain checks the certificate chain against the system trust store.
func validateChain(state *tls.ConnectionState, target, serverName string) bool {
	if len(state.PeerCertificates) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]

	dnsName := serverName
	if dnsName == "" {
		dnsName = target
	}

	opts := x509.VerifyOptions{
		DNSName: dnsName,
	}
	if len(state.PeerCertificates) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		opts.Intermediates = intermediates
	}
	_, err := leaf.Verify(opts)
	return err == nil
}

// extractForwardSecrecy checks the negotiated cipher for forward secrecy.
func extractForwardSecrecy(state *tls.ConnectionState) (bool, string) {
	name := tls.CipherSuiteName(state.CipherSuite)
	if state.Version == tls.VersionTLS13 {
		return true, "ECDHE (TLS 1.3)"
	}
	if strings.Contains(name, "ECDHE") {
		return true, "ECDHE"
	}
	if strings.Contains(name, "DHE") && !strings.Contains(name, "ECDHE") {
		return true, "DHE"
	}
	return false, "RSA (no forward secrecy)"
}

// extractChainCerts builds ChainCert entries for every cert in the chain.
func extractChainCerts(state *tls.ConnectionState, leaf *x509.Certificate) []ChainCert {
	certs := make([]ChainCert, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		certKeyAlg, certKeySize := extractKeyInfo(cert)

		certSerial := ""
		if cert.SerialNumber != nil {
			certSerial = fmt.Sprintf("%X", cert.SerialNumber)
		}

		var certSANs []string
		if cert == leaf {
			certSANs = cert.DNSNames
			if len(certSANs) > 20 {
				certSANs = certSANs[:20]
			}
		}

		certs = append(certs, ChainCert{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			ValidFrom:    cert.NotBefore.UTC().Format(time.RFC3339),
			ValidTo:      cert.NotAfter.UTC().Format(time.RFC3339),
			KeyAlg:       certKeyAlg,
			KeySize:      certKeySize,
			Serial:       certSerial,
			SANs:         certSANs,
			IsSelfSigned: cert.Issuer.String() == cert.Subject.String(),
			SignatureAlg: cert.SignatureAlgorithm.String(),
		})
	}
	return certs
}


// isEOFLike returns true when the error looks like the remote server
// dropped the connection during the TLS handshake — a sign that the
// server rejected Go's default ClientHello fingerprint.
func isEOFLike(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "connection refused")
}
