package probe

import (
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// ClassifyCipher returns a strength rating for a TLS cipher suite.
func ClassifyCipher(cs *tls.CipherSuite) string {
	if cs == nil {
		return "unknown"
	}
	name := cs.Name

	// Insecure: RC4, NULL, EXPORT, anonymous
	if strings.Contains(name, "RC4") ||
		strings.Contains(name, "NULL") ||
		strings.Contains(name, "EXPORT") ||
		strings.Contains(name, "anon") {
		return "insecure"
	}

	// TLS 1.3 suites are always strong
	for _, v := range cs.SupportedVersions {
		if v == tls.VersionTLS13 {
			return "strong"
		}
	}

	// ECDHE + AEAD = strong
	if strings.Contains(name, "ECDHE") && (strings.Contains(name, "GCM") || strings.Contains(name, "CHACHA")) {
		return "strong"
	}

	// Weak: 3DES, CBC without FS, RSA key exchange
	if strings.Contains(name, "3DES") || strings.Contains(name, "DES_EDE") {
		return "weak"
	}
	if strings.Contains(name, "CBC") && !strings.Contains(name, "ECDHE") {
		return "weak"
	}
	if strings.HasPrefix(name, "TLS_RSA_WITH_") {
		return "weak"
	}

	return "acceptable"
}

// enumerateCiphers probes a target to discover which cipher suites it supports.
func enumerateCiphers(addr, serverName, startTLSProto string, timeout time.Duration, allowPrivate bool) []CipherInfo {
	var supported []CipherInfo
	cipherTimeout := 5 * time.Second

	// Test TLS 1.3 — server picks the cipher
	if conn13 := dialForCipher(addr, serverName, startTLSProto, cipherTimeout, tls.VersionTLS13, tls.VersionTLS13, nil); conn13 != nil {
		state := conn13.ConnectionState()
		supported = append(supported, CipherInfo{
			Name:     tls.CipherSuiteName(state.CipherSuite),
			ID:       state.CipherSuite,
			Strength: "strong",
		})
		conn13.Close()
	}

	// Test TLS 1.2 ciphers one by one
	allSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, cs := range allSuites {
		tls13Only := true
		for _, v := range cs.SupportedVersions {
			if v != tls.VersionTLS13 {
				tls13Only = false
				break
			}
		}
		if tls13Only {
			continue
		}

		if conn := dialForCipher(addr, serverName, startTLSProto, 3*time.Second, tls.VersionTLS10, tls.VersionTLS12, []uint16{cs.ID}); conn != nil {
			supported = append(supported, CipherInfo{
				Name:     cs.Name,
				ID:       cs.ID,
				Strength: ClassifyCipher(cs),
			})
			conn.Close()
		}
	}

	return supported
}

// dialForCipher connects with specific TLS version and cipher constraints.
func dialForCipher(addr, serverName, startTLSProto string, timeout time.Duration, minVer, maxVer uint16, cipherSuites []uint16) *tls.Conn {
	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         minVer,
		MaxVersion:         maxVer,
		CipherSuites:       cipherSuites,
	}

	if startTLSProto != "" {
		conn, err := dialSTARTTLSWithConfig(addr, serverName, startTLSProto, timeout, tlsConf)
		if err != nil {
			return nil
		}
		return conn
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	if err != nil {
		return nil
	}
	return conn
}
