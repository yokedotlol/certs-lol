package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// DetectProtocol returns the STARTTLS protocol implied by a port number.
// Returns "" for direct TLS ports (443, 465, 993, 995) and unknown ports.
func DetectProtocol(port int) string {
	switch port {
	case 25, 587:
		return "smtp"
	case 143:
		return "imap"
	case 110:
		return "pop3"
	default:
		return ""
	}
}

// DialSTARTTLS negotiates STARTTLS on a plaintext connection, then upgrades to TLS.
func DialSTARTTLS(addr, serverName, proto string, timeout time.Duration) (*tls.Conn, error) {
	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
	}
	return dialSTARTTLSWithConfig(addr, serverName, proto, timeout, tlsConf)
}

// dialSTARTTLSInsecure is like DialSTARTTLS but skips certificate verification.
func dialSTARTTLSInsecure(addr, serverName, proto string, timeout time.Duration) (*tls.Conn, error) {
	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}
	return dialSTARTTLSWithConfig(addr, serverName, proto, timeout, tlsConf)
}

// dialSTARTTLSWithConfig does the plaintext negotiation then upgrades with the given TLS config.
func dialSTARTTLSWithConfig(addr, serverName, proto string, timeout time.Duration, tlsConf *tls.Config) (*tls.Conn, error) {
	// Connect plaintext
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp connect: %w", err)
	}

	// Set deadline for the entire STARTTLS negotiation
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	reader := bufio.NewReader(conn)

	switch proto {
	case "smtp":
		err = negotiateSMTP(conn, reader, serverName)
	case "imap":
		err = negotiateIMAP(conn, reader)
	case "pop3":
		err = negotiatePOP3(conn, reader)
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported STARTTLS protocol: %s", proto)
	}

	if err != nil {
		conn.Close()
		return nil, err
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls handshake after STARTTLS: %w", err)
	}

	return tlsConn, nil
}

// negotiateSMTP performs SMTP STARTTLS negotiation.
// Flow: read greeting → EHLO → check 250-STARTTLS → STARTTLS → 220
func negotiateSMTP(conn net.Conn, reader *bufio.Reader, serverName string) error {
	// Read greeting (220)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("smtp greeting: %w", err)
	}
	if !strings.HasPrefix(line, "220") {
		return fmt.Errorf("smtp: unexpected greeting: %s", strings.TrimSpace(line))
	}

	// Send EHLO
	ehloHost := serverName
	if ehloHost == "" {
		ehloHost = "probe.certs.lol"
	}
	fmt.Fprintf(conn, "EHLO %s\r\n", ehloHost)

	// Read EHLO response — multi-line (250-)
	hasSTARTTLS := false
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("smtp ehlo response: %w", err)
		}
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			hasSTARTTLS = true
		}
		// Last line is "250 " (space, not dash)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	if !hasSTARTTLS {
		return fmt.Errorf("smtp: server does not advertise STARTTLS")
	}

	// Send STARTTLS
	fmt.Fprintf(conn, "STARTTLS\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("smtp starttls response: %w", err)
	}
	if !strings.HasPrefix(line, "220") {
		return fmt.Errorf("smtp: STARTTLS rejected: %s", strings.TrimSpace(line))
	}

	return nil
}

// negotiateIMAP performs IMAP STARTTLS negotiation.
// Flow: read greeting → CAPABILITY → check STARTTLS → STARTTLS → OK
func negotiateIMAP(conn net.Conn, reader *bufio.Reader) error {
	// Read greeting (* OK)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("imap greeting: %w", err)
	}
	if !strings.HasPrefix(line, "* OK") && !strings.HasPrefix(line, "* PREAUTH") {
		return fmt.Errorf("imap: unexpected greeting: %s", strings.TrimSpace(line))
	}

	// Send CAPABILITY
	fmt.Fprintf(conn, "a001 CAPABILITY\r\n")
	hasSTARTTLS := false
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("imap capability: %w", err)
		}
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			hasSTARTTLS = true
		}
		if strings.HasPrefix(line, "a001 ") {
			break
		}
	}

	if !hasSTARTTLS {
		return fmt.Errorf("imap: server does not advertise STARTTLS")
	}

	// Send STARTTLS
	fmt.Fprintf(conn, "a002 STARTTLS\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("imap starttls response: %w", err)
	}
	if !strings.HasPrefix(line, "a002 OK") {
		return fmt.Errorf("imap: STARTTLS rejected: %s", strings.TrimSpace(line))
	}

	return nil
}

// negotiatePOP3 performs POP3 STARTTLS negotiation.
// Flow: read greeting → STLS → +OK
func negotiatePOP3(conn net.Conn, reader *bufio.Reader) error {
	// Read greeting (+OK)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3 greeting: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("pop3: unexpected greeting: %s", strings.TrimSpace(line))
	}

	// Send STLS
	fmt.Fprintf(conn, "STLS\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("pop3 stls response: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("pop3: STLS rejected: %s", strings.TrimSpace(line))
	}

	return nil
}
