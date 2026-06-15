// Package probe provides the core TLS scanning engine shared by
// the certs CLI and the yoke-probe HTTP proxy.
package probe

// SSLResult holds the complete TLS scan output for a single target.
type SSLResult struct {
	Grade          string      `json:"grade"`
	Issuer         string      `json:"issuer"`
	Subject        string      `json:"subject"`
	ValidFrom      string      `json:"valid_from"`
	ValidTo        string      `json:"valid_to"`
	DaysRemaining  int         `json:"days_remaining"`
	KeyAlg         string      `json:"key_alg"`
	KeySize        int         `json:"key_size"`
	Protocols      []string    `json:"protocols"`
	ChainDepth     int         `json:"chain_depth"`
	ChainValid     bool        `json:"chain_valid"`
	ChainCerts     []ChainCert `json:"chain_certs,omitempty"`
	SANs           []string    `json:"sans"`
	Serial         string      `json:"serial"`
	Fingerprint    string      `json:"fingerprint"`
	ProbeMs        int         `json:"probe_ms"`
	Error          *string     `json:"error"`
	Ciphers        []CipherInfo `json:"ciphers"`
	OCSPStapling   bool        `json:"ocsp_stapling"`
	SCTCount       int         `json:"sct_count"`
	HasSCTs        bool        `json:"has_scts"`
	ForwardSecrecy bool        `json:"forward_secrecy"`
	KeyExchange    string      `json:"key_exchange"`
	SignatureAlg   string      `json:"signature_alg"`

	// X.509 extension fields
	CertType       string   `json:"cert_type"`                    // "DV", "OV", "EV"
	ExtKeyUsage    []string `json:"ext_key_usage,omitempty"`      // ["serverAuth", "clientAuth", ...]
	KeyUsage       []string `json:"key_usage,omitempty"`          // ["digitalSignature", "keyEncipherment", ...]
	OCSPMustStaple bool     `json:"ocsp_must_staple"`
	OCSPServers    []string `json:"ocsp_servers,omitempty"`
	IssuingCertURL []string `json:"issuing_cert_url,omitempty"`
	CRLEndpoints   []string `json:"crl_endpoints,omitempty"`
	IsCA           bool     `json:"is_ca"`
	PolicyOIDs     []string `json:"policy_oids,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`       // IP SANs

	// STARTTLS fields
	StartTLS      bool   `json:"starttls"`
	StartTLSProto string `json:"starttls_proto,omitempty"`

	// FallbackPort is set when --mx fell back from port 25 to another port.
	FallbackPort int `json:"fallback_port,omitempty"`
	MXHost        string `json:"mx_host,omitempty"`
	MXPriority    int    `json:"mx_priority,omitempty"`
}

// CipherInfo describes a single cipher suite and its strength.
type CipherInfo struct {
	Name     string `json:"name"`
	ID       uint16 `json:"id"`
	Strength string `json:"strength"` // "strong", "acceptable", "weak", "insecure"
}

// ChainCert describes a single certificate in the chain.
type ChainCert struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	ValidFrom    string   `json:"valid_from"`
	ValidTo      string   `json:"valid_to"`
	KeyAlg       string   `json:"key_alg"`
	KeySize      int      `json:"key_size"`
	Serial       string   `json:"serial"`
	SANs         []string `json:"sans,omitempty"`
	IsSelfSigned bool     `json:"is_self_signed"`
	SignatureAlg string   `json:"signature_alg"`
}

// Options configures a TLS probe.
type Options struct {
	// AllowPrivate permits connections to RFC1918 and other reserved IPs.
	// Default false (SSRF protection on). CLI sets true by default.
	AllowPrivate bool

	// Port to connect on. Default 443.
	Port int

	// TimeoutSec per-connection timeout. Default 8.
	TimeoutSec int

	// StartTLSProto forces a specific STARTTLS protocol.
	// Empty = direct TLS. "smtp", "imap", "pop3" trigger negotiation.
	StartTLSProto string

	// SkipCipherEnum skips per-cipher probing (faster, less detail).
	SkipCipherEnum bool

	// Verbose, if non-nil, is called with diagnostic messages about
	// the connection process (DNS resolution, each dial attempt, fallback).
	Verbose func(string)
}

// DefaultOptions returns probe options suitable for the hosted API
// (SSRF protection on, port 443).
func DefaultOptions() Options {
	return Options{
		AllowPrivate: false,
		Port:         443,
		TimeoutSec:   8,
	}
}

// CLIOptions returns probe options suitable for CLI use
// (private IPs allowed, port 443).
func CLIOptions() Options {
	return Options{
		AllowPrivate: true,
		Port:         443,
		TimeoutSec:   8,
	}
}
