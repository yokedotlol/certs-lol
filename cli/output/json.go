package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/yokedotlol/certs-lol/cli/assert"
	"github.com/yokedotlol/certs-lol/enrich"
	"github.com/yokedotlol/certs-lol/probe"
)

// JSONOutput is the top-level JSON structure for a single scan.
type JSONOutput struct {
	Target         string             `json:"target"`
	Grade          string             `json:"grade"`
	Issuer         string             `json:"issuer"`
	Subject        string             `json:"subject"`
	ValidFrom      string             `json:"valid_from"`
	ValidTo        string             `json:"valid_to"`
	DaysRemaining  int                `json:"days_remaining"`
	KeyAlg         string             `json:"key_alg"`
	KeySize        int                `json:"key_size"`
	Protocols      []string           `json:"protocols"`
	ChainDepth     int                `json:"chain_depth"`
	ChainValid     bool               `json:"chain_valid"`
	ChainCerts     []probe.ChainCert  `json:"chain_certs,omitempty"`
	SANs           []string           `json:"sans"`
	Serial         string             `json:"serial"`
	Fingerprint    string             `json:"fingerprint"`
	Ciphers        []probe.CipherInfo `json:"ciphers"`
	OCSPStapling   bool               `json:"ocsp_stapling"`
	SCTCount       int                `json:"sct_count"`
	HasSCTs        bool               `json:"has_scts"`
	ForwardSecrecy bool               `json:"forward_secrecy"`
	KeyExchange    string             `json:"key_exchange"`
	SignatureAlg   string             `json:"signature_alg"`

	// X.509 extension fields
	CertType       string   `json:"cert_type"`
	ExtKeyUsage    []string `json:"ext_key_usage,omitempty"`
	KeyUsage       []string `json:"key_usage,omitempty"`
	OCSPMustStaple bool     `json:"ocsp_must_staple"`
	OCSPServers    []string `json:"ocsp_servers,omitempty"`
	IssuingCertURL []string `json:"issuing_cert_url,omitempty"`
	CRLEndpoints   []string `json:"crl_endpoints,omitempty"`
	IsCA           bool     `json:"is_ca"`
	PolicyOIDs     []string `json:"policy_oids,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`

	// STARTTLS fields
	StartTLS      bool   `json:"starttls"`
	StartTLSProto string `json:"starttls_proto,omitempty"`
	MXHost        string `json:"mx_host,omitempty"`
	MXPriority    int    `json:"mx_priority,omitempty"`

	Error      *string         `json:"error"`
	Enrichment *enrich.Result  `json:"enrichment,omitempty"`
	Assertions *assert.Results `json:"assertions,omitempty"`
	Meta       JSONMeta        `json:"_meta"`
}

// JSONMeta holds metadata about the scan.
type JSONMeta struct {
	Source    string `json:"source"`
	Version  string `json:"version"`
	ProbeMs  int    `json:"probe_ms"`
	Timestamp string `json:"timestamp"`
}

// JSON writes machine-readable JSON output.
func JSON(w io.Writer, target string, result probe.SSLResult, enrichResult *enrich.Result, assertions *assert.Results, version string) error {
	out := JSONOutput{
		Target:         target,
		Grade:          result.Grade,
		Issuer:         result.Issuer,
		Subject:        result.Subject,
		ValidFrom:      result.ValidFrom,
		ValidTo:        result.ValidTo,
		DaysRemaining:  result.DaysRemaining,
		KeyAlg:         result.KeyAlg,
		KeySize:        result.KeySize,
		Protocols:      result.Protocols,
		ChainDepth:     result.ChainDepth,
		ChainValid:     result.ChainValid,
		ChainCerts:     result.ChainCerts,
		SANs:           result.SANs,
		Serial:         result.Serial,
		Fingerprint:    result.Fingerprint,
		Ciphers:        result.Ciphers,
		OCSPStapling:   result.OCSPStapling,
		SCTCount:       result.SCTCount,
		HasSCTs:        result.HasSCTs,
		ForwardSecrecy: result.ForwardSecrecy,
		KeyExchange:    result.KeyExchange,
		SignatureAlg:   result.SignatureAlg,
		CertType:       result.CertType,
		ExtKeyUsage:    result.ExtKeyUsage,
		KeyUsage:       result.KeyUsage,
		OCSPMustStaple: result.OCSPMustStaple,
		OCSPServers:    result.OCSPServers,
		IssuingCertURL: result.IssuingCertURL,
		CRLEndpoints:   result.CRLEndpoints,
		IsCA:           result.IsCA,
		PolicyOIDs:     result.PolicyOIDs,
		IPAddresses:    result.IPAddresses,
		StartTLS:       result.StartTLS,
		StartTLSProto:  result.StartTLSProto,
		MXHost:         result.MXHost,
		MXPriority:     result.MXPriority,
		Error:          result.Error,
		Enrichment:     enrichResult,
		Assertions:     assertions,
		Meta: JSONMeta{
			Source:    "cli",
			Version:  version,
			ProbeMs:  result.ProbeMs,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("json encode: %w", err)
	}
	return nil
}
