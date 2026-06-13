// Package enrich provides TLS enrichment data: HSTS, DNS security
// (DNSSEC, CAA, DANE), HTTP/3 detection, and compliance mapping.
// All checks use public APIs (Cloudflare DoH, hstspreload.org) —
// no authentication required.
package enrich

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Result holds all enrichment data for a target.
type Result struct {
	HSTS        HSTSInfo        `json:"hsts"`
	HTTP3       HTTP3Info       `json:"http3"`
	DNSSecurity DNSSecurityInfo `json:"dns_security"`
	Compliance  []ComplianceResult `json:"compliance"`
}

// HSTSInfo describes the Strict-Transport-Security configuration.
type HSTSInfo struct {
	Enabled           bool  `json:"enabled"`
	MaxAge            *int  `json:"max_age"`
	IncludeSubdomains bool  `json:"include_subdomains"`
	Preload           bool  `json:"preload"`
	OnPreloadList     bool  `json:"on_preload_list"`
}

// HTTP3Info describes HTTP/2 and HTTP/3 support.
type HTTP3Info struct {
	Supported bool    `json:"supported"`
	HTTP2     bool    `json:"http2"`
	AltSvc    *string `json:"alt_svc"`
}

// DNSSecurityInfo describes DNSSEC, CAA, and DANE/TLSA records.
type DNSSecurityInfo struct {
	DNSSEC   bool     `json:"dnssec"`
	CAA      []string `json:"caa"`
	DANETLSA *string  `json:"dane_tlsa"`
}

// Options configures enrichment.
type Options struct {
	// Port for HSTS and HTTP/3 checks. Default 443.
	Port int
	// TimeoutSec for each enrichment call. Default 8.
	TimeoutSec int
	// UserAgent for HTTP requests.
	UserAgent string
}

// DefaultOptions returns enrichment options with sensible defaults.
func DefaultOptions() Options {
	return Options{
		Port:       443,
		TimeoutSec: 8,
		UserAgent:  "certs/1.0 (TLS scanner; https://certs.lol)",
	}
}

// Enrich performs all enrichment checks for a domain in parallel.
// For IP targets, only DNS security checks run (HSTS/HTTP3 need a hostname).
func Enrich(domain string, opts Options) Result {
	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.TimeoutSec == 0 {
		opts.TimeoutSec = 8
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "certs/1.0 (TLS scanner; https://certs.lol)"
	}

	timeout := time.Duration(opts.TimeoutSec) * time.Second

	type hstsResult struct{ v HSTSInfo }
	type http3Result struct{ v HTTP3Info }
	type dnsResult struct{ v DNSSecurityInfo }

	hstsCh := make(chan hstsResult, 1)
	http3Ch := make(chan http3Result, 1)
	dnsCh := make(chan dnsResult, 1)

	go func() {
		hstsCh <- hstsResult{fetchHSTS(domain, opts.Port, timeout, opts.UserAgent)}
	}()
	go func() {
		http3Ch <- http3Result{fetchHTTP3(domain, opts.Port, timeout, opts.UserAgent)}
	}()
	go func() {
		dnsCh <- dnsResult{fetchDNSSecurity(domain, opts.Port, timeout)}
	}()

	hsts := (<-hstsCh).v
	http3 := (<-http3Ch).v
	dns := (<-dnsCh).v

	return Result{
		HSTS:        hsts,
		HTTP3:       http3,
		DNSSecurity: dns,
	}
}

// ─── HSTS ───────────────────────────────────────────────────────────

func fetchHSTS(domain string, port int, timeout time.Duration, ua string) HSTSInfo {
	def := HSTSInfo{}

	target := fmt.Sprintf("https://%s", domain)
	if port != 443 {
		target = fmt.Sprintf("https://%s:%d", domain, port)
	}

	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("HEAD", target, nil)
	if err != nil {
		return def
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return def
	}
	defer resp.Body.Close()

	hstsHeader := resp.Header.Get("Strict-Transport-Security")
	if hstsHeader == "" {
		return def
	}

	result := HSTSInfo{Enabled: true}

	// Parse max-age
	for _, part := range strings.Split(hstsHeader, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			if v, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(part), "max-age=")); err == nil {
				result.MaxAge = &v
			}
		}
		if strings.EqualFold(part, "includeSubDomains") {
			result.IncludeSubdomains = true
		}
		if strings.EqualFold(part, "preload") {
			result.Preload = true
		}
	}

	// Check preload list
	result.OnPreloadList = checkPreloadList(domain, timeout)

	return result
}

func checkPreloadList(domain string, timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(fmt.Sprintf("https://hstspreload.org/api/v2/status?domain=%s", url.QueryEscape(domain)))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	var data struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false
	}
	return data.Status == "preloaded"
}

// ─── HTTP/3 ─────────────────────────────────────────────────────────

func fetchHTTP3(domain string, port int, timeout time.Duration, ua string) HTTP3Info {
	target := fmt.Sprintf("https://%s", domain)
	if port != 443 {
		target = fmt.Sprintf("https://%s:%d", domain, port)
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("HEAD", target, nil)
	if err != nil {
		return HTTP3Info{}
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return HTTP3Info{}
	}
	defer resp.Body.Close()

	http2 := resp.ProtoMajor == 2
	altSvc := resp.Header.Get("Alt-Svc")

	result := HTTP3Info{HTTP2: http2}
	if altSvc != "" {
		result.AltSvc = &altSvc
		if strings.Contains(altSvc, "h3=") || strings.Contains(altSvc, "h3-") {
			result.Supported = true
		}
	}

	return result
}

// ─── DNS Security (DNSSEC, CAA, DANE via Cloudflare DoH) ────────────

func fetchDNSSecurity(domain string, port int, timeout time.Duration) DNSSecurityInfo {
	type dnssecResult struct{ v bool }
	type caaResult struct{ v []string }
	type daneResult struct{ v *string }

	dnssecCh := make(chan dnssecResult, 1)
	caaCh := make(chan caaResult, 1)
	daneCh := make(chan daneResult, 1)

	go func() { dnssecCh <- dnssecResult{checkDNSSEC(domain, timeout)} }()
	go func() { caaCh <- caaResult{checkCAA(domain, timeout)} }()
	go func() {
		tlsaName := fmt.Sprintf("_%d._tcp.%s", port, domain)
		daneCh <- daneResult{checkDANE(tlsaName, timeout)}
	}()

	return DNSSecurityInfo{
		DNSSEC:   (<-dnssecCh).v,
		CAA:      (<-caaCh).v,
		DANETLSA: (<-daneCh).v,
	}
}

func checkDNSSEC(domain string, timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=A&do=true", url.QueryEscape(domain)), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}

	var data struct {
		AD bool `json:"AD"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false
	}
	return data.AD
}

func checkCAA(domain string, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=CAA", url.QueryEscape(domain)), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	var data struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	var records []string
	for _, a := range data.Answer {
		if a.Type == 257 {
			if parsed := parseCAAData(a.Data); parsed != "" {
				records = append(records, parsed)
			}
		}
	}
	return records
}

// parseCAAData handles both presentation format and wire format from DoH.
func parseCAAData(raw string) string {
	if raw == "" {
		return ""
	}

	// Presentation format: 0 issue "digicert.com"
	parts := strings.SplitN(raw, " ", 3)
	if len(parts) == 3 {
		if _, err := strconv.Atoi(parts[0]); err == nil {
			value := strings.Trim(parts[2], "\"")
			return parts[1] + " " + value
		}
	}

	// Wire format: \# NN HH HH ...
	if strings.HasPrefix(raw, "\\#") {
		wireStr := strings.TrimSpace(raw[strings.Index(raw, " ")+1:])
		// Skip the length field
		parts := strings.Fields(wireStr)
		if len(parts) < 2 {
			return raw
		}
		hexStr := strings.Join(parts[1:], "")
		bytes := make([]byte, 0, len(hexStr)/2)
		for i := 0; i+1 < len(hexStr); i += 2 {
			b, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
			if err != nil {
				return raw
			}
			bytes = append(bytes, byte(b))
		}
		if len(bytes) < 2 {
			return raw
		}
		tagLen := int(bytes[1])
		if len(bytes) < 2+tagLen {
			return raw
		}
		tag := string(bytes[2 : 2+tagLen])
		value := string(bytes[2+tagLen:])
		return tag + " " + value
	}

	return raw
}

func checkDANE(tlsaName string, timeout time.Duration) *string {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=TLSA", url.QueryEscape(tlsaName)), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != 200 {
		return nil
	}

	var data struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	var tlsa []string
	for _, a := range data.Answer {
		if a.Type == 52 {
			tlsa = append(tlsa, a.Data)
		}
	}
	if len(tlsa) == 0 {
		return nil
	}

	result := strings.Join(tlsa, "; ")
	return &result
}
