package cmd

import "testing"

func TestIsPort25Blocked(t *testing.T) {
	tests := []struct {
		name   string
		errStr string
		want   bool
	}{
		// Should detect as blocked
		{"timeout", "dial tcp 142.250.115.27:25: i/o timeout", true},
		{"connection refused", "dial tcp 142.250.115.27:25: connect: connection refused", true},
		{"connection timed out", "dial tcp 142.250.115.27:25: connect: connection timed out", true},
		{"network unreachable", "dial tcp 142.250.115.27:25: connect: network is unreachable", true},
		{"no route", "dial tcp 142.250.115.27:25: connect: no route to host", true},
		{"operation timed out", "dial tcp: operation timed out", true},
		{"context deadline", "context deadline exceeded", true},

		// Should NOT detect as blocked (real TLS/protocol errors)
		{"starttls not advertised", "smtp: server does not advertise STARTTLS", false},
		{"tls handshake", "tls handshake after STARTTLS: remote error: tls: handshake failure", false},
		{"unexpected greeting", "smtp: unexpected greeting: 554 No SMTP service here", false},
		{"cert error", "x509: certificate signed by unknown authority", false},
		{"eof", "EOF", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPort25Blocked(tt.errStr)
			if got != tt.want {
				t.Errorf("isPort25Blocked(%q) = %v, want %v", tt.errStr, got, tt.want)
			}
		})
	}
}

func TestSummarizeConnError(t *testing.T) {
	tests := []struct {
		errStr string
		want   string
	}{
		{"dial tcp 142.250.115.27:25: i/o timeout", "timeout"},
		{"dial tcp 142.250.115.27:25: connect: connection timed out", "timeout"},
		{"context deadline exceeded", "timeout"},
		{"dial tcp 142.250.115.27:25: connect: connection refused", "refused"},
		{"dial tcp 142.250.115.27:25: connect: network is unreachable", "unreachable"},
		{"dial tcp 142.250.115.27:25: connect: no route to host", "unreachable"},
		{"some other error", "connection failed"},
	}

	for _, tt := range tests {
		t.Run(tt.errStr, func(t *testing.T) {
			got := summarizeConnError(tt.errStr)
			if got != tt.want {
				t.Errorf("summarizeConnError(%q) = %q, want %q", tt.errStr, got, tt.want)
			}
		})
	}
}
