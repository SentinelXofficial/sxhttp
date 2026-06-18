package detect

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

// TLSInfo holds extracted TLS/certificate metadata.
type TLSInfo struct {
	Version string   `json:"version,omitempty"`
	Cipher  string   `json:"cipher,omitempty"`
	Subject string   `json:"subject,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
	Expiry  string   `json:"expiry,omitempty"`
	SANs    []string `json:"sans,omitempty"`
	Expired bool     `json:"expired,omitempty"`
}

var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS1.0",
	tls.VersionTLS11: "TLS1.1",
	tls.VersionTLS12: "TLS1.2",
	tls.VersionTLS13: "TLS1.3",
}

// ExtractTLS pulls TLS metadata from an HTTP response.
// Returns nil if the response is not HTTPS or has no certificate.
func ExtractTLS(resp *http.Response) *TLSInfo {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}

	cert := resp.TLS.PeerCertificates[0]

	version := tlsVersionNames[resp.TLS.Version]
	if version == "" {
		version = "unknown"
	}

	cipher := tls.CipherSuiteName(resp.TLS.CipherSuite)

	subject := cert.Subject.CommonName
	issuer := cert.Issuer.CommonName
	expiry := cert.NotAfter.UTC().Format(time.DateOnly)
	expired := time.Now().After(cert.NotAfter)

	// Collect SANs (dedupe against CN)
	var sans []string
	seen := map[string]bool{strings.ToLower(subject): true}
	for _, san := range cert.DNSNames {
		lower := strings.ToLower(san)
		if !seen[lower] {
			seen[lower] = true
			sans = append(sans, san)
		}
	}

	return &TLSInfo{
		Version: version,
		Cipher:  cipher,
		Subject: subject,
		Issuer:  issuer,
		Expiry:  expiry,
		SANs:    sans,
		Expired: expired,
	}
}
