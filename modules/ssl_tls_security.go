package modules

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// SSLTLSSecurityModule SSL/TLS security checks module
type SSLTLSSecurityModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewSSLTLSSecurityModule creates new SSL/TLS security module
func NewSSLTLSSecurityModule(cfg *config.Config, log *logger.Logger) Module {
	return &SSLTLSSecurityModule{
		BaseModule: NewBaseModule("ssl_tls_security", "SSL/TLS Security Configuration Scanner"),
		config:     cfg,
		logger:     log,
	}
}

// Run executes SSL/TLS security module
func (s *SSLTLSSecurityModule) Run(client *http.Client) (*ModuleResult, error) {
	s.Start()
	defer s.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := s.config.GetBaseURL()

	// HTTPS check
	if s.config.ParsedURL.Scheme != "https" {
		info = append(info, CreateInformation("ssl_status", "SSL/TLS Status",
			"SSL/TLS kullanımı", "Not Used (HTTP)"))

		// Warning for HTTP usage
		vuln := CreateVulnerability(
			"SSL-TLS-001",
			"Unencrypted HTTP Connection",
			"Site does not use HTTPS, all traffic is unencrypted",
			"HIGH",
			7.4,
		)
		vuln.URL = baseURL
		vuln.Evidence = "HTTP protocol is being used"
		vuln.Remediation = "Switch to HTTPS and redirect HTTP traffic to HTTPS"
		vuln.CWE = "CWE-319"
		vuln.OWASP = "A02:2021 – Cryptographic Failures"
		vulnerabilities = append(vulnerabilities, vuln)

		return s.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
	}

	host := s.config.ParsedURL.Host
	port := s.config.ParsedURL.Port()
	if port == "" {
		port = "443"
	}

	// 1. SSL/TLS Certificate Check
	s.logger.Debug("Performing SSL/TLS certificate checks...")
	certVulns, certInfo := s.checkSSLCertificate(host, port)
	vulnerabilities = append(vulnerabilities, certVulns...)
	info = append(info, certInfo...)

	// 2. SSL/TLS Protocol Versions
	s.logger.Debug("Checking SSL/TLS protocol versions...")
	protocolVulns, protocolInfo := s.checkProtocolVersions(host, port)
	vulnerabilities = append(vulnerabilities, protocolVulns...)
	info = append(info, protocolInfo...)

	// 3. Cipher Suites Check
	s.logger.Debug("Checking cipher suites...")
	cipherVulns, cipherInfo := s.checkCipherSuites(host, port)
	vulnerabilities = append(vulnerabilities, cipherVulns...)
	info = append(info, cipherInfo...)

	// 4. SSL/TLS Security Headers
	s.logger.Debug("Checking SSL/TLS security headers...")
	headerVulns := s.checkSecurityHeaders(client, baseURL)
	vulnerabilities = append(vulnerabilities, headerVulns...)

	// 5. SSL/TLS Renegotiation
	s.logger.Debug("Checking SSL/TLS renegotiation...")
	renegotiationVulns := s.checkRenegotiation(host, port)
	vulnerabilities = append(vulnerabilities, renegotiationVulns...)

	// 6. SNI (Server Name Indication) Check
	s.logger.Debug("Performing SNI checks...")
	sniVulns, sniInfo := s.checkSNI(host, port)
	vulnerabilities = append(vulnerabilities, sniVulns...)
	info = append(info, sniInfo...)

	// 7. Mixed Content Detection
	s.logger.Debug("Checking mixed content...")
	mixedContentVulns := s.checkMixedContent(client, baseURL)
	vulnerabilities = append(vulnerabilities, mixedContentVulns...)

	return s.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// checkSSLCertificate SSL sertifika kontrollerini yapar
func (s *SSLTLSSecurityModule) checkSSLCertificate(host, port string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	// Establish TLS connection
	conn, err := tls.Dial("tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: true, // Skip certificate verification
	})
	if err != nil {
		return vulns, info
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		// Sertifika bilgileri
		info = append(info, CreateInformation("cert_subject", "Certificate Subject",
			"Sertifika subject", cert.Subject.String()))
		info = append(info, CreateInformation("cert_issuer", "Certificate Issuer",
			"Sertifika issuer", cert.Issuer.String()))
		info = append(info, CreateInformation("cert_not_before", "Certificate Valid From",
			"Certificate validity start", cert.NotBefore.Format("2006-01-02 15:04:05")))
		info = append(info, CreateInformation("cert_not_after", "Certificate Valid Until",
			"Certificate validity end", cert.NotAfter.Format("2006-01-02 15:04:05")))

		// Certificate expiry check
		now := time.Now()
		if cert.NotAfter.Before(now) {
			vuln := CreateVulnerability(
				"SSL-TLS-002",
				"Expired SSL Certificate",
				"SSL certificate has expired",
				"HIGH",
				7.4,
			)
			vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
			vuln.Evidence = fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02"))
			vuln.Remediation = "SSL sertifikasını yenileyin"
			vuln.CWE = "CWE-295"
			vuln.OWASP = "A02:2021 – Cryptographic Failures"
			vulns = append(vulns, vuln)
		} else if cert.NotAfter.Before(now.AddDate(0, 0, 30)) {
			// Will expire within 30 days
			vuln := CreateVulnerability(
				"SSL-TLS-003",
				"SSL Certificate Expiring Soon",
				"SSL certificate will expire soon",
				"MEDIUM",
				5.3,
			)
			vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
			vuln.Evidence = fmt.Sprintf("Certificate will expire on %s", cert.NotAfter.Format("2006-01-02"))
			vuln.Remediation = "SSL sertifikasını yenileyin"
			vuln.CWE = "CWE-295"
			vulns = append(vulns, vuln)
		}

		// Self-signed certificate check
		if cert.Issuer.String() == cert.Subject.String() {
			vuln := CreateVulnerability(
				"SSL-TLS-004",
				"Self-Signed SSL Certificate",
				"Self-signed SSL sertifikası kullanılıyor",
				"MEDIUM",
				6.1,
			)
			vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
			vuln.Evidence = "Issuer ve Subject aynı"
			vuln.Remediation = "Obtain certificate from trusted CA"
			vuln.CWE = "CWE-295"
			vuln.OWASP = "A02:2021 – Cryptographic Failures"
			vulns = append(vulns, vuln)
		}

		// Weak signature algorithm check
		sigAlg := cert.SignatureAlgorithm.String()
		info = append(info, CreateInformation("cert_signature_algorithm", "Certificate Signature Algorithm",
			"Sertifika imza algoritması", sigAlg))

		weakAlgorithms := []string{"MD5", "SHA1"}
		for _, weak := range weakAlgorithms {
			if strings.Contains(strings.ToUpper(sigAlg), weak) {
				vuln := CreateVulnerability(
					"SSL-TLS-005",
					"Weak Certificate Signature Algorithm",
					fmt.Sprintf("Zayıf sertifika imza algoritması: %s", sigAlg),
					"MEDIUM",
					5.3,
				)
				vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
				vuln.Evidence = fmt.Sprintf("Signature algorithm: %s", sigAlg)
				vuln.Remediation = "Use SHA-256 or stronger algorithm"
				vuln.CWE = "CWE-327"
				vuln.OWASP = "A02:2021 – Cryptographic Failures"
				vulns = append(vulns, vuln)
				break
			}
		}

		// Key size check
		keySize := 0
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			keySize = pub.N.BitLen()
		case *ecdsa.PublicKey:
			keySize = pub.Curve.Params().BitSize
		}

		if keySize > 0 {
			info = append(info, CreateInformation("cert_key_size", "Certificate Key Size",
				"Sertifika anahtar boyutu", fmt.Sprintf("%d bits", keySize)))

			if keySize < 2048 {
				vuln := CreateVulnerability(
					"SSL-TLS-006",
					"Weak Certificate Key Size",
					fmt.Sprintf("Zayıf sertifika anahtar boyutu: %d bits", keySize),
					"HIGH",
					7.4,
				)
				vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
				vuln.Evidence = fmt.Sprintf("Key size: %d bits", keySize)
				vuln.Remediation = "Use at least 2048-bit RSA or 256-bit ECDSA"
				vuln.CWE = "CWE-326"
				vuln.OWASP = "A02:2021 – Cryptographic Failures"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, info
}

// checkProtocolVersions SSL/TLS protokol versiyonlarını kontrol eder
func (s *SSLTLSSecurityModule) checkProtocolVersions(host, port string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	// Test edilecek protokol versiyonları
	protocols := map[string]uint16{
		"SSLv3":   tls.VersionSSL30,
		"TLS 1.0": tls.VersionTLS10,
		"TLS 1.1": tls.VersionTLS11,
		"TLS 1.2": tls.VersionTLS12,
		"TLS 1.3": tls.VersionTLS13,
	}

	var supportedProtocols []string

	for protocolName, version := range protocols {
		config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
		}

		conn, err := tls.Dial("tcp", host+":"+port, config)
		if err == nil {
			conn.Close()
			supportedProtocols = append(supportedProtocols, protocolName)

			info = append(info, CreateInformation("supported_protocol", "Supported Protocol",
				fmt.Sprintf("Desteklenen protokol: %s", protocolName), protocolName))

			// Vulnerability for old protocols
			if version <= tls.VersionTLS11 {
				severity := "HIGH"
				cvss := 7.4

				if version == tls.VersionSSL30 {
					severity = "CRITICAL"
					cvss = 9.8
				}

				vuln := CreateVulnerability(
					"SSL-TLS-007",
					fmt.Sprintf("Insecure SSL/TLS Protocol: %s", protocolName),
					fmt.Sprintf("Insecure SSL/TLS protocol supported: %s", protocolName),
					severity,
					cvss,
				)
				vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
				vuln.Evidence = fmt.Sprintf("%s protocol is active", protocolName)
				vuln.Remediation = "Use only TLS 1.2 and TLS 1.3"
				vuln.CWE = "CWE-327"
				vuln.OWASP = "A02:2021 – Cryptographic Failures"

				if version == tls.VersionSSL30 {
					vuln.References = []string{"CVE-2014-3566"} // POODLE
				}

				vulns = append(vulns, vuln)
			}
		}
	}

	if len(supportedProtocols) == 0 {
		info = append(info, CreateInformation("supported_protocols", "Supported Protocols",
			"Desteklenen protokoller", "None detected"))
	}

	return vulns, info
}

// checkCipherSuites cipher suites kontrollerini yapar
func (s *SSLTLSSecurityModule) checkCipherSuites(host, port string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	// Establish TLS connection
	conn, err := tls.Dial("tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return vulns, info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)

	info = append(info, CreateInformation("cipher_suite", "Negotiated Cipher Suite",
		"Negotiate edilen cipher suite", cipherSuite))

	// Weak cipher suite check
	weakCiphers := []string{
		"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ADH", "AECDH",
	}

	upperCipher := strings.ToUpper(cipherSuite)
	for _, weak := range weakCiphers {
		if strings.Contains(upperCipher, weak) {
			vuln := CreateVulnerability(
				"SSL-TLS-008",
				"Weak Cipher Suite",
				fmt.Sprintf("Zayıf cipher suite kullanılıyor: %s", cipherSuite),
				"HIGH",
				7.4,
			)
			vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
			vuln.Evidence = fmt.Sprintf("Cipher suite: %s", cipherSuite)
			vuln.Remediation = "Use strong cipher suites (AES-GCM, ChaCha20-Poly1305)"
			vuln.CWE = "CWE-327"
			vuln.OWASP = "A02:2021 – Cryptographic Failures"
			vulns = append(vulns, vuln)
			break
		}
	}

	return vulns, info
}

// checkSecurityHeaders checks SSL/TLS security headers
func (s *SSLTLSSecurityModule) checkSecurityHeaders(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns
	}
	s.IncrementRequests()

	// HSTS (HTTP Strict Transport Security) check
	hstsHeader := resp.GetHeader("Strict-Transport-Security")
	if hstsHeader == "" {
		vuln := CreateVulnerability(
			"SSL-TLS-009",
			"Missing HSTS Header",
			"HTTP Strict Transport Security (HSTS) header eksik",
			"MEDIUM",
			6.1,
		)
		vuln.URL = baseURL
		vuln.Evidence = "Strict-Transport-Security header bulunamadı"
		vuln.Remediation = "HSTS header'ını ekleyin: Strict-Transport-Security: max-age=31536000; includeSubDomains"
		vuln.CWE = "CWE-319"
		vuln.OWASP = "A05:2021 – Security Misconfiguration"
		vulns = append(vulns, vuln)
	} else {
		// HSTS configuration check
		if !strings.Contains(hstsHeader, "includeSubDomains") {
			vuln := CreateVulnerability(
				"SSL-TLS-010",
				"HSTS Missing includeSubDomains",
				"HSTS header'ında includeSubDomains direktifi eksik",
				"LOW",
				3.1,
			)
			vuln.URL = baseURL
			vuln.Evidence = hstsHeader
			vuln.Remediation = "HSTS header'ına includeSubDomains ekleyin"
			vuln.CWE = "CWE-319"
			vulns = append(vulns, vuln)
		}

		if !strings.Contains(hstsHeader, "preload") {
			vuln := CreateVulnerability(
				"SSL-TLS-011",
				"HSTS Missing preload",
				"HSTS header'ında preload direktifi eksik",
				"LOW",
				2.6,
			)
			vuln.URL = baseURL
			vuln.Evidence = hstsHeader
			vuln.Remediation = "HSTS header'ına preload ekleyin"
			vuln.CWE = "CWE-319"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkRenegotiation SSL/TLS renegotiation kontrollerini yapar
func (s *SSLTLSSecurityModule) checkRenegotiation(host, port string) []Vulnerability {
	var vulns []Vulnerability

	// Renegotiation testi (basit implementasyon)
	config := &tls.Config{
		InsecureSkipVerify: true,
		Renegotiation:      tls.RenegotiateOnceAsClient,
	}

	conn, err := tls.Dial("tcp", host+":"+port, config)
	if err != nil {
		return vulns
	}
	defer conn.Close()

	// Renegotiation denemesi
	err = conn.Handshake()
	if err == nil {
		// If renegotiation is possible, it could be a vulnerability
		vuln := CreateVulnerability(
			"SSL-TLS-012",
			"SSL/TLS Renegotiation Enabled",
			"SSL/TLS renegotiation active - may be vulnerable to DoS attacks",
			"MEDIUM",
			5.3,
		)
		vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
		vuln.Evidence = "TLS renegotiation is possible"
		vuln.Remediation = "Disable TLS renegotiation"
		vuln.CWE = "CWE-400"
		vuln.OWASP = "A06:2021 – Vulnerable and Outdated Components"
		vuln.References = []string{"CVE-2009-3555"}
		vulns = append(vulns, vuln)
	}

	return vulns
}

// checkSNI SNI (Server Name Indication) kontrollerini yapar
func (s *SSLTLSSecurityModule) checkSNI(host, port string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	// Connection with SNI
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	conn, err := tls.Dial("tcp", host+":"+port, config)
	if err == nil {
		conn.Close()
		info = append(info, CreateInformation("sni_support", "SNI Support",
			"Server Name Indication support", "Supported"))

		// SNI bypass testi
		configNoSNI := &tls.Config{
			InsecureSkipVerify: true,
			// ServerName belirtme
		}

		connNoSNI, err := tls.Dial("tcp", host+":"+port, configNoSNI)
		if err == nil {
			connNoSNI.Close()

			// If connection can be established without SNI
			vuln := CreateVulnerability(
				"SSL-TLS-013",
				"SNI Bypass Possible",
				"SSL connection can be established without SNI",
				"LOW",
				3.1,
			)
			vuln.URL = fmt.Sprintf("https://%s:%s", host, port)
			vuln.Evidence = "Connection successful without SNI"
			vuln.Remediation = "SNI gereksinimini zorunlu hale getirin"
			vuln.CWE = "CWE-295"
			vulns = append(vulns, vuln)
		}
	} else {
		info = append(info, CreateInformation("sni_support", "SNI Support",
			"Server Name Indication support", "Not Supported"))
	}

	return vulns, info
}

// checkMixedContent mixed content kontrollerini yapar
func (s *SSLTLSSecurityModule) checkMixedContent(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns
	}
	s.IncrementRequests()

	// HTTP resource'ları ara
	httpPatterns := []string{
		`src="http://`,
		`href="http://`,
		`action="http://`,
		`url(http://`,
	}

	lowerBody := strings.ToLower(resp.Body)
	for _, pattern := range httpPatterns {
		if strings.Contains(lowerBody, pattern) {
			vuln := CreateVulnerability(
				"SSL-TLS-014",
				"Mixed Content Detected",
				"HTTPS sayfasında HTTP resource'ları tespit edildi",
				"MEDIUM",
				6.1,
			)
			vuln.URL = baseURL
			vuln.Evidence = fmt.Sprintf("Pattern found: %s", pattern)
			vuln.Remediation = "Convert all resources to HTTPS"
			vuln.CWE = "CWE-319"
			vuln.OWASP = "A02:2021 – Cryptographic Failures"
			vulns = append(vulns, vuln)
			break // Bir tane bulunca yeter
		}
	}

	return vulns
}
