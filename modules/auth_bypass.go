package modules

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/pkg/http"
)

// AuthBypassModule IIS authentication bypass zafiyetlerini tespit eder
type AuthBypassModule struct {
	*BaseModule
	client         *http.Client
	baseURL        string
	bypassMethods  []AuthBypassMethod
	testEndpoints  []string
}

// AuthBypassMethod authentication bypass metodu
type AuthBypassMethod struct {
	Name        string
	Description string
	Method      string
	Headers     map[string]string
	Payload     string
	CVE         string
	RiskLevel   string
}

// NewAuthBypassModule yeni authentication bypass modülü oluşturur
func NewAuthBypassModule(client *http.Client, baseURL string) *AuthBypassModule {
	module := &AuthBypassModule{
		BaseModule: NewBaseModule("IIS Auth Bypass", "IIS authentication bypass vulnerability detection"),
		client:     client,
		baseURL:    baseURL,
	}
	module.initBypassMethods()
	module.initTestEndpoints()
	return module
}

// initBypassMethods authentication bypass metodlarını başlatır
func (m *AuthBypassModule) initBypassMethods() {
	m.bypassMethods = []AuthBypassMethod{
		// NTLM Authentication Bypass
		{
			Name:        "NTLM Type 1 Message Bypass",
			Description: "NTLM authentication bypass using malformed Type 1 message",
			Method:      "GET",
			Headers: map[string]string{
				"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
			},
			CVE:       "CVE-2008-0015",
			RiskLevel: "HIGH",
		},
		{
			Name:        "NTLM Null Session",
			Description: "NTLM null session authentication bypass",
			Method:      "GET",
			Headers: map[string]string{
				"Authorization": "NTLM TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAA=",
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
		},
		// Kerberos Delegation Attacks
		{
			Name:        "Kerberos Delegation Bypass",
			Description: "Kerberos constrained delegation bypass attempt",
			Method:      "GET",
			Headers: map[string]string{
				"Authorization": "Negotiate YIIBfAYGKwYBBQUCoIIBcDCCAWygJDAiBgkqhkiG9w0BAQUFAKEVMBMGCSqGSIb3DQEBCgQGKoZIhvcNAQ==",
			},
			CVE:       "",
			RiskLevel: "HIGH",
		},
		// Windows Integrated Authentication Flaws
		{
			Name:        "Windows Auth Header Manipulation",
			Description: "Windows Integrated Authentication header manipulation",
			Method:      "GET",
			Headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("\\::")),
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
		},
		{
			Name:        "Domain Bypass Attempt",
			Description: "Domain authentication bypass using UNC paths",
			Method:      "GET",
			Headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("domain\\\\user:")),
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
		},
		// Anonymous Authentication Misconfigurations
		{
			Name:        "Anonymous Auth Override",
			Description: "Anonymous authentication override attempt",
			Method:      "GET",
			Headers: map[string]string{
				"X-Anonymous-User": "true",
				"X-Auth-User":      "anonymous",
			},
			CVE:       "",
			RiskLevel: "LOW",
		},
		// Client Certificate Bypass
		{
			Name:        "Client Certificate Bypass",
			Description: "Client certificate authentication bypass",
			Method:      "GET",
			Headers: map[string]string{
				"X-SSL-Client-Verify": "SUCCESS",
				"X-SSL-Client-DN":     "CN=admin,O=test",
			},
			CVE:       "",
			RiskLevel: "HIGH",
		},
		{
			Name:        "Certificate Header Injection",
			Description: "SSL client certificate header injection",
			Method:      "GET",
			Headers: map[string]string{
				"SSL_CLIENT_CERT": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xODA2MjcwODUwMTJaFw0xOTA2MjcwODUwMTJaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDTwqq/ynVj36WsENXEOvs9yNNXJ9Ob7rMmkPV9+SRhyiGYuJUqmenZdvKGRrmrnl7ZriG38XcMbVtVs8QjGGPzAgMBAAEwDQYJKoZIhvcNAQELBQADQQA9TyPuzjiRl7lwWBBTBBsg9C2sV8CX4orqwquyDkXZJpEVwDBKJDRgqWhqicNdmmpMc+uM61BRuIDjrqAXeM39\n-----END CERTIFICATE-----",
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
		},
		// HTTP Method Bypass
		{
			Name:        "HTTP Method Override",
			Description: "HTTP method override for authentication bypass",
			Method:      "POST",
			Headers: map[string]string{
				"X-HTTP-Method-Override": "GET",
				"X-Original-Method":      "OPTIONS",
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
		},
		// Host Header Injection
		{
			Name:        "Host Header Authentication Bypass",
			Description: "Host header injection for authentication bypass",
			Method:      "GET",
			Headers: map[string]string{
				"Host": "localhost",
				"X-Forwarded-Host": "admin.local",
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
		},
		// IIS Specific Bypasses
		{
			Name:        "IIS ISAPI Filter Bypass",
			Description: "IIS ISAPI filter authentication bypass",
			Method:      "GET",
			Headers: map[string]string{
				"X-ISAPI-Filter": "bypass",
				"X-IIS-Auth":     "disabled",
			},
			CVE:       "",
			RiskLevel: "HIGH",
		},
		{
			Name:        "IIS Application Pool Bypass",
			Description: "IIS application pool identity bypass",
			Method:      "GET",
			Headers: map[string]string{
				"X-AppPool-Identity": "NetworkService",
				"X-Process-User":     "IIS_IUSRS",
			},
			CVE:       "",
			RiskLevel: "HIGH",
		},
	}
}

// initTestEndpoints test edilecek endpoint'leri başlatır
func (m *AuthBypassModule) initTestEndpoints() {
	m.testEndpoints = []string{
		"/admin",
		"/administrator",
		"/management",
		"/secure",
		"/protected",
		"/private",
		"/internal",
		"/config",
		"/settings",
		"/dashboard",
		"/panel",
		"/control",
		"/api/admin",
		"/api/internal",
		"/webadmin",
		"/siteadmin",
		"/systemadmin",
	}
}

// Run authentication bypass taramasını çalıştırır
func (m *AuthBypassModule) Run(client *http.Client) (*ModuleResult, error) {
	m.Start()
	defer m.End()

	var vulnerabilities []Vulnerability
	var info []Information

	// Test each bypass method against protected endpoints
	for _, endpoint := range m.testEndpoints {
		for _, method := range m.bypassMethods {
			vuln := m.testAuthBypass(endpoint, method)
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, *vuln)
			}
			time.Sleep(100 * time.Millisecond) // Rate limiting
		}
	}

	// Test for common authentication misconfigurations
	vulns := m.testAuthMisconfigurations()
	vulnerabilities = append(vulnerabilities, vulns...)

	// Test for default credentials
	vulns = m.testDefaultCredentials()
	vulnerabilities = append(vulnerabilities, vulns...)

	// Add informational findings
	info = append(info, CreateInformation(
		"scan_info",
		"Authentication Bypass Scan Completed",
		fmt.Sprintf("Tested %d bypass methods against %d endpoints", len(m.bypassMethods), len(m.testEndpoints)),
		fmt.Sprintf("%d methods tested", len(m.bypassMethods)),
	))

	status := "completed"
	if len(vulnerabilities) > 0 {
		status = "vulnerabilities_found"
	}

	return m.CreateResult(status, vulnerabilities, info, nil), nil
}

// testAuthBypass belirli bir authentication bypass metodunu test eder
func (m *AuthBypassModule) testAuthBypass(endpoint string, method AuthBypassMethod) *Vulnerability {
	m.IncrementRequests()

	testURL := m.baseURL + endpoint
	
	// First, test without bypass to establish baseline
	baselineResp, err := m.client.Get(testURL)
	if err != nil {
		return nil
	}
	defer baselineResp.Body.Close()

	// If endpoint is not protected, skip
	if baselineResp.StatusCode != 401 && baselineResp.StatusCode != 403 {
		return nil
	}

	// Now test with bypass method
	req, err := http.NewRequest(method.Method, testURL, nil)
	if err != nil {
		return nil
	}

	// Add bypass headers
	for key, value := range method.Headers {
		req.Header.Set(key, value)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if bypass was successful
	if m.isBypassSuccessful(baselineResp.StatusCode, resp.StatusCode) {
		severity := m.getSeverityFromRisk(method.RiskLevel)
		cvss := m.getCVSSFromRisk(method.RiskLevel)

		vulnerability := &Vulnerability{
			ID:          fmt.Sprintf("IIS-AUTH-BYPASS-%s", strings.ToUpper(strings.ReplaceAll(method.Name, " ", "-"))),
			Title:       fmt.Sprintf("Authentication Bypass - %s", method.Name),
			Description: method.Description,
			Severity:    severity,
			CVSS:        cvss,
			CWE:         "CWE-287",
			OWASP:       "A07:2021 – Identification and Authentication Failures",
			URL:         testURL,
			Method:      method.Method,
			Evidence:    fmt.Sprintf("Baseline status: %d, Bypass status: %d", baselineResp.StatusCode, resp.StatusCode),
			References:  []string{
				"https://owasp.org/www-community/attacks/Authentication_bypass",
			},
			Remediation: "Implement proper authentication validation and fix authentication bypass vulnerabilities.",
			Metadata: map[string]string{
				"bypass_method": method.Name,
				"risk_level":    method.RiskLevel,
			},
		}

		if method.CVE != "" {
			vulnerability.References = append(vulnerability.References,
				fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", method.CVE))
		}

		return vulnerability
	}

	return nil
}

// testAuthMisconfigurations authentication yanlış yapılandırmalarını test eder
func (m *AuthBypassModule) testAuthMisconfigurations() []Vulnerability {
	var vulnerabilities []Vulnerability

	misconfigurations := []struct {
		path        string
		description string
		severity    string
	}{
		{
			path:        "/web.config",
			description: "Web.config file accessible - may contain authentication settings",
			severity:    "HIGH",
		},
		{
			path:        "/machine.config",
			description: "Machine.config file accessible - contains system authentication settings",
			severity:    "CRITICAL",
		},
		{
			path:        "/.well-known/security.txt",
			description: "Security.txt file may reveal authentication information",
			severity:    "LOW",
		},
	}

	for _, config := range misconfigurations {
		m.IncrementRequests()

		testURL := m.baseURL + config.path
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "IIS-AUTH-MISCONFIGURATION",
				Title:       "Authentication Configuration Exposure",
				Description: config.description,
				Severity:    config.severity,
				CVSS:        m.getCVSSFromSeverity(config.severity),
				CWE:         "CWE-200",
				OWASP:       "A05:2021 – Security Misconfiguration",
				URL:         testURL,
				Method:      "GET",
				Evidence:    fmt.Sprintf("Configuration file accessible with status %d", resp.StatusCode),
				References: []string{
					"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
				},
				Remediation: "Restrict access to configuration files and implement proper file permissions.",
				Metadata: map[string]string{
					"config_type": config.path,
				},
			})
		}
	}

	return vulnerabilities
}

// testDefaultCredentials varsayılan kimlik bilgilerini test eder
func (m *AuthBypassModule) testDefaultCredentials() []Vulnerability {
	var vulnerabilities []Vulnerability

	defaultCreds := []struct {
		username string
		password string
		service  string
	}{
		{"admin", "admin", "Generic Admin"},
		{"administrator", "administrator", "Windows Administrator"},
		{"admin", "password", "Generic Admin"},
		{"admin", "", "Empty Password Admin"},
		{"guest", "guest", "Guest Account"},
		{"iusr", "", "IIS Anonymous User"},
		{"iwam", "", "IIS WAM User"},
		{"aspnet", "", "ASP.NET User"},
	}

	for _, cred := range defaultCreds {
		m.IncrementRequests()

		// Test against admin endpoints
		for _, endpoint := range []string{"/admin", "/administrator", "/management"} {
			testURL := m.baseURL + endpoint
			
			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}

			// Add basic auth
			auth := base64.StdEncoding.EncodeToString([]byte(cred.username + ":" + cred.password))
			req.Header.Set("Authorization", "Basic "+auth)

			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "IIS-DEFAULT-CREDENTIALS",
					Title:       "Default Credentials Found",
					Description: fmt.Sprintf("Default credentials found for %s service", cred.service),
					Severity:    "CRITICAL",
					CVSS:        9.8,
					CWE:         "CWE-798",
					OWASP:       "A07:2021 – Identification and Authentication Failures",
					URL:         testURL,
					Method:      "GET",
					Payload:     fmt.Sprintf("Username: %s, Password: %s", cred.username, cred.password),
					Evidence:    fmt.Sprintf("Authentication successful with status %d", resp.StatusCode),
					References: []string{
						"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
					},
					Remediation: "Change default credentials immediately and implement strong password policies.",
					Metadata: map[string]string{
						"username": cred.username,
						"service":  cred.service,
					},
				})
			}
		}
	}

	return vulnerabilities
}

// isBypassSuccessful bypass başarısını kontrol eder
func (m *AuthBypassModule) isBypassSuccessful(baselineStatus, bypassStatus int) bool {
	// If baseline was 401/403 and bypass is 200, it's successful
	if (baselineStatus == 401 || baselineStatus == 403) && bypassStatus == 200 {
		return true
	}

	// If baseline was 401/403 and bypass is 302 (redirect), might be successful
	if (baselineStatus == 401 || baselineStatus == 403) && bypassStatus == 302 {
		return true
	}

	// If status code changed significantly, might indicate bypass
	if baselineStatus >= 400 && bypassStatus < 400 {
		return true
	}

	return false
}

// getSeverityFromRisk risk level'dan severity döndürür
func (m *AuthBypassModule) getSeverityFromRisk(riskLevel string) string {
	switch riskLevel {
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// getCVSSFromRisk risk level'dan CVSS skoru döndürür
func (m *AuthBypassModule) getCVSSFromRisk(riskLevel string) float64 {
	switch riskLevel {
	case "HIGH":
		return 8.1
	case "MEDIUM":
		return 6.1
	case "LOW":
		return 4.3
	default:
		return 6.1
	}
}

// getCVSSFromSeverity severity'den CVSS skoru döndürür
func (m *AuthBypassModule) getCVSSFromSeverity(severity string) float64 {
	switch severity {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 7.0
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 3.0
	default:
		return 5.0
	}
}
