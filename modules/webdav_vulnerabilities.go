package modules

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/pkg/http"
)

// WebDAVModule IIS WebDAV zafiyetlerini tespit eder
type WebDAVModule struct {
	*BaseModule
	client  *http.Client
	baseURL string
	methods []WebDAVMethod
}

// WebDAVMethod WebDAV metodu yapısı
type WebDAVMethod struct {
	Name        string
	Method      string
	Description string
	Payload     string
	Headers     map[string]string
	RiskLevel   string
	CVE         string
}

// NewWebDAVModule yeni WebDAV modülü oluşturur
func NewWebDAVModule(client *http.Client, baseURL string) *WebDAVModule {
	module := &WebDAVModule{
		BaseModule: NewBaseModule("IIS WebDAV", "IIS WebDAV vulnerability detection"),
		client:     client,
		baseURL:    baseURL,
	}
	module.initMethods()
	return module
}

// initMethods WebDAV metodlarını başlatır
func (m *WebDAVModule) initMethods() {
	m.methods = []WebDAVMethod{
		// PROPFIND Method Abuse
		{
			Name:        "PROPFIND Information Disclosure",
			Method:      "PROPFIND",
			Description: "PROPFIND method abuse for information disclosure",
			Payload: `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
</D:propfind>`,
			Headers: map[string]string{
				"Content-Type": "text/xml",
				"Depth":        "infinity",
			},
			RiskLevel: "MEDIUM",
			CVE:       "",
		},
		{
			Name:        "PROPFIND Directory Enumeration",
			Method:      "PROPFIND",
			Description: "Directory enumeration using PROPFIND with depth infinity",
			Payload: `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:displayname/>
    <D:getcontentlength/>
    <D:getcontenttype/>
    <D:getlastmodified/>
    <D:creationdate/>
    <D:resourcetype/>
  </D:prop>
</D:propfind>`,
			Headers: map[string]string{
				"Content-Type": "text/xml",
				"Depth":        "infinity",
			},
			RiskLevel: "HIGH",
			CVE:       "",
		},
		// LOCK/UNLOCK Method Exploitation
		{
			Name:        "LOCK Method DoS",
			Method:      "LOCK",
			Description: "LOCK method denial of service attack",
			Payload: `<?xml version="1.0" encoding="utf-8"?>
<D:lockinfo xmlns:D="DAV:">
  <D:lockscope><D:exclusive/></D:lockscope>
  <D:locktype><D:write/></D:locktype>
  <D:owner>
    <D:href>` + strings.Repeat("A", 10000) + `</D:href>
  </D:owner>
</D:lockinfo>`,
			Headers: map[string]string{
				"Content-Type": "text/xml",
				"Timeout":      "Infinite",
			},
			RiskLevel: "MEDIUM",
			CVE:       "",
		},
		{
			Name:        "UNLOCK Without Token",
			Method:      "UNLOCK",
			Description: "UNLOCK method without proper lock token",
			Payload:     "",
			Headers: map[string]string{
				"Lock-Token": "<invalid-token>",
			},
			RiskLevel: "LOW",
			CVE:       "",
		},
		// WebDAV Authentication Bypass
		{
			Name:        "WebDAV Auth Bypass via MOVE",
			Method:      "MOVE",
			Description: "WebDAV authentication bypass using MOVE method",
			Payload:     "",
			Headers: map[string]string{
				"Destination": "/admin/test.txt",
				"Overwrite":   "T",
			},
			RiskLevel: "HIGH",
			CVE:       "CVE-2017-7269",
		},
		{
			Name:        "WebDAV Auth Bypass via COPY",
			Method:      "COPY",
			Description: "WebDAV authentication bypass using COPY method",
			Payload:     "",
			Headers: map[string]string{
				"Destination": "/protected/copy.txt",
				"Overwrite":   "F",
			},
			RiskLevel: "HIGH",
			CVE:       "",
		},
		// File Upload via WebDAV
		{
			Name:        "WebDAV File Upload",
			Method:      "PUT",
			Description: "File upload attempt via WebDAV PUT method",
			Payload:     "<%@ Page Language=\"C#\" %>\n<%Response.Write(\"WebDAV Upload Test\");%>",
			Headers: map[string]string{
				"Content-Type": "text/plain",
			},
			RiskLevel: "CRITICAL",
			CVE:       "",
		},
		{
			Name:        "WebDAV ASP Upload",
			Method:      "PUT",
			Description: "ASP file upload via WebDAV",
			Payload:     "<%Response.Write(\"ASP Upload Successful\")%>",
			Headers: map[string]string{
				"Content-Type": "application/octet-stream",
			},
			RiskLevel: "CRITICAL",
			CVE:       "",
		},
		// Directory Creation
		{
			Name:        "WebDAV Directory Creation",
			Method:      "MKCOL",
			Description: "Directory creation using MKCOL method",
			Payload:     "",
			Headers:     map[string]string{},
			RiskLevel:   "MEDIUM",
			CVE:         "",
		},
		// WebDAV Buffer Overflow
		{
			Name:        "WebDAV Buffer Overflow",
			Method:      "PROPFIND",
			Description: "WebDAV buffer overflow attempt",
			Payload: `<?xml version="1.0"?>
<a:propfind xmlns:a="DAV:" xmlns:b="` + strings.Repeat("A", 100000) + `">
<a:prop><a:displayname/></a:prop>
</a:propfind>`,
			Headers: map[string]string{
				"Content-Type": "text/xml",
			},
			RiskLevel: "HIGH",
			CVE:       "CVE-2017-7269",
		},
		// IIS 6.0 WebDAV Vulnerability
		{
			Name:        "IIS 6.0 WebDAV ScStoragePathFromUrl",
			Method:      "PROPFIND",
			Description: "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow",
			Payload: `<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
<D:prop>
<D:getcontentlength xmlns:D="DAV:" xmlns:b="urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/">
</D:prop>
</D:propfind>`,
			Headers: map[string]string{
				"Content-Type": "text/xml",
				"If":           "<http://localhost/aaaaaaa" + strings.Repeat("A", 100) + "> (<DAV:no-lock>)",
			},
			RiskLevel: "CRITICAL",
			CVE:       "CVE-2017-7269",
		},
	}
}

// Run WebDAV taramasını çalıştırır
func (m *WebDAVModule) Run(client *http.Client) (*ModuleResult, error) {
	m.Start()
	defer m.End()

	var vulnerabilities []Vulnerability
	var info []Information

	// First check if WebDAV is enabled
	webdavEnabled := m.checkWebDAVEnabled()
	if !webdavEnabled {
		info = append(info, CreateInformation(
			"webdav_status",
			"WebDAV Status",
			"WebDAV appears to be disabled on this server",
			"disabled",
		))
		return m.CreateResult("completed", vulnerabilities, info, nil), nil
	}

	info = append(info, CreateInformation(
		"webdav_status",
		"WebDAV Status",
		"WebDAV is enabled on this server",
		"enabled",
	))

	// Test each WebDAV method
	for _, method := range m.methods {
		vuln := m.testWebDAVMethod(method)
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
		time.Sleep(200 * time.Millisecond) // Rate limiting
	}

	// Test for specific WebDAV vulnerabilities
	vulns := m.testSpecificWebDAVVulns()
	vulnerabilities = append(vulnerabilities, vulns...)

	// Test WebDAV file operations
	vulns = m.testWebDAVFileOperations()
	vulnerabilities = append(vulnerabilities, vulns...)

	// Add informational findings
	info = append(info, CreateInformation(
		"scan_info",
		"WebDAV Scan Completed",
		fmt.Sprintf("Tested %d WebDAV methods", len(m.methods)),
		fmt.Sprintf("%d methods tested", len(m.methods)),
	))

	status := "completed"
	if len(vulnerabilities) > 0 {
		status = "vulnerabilities_found"
	}

	return m.CreateResult(status, vulnerabilities, info, nil), nil
}

// checkWebDAVEnabled WebDAV'ın etkin olup olmadığını kontrol eder
func (m *WebDAVModule) checkWebDAVEnabled() bool {
	m.IncrementRequests()

	req, err := http.NewRequest("OPTIONS", m.baseURL, nil)
	if err != nil {
		return false
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check for WebDAV methods in Allow header
	allowHeader := resp.Header.Get("Allow")
	webdavMethods := []string{"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
	
	for _, method := range webdavMethods {
		if strings.Contains(strings.ToUpper(allowHeader), method) {
			return true
		}
	}

	// Check DAV header
	davHeader := resp.Header.Get("DAV")
	if davHeader != "" {
		return true
	}

	return false
}

// testWebDAVMethod belirli bir WebDAV metodunu test eder
func (m *WebDAVModule) testWebDAVMethod(method WebDAVMethod) *Vulnerability {
	m.IncrementRequests()

	// Construct test URL
	testURL := m.baseURL + "/test"
	if method.Method == "PUT" {
		testURL += ".aspx"
	}

	var req *http.Request
	var err error

	if method.Payload != "" {
		req, err = http.NewRequest(method.Method, testURL, strings.NewReader(method.Payload))
	} else {
		req, err = http.NewRequest(method.Method, testURL, nil)
	}

	if err != nil {
		return nil
	}

	// Add custom headers
	for key, value := range method.Headers {
		req.Header.Set(key, value)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for vulnerability indicators
	if m.isWebDAVVulnerable(resp, method) {
		return m.createWebDAVVulnerability(method, testURL, resp)
	}

	return nil
}

// testSpecificWebDAVVulns belirli WebDAV zafiyetlerini test eder
func (m *WebDAVModule) testSpecificWebDAVVulns() []Vulnerability {
	var vulnerabilities []Vulnerability

	// Test for CVE-2017-7269 (IIS 6.0 WebDAV)
	vuln := m.testCVE20177269()
	if vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test for WebDAV information disclosure
	vuln = m.testWebDAVInfoDisclosure()
	if vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testCVE20177269 CVE-2017-7269 zafiyetini test eder
func (m *WebDAVModule) testCVE20177269() *Vulnerability {
	m.IncrementRequests()

	testURL := m.baseURL + "/test.txt"
	
	payload := `<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
<D:prop>
<D:getcontentlength xmlns:D="DAV:" xmlns:b="urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/">
</D:prop>
</D:propfind>`

	req, err := http.NewRequest("PROPFIND", testURL, strings.NewReader(payload))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("If", "<http://localhost/aaaaaaa"+strings.Repeat("A", 100)+"> (<DAV:no-lock>)")

	resp, err := m.client.Do(req)
	if err != nil {
		// Connection error might indicate successful exploitation
		if strings.Contains(err.Error(), "connection") {
			return &Vulnerability{
				ID:          "IIS-WEBDAV-CVE-2017-7269",
				Title:       "IIS 6.0 WebDAV ScStoragePathFromUrl Buffer Overflow",
				Description: "IIS 6.0 WebDAV service is vulnerable to buffer overflow (CVE-2017-7269)",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				CWE:         "CWE-119",
				OWASP:       "A06:2021 – Vulnerable and Outdated Components",
				URL:         testURL,
				Method:      "PROPFIND",
				Evidence:    "Connection error during exploitation attempt",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269",
					"https://www.exploit-db.com/exploits/41738",
				},
				Remediation: "Update IIS to a newer version or disable WebDAV if not required.",
				Metadata: map[string]string{
					"cve": "CVE-2017-7269",
				},
			}
		}
		return nil
	}
	defer resp.Body.Close()

	// Check for error responses that might indicate vulnerability
	if resp.StatusCode >= 500 {
		return &Vulnerability{
			ID:          "IIS-WEBDAV-CVE-2017-7269",
			Title:       "Potential IIS 6.0 WebDAV Vulnerability",
			Description: "Server returned error response to CVE-2017-7269 test",
			Severity:    "HIGH",
			CVSS:        8.1,
			CWE:         "CWE-119",
			OWASP:       "A06:2021 – Vulnerable and Outdated Components",
			URL:         testURL,
			Method:      "PROPFIND",
			Evidence:    fmt.Sprintf("Server error response: %d", resp.StatusCode),
			References: []string{
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269",
			},
			Remediation: "Verify IIS version and apply security updates.",
			Metadata: map[string]string{
				"cve": "CVE-2017-7269",
			},
		}
	}

	return nil
}

// testWebDAVInfoDisclosure WebDAV bilgi sızıntısını test eder
func (m *WebDAVModule) testWebDAVInfoDisclosure() *Vulnerability {
	m.IncrementRequests()

	payload := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
</D:propfind>`

	req, err := http.NewRequest("PROPFIND", m.baseURL, strings.NewReader(payload))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("Depth", "1")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 207 { // Multi-Status response
		return &Vulnerability{
			ID:          "IIS-WEBDAV-INFO-DISCLOSURE",
			Title:       "WebDAV Information Disclosure",
			Description: "WebDAV PROPFIND method reveals directory structure and file information",
			Severity:    "MEDIUM",
			CVSS:        5.3,
			CWE:         "CWE-200",
			OWASP:       "A01:2021 – Broken Access Control",
			URL:         m.baseURL,
			Method:      "PROPFIND",
			Evidence:    fmt.Sprintf("Multi-Status response (%d) reveals directory information", resp.StatusCode),
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
			},
			Remediation: "Restrict WebDAV access or disable directory browsing.",
			Metadata: map[string]string{
				"method": "PROPFIND",
			},
		}
	}

	return nil
}

// testWebDAVFileOperations WebDAV dosya işlemlerini test eder
func (m *WebDAVModule) testWebDAVFileOperations() []Vulnerability {
	var vulnerabilities []Vulnerability

	// Test file upload
	vuln := m.testWebDAVFileUpload()
	if vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	// Test directory creation
	vuln = m.testWebDAVDirectoryCreation()
	if vuln != nil {
		vulnerabilities = append(vulnerabilities, *vuln)
	}

	return vulnerabilities
}

// testWebDAVFileUpload WebDAV dosya yükleme test eder
func (m *WebDAVModule) testWebDAVFileUpload() *Vulnerability {
	m.IncrementRequests()

	testFile := "/webdav_test_" + fmt.Sprintf("%d", time.Now().Unix()) + ".txt"
	testURL := m.baseURL + testFile
	testContent := "WebDAV Upload Test - " + time.Now().String()

	req, err := http.NewRequest("PUT", testURL, strings.NewReader(testContent))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "text/plain")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 201 || resp.StatusCode == 204 {
		// Try to verify upload by reading the file
		m.IncrementRequests()
		verifyResp, err := m.client.Get(testURL)
		if err == nil {
			defer verifyResp.Body.Close()
			if verifyResp.StatusCode == 200 {
				// Clean up - try to delete the file
				m.IncrementRequests()
				delReq, _ := http.NewRequest("DELETE", testURL, nil)
				m.client.Do(delReq)

				return &Vulnerability{
					ID:          "IIS-WEBDAV-FILE-UPLOAD",
					Title:       "WebDAV File Upload Enabled",
					Description: "WebDAV allows file upload via PUT method",
					Severity:    "HIGH",
					CVSS:        7.5,
					CWE:         "CWE-434",
					OWASP:       "A04:2021 – Insecure Design",
					URL:         testURL,
					Method:      "PUT",
					Evidence:    fmt.Sprintf("File uploaded successfully with status %d", resp.StatusCode),
					References: []string{
						"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
					},
					Remediation: "Disable WebDAV file upload or implement strict file type validation.",
					Metadata: map[string]string{
						"upload_method": "PUT",
					},
				}
			}
		}
	}

	return nil
}

// testWebDAVDirectoryCreation WebDAV dizin oluşturma test eder
func (m *WebDAVModule) testWebDAVDirectoryCreation() *Vulnerability {
	m.IncrementRequests()

	testDir := "/webdav_test_dir_" + fmt.Sprintf("%d", time.Now().Unix())
	testURL := m.baseURL + testDir

	req, err := http.NewRequest("MKCOL", testURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 201 {
		// Clean up - try to delete the directory
		m.IncrementRequests()
		delReq, _ := http.NewRequest("DELETE", testURL, nil)
		m.client.Do(delReq)

		return &Vulnerability{
			ID:          "IIS-WEBDAV-DIR-CREATION",
			Title:       "WebDAV Directory Creation Enabled",
			Description: "WebDAV allows directory creation via MKCOL method",
			Severity:    "MEDIUM",
			CVSS:        5.3,
			CWE:         "CWE-732",
			OWASP:       "A01:2021 – Broken Access Control",
			URL:         testURL,
			Method:      "MKCOL",
			Evidence:    fmt.Sprintf("Directory created successfully with status %d", resp.StatusCode),
			References: []string{
				"https://tools.ietf.org/html/rfc4918",
			},
			Remediation: "Disable WebDAV directory creation or implement proper access controls.",
			Metadata: map[string]string{
				"creation_method": "MKCOL",
			},
		}
	}

	return nil
}

// isWebDAVVulnerable WebDAV zafiyeti kontrolü
func (m *WebDAVModule) isWebDAVVulnerable(resp *http.Response, method WebDAVMethod) bool {
	switch method.Method {
	case "PROPFIND":
		return resp.StatusCode == 207 || resp.StatusCode == 200
	case "PUT":
		return resp.StatusCode == 201 || resp.StatusCode == 204
	case "MKCOL":
		return resp.StatusCode == 201
	case "COPY", "MOVE":
		return resp.StatusCode == 201 || resp.StatusCode == 204
	case "LOCK":
		return resp.StatusCode == 200
	case "UNLOCK":
		return resp.StatusCode == 204
	default:
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}
}

// createWebDAVVulnerability WebDAV zafiyeti oluşturur
func (m *WebDAVModule) createWebDAVVulnerability(method WebDAVMethod, testURL string, resp *http.Response) *Vulnerability {
	severity := m.getSeverityFromRisk(method.RiskLevel)
	cvss := m.getCVSSFromRisk(method.RiskLevel)

	vulnerability := &Vulnerability{
		ID:          fmt.Sprintf("IIS-WEBDAV-%s", strings.ToUpper(strings.ReplaceAll(method.Name, " ", "-"))),
		Title:       fmt.Sprintf("WebDAV Vulnerability - %s", method.Name),
		Description: method.Description,
		Severity:    severity,
		CVSS:        cvss,
		CWE:         "CWE-200",
		OWASP:       "A05:2021 – Security Misconfiguration",
		URL:         testURL,
		Method:      method.Method,
		Payload:     method.Payload,
		Evidence:    fmt.Sprintf("WebDAV method %s successful with status %d", method.Method, resp.StatusCode),
		References: []string{
			"https://tools.ietf.org/html/rfc4918",
		},
		Remediation: "Disable WebDAV if not required or implement proper access controls.",
		Metadata: map[string]string{
			"webdav_method": method.Method,
			"risk_level":    method.RiskLevel,
		},
	}

	if method.CVE != "" {
		vulnerability.References = append(vulnerability.References,
			fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", method.CVE))
	}

	return vulnerability
}

// getSeverityFromRisk risk level'dan severity döndürür
func (m *WebDAVModule) getSeverityFromRisk(riskLevel string) string {
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
func (m *WebDAVModule) getCVSSFromRisk(riskLevel string) float64 {
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
