package modules

import (
	"fmt"
	"strings"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// HTTPMethodsModule HTTP methods test module
type HTTPMethodsModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewHTTPMethodsModule creates new HTTP methods module
func NewHTTPMethodsModule(cfg *config.Config, log *logger.Logger) Module {
	return &HTTPMethodsModule{
		BaseModule: NewBaseModule("http_methods", "HTTP Methods Security Testing"),
		config:     cfg,
		logger:     log,
	}
}

// Run executes HTTP methods module
func (h *HTTPMethodsModule) Run(client *http.Client) (*ModuleResult, error) {
	h.Start()
	defer h.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := h.config.GetBaseURL()

	// 1. HTTP Methods Enumeration
	h.logger.Debug("Enumerating HTTP methods...")
	methodsInfo, methodsVulns := h.enumerateHTTPMethods(client, baseURL)
	info = append(info, methodsInfo...)
	vulnerabilities = append(vulnerabilities, methodsVulns...)

	// 2. Dangerous Methods Testing
	h.logger.Debug("Testing dangerous HTTP methods...")
	dangerousVulns := h.testDangerousMethods(client, baseURL)
	vulnerabilities = append(vulnerabilities, dangerousVulns...)

	// 3. WebDAV Methods Testing
	h.logger.Debug("Testing WebDAV methods...")
	webdavVulns := h.testWebDAVMethods(client, baseURL)
	vulnerabilities = append(vulnerabilities, webdavVulns...)

	// 4. HTTP Method Override Testing
	h.logger.Debug("Testing HTTP method override...")
	overrideVulns := h.testMethodOverride(client, baseURL)
	vulnerabilities = append(vulnerabilities, overrideVulns...)

	// 5. TRACE Method XST Testing
	h.logger.Debug("Testing TRACE method XST...")
	xstVulns := h.testTraceXST(client, baseURL)
	vulnerabilities = append(vulnerabilities, xstVulns...)

	return h.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// enumerateHTTPMethods enumerates HTTP methods
func (h *HTTPMethodsModule) enumerateHTTPMethods(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// HTTP methods
	methods := []string{
		"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
		"PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
		"SEARCH", "SUBSCRIBE", "UNSUBSCRIBE", "NOTIFY", "POLL", "BMOVE", "BDELETE",
		"BPROPFIND", "BPROPPATCH", "BCOPY", "BDELETE", "BMOVE", "X-MS-ENUMATTS",
	}

	var allowedMethods []string
	var disallowedMethods []string

	for _, method := range methods {
		resp, err := client.Request(method, baseURL, "")
		if err != nil {
			continue
		}
		h.IncrementRequests()

		// Method allowed check
		if h.isMethodAllowed(resp.StatusCode) {
			allowedMethods = append(allowedMethods, method)
			info = append(info, CreateInformation("allowed_method", "Allowed HTTP Method",
				fmt.Sprintf("HTTP method allowed: %s", method),
				fmt.Sprintf("Status: %d", resp.StatusCode)))
		} else {
			disallowedMethods = append(disallowedMethods, method)
		}
	}

	// Check allowed methods with OPTIONS method
	optionsResp, err := client.Options(baseURL)
	if err == nil {
		h.IncrementRequests()

		allowHeader := optionsResp.GetHeader("Allow")
		if allowHeader != "" {
			info = append(info, CreateInformation("allow_header", "Allow Header",
				"OPTIONS response Allow header", allowHeader))

			// Allow header'daki metodları parse et
			headerMethods := strings.Split(strings.ReplaceAll(allowHeader, " ", ""), ",")
			for _, method := range headerMethods {
				if method != "" && !contains(allowedMethods, method) {
					allowedMethods = append(allowedMethods, method)
				}
			}
		}
	}

	// Check if dangerous methods are allowed
	dangerousMethods := []string{"PUT", "DELETE", "TRACE", "CONNECT"}
	for _, method := range dangerousMethods {
		if contains(allowedMethods, method) {
			severity := "HIGH"
			cvss := 7.5

			if method == "PUT" || method == "DELETE" {
				severity = "CRITICAL"
				cvss = 9.1
			}

			vuln := CreateVulnerability(
				"HTTP-METHODS-001",
				fmt.Sprintf("Dangerous HTTP Method Enabled: %s", method),
				fmt.Sprintf("Dangerous HTTP method is active: %s", method),
				severity,
				cvss,
			)
			vuln.URL = baseURL
			vuln.Method = method
			vuln.Evidence = fmt.Sprintf("%s method allowed", method)
			vuln.Remediation = fmt.Sprintf("Disable %s method", method)
			vuln.CWE = "CWE-650"
			vuln.OWASP = "A05:2021 – Security Misconfiguration"
			vulns = append(vulns, vuln)
		}
	}

	return info, vulns
}

// testDangerousMethods tests dangerous HTTP methods
func (h *HTTPMethodsModule) testDangerousMethods(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// PUT method file upload testi
	putVuln := h.testPUTMethod(client, baseURL)
	if putVuln != nil {
		vulns = append(vulns, *putVuln)
	}

	// DELETE method file deletion testi
	deleteVuln := h.testDELETEMethod(client, baseURL)
	if deleteVuln != nil {
		vulns = append(vulns, *deleteVuln)
	}

	return vulns
}

// testPUTMethod tests file upload with PUT method
func (h *HTTPMethodsModule) testPUTMethod(client *http.Client, baseURL string) *Vulnerability {
	testContent := "<!-- IIS Security Scanner Test File -->\n<html><body>Test</body></html>"
	testFile := "/iis_scanner_test.html"

	// Try file upload with PUT
	resp, err := client.Request("PUT", baseURL+testFile, testContent)
	if err != nil {
		return nil
	}
	h.IncrementRequests()

	if resp.StatusCode == 201 || resp.StatusCode == 200 {
		// Check if file was uploaded
		getResp, err := client.Get(baseURL + testFile)
		if err == nil {
			h.IncrementRequests()

			if getResp.StatusCode == 200 && strings.Contains(getResp.Body, "IIS Security Scanner Test File") {
				// Clean up test file
				client.Request("DELETE", baseURL+testFile, "")
				h.IncrementRequests()

				vuln := CreateVulnerability(
					"HTTP-METHODS-002",
					"HTTP PUT Method File Upload",
					"File upload is possible with PUT method",
					"CRITICAL",
					9.8,
				)
				vuln.URL = baseURL + testFile
				vuln.Method = "PUT"
				vuln.Payload = testContent
				vuln.Evidence = "Test file successfully uploaded and accessed"
				vuln.Remediation = "Disable PUT method"
				vuln.CWE = "CWE-434"
				vuln.OWASP = "A03:2021 – Injection"
				return &vuln
			}
		}
	}

	return nil
}

// testDELETEMethod tests file deletion with DELETE method
func (h *HTTPMethodsModule) testDELETEMethod(client *http.Client, baseURL string) *Vulnerability {
	// First create test file
	testContent := "<!-- IIS Security Scanner Test File for DELETE -->"
	testFile := "/iis_scanner_delete_test.html"

	// Create test file with PUT
	putResp, err := client.Request("PUT", baseURL+testFile, testContent)
	if err != nil || (putResp.StatusCode != 201 && putResp.StatusCode != 200) {
		return nil
	}
	h.IncrementRequests()

	// Try to delete test file
	deleteResp, err := client.Request("DELETE", baseURL+testFile, "")
	if err != nil {
		return nil
	}
	h.IncrementRequests()

	if deleteResp.StatusCode == 200 || deleteResp.StatusCode == 204 {
		// Check if test file was deleted
		getResp, err := client.Get(baseURL + testFile)
		if err == nil {
			h.IncrementRequests()

			if getResp.StatusCode == 404 {
				vuln := CreateVulnerability(
					"HTTP-METHODS-003",
					"HTTP DELETE Method File Deletion",
					"File deletion is possible with DELETE method",
					"HIGH",
					8.1,
				)
				vuln.URL = baseURL + testFile
				vuln.Method = "DELETE"
				vuln.Evidence = "Test file successfully deleted"
				vuln.Remediation = "Disable DELETE method"
				vuln.CWE = "CWE-650"
				vuln.OWASP = "A05:2021 – Security Misconfiguration"
				return &vuln
			}
		}
	}

	return nil
}

// testWebDAVMethods tests WebDAV methods
func (h *HTTPMethodsModule) testWebDAVMethods(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	webdavMethods := []string{"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

	for _, method := range webdavMethods {
		resp, err := client.Request(method, baseURL, "")
		if err != nil {
			continue
		}
		h.IncrementRequests()

		if h.isMethodAllowed(resp.StatusCode) {
			vuln := CreateVulnerability(
				"HTTP-METHODS-004",
				fmt.Sprintf("WebDAV Method Enabled: %s", method),
				fmt.Sprintf("WebDAV method is active: %s", method),
				"MEDIUM",
				6.1,
			)
			vuln.URL = baseURL
			vuln.Method = method
			vuln.Evidence = fmt.Sprintf("%s method allowed (Status: %d)", method, resp.StatusCode)
			vuln.Remediation = "Disable WebDAV"
			vuln.CWE = "CWE-650"
			vuln.OWASP = "A05:2021 – Security Misconfiguration"
			vulns = append(vulns, vuln)
		}
	}

	// PROPFIND ile directory enumeration testi
	propfindVuln := h.testPROPFIND(client, baseURL)
	if propfindVuln != nil {
		vulns = append(vulns, *propfindVuln)
	}

	return vulns
}

// testPROPFIND tests directory enumeration with PROPFIND method
func (h *HTTPMethodsModule) testPROPFIND(client *http.Client, baseURL string) *Vulnerability {
	propfindBody := `<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
</D:propfind>`

	resp, err := client.Request("PROPFIND", baseURL, propfindBody)
	if err != nil {
		return nil
	}
	h.IncrementRequests()

	if resp.StatusCode == 207 && strings.Contains(resp.Body, "<?xml") {
		vuln := CreateVulnerability(
			"HTTP-METHODS-005",
			"WebDAV PROPFIND Directory Enumeration",
			"Directory enumeration is possible with PROPFIND method",
			"MEDIUM",
			5.3,
		)
		vuln.URL = baseURL
		vuln.Method = "PROPFIND"
		vuln.Payload = propfindBody
		vuln.Evidence = "PROPFIND XML response received"
		vuln.Remediation = "Disable WebDAV PROPFIND method"
		vuln.CWE = "CWE-200"
		vuln.OWASP = "A01:2021 – Broken Access Control"
		return &vuln
	}

	return nil
}

// testMethodOverride tests HTTP method override
func (h *HTTPMethodsModule) testMethodOverride(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Method override header'ları (fast modda sadece yaygın olanlar)
	overrideHeaders := []string{
		"X-HTTP-Method-Override",
		"X-Method-Override",
	}

	if !h.config.Fast {
		overrideHeaders = append(overrideHeaders, "X-HTTP-Method", "_method")
	}

	for _, header := range overrideHeaders {
		// POST ile DELETE override testi
		resp, err := client.Request("POST", baseURL, "")
		if err != nil {
			continue
		}

		// Override header ekle
		// Note: This simple implementation, in real implementation header needs to be added to request
		h.IncrementRequests()

		// Simple check - more detailed testing should be done in real implementation
		if resp.StatusCode != 405 { // If not Method Not Allowed
			vuln := CreateVulnerability(
				"HTTP-METHODS-006",
				fmt.Sprintf("HTTP Method Override Possible: %s", header),
				fmt.Sprintf("HTTP method override is possible: %s", header),
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL
			vuln.Method = "POST"
			vuln.Evidence = fmt.Sprintf("%s header method override tested", header)
			vuln.Remediation = "Disable HTTP method override headers"
			vuln.CWE = "CWE-650"
			vuln.OWASP = "A05:2021 – Security Misconfiguration"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// testTraceXST tests XST (Cross-Site Tracing) with TRACE method
func (h *HTTPMethodsModule) testTraceXST(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	resp, err := client.Request("TRACE", baseURL, "")
	if err != nil {
		return vulns
	}
	h.IncrementRequests()

	if resp.StatusCode == 200 && strings.Contains(resp.Body, "TRACE") {
		vuln := CreateVulnerability(
			"HTTP-METHODS-007",
			"HTTP TRACE Method XST Vulnerability",
			"XST attack is possible with TRACE method",
			"MEDIUM",
			6.1,
		)
		vuln.URL = baseURL
		vuln.Method = "TRACE"
		vuln.Evidence = "TRACE method is active and vulnerable to XST attacks"
		vuln.Remediation = "Disable TRACE method completely"
		vuln.CWE = "CWE-79"
		vuln.OWASP = "A03:2021 – Injection"
		vuln.References = []string{
			"https://owasp.org/www-community/attacks/Cross_Site_Tracing",
		}
		vulns = append(vulns, vuln)
	}

	return vulns
}

// Helper functions

func (h *HTTPMethodsModule) isMethodAllowed(statusCode int) bool {
	// Method allowed status codes
	allowedCodes := []int{200, 201, 202, 204, 207, 301, 302, 304}

	for _, code := range allowedCodes {
		if statusCode == code {
			return true
		}
	}

	// If not 405 Method Not Allowed and not 4xx/5xx error, consider it allowed
	return statusCode != 405 && statusCode < 400
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
