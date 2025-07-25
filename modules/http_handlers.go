package modules

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ibrahmsql/iismap/pkg/http"
)

// HTTPHandlerModule IIS HTTP handler zafiyetlerini tespit eder
type HTTPHandlerModule struct {
	*BaseModule
	client   *http.Client
	baseURL  string
	handlers []HTTPHandler
}

// HTTPHandler HTTP handler yapısı
type HTTPHandler struct {
	Name        string
	Path        string
	Extension   string
	Description string
	RiskLevel   string
	TestMethods []string
}

// NewHTTPHandlerModule yeni HTTP handler modülü oluşturur
func NewHTTPHandlerModule(client *http.Client, baseURL string) *HTTPHandlerModule {
	module := &HTTPHandlerModule{
		BaseModule: NewBaseModule("IIS HTTP Handlers", "IIS HTTP handler vulnerability detection"),
		client:     client,
		baseURL:    baseURL,
	}
	module.initHandlers()
	return module
}

// initHandlers HTTP handler listesini başlatır
func (m *HTTPHandlerModule) initHandlers() {
	m.handlers = []HTTPHandler{
		// .NET Remoting Services
		{
			Name:        ".NET Remoting Service",
			Path:        "/RemotingServices",
			Extension:   ".rem",
			Description: ".NET Remoting services exposure",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST", "OPTIONS"},
		},
		{
			Name:        ".NET Remoting SOAP",
			Path:        "/RemotingServices",
			Extension:   ".soap",
			Description: ".NET Remoting SOAP endpoint",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST"},
		},
		// WCF Services
		{
			Name:        "WCF Service",
			Path:        "/Services",
			Extension:   ".svc",
			Description: "Windows Communication Foundation service",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST", "OPTIONS"},
		},
		{
			Name:        "WCF WSDL",
			Path:        "/Services",
			Extension:   ".svc/wsdl",
			Description: "WCF WSDL metadata exposure",
			RiskLevel:   "LOW",
			TestMethods: []string{"GET"},
		},
		{
			Name:        "WCF MEX",
			Path:        "/Services",
			Extension:   ".svc/mex",
			Description: "WCF metadata exchange endpoint",
			RiskLevel:   "LOW",
			TestMethods: []string{"GET"},
		},
		// ASMX Web Services
		{
			Name:        "ASMX Web Service",
			Path:        "/WebServices",
			Extension:   ".asmx",
			Description: "ASP.NET Web Service (ASMX)",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "ASMX WSDL",
			Path:        "/WebServices",
			Extension:   ".asmx?wsdl",
			Description: "ASMX WSDL metadata exposure",
			RiskLevel:   "LOW",
			TestMethods: []string{"GET"},
		},
		{
			Name:        "ASMX Disco",
			Path:        "/WebServices",
			Extension:   ".asmx?disco",
			Description: "ASMX discovery document",
			RiskLevel:   "LOW",
			TestMethods: []string{"GET"},
		},
		// SharePoint Services
		{
			Name:        "SharePoint Web Service",
			Path:        "/_vti_bin",
			Extension:   ".asmx",
			Description: "SharePoint web service endpoint",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "SharePoint Lists Service",
			Path:        "/_vti_bin/lists.asmx",
			Extension:   "",
			Description: "SharePoint Lists web service",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "SharePoint UserGroup Service",
			Path:        "/_vti_bin/usergroup.asmx",
			Extension:   "",
			Description: "SharePoint UserGroup web service",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "SharePoint Webs Service",
			Path:        "/_vti_bin/webs.asmx",
			Extension:   "",
			Description: "SharePoint Webs web service",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST"},
		},
		// Exchange OWA
		{
			Name:        "Exchange OWA",
			Path:        "/owa",
			Extension:   "",
			Description: "Exchange Outlook Web Access",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "Exchange EWS",
			Path:        "/EWS/Exchange.asmx",
			Extension:   "",
			Description: "Exchange Web Services",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "Exchange ActiveSync",
			Path:        "/Microsoft-Server-ActiveSync",
			Extension:   "",
			Description: "Exchange ActiveSync endpoint",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST", "OPTIONS"},
		},
		{
			Name:        "Exchange Autodiscover",
			Path:        "/autodiscover/autodiscover.xml",
			Extension:   "",
			Description: "Exchange Autodiscover service",
			RiskLevel:   "LOW",
			TestMethods: []string{"GET", "POST"},
		},
		// Generic Handlers
		{
			Name:        "Generic Handler",
			Path:        "/Handlers",
			Extension:   ".ashx",
			Description: "Generic ASP.NET handler",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "HTTP Module",
			Path:        "/Modules",
			Extension:   ".axd",
			Description: "ASP.NET HTTP module",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST"},
		},
		// Crystal Reports
		{
			Name:        "Crystal Reports Viewer",
			Path:        "/CrystalReportWebFormViewer",
			Extension:   ".aspx",
			Description: "Crystal Reports web viewer",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST"},
		},
		// Telerik Controls
		{
			Name:        "Telerik RadUpload",
			Path:        "/Telerik.Web.UI.WebResource.axd",
			Extension:   "",
			Description: "Telerik RadUpload handler",
			RiskLevel:   "HIGH",
			TestMethods: []string{"GET", "POST"},
		},
		{
			Name:        "Telerik DialogHandler",
			Path:        "/Telerik.Web.UI.DialogHandler.axd",
			Extension:   "",
			Description: "Telerik dialog handler",
			RiskLevel:   "MEDIUM",
			TestMethods: []string{"GET", "POST"},
		},
	}
}

// Run HTTP handler taramasını çalıştırır
func (m *HTTPHandlerModule) Run(client *http.Client) (*ModuleResult, error) {
	m.Start()
	defer m.End()

	var vulnerabilities []Vulnerability
	var info []Information

	// Test each handler
	for _, handler := range m.handlers {
		vulns := m.testHandler(handler)
		vulnerabilities = append(vulnerabilities, vulns...)
		time.Sleep(100 * time.Millisecond) // Rate limiting
	}

	// Enumerate common service directories
	serviceDirectories := []string{
		"/bin",
		"/App_Code",
		"/App_Data",
		"/Services",
		"/WebServices",
		"/api",
		"/handlers",
		"/_vti_bin",
		"/owa",
		"/exchange",
	}

	for _, dir := range serviceDirectories {
		vulns := m.enumerateDirectory(dir)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	// Test for common vulnerable handlers
	vulns := m.testVulnerableHandlers()
	vulnerabilities = append(vulnerabilities, vulns...)

	// Add informational findings
	info = append(info, CreateInformation(
		"scan_info",
		"HTTP Handler Scan Completed",
		fmt.Sprintf("Tested %d HTTP handlers", len(m.handlers)),
		fmt.Sprintf("%d handlers tested", len(m.handlers)),
	))

	status := "completed"
	if len(vulnerabilities) > 0 {
		status = "vulnerabilities_found"
	}

	return m.CreateResult(status, vulnerabilities, info, nil), nil
}

// testHandler belirli bir handler'ı test eder
func (m *HTTPHandlerModule) testHandler(handler HTTPHandler) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Test different paths and extensions
	testPaths := m.generateTestPaths(handler)

	for _, testPath := range testPaths {
		for _, method := range handler.TestMethods {
			m.IncrementRequests()

			vuln := m.testHandlerPath(testPath, method, handler)
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, *vuln)
			}
		}
	}

	return vulnerabilities
}

// generateTestPaths handler için test path'lerini oluşturur
func (m *HTTPHandlerModule) generateTestPaths(handler HTTPHandler) []string {
	var paths []string

	baseURL, _ := url.Parse(m.baseURL)

	// Direct path test
	if handler.Extension != "" {
		paths = append(paths, baseURL.String()+handler.Path+handler.Extension)
	} else {
		paths = append(paths, baseURL.String()+handler.Path)
	}

	// Common variations
	variations := []string{
		"/default",
		"/test",
		"/service",
		"/api",
		"/v1",
		"/v2",
	}

	for _, variation := range variations {
		if handler.Extension != "" {
			paths = append(paths, baseURL.String()+handler.Path+variation+handler.Extension)
		} else {
			paths = append(paths, baseURL.String()+handler.Path+variation)
		}
	}

	return paths
}

// testHandlerPath belirli bir path'i test eder
func (m *HTTPHandlerModule) testHandlerPath(testURL, method string, handler HTTPHandler) *Vulnerability {
	req, err := http.NewRequest(method, testURL, nil)
	if err != nil {
		return nil
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for handler exposure indicators
	if m.isHandlerExposed(resp, handler) {
		severity := m.getSeverityFromRisk(handler.RiskLevel)
		cvss := m.getCVSSFromRisk(handler.RiskLevel)

		return &Vulnerability{
			ID:          fmt.Sprintf("IIS-HANDLER-%s", strings.ToUpper(strings.ReplaceAll(handler.Name, " ", "-"))),
			Title:       fmt.Sprintf("Exposed %s", handler.Name),
			Description: fmt.Sprintf("%s is exposed and accessible", handler.Description),
			Severity:    severity,
			CVSS:        cvss,
			CWE:         "CWE-200",
			OWASP:       "A01:2021 – Broken Access Control",
			URL:         testURL,
			Method:      method,
			Evidence:    fmt.Sprintf("Handler accessible with status %d", resp.StatusCode),
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
			},
			Remediation: "Restrict access to sensitive handlers and implement proper authentication.",
			Metadata: map[string]string{
				"handler_type": handler.Name,
				"risk_level":   handler.RiskLevel,
			},
		}
	}

	return nil
}

// enumerateDirectory dizin enumeration yapar
func (m *HTTPHandlerModule) enumerateDirectory(directory string) []Vulnerability {
	var vulnerabilities []Vulnerability

	m.IncrementRequests()

	testURL := m.baseURL + directory
	resp, err := m.client.Get(testURL)
	if err != nil {
		return vulnerabilities
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 403 {
		// Directory exists, check for directory listing
		if m.hasDirectoryListing(resp) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "IIS-DIRECTORY-LISTING",
				Title:       "Directory Listing Enabled",
				Description: fmt.Sprintf("Directory listing is enabled for %s", directory),
				Severity:    "MEDIUM",
				CVSS:        5.3,
				CWE:         "CWE-548",
				OWASP:       "A05:2021 – Security Misconfiguration",
				URL:         testURL,
				Method:      "GET",
				Evidence:    fmt.Sprintf("Directory listing accessible at %s", directory),
				References: []string{
					"https://owasp.org/www-community/vulnerabilities/Directory_indexing",
				},
				Remediation: "Disable directory browsing in IIS configuration.",
				Metadata: map[string]string{
					"directory": directory,
				},
			})
		}
	}

	return vulnerabilities
}

// testVulnerableHandlers bilinen zafiyet içeren handler'ları test eder
func (m *HTTPHandlerModule) testVulnerableHandlers() []Vulnerability {
	var vulnerabilities []Vulnerability

	vulnerableHandlers := []struct {
		path        string
		description string
		cve         string
	}{
		{
			path:        "/Telerik.Web.UI.WebResource.axd?type=rau",
			description: "Telerik RadAsyncUpload vulnerability",
			cve:         "CVE-2017-9248",
		},
		{
			path:        "/Telerik.Web.UI.DialogHandler.axd",
			description: "Telerik DialogHandler vulnerability",
			cve:         "CVE-2017-11317",
		},
		{
			path:        "/elmah.axd",
			description: "ELMAH error log exposure",
			cve:         "",
		},
		{
			path:        "/trace.axd",
			description: "ASP.NET trace handler exposure",
			cve:         "",
		},
	}

	for _, handler := range vulnerableHandlers {
		m.IncrementRequests()

		testURL := m.baseURL + handler.path
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			vulnerability := Vulnerability{
				ID:          fmt.Sprintf("IIS-VULNERABLE-HANDLER-%s", handler.cve),
				Title:       "Vulnerable Handler Exposed",
				Description: handler.description,
				Severity:    "HIGH",
				CVSS:        7.5,
				CWE:         "CWE-200",
				OWASP:       "A06:2021 – Vulnerable and Outdated Components",
				URL:         testURL,
				Method:      "GET",
				Evidence:    fmt.Sprintf("Vulnerable handler accessible with status %d", resp.StatusCode),
				Remediation: "Update or remove vulnerable handlers.",
				Metadata: map[string]string{
					"cve": handler.cve,
				},
			}

			if handler.cve != "" {
				vulnerability.References = []string{
					fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", handler.cve),
				}
			}

			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

// isHandlerExposed handler'ın expose olup olmadığını kontrol eder
func (m *HTTPHandlerModule) isHandlerExposed(resp *http.Response, handler HTTPHandler) bool {
	// Check status codes
	if resp.StatusCode == 200 || resp.StatusCode == 500 {
		return true
	}

	// Check for specific content types
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/xml") ||
		strings.Contains(contentType, "application/soap+xml") ||
		strings.Contains(contentType, "application/json") {
		return true
	}

	// Check for WSDL content
	if strings.Contains(resp.Header.Get("Content-Type"), "text/xml") &&
		strings.Contains(strings.ToLower(resp.Header.Get("Content-Preview")), "wsdl") {
		return true
	}

	return false
}

// hasDirectoryListing directory listing kontrolü
func (m *HTTPHandlerModule) hasDirectoryListing(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		// Check for directory listing indicators in headers or content
		return strings.Contains(strings.ToLower(resp.Header.Get("Server")), "iis") &&
			resp.StatusCode == 200
	}
	return false
}

// getSeverityFromRisk risk level'dan severity döndürür
func (m *HTTPHandlerModule) getSeverityFromRisk(riskLevel string) string {
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
func (m *HTTPHandlerModule) getCVSSFromRisk(riskLevel string) float64 {
	switch riskLevel {
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 3.0
	default:
		return 5.0
	}
}
