package modules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// FingerprintModule IIS fingerprinting module
type FingerprintModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewFingerprintModule creates a new fingerprint module
func NewFingerprintModule(cfg *config.Config, log *logger.Logger) Module {
	return &FingerprintModule{
		BaseModule: NewBaseModule("fingerprint", "IIS Version Detection & Fingerprinting"),
		config:     cfg,
		logger:     log,
	}
}

// Run runs the fingerprinting module
func (f *FingerprintModule) Run(client *http.Client) (*ModuleResult, error) {
	f.Start()
	defer f.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := f.config.GetBaseURL()

	// 1. Server Header Analysis
	f.logger.Debug("Server header analysis in progress...")
	serverInfo, serverVulns := f.analyzeServerHeaders(client, baseURL)
	info = append(info, serverInfo...)
	vulnerabilities = append(vulnerabilities, serverVulns...)

	// 2. IIS Version-Specific Response Pattern Analysis
	f.logger.Debug("IIS version pattern analysis in progress...")
	versionInfo, versionVulns := f.analyzeVersionPatterns(client, baseURL)
	info = append(info, versionInfo...)
	vulnerabilities = append(vulnerabilities, versionVulns...)

	// 3. Hidden IIS Modules Detection
	f.logger.Debug("Scanning for hidden IIS modules...")
	moduleInfo, moduleVulns := f.detectHiddenModules(client, baseURL)
	info = append(info, moduleInfo...)
	vulnerabilities = append(vulnerabilities, moduleVulns...)

	// 4. ISAPI Extension Enumeration
	f.logger.Debug("Scanning ISAPI extensions...")
	isapiInfo, isapiVulns := f.enumerateISAPIExtensions(client, baseURL)
	info = append(info, isapiInfo...)
	vulnerabilities = append(vulnerabilities, isapiVulns...)

	// 5. ETW Leak Detection
	f.logger.Debug("ETW leak detection in progress...")
	etwInfo, etwVulns := f.detectETWLeaks(client, baseURL)
	info = append(info, etwInfo...)
	vulnerabilities = append(vulnerabilities, etwVulns...)

	return f.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// analyzeServerHeaders analyzes server headers
func (f *FingerprintModule) analyzeServerHeaders(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	resp, err := client.Head(baseURL)
	if err != nil {
		return info, vulns
	}
	f.IncrementRequests()

	// Server header check
	serverHeader := resp.GetHeader("Server")
	if serverHeader != "" {
		info = append(info, CreateInformation("server", "Server Header",
			"IIS server header information", serverHeader))

		// IIS version detection
		if strings.Contains(strings.ToLower(serverHeader), "iis") {
			version := f.extractIISVersion(serverHeader)
			if version != "" {
				info = append(info, CreateInformation("version", "IIS Version",
					"Detected IIS version", version))

				// Old version check
				if f.isVulnerableVersion(version) {
					vuln := CreateVulnerability(
						"IIS-FINGERPRINT-001",
						"Outdated IIS Version Detected",
						fmt.Sprintf("Outdated IIS version detected: %s", version),
						"MEDIUM",
						5.3,
					)
					vuln.URL = baseURL
					vuln.Evidence = serverHeader
					vuln.Remediation = "Update IIS to the latest version"
					vulns = append(vulns, vuln)
				}
			}
		}

		// Information disclosure
		if f.isVerboseServerHeader(serverHeader) {
			vuln := CreateVulnerability(
				"IIS-FINGERPRINT-002",
				"Verbose Server Header Information Disclosure",
				"Server header contains too much information",
				"LOW",
				3.1,
			)
			vuln.URL = baseURL
			vuln.Evidence = serverHeader
			vuln.Remediation = "Minimize or hide the server header"
			vulns = append(vulns, vuln)
		}
	}

	// X-Powered-By header check
	poweredBy := resp.GetHeader("X-Powered-By")
	if poweredBy != "" {
		info = append(info, CreateInformation("powered_by", "X-Powered-By Header",
			"X-Powered-By header information", poweredBy))

		vuln := CreateVulnerability(
			"IIS-FINGERPRINT-003",
			"X-Powered-By Header Information Disclosure",
			"X-Powered-By header exposes technology information",
			"LOW",
			2.6,
		)
		vuln.URL = baseURL
		vuln.Evidence = poweredBy
		vuln.Remediation = "Remove the X-Powered-By header"
		vulns = append(vulns, vuln)
	}

	// X-AspNet-Version header check
	aspNetVersion := resp.GetHeader("X-AspNet-Version")
	if aspNetVersion != "" {
		info = append(info, CreateInformation("aspnet_version", "ASP.NET Version",
			"ASP.NET version information", aspNetVersion))

		vuln := CreateVulnerability(
			"IIS-FINGERPRINT-004",
			"ASP.NET Version Information Disclosure",
			"ASP.NET version information is being exposed",
			"LOW",
			2.6,
		)
		vuln.URL = baseURL
		vuln.Evidence = aspNetVersion
		vuln.Remediation = "Hide the ASP.NET version header"
		vulns = append(vulns, vuln)
	}

	return info, vulns
}

// analyzeVersionPatterns analyzes IIS version patterns
func (f *FingerprintModule) analyzeVersionPatterns(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// 404 error page analysis
	resp, err := client.Get(baseURL + "/nonexistent-page-" + fmt.Sprintf("%d", f.startTime.Unix()))
	if err == nil && resp.StatusCode == 404 {
		f.IncrementRequests()

		// IIS error page patterns
		patterns := map[string]string{
			"IIS 6.0":  `HTTP Error 404 - File or directory not found`,
			"IIS 7.0":  `HTTP Error 404.0 - Not Found`,
			"IIS 7.5":  `HTTP Error 404.0 - Not Found`,
			"IIS 8.0":  `HTTP Error 404.0 - Not Found`,
			"IIS 8.5":  `HTTP Error 404.0 - Not Found`,
			"IIS 10.0": `HTTP Error 404.0 - Not Found`,
		}

		for version, pattern := range patterns {
			if matched, _ := regexp.MatchString(pattern, resp.Body); matched {
				info = append(info, CreateInformation("version_pattern", "IIS Version (Pattern)",
					"Version detected from error page pattern", version))
				break
			}
		}
	}

	return info, vulns
}

// detectHiddenModules detects hidden IIS modules
func (f *FingerprintModule) detectHiddenModules(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// Common IIS module paths
	modulePaths := []string{
		"/iisadmin/",
		"/scripts/",
		"/msadc/",
		"/iissamples/",
		"/iishelp/",
		"/_vti_bin/",
		"/_vti_pvt/",
		"/aspnet_client/",
	}

	for _, path := range modulePaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		f.IncrementRequests()

		if resp.StatusCode != 404 {
			info = append(info, CreateInformation("hidden_module", "Hidden IIS Module",
				"Accessible IIS module detected", path))

			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				vuln := CreateVulnerability(
					"IIS-FINGERPRINT-005",
					"Accessible IIS Administrative Path",
					fmt.Sprintf("IIS administrative path accessible: %s", path),
					"MEDIUM",
					4.3,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
				vuln.Remediation = "Disable unnecessary IIS modules"
				vulns = append(vulns, vuln)
			}
		}
	}

	return info, vulns
}

// enumerateISAPIExtensions enumerates ISAPI extensions
func (f *FingerprintModule) enumerateISAPIExtensions(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// Common ISAPI extensions
	extensions := []string{
		".asp", ".aspx", ".asa", ".cer", ".cdx", ".htr", ".ida", ".idq",
		".idc", ".shtm", ".shtml", ".stm", ".printer", ".htw", ".dll",
	}

	for _, ext := range extensions {
		testURL := baseURL + "/test" + ext
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		f.IncrementRequests()

		// Responses other than 404 are interesting
		if resp.StatusCode != 404 {
			info = append(info, CreateInformation("isapi_extension", "ISAPI Extension",
				"Active ISAPI extension detected", ext))

			// Some extensions can pose security risks
			dangerousExts := []string{".htr", ".ida", ".idq", ".idc", ".printer", ".htw"}
			for _, dangerous := range dangerousExts {
				if ext == dangerous {
					vuln := CreateVulnerability(
						"IIS-FINGERPRINT-006",
						"Dangerous ISAPI Extension Enabled",
						fmt.Sprintf("Dangerous ISAPI extension active: %s", ext),
						"HIGH",
						7.5,
					)
					vuln.URL = testURL
					vuln.Method = "GET"
					vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
					vuln.Remediation = "Disable unnecessary ISAPI extensions"
					vulns = append(vulns, vuln)
					break
				}
			}
		}
	}

	return info, vulns
}

// detectETWLeaks detects ETW leaks
func (f *FingerprintModule) detectETWLeaks(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// Requests that can trigger ETW trace information
	etwTriggers := []string{
		"/?debug=true",
		"/?trace=true",
		"/trace.axd",
		"/elmah.axd",
	}

	for _, trigger := range etwTriggers {
		resp, err := client.Get(baseURL + trigger)
		if err != nil {
			continue
		}
		f.IncrementRequests()

		// ETW leak patterns
		etwPatterns := []string{
			"System.Diagnostics.Eventing",
			"EventSource",
			"ETW",
			"Event Tracing",
			"TraceEvent",
		}

		for _, pattern := range etwPatterns {
			if strings.Contains(resp.Body, pattern) {
				vuln := CreateVulnerability(
					"IIS-FINGERPRINT-007",
					"ETW (Event Tracing for Windows) Information Leak",
					"ETW trace information is being leaked",
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL + trigger
				vuln.Method = "GET"
				vuln.Evidence = pattern
				vuln.Remediation = "Disable debug and trace features in production"
				vulns = append(vulns, vuln)
				break
			}
		}
	}

	return info, vulns
}

// extractIISVersion extracts IIS version from server header
func (f *FingerprintModule) extractIISVersion(serverHeader string) string {
	re := regexp.MustCompile(`IIS/(\d+\.\d+)`)
	matches := re.FindStringSubmatch(serverHeader)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// isVulnerableVersion checks if IIS version contains vulnerabilities
func (f *FingerprintModule) isVulnerableVersion(version string) bool {
	vulnerableVersions := []string{"6.0", "7.0", "7.5", "8.0"}
	for _, vulnVersion := range vulnerableVersions {
		if version == vulnVersion {
			return true
		}
	}
	return false
}

// isVerboseServerHeader checks if server header contains too much information
func (f *FingerprintModule) isVerboseServerHeader(serverHeader string) bool {
	verboseIndicators := []string{"Microsoft-IIS", "ASP.NET", "Windows", "Server"}
	count := 0
	for _, indicator := range verboseIndicators {
		if strings.Contains(serverHeader, indicator) {
			count++
		}
	}
	return count > 2
}
