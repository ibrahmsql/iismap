package modules

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// ASPNETSecurityModule ASP.NET security controls module
type ASPNETSecurityModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewASPNETSecurityModule creates new ASP.NET security module
func NewASPNETSecurityModule(cfg *config.Config, log *logger.Logger) Module {
	return &ASPNETSecurityModule{
		BaseModule: NewBaseModule("aspnet_security", "ASP.NET Security Vulnerabilities Scanner"),
		config:     cfg,
		logger:     log,
	}
}

// Run executes ASP.NET security module
func (a *ASPNETSecurityModule) Run(client *http.Client) (*ModuleResult, error) {
	a.Start()
	defer a.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := a.config.GetBaseURL()

	// 1. ViewState Security Controls
	a.logger.Debug("Performing ViewState security controls...")
	viewStateVulns, viewStateInfo := a.checkViewStateSecurity(client, baseURL)
	vulnerabilities = append(vulnerabilities, viewStateVulns...)
	info = append(info, viewStateInfo...)

	// 2. Event Validation Controls
	a.logger.Debug("Performing event validation controls...")
	eventVulns, eventInfo := a.checkEventValidation(client, baseURL)
	vulnerabilities = append(vulnerabilities, eventVulns...)
	info = append(info, eventInfo...)

	// 3. Trace.axd Exposure
	a.logger.Debug("Checking trace.axd exposure...")
	traceVulns := a.checkTraceExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, traceVulns...)

	// 4. Elmah.axd Exposure
	a.logger.Debug("Checking elmah.axd exposure...")
	elmahVulns := a.checkElmahExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, elmahVulns...)

	// 5. ASP.NET Error Information Disclosure
	a.logger.Debug("Checking ASP.NET error information disclosure...")
	errorVulns := a.checkErrorInformationDisclosure(client, baseURL)
	vulnerabilities = append(vulnerabilities, errorVulns...)

	// 6. Session Management Controls
	a.logger.Debug("Performing session management controls...")
	sessionVulns, sessionInfo := a.checkSessionManagement(client, baseURL)
	vulnerabilities = append(vulnerabilities, sessionVulns...)
	info = append(info, sessionInfo...)

	// 7. Padding Oracle Attacks
	a.logger.Debug("Testing padding oracle attacks...")
	paddingVulns := a.checkPaddingOracle(client, baseURL)
	vulnerabilities = append(vulnerabilities, paddingVulns...)

	// 8. ASP.NET Version Information Disclosure
	a.logger.Debug("Checking ASP.NET version information disclosure...")
	versionVulns, versionInfo := a.checkVersionDisclosure(client, baseURL)
	vulnerabilities = append(vulnerabilities, versionVulns...)
	info = append(info, versionInfo...)

	return a.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// checkViewStateSecurity performs ViewState security controls
func (a *ASPNETSecurityModule) checkViewStateSecurity(client *http.Client, baseURL string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	// Ana sayfayı al
	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns, info
	}
	a.IncrementRequests()

	// Check for ViewState existence
	viewStateRegex := regexp.MustCompile(`__VIEWSTATE[^>]*value="([^"]*)"`)
	matches := viewStateRegex.FindStringSubmatch(resp.Body)

	if len(matches) > 1 {
		viewState := matches[1]
		info = append(info, CreateInformation("viewstate_found", "ViewState Found",
			"ASP.NET ViewState detected", "Present"))

		// Decode ViewState
		decodedViewState, err := base64.StdEncoding.DecodeString(viewState)
		if err == nil {
			info = append(info, CreateInformation("viewstate_size", "ViewState Size",
				"ViewState size", fmt.Sprintf("%d bytes", len(decodedViewState))))

			// ViewState MAC check
			if !a.hasViewStateMAC(decodedViewState) {
				vuln := CreateVulnerability(
					"ASPNET-001",
					"ViewState MAC Validation Disabled",
					"ViewState MAC validation is disabled. This leaves the system vulnerable to ViewState manipulation attacks.",
					"HIGH",
					7.5,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = "ViewState MAC hash not found"
				vuln.Remediation = "Set enableViewStateMAC='true' in web.config"
				vuln.CWE = "CWE-345"
				vuln.OWASP = "A08:2021 – Software and Data Integrity Failures"
				vulns = append(vulns, vuln)
			}

			// ViewState encryption check
			if !a.isViewStateEncrypted(decodedViewState) {
				vuln := CreateVulnerability(
					"ASPNET-002",
					"ViewState Not Encrypted",
					"ViewState not encrypted. Sensitive information may be stored in ViewState in plain text.",
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = "ViewState encryption not detected"
				vuln.Remediation = "Set viewStateEncryptionMode='Always' in web.config"
				vuln.CWE = "CWE-311"
				vuln.OWASP = "A02:2021 – Cryptographic Failures"
				vulns = append(vulns, vuln)
			}

			// ViewState manipulation test
			manipulatedViewState := a.manipulateViewState(viewState)
			if manipulatedViewState != "" {
				manipulationVuln := a.testViewStateManipulation(client, baseURL, manipulatedViewState)
				if manipulationVuln != nil {
					vulns = append(vulns, *manipulationVuln)
				}
			}
		}
	} else {
		info = append(info, CreateInformation("viewstate_found", "ViewState Found",
			"ASP.NET ViewState detected", "Not Present"))
	}

	return vulns, info
}

// checkEventValidation performs event validation controls
func (a *ASPNETSecurityModule) checkEventValidation(client *http.Client, baseURL string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns, info
	}
	a.IncrementRequests()

	// Check for Event validation existence
	if strings.Contains(resp.Body, "__EVENTVALIDATION") {
		info = append(info, CreateInformation("event_validation", "Event Validation",
			"ASP.NET Event Validation detected", "Enabled"))

		// Event validation bypass test
		bypassVuln := a.testEventValidationBypass(client, baseURL)
		if bypassVuln != nil {
			vulns = append(vulns, *bypassVuln)
		}
	} else {
		info = append(info, CreateInformation("event_validation", "Event Validation",
			"ASP.NET Event Validation detected", "Disabled"))

		vuln := CreateVulnerability(
			"ASPNET-003",
			"Event Validation Disabled",
			"ASP.NET Event Validation disabled. This weakens protection against CSRF attacks.",
			"MEDIUM",
			6.1,
		)
		vuln.URL = baseURL
		vuln.Method = "GET"
		vuln.Evidence = "__EVENTVALIDATION field not found"
		vuln.Remediation = "Set enableEventValidation='true' in web.config"
		vuln.CWE = "CWE-352"
		vuln.OWASP = "A01:2021 – Broken Access Control"
		vulns = append(vulns, vuln)
	}

	return vulns, info
}

// checkTraceExposure checks Trace.axd exposure
func (a *ASPNETSecurityModule) checkTraceExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	tracePaths := []string{
		"/trace.axd",
		"/Trace.axd",
		"/TRACE.AXD",
		"/app/trace.axd",
		"/admin/trace.axd",
	}

	for _, path := range tracePaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		a.IncrementRequests()

		if resp.StatusCode == 200 && strings.Contains(resp.Body, "Application Trace") {
			vuln := CreateVulnerability(
				"ASPNET-004",
				"ASP.NET Trace Information Disclosure",
				fmt.Sprintf("ASP.NET trace page accessible: %s", path),
				"HIGH",
				7.5,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "Application Trace page accessible"
			vuln.Remediation = "Set trace enabled='false' in web.config"
			vuln.CWE = "CWE-200"
			vuln.OWASP = "A01:2021 – Broken Access Control"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkElmahExposure checks Elmah.axd exposure
func (a *ASPNETSecurityModule) checkElmahExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	elmahPaths := []string{
		"/elmah.axd",
		"/Elmah.axd",
		"/ELMAH.AXD",
		"/admin/elmah.axd",
		"/errors/elmah.axd",
	}

	for _, path := range elmahPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		a.IncrementRequests()

		if resp.StatusCode == 200 && (strings.Contains(resp.Body, "Error Log") ||
			strings.Contains(resp.Body, "ELMAH")) {
			vuln := CreateVulnerability(
				"ASPNET-005",
				"ELMAH Error Log Exposure",
				fmt.Sprintf("ELMAH error log page accessible: %s", path),
				"HIGH",
				7.5,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "ELMAH error log page accessible"
			vuln.Remediation = "Disable ELMAH in production or restrict access"
			vuln.CWE = "CWE-200"
			vuln.OWASP = "A09:2021 – Security Logging and Monitoring Failures"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkErrorInformationDisclosure checks ASP.NET error information disclosure
func (a *ASPNETSecurityModule) checkErrorInformationDisclosure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Error triggering requests
	errorTriggers := []string{
		"/nonexistent.aspx",
		"/test.aspx?param=<script>",
		"/admin.aspx",
		"/login.aspx?user='",
	}

	for _, trigger := range errorTriggers {
		resp, err := client.Get(baseURL + trigger)
		if err != nil {
			continue
		}
		a.IncrementRequests()

		if resp.StatusCode >= 400 && a.containsDetailedErrorInfo(resp.Body) {
			vuln := CreateVulnerability(
				"ASPNET-006",
				"ASP.NET Detailed Error Information Disclosure",
				"ASP.NET detailed error messages are being exposed",
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + trigger
			vuln.Method = "GET"
			vuln.Evidence = "Detailed error message detected"
			vuln.Remediation = "Set customErrors mode='On' in web.config"
			vuln.CWE = "CWE-200"
			vuln.OWASP = "A09:2021 – Security Logging and Monitoring Failures"
			vulns = append(vulns, vuln)
			break // One finding is enough
		}
	}

	return vulns
}

// checkSessionManagement performs session management checks
func (a *ASPNETSecurityModule) checkSessionManagement(client *http.Client, baseURL string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns, info
	}
	a.IncrementRequests()

	// Session cookie check
	for _, cookie := range resp.Headers["Set-Cookie"] {
		if strings.Contains(strings.ToLower(cookie), "asp.net_sessionid") {
			info = append(info, CreateInformation("session_cookie", "ASP.NET Session Cookie",
				"ASP.NET session cookie detected", cookie))

			// HttpOnly check
			if !strings.Contains(strings.ToLower(cookie), "httponly") {
				vuln := CreateVulnerability(
					"ASPNET-007",
					"Session Cookie Missing HttpOnly Flag",
					"ASP.NET session cookie does not contain HttpOnly flag",
					"MEDIUM",
					6.1,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = cookie
				vuln.Remediation = "Set httpOnlyCookies='true' in web.config"
				vuln.CWE = "CWE-1004"
				vuln.OWASP = "A05:2021 – Security Misconfiguration"
				vulns = append(vulns, vuln)
			}

			// Secure flag check (for HTTPS)
			if a.config.ParsedURL.Scheme == "https" && !strings.Contains(strings.ToLower(cookie), "secure") {
				vuln := CreateVulnerability(
					"ASPNET-008",
					"Session Cookie Missing Secure Flag",
					"ASP.NET session cookie over HTTPS does not contain Secure flag",
					"MEDIUM",
					6.1,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = cookie
				vuln.Remediation = "Set requireSSL='true' in web.config"
				vuln.CWE = "CWE-614"
				vuln.OWASP = "A05:2021 – Security Misconfiguration"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, info
}

// checkPaddingOracle tests padding oracle attacks
func (a *ASPNETSecurityModule) checkPaddingOracle(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Padding oracle test with ViewState
	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns
	}
	a.IncrementRequests()

	viewStateRegex := regexp.MustCompile(`__VIEWSTATE[^>]*value="([^"]*)"`)
	matches := viewStateRegex.FindStringSubmatch(resp.Body)

	if len(matches) > 1 {
		originalViewState := matches[1]

		// Manipulate ViewState (for padding oracle)
		manipulatedViewState := a.createPaddingOraclePayload(originalViewState)

		// Send POST request
		formData := url.Values{}
		formData.Set("__VIEWSTATE", manipulatedViewState)

		postResp, err := client.Post(baseURL, formData.Encode())
		if err == nil {
			a.IncrementRequests()

			// Padding oracle indicators
			if a.isPaddingOracleVulnerable(postResp.Body) {
				vuln := CreateVulnerability(
					"ASPNET-009",
					"ASP.NET Padding Oracle Vulnerability",
					"ASP.NET padding oracle vulnerability detected",
					"HIGH",
					8.1,
				)
				vuln.URL = baseURL
				vuln.Method = "POST"
				vuln.Payload = manipulatedViewState
				vuln.Evidence = "Padding oracle response pattern detected"
				vuln.Remediation = "Update ASP.NET and use custom error pages"
				vuln.CWE = "CWE-209"
				vuln.OWASP = "A02:2021 – Cryptographic Failures"
				vuln.References = []string{
					"CVE-2010-3332",
					"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070",
				}
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// checkVersionDisclosure checks ASP.NET version disclosure
func (a *ASPNETSecurityModule) checkVersionDisclosure(client *http.Client, baseURL string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	resp, err := client.Head(baseURL)
	if err != nil {
		return vulns, info
	}
	a.IncrementRequests()

	// X-AspNet-Version header
	aspNetVersion := resp.GetHeader("X-AspNet-Version")
	if aspNetVersion != "" {
		info = append(info, CreateInformation("aspnet_version_header", "ASP.NET Version Header",
			"X-AspNet-Version header", aspNetVersion))

		vuln := CreateVulnerability(
			"ASPNET-010",
			"ASP.NET Version Information Disclosure",
			"ASP.NET version information is exposed in HTTP header",
			"LOW",
			3.1,
		)
		vuln.URL = baseURL
		vuln.Method = "HEAD"
		vuln.Evidence = aspNetVersion
		vuln.Remediation = "Set enableVersionHeader='false' in web.config"
		vuln.CWE = "CWE-200"
		vuln.OWASP = "A05:2021 – Security Misconfiguration"
		vulns = append(vulns, vuln)
	}

	return vulns, info
}

// Helper functions

func (a *ASPNETSecurityModule) hasViewStateMAC(viewState []byte) bool {
	// ViewState MAC check (simple implementation)
	return len(viewState) > 20 && viewState[len(viewState)-20:] != nil
}

func (a *ASPNETSecurityModule) isViewStateEncrypted(viewState []byte) bool {
	// ViewState encryption check (simple implementation)
	// Encrypted ViewState usually appears more random
	return len(viewState) > 0 && viewState[0] != 0xFF
}

func (a *ASPNETSecurityModule) manipulateViewState(viewState string) string {
	// ViewState manipulation (simple implementation)
	if len(viewState) > 10 {
		// Change last character
		manipulated := viewState[:len(viewState)-1] + "A"
		return manipulated
	}
	return ""
}

func (a *ASPNETSecurityModule) testViewStateManipulation(client *http.Client, baseURL, manipulatedViewState string) *Vulnerability {
	formData := url.Values{}
	formData.Set("__VIEWSTATE", manipulatedViewState)

	resp, err := client.Post(baseURL, formData.Encode())
	if err != nil {
		return nil
	}
	a.IncrementRequests()

	// If ViewState manipulation is successful
	if resp.StatusCode == 200 && !strings.Contains(resp.Body, "ViewState") {
		vuln := CreateVulnerability(
			"ASPNET-011",
			"ViewState Manipulation Possible",
			"ViewState manipulation appears possible",
			"MEDIUM",
			6.1,
		)
		vuln.URL = baseURL
		vuln.Method = "POST"
		vuln.Payload = manipulatedViewState
		vuln.Evidence = "Manipulated ViewState accepted"
		vuln.Remediation = "Enable ViewState MAC validation"
		vuln.CWE = "CWE-345"
		return &vuln
	}

	return nil
}

func (a *ASPNETSecurityModule) testEventValidationBypass(client *http.Client, baseURL string) *Vulnerability {
	// Event validation bypass test (simple implementation)
	formData := url.Values{}
	formData.Set("__EVENTTARGET", "test")
	formData.Set("__EVENTARGUMENT", "test")

	resp, err := client.Post(baseURL, formData.Encode())
	if err != nil {
		return nil
	}
	a.IncrementRequests()

	if resp.StatusCode == 200 {
		vuln := CreateVulnerability(
			"ASPNET-012",
			"Event Validation Bypass",
			"Event validation bypass possible",
			"MEDIUM",
			5.3,
		)
		vuln.URL = baseURL
		vuln.Method = "POST"
		vuln.Evidence = "Event validation bypass successful"
		vuln.Remediation = "Enable event validation"
		vuln.CWE = "CWE-352"
		return &vuln
	}

	return nil
}

func (a *ASPNETSecurityModule) containsDetailedErrorInfo(body string) bool {
	errorIndicators := []string{
		"Server Error",
		"Stack Trace",
		"Source Error",
		"System.Web",
		"at System.",
		"Exception Details",
		"Version Information",
	}

	for _, indicator := range errorIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	return false
}

func (a *ASPNETSecurityModule) createPaddingOraclePayload(viewState string) string {
	// Create padding oracle payload (simple implementation)
	decoded, err := base64.StdEncoding.DecodeString(viewState)
	if err != nil {
		return viewState
	}

	// Change last byte
	if len(decoded) > 0 {
		decoded[len(decoded)-1] ^= 0x01
	}

	return base64.StdEncoding.EncodeToString(decoded)
}

func (a *ASPNETSecurityModule) isPaddingOracleVulnerable(responseBody string) bool {
	// Padding oracle vulnerability indicators
	oracleIndicators := []string{
		"padding is invalid",
		"Invalid viewstate",
		"MAC validation failed",
		"Validation of viewstate MAC failed",
	}

	lowerBody := strings.ToLower(responseBody)
	for _, indicator := range oracleIndicators {
		if strings.Contains(lowerBody, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}
