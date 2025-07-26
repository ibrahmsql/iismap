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

// ASPNETSecurityModule ASP.NET güvenlik kontrolleri modülü
type ASPNETSecurityModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewASPNETSecurityModule yeni ASP.NET security modülü oluşturur
func NewASPNETSecurityModule(cfg *config.Config, log *logger.Logger) Module {
	return &ASPNETSecurityModule{
		BaseModule: NewBaseModule("aspnet_security", "ASP.NET Security Vulnerabilities Scanner"),
		config:     cfg,
		logger:     log,
	}
}

// Run ASP.NET security modülünü çalıştırır
func (a *ASPNETSecurityModule) Run(client *http.Client) (*ModuleResult, error) {
	a.Start()
	defer a.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := a.config.GetBaseURL()

	// 1. ViewState Security Kontrolleri
	a.logger.Debug("ViewState güvenlik kontrolleri yapılıyor...")
	viewStateVulns, viewStateInfo := a.checkViewStateSecurity(client, baseURL)
	vulnerabilities = append(vulnerabilities, viewStateVulns...)
	info = append(info, viewStateInfo...)

	// 2. Event Validation Kontrolleri
	a.logger.Debug("Event validation kontrolleri yapılıyor...")
	eventVulns, eventInfo := a.checkEventValidation(client, baseURL)
	vulnerabilities = append(vulnerabilities, eventVulns...)
	info = append(info, eventInfo...)

	// 3. Trace.axd Exposure
	a.logger.Debug("Trace.axd exposure kontrol ediliyor...")
	traceVulns := a.checkTraceExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, traceVulns...)

	// 4. Elmah.axd Exposure
	a.logger.Debug("Elmah.axd exposure kontrol ediliyor...")
	elmahVulns := a.checkElmahExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, elmahVulns...)

	// 5. ASP.NET Error Information Disclosure
	a.logger.Debug("ASP.NET error information disclosure kontrol ediliyor...")
	errorVulns := a.checkErrorInformationDisclosure(client, baseURL)
	vulnerabilities = append(vulnerabilities, errorVulns...)

	// 6. Session Management Kontrolleri
	a.logger.Debug("Session management kontrolleri yapılıyor...")
	sessionVulns, sessionInfo := a.checkSessionManagement(client, baseURL)
	vulnerabilities = append(vulnerabilities, sessionVulns...)
	info = append(info, sessionInfo...)

	// 7. Padding Oracle Attacks
	a.logger.Debug("Padding oracle saldırıları test ediliyor...")
	paddingVulns := a.checkPaddingOracle(client, baseURL)
	vulnerabilities = append(vulnerabilities, paddingVulns...)

	// 8. ASP.NET Version Information Disclosure
	a.logger.Debug("ASP.NET version information disclosure kontrol ediliyor...")
	versionVulns, versionInfo := a.checkVersionDisclosure(client, baseURL)
	vulnerabilities = append(vulnerabilities, versionVulns...)
	info = append(info, versionInfo...)

	return a.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// checkViewStateSecurity ViewState güvenlik kontrollerini yapar
func (a *ASPNETSecurityModule) checkViewStateSecurity(client *http.Client, baseURL string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	// Ana sayfayı al
	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns, info
	}
	a.IncrementRequests()

	// ViewState varlığını kontrol et
	viewStateRegex := regexp.MustCompile(`__VIEWSTATE[^>]*value="([^"]*)"`)
	matches := viewStateRegex.FindStringSubmatch(resp.Body)

	if len(matches) > 1 {
		viewState := matches[1]
		info = append(info, CreateInformation("viewstate_found", "ViewState Found",
			"ASP.NET ViewState tespit edildi", "Present"))

		// ViewState decode et
		decodedViewState, err := base64.StdEncoding.DecodeString(viewState)
		if err == nil {
			info = append(info, CreateInformation("viewstate_size", "ViewState Size",
				"ViewState boyutu", fmt.Sprintf("%d bytes", len(decodedViewState))))

			// ViewState MAC kontrolü
			if !a.hasViewStateMAC(decodedViewState) {
				vuln := CreateVulnerability(
					"ASPNET-001",
					"ViewState MAC Validation Disabled",
					"ViewState MAC doğrulaması devre dışı. Bu durum ViewState manipulation saldırılarına açık bırakır.",
					"HIGH",
					7.5,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = "ViewState MAC hash bulunamadı"
				vuln.Remediation = "web.config'de enableViewStateMAC='true' ayarlayın"
				vuln.CWE = "CWE-345"
				vuln.OWASP = "A08:2021 – Software and Data Integrity Failures"
				vulns = append(vulns, vuln)
			}

			// ViewState encryption kontrolü
			if !a.isViewStateEncrypted(decodedViewState) {
				vuln := CreateVulnerability(
					"ASPNET-002",
					"ViewState Not Encrypted",
					"ViewState şifrelenmemiş. Hassas bilgiler ViewState'de açık olarak saklanabilir.",
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = "ViewState encryption tespit edilmedi"
				vuln.Remediation = "web.config'de viewStateEncryptionMode='Always' ayarlayın"
				vuln.CWE = "CWE-311"
				vuln.OWASP = "A02:2021 – Cryptographic Failures"
				vulns = append(vulns, vuln)
			}

			// ViewState manipulation testi
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
			"ASP.NET ViewState tespit edildi", "Not Present"))
	}

	return vulns, info
}

// checkEventValidation Event validation kontrollerini yapar
func (a *ASPNETSecurityModule) checkEventValidation(client *http.Client, baseURL string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns, info
	}
	a.IncrementRequests()

	// Event validation varlığını kontrol et
	if strings.Contains(resp.Body, "__EVENTVALIDATION") {
		info = append(info, CreateInformation("event_validation", "Event Validation",
			"ASP.NET Event Validation tespit edildi", "Enabled"))

		// Event validation bypass testi
		bypassVuln := a.testEventValidationBypass(client, baseURL)
		if bypassVuln != nil {
			vulns = append(vulns, *bypassVuln)
		}
	} else {
		info = append(info, CreateInformation("event_validation", "Event Validation",
			"ASP.NET Event Validation tespit edildi", "Disabled"))

		vuln := CreateVulnerability(
			"ASPNET-003",
			"Event Validation Disabled",
			"ASP.NET Event Validation devre dışı. Bu durum CSRF saldırılarına karşı korumayı zayıflatır.",
			"MEDIUM",
			6.1,
		)
		vuln.URL = baseURL
		vuln.Method = "GET"
		vuln.Evidence = "__EVENTVALIDATION field bulunamadı"
		vuln.Remediation = "web.config'de enableEventValidation='true' ayarlayın"
		vuln.CWE = "CWE-352"
		vuln.OWASP = "A01:2021 – Broken Access Control"
		vulns = append(vulns, vuln)
	}

	return vulns, info
}

// checkTraceExposure Trace.axd exposure'ını kontrol eder
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
				fmt.Sprintf("ASP.NET trace sayfası erişilebilir: %s", path),
				"HIGH",
				7.5,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "Application Trace sayfası erişilebilir"
			vuln.Remediation = "web.config'de trace enabled='false' ayarlayın"
			vuln.CWE = "CWE-200"
			vuln.OWASP = "A01:2021 – Broken Access Control"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkElmahExposure Elmah.axd exposure'ını kontrol eder
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
				fmt.Sprintf("ELMAH error log sayfası erişilebilir: %s", path),
				"HIGH",
				7.5,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "ELMAH error log sayfası erişilebilir"
			vuln.Remediation = "ELMAH'ı production'da devre dışı bırakın veya erişimi kısıtlayın"
			vuln.CWE = "CWE-200"
			vuln.OWASP = "A09:2021 – Security Logging and Monitoring Failures"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkErrorInformationDisclosure ASP.NET error information disclosure'ını kontrol eder
func (a *ASPNETSecurityModule) checkErrorInformationDisclosure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Error tetikleyici istekler
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
				"ASP.NET detaylı hata mesajları açığa çıkıyor",
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + trigger
			vuln.Method = "GET"
			vuln.Evidence = "Detaylı hata mesajı tespit edildi"
			vuln.Remediation = "web.config'de customErrors mode='On' ayarlayın"
			vuln.CWE = "CWE-200"
			vuln.OWASP = "A09:2021 – Security Logging and Monitoring Failures"
			vulns = append(vulns, vuln)
			break // Bir tane bulunca yeter
		}
	}

	return vulns
}

// checkSessionManagement session management kontrollerini yapar
func (a *ASPNETSecurityModule) checkSessionManagement(client *http.Client, baseURL string) ([]Vulnerability, []Information) {
	var vulns []Vulnerability
	var info []Information

	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns, info
	}
	a.IncrementRequests()

	// Session cookie kontrolü
	for _, cookie := range resp.Headers["Set-Cookie"] {
		if strings.Contains(strings.ToLower(cookie), "asp.net_sessionid") {
			info = append(info, CreateInformation("session_cookie", "ASP.NET Session Cookie",
				"ASP.NET session cookie tespit edildi", cookie))

			// HttpOnly kontrolü
			if !strings.Contains(strings.ToLower(cookie), "httponly") {
				vuln := CreateVulnerability(
					"ASPNET-007",
					"Session Cookie Missing HttpOnly Flag",
					"ASP.NET session cookie'si HttpOnly flag'i içermiyor",
					"MEDIUM",
					6.1,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = cookie
				vuln.Remediation = "web.config'de httpOnlyCookies='true' ayarlayın"
				vuln.CWE = "CWE-1004"
				vuln.OWASP = "A05:2021 – Security Misconfiguration"
				vulns = append(vulns, vuln)
			}

			// Secure flag kontrolü (HTTPS için)
			if a.config.ParsedURL.Scheme == "https" && !strings.Contains(strings.ToLower(cookie), "secure") {
				vuln := CreateVulnerability(
					"ASPNET-008",
					"Session Cookie Missing Secure Flag",
					"HTTPS üzerinde ASP.NET session cookie'si Secure flag'i içermiyor",
					"MEDIUM",
					6.1,
				)
				vuln.URL = baseURL
				vuln.Method = "GET"
				vuln.Evidence = cookie
				vuln.Remediation = "web.config'de requireSSL='true' ayarlayın"
				vuln.CWE = "CWE-614"
				vuln.OWASP = "A05:2021 – Security Misconfiguration"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, info
}

// checkPaddingOracle padding oracle saldırılarını test eder
func (a *ASPNETSecurityModule) checkPaddingOracle(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// ViewState ile padding oracle testi
	resp, err := client.Get(baseURL)
	if err != nil {
		return vulns
	}
	a.IncrementRequests()

	viewStateRegex := regexp.MustCompile(`__VIEWSTATE[^>]*value="([^"]*)"`)
	matches := viewStateRegex.FindStringSubmatch(resp.Body)

	if len(matches) > 1 {
		originalViewState := matches[1]

		// ViewState'i manipüle et (padding oracle için)
		manipulatedViewState := a.createPaddingOraclePayload(originalViewState)

		// POST isteği gönder
		formData := url.Values{}
		formData.Set("__VIEWSTATE", manipulatedViewState)

		postResp, err := client.Post(baseURL, formData.Encode())
		if err == nil {
			a.IncrementRequests()

			// Padding oracle göstergeleri
			if a.isPaddingOracleVulnerable(postResp.Body) {
				vuln := CreateVulnerability(
					"ASPNET-009",
					"ASP.NET Padding Oracle Vulnerability",
					"ASP.NET padding oracle zafiyeti tespit edildi",
					"HIGH",
					8.1,
				)
				vuln.URL = baseURL
				vuln.Method = "POST"
				vuln.Payload = manipulatedViewState
				vuln.Evidence = "Padding oracle response pattern tespit edildi"
				vuln.Remediation = "ASP.NET'i güncelleyin ve custom error pages kullanın"
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

// checkVersionDisclosure ASP.NET version disclosure'ını kontrol eder
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
			"X-AspNet-Version header'ı", aspNetVersion))

		vuln := CreateVulnerability(
			"ASPNET-010",
			"ASP.NET Version Information Disclosure",
			"ASP.NET versiyon bilgisi HTTP header'ında açığa çıkıyor",
			"LOW",
			3.1,
		)
		vuln.URL = baseURL
		vuln.Method = "HEAD"
		vuln.Evidence = aspNetVersion
		vuln.Remediation = "web.config'de enableVersionHeader='false' ayarlayın"
		vuln.CWE = "CWE-200"
		vuln.OWASP = "A05:2021 – Security Misconfiguration"
		vulns = append(vulns, vuln)
	}

	return vulns, info
}

// Helper functions

func (a *ASPNETSecurityModule) hasViewStateMAC(viewState []byte) bool {
	// ViewState MAC kontrolü (basit implementasyon)
	return len(viewState) > 20 && viewState[len(viewState)-20:] != nil
}

func (a *ASPNETSecurityModule) isViewStateEncrypted(viewState []byte) bool {
	// ViewState encryption kontrolü (basit implementasyon)
	// Şifrelenmiş ViewState genellikle daha rastgele görünür
	return len(viewState) > 0 && viewState[0] != 0xFF
}

func (a *ASPNETSecurityModule) manipulateViewState(viewState string) string {
	// ViewState manipulation (basit implementasyon)
	if len(viewState) > 10 {
		// Son karakteri değiştir
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

	// ViewState manipulation başarılıysa
	if resp.StatusCode == 200 && !strings.Contains(resp.Body, "ViewState") {
		vuln := CreateVulnerability(
			"ASPNET-011",
			"ViewState Manipulation Possible",
			"ViewState manipulation mümkün görünüyor",
			"MEDIUM",
			6.1,
		)
		vuln.URL = baseURL
		vuln.Method = "POST"
		vuln.Payload = manipulatedViewState
		vuln.Evidence = "Manipulated ViewState accepted"
		vuln.Remediation = "ViewState MAC validation'ı etkinleştirin"
		vuln.CWE = "CWE-345"
		return &vuln
	}

	return nil
}

func (a *ASPNETSecurityModule) testEventValidationBypass(client *http.Client, baseURL string) *Vulnerability {
	// Event validation bypass testi (basit implementasyon)
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
			"Event validation bypass mümkün",
			"MEDIUM",
			5.3,
		)
		vuln.URL = baseURL
		vuln.Method = "POST"
		vuln.Evidence = "Event validation bypass successful"
		vuln.Remediation = "Event validation'ı etkinleştirin"
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
	// Padding oracle payload oluştur (basit implementasyon)
	decoded, err := base64.StdEncoding.DecodeString(viewState)
	if err != nil {
		return viewState
	}

	// Son byte'ı değiştir
	if len(decoded) > 0 {
		decoded[len(decoded)-1] ^= 0x01
	}

	return base64.StdEncoding.EncodeToString(decoded)
}

func (a *ASPNETSecurityModule) isPaddingOracleVulnerable(responseBody string) bool {
	// Padding oracle vulnerability göstergeleri
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
