package modules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// FingerprintModule IIS fingerprinting modülü
type FingerprintModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewFingerprintModule yeni fingerprint modülü oluşturur
func NewFingerprintModule(cfg *config.Config, log *logger.Logger) Module {
	return &FingerprintModule{
		BaseModule: NewBaseModule("fingerprint", "IIS Version Detection & Fingerprinting"),
		config:     cfg,
		logger:     log,
	}
}

// Run fingerprinting modülünü çalıştırır
func (f *FingerprintModule) Run(client *http.Client) (*ModuleResult, error) {
	f.Start()
	defer f.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := f.config.GetBaseURL()

	// 1. Server Header Analizi
	f.logger.Debug("Server header analizi yapılıyor...")
	serverInfo, serverVulns := f.analyzeServerHeaders(client, baseURL)
	info = append(info, serverInfo...)
	vulnerabilities = append(vulnerabilities, serverVulns...)

	// 2. IIS Version-Specific Response Pattern Analizi
	f.logger.Debug("IIS version pattern analizi yapılıyor...")
	versionInfo, versionVulns := f.analyzeVersionPatterns(client, baseURL)
	info = append(info, versionInfo...)
	vulnerabilities = append(vulnerabilities, versionVulns...)

	// 3. Hidden IIS Modules Tespiti
	f.logger.Debug("Gizli IIS modülleri taranıyor...")
	moduleInfo, moduleVulns := f.detectHiddenModules(client, baseURL)
	info = append(info, moduleInfo...)
	vulnerabilities = append(vulnerabilities, moduleVulns...)

	// 4. ISAPI Extension Enumeration
	f.logger.Debug("ISAPI extension'ları taranıyor...")
	isapiInfo, isapiVulns := f.enumerateISAPIExtensions(client, baseURL)
	info = append(info, isapiInfo...)
	vulnerabilities = append(vulnerabilities, isapiVulns...)

	// 5. ETW Leak Tespiti
	f.logger.Debug("ETW leak tespiti yapılıyor...")
	etwInfo, etwVulns := f.detectETWLeaks(client, baseURL)
	info = append(info, etwInfo...)
	vulnerabilities = append(vulnerabilities, etwVulns...)

	return f.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// analyzeServerHeaders server header'larını analiz eder
func (f *FingerprintModule) analyzeServerHeaders(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	resp, err := client.Head(baseURL)
	if err != nil {
		return info, vulns
	}
	f.IncrementRequests()

	// Server header kontrolü
	serverHeader := resp.GetHeader("Server")
	if serverHeader != "" {
		info = append(info, CreateInformation("server", "Server Header",
			"IIS server header bilgisi", serverHeader))

		// IIS version tespiti
		if strings.Contains(strings.ToLower(serverHeader), "iis") {
			version := f.extractIISVersion(serverHeader)
			if version != "" {
				info = append(info, CreateInformation("version", "IIS Version",
					"Tespit edilen IIS versiyonu", version))

				// Eski versiyon kontrolü
				if f.isVulnerableVersion(version) {
					vuln := CreateVulnerability(
						"IIS-FINGERPRINT-001",
						"Outdated IIS Version Detected",
						fmt.Sprintf("Eski IIS versiyonu tespit edildi: %s", version),
						"MEDIUM",
						5.3,
					)
					vuln.URL = baseURL
					vuln.Evidence = serverHeader
					vuln.Remediation = "IIS'i en son sürüme güncelleyin"
					vulns = append(vulns, vuln)
				}
			}
		}

		// Information disclosure
		if f.isVerboseServerHeader(serverHeader) {
			vuln := CreateVulnerability(
				"IIS-FINGERPRINT-002",
				"Verbose Server Header Information Disclosure",
				"Server header'ı fazla bilgi içeriyor",
				"LOW",
				3.1,
			)
			vuln.URL = baseURL
			vuln.Evidence = serverHeader
			vuln.Remediation = "Server header'ını minimize edin veya gizleyin"
			vulns = append(vulns, vuln)
		}
	}

	// X-Powered-By header kontrolü
	poweredBy := resp.GetHeader("X-Powered-By")
	if poweredBy != "" {
		info = append(info, CreateInformation("powered_by", "X-Powered-By Header",
			"X-Powered-By header bilgisi", poweredBy))

		vuln := CreateVulnerability(
			"IIS-FINGERPRINT-003",
			"X-Powered-By Header Information Disclosure",
			"X-Powered-By header'ı teknoloji bilgilerini açığa çıkarıyor",
			"LOW",
			2.6,
		)
		vuln.URL = baseURL
		vuln.Evidence = poweredBy
		vuln.Remediation = "X-Powered-By header'ını kaldırın"
		vulns = append(vulns, vuln)
	}

	// X-AspNet-Version header kontrolü
	aspNetVersion := resp.GetHeader("X-AspNet-Version")
	if aspNetVersion != "" {
		info = append(info, CreateInformation("aspnet_version", "ASP.NET Version",
			"ASP.NET versiyon bilgisi", aspNetVersion))

		vuln := CreateVulnerability(
			"IIS-FINGERPRINT-004",
			"ASP.NET Version Information Disclosure",
			"ASP.NET versiyon bilgisi açığa çıkıyor",
			"LOW",
			2.6,
		)
		vuln.URL = baseURL
		vuln.Evidence = aspNetVersion
		vuln.Remediation = "ASP.NET version header'ını gizleyin"
		vulns = append(vulns, vuln)
	}

	return info, vulns
}

// analyzeVersionPatterns IIS version pattern'larını analiz eder
func (f *FingerprintModule) analyzeVersionPatterns(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// 404 error page analizi
	resp, err := client.Get(baseURL + "/nonexistent-page-" + fmt.Sprintf("%d", f.startTime.Unix()))
	if err == nil && resp.StatusCode == 404 {
		f.IncrementRequests()

		// IIS error page pattern'ları
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
					"Error page pattern'ından tespit edilen versiyon", version))
				break
			}
		}
	}

	return info, vulns
}

// detectHiddenModules gizli IIS modüllerini tespit eder
func (f *FingerprintModule) detectHiddenModules(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// Yaygın IIS modül path'leri
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
				"Erişilebilir IIS modülü tespit edildi", path))

			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				vuln := CreateVulnerability(
					"IIS-FINGERPRINT-005",
					"Accessible IIS Administrative Path",
					fmt.Sprintf("IIS yönetim path'i erişilebilir: %s", path),
					"MEDIUM",
					4.3,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
				vuln.Remediation = "Gereksiz IIS modüllerini devre dışı bırakın"
				vulns = append(vulns, vuln)
			}
		}
	}

	return info, vulns
}

// enumerateISAPIExtensions ISAPI extension'ları enumerate eder
func (f *FingerprintModule) enumerateISAPIExtensions(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// Yaygın ISAPI extension'ları
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

		// 404 dışındaki yanıtlar ilginç
		if resp.StatusCode != 404 {
			info = append(info, CreateInformation("isapi_extension", "ISAPI Extension",
				"Aktif ISAPI extension tespit edildi", ext))

			// Bazı extension'lar güvenlik riski oluşturabilir
			dangerousExts := []string{".htr", ".ida", ".idq", ".idc", ".printer", ".htw"}
			for _, dangerous := range dangerousExts {
				if ext == dangerous {
					vuln := CreateVulnerability(
						"IIS-FINGERPRINT-006",
						"Dangerous ISAPI Extension Enabled",
						fmt.Sprintf("Tehlikeli ISAPI extension aktif: %s", ext),
						"HIGH",
						7.5,
					)
					vuln.URL = testURL
					vuln.Method = "GET"
					vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
					vuln.Remediation = "Gereksiz ISAPI extension'ları devre dışı bırakın"
					vulns = append(vulns, vuln)
					break
				}
			}
		}
	}

	return info, vulns
}

// detectETWLeaks ETW leak'lerini tespit eder
func (f *FingerprintModule) detectETWLeaks(client *http.Client, baseURL string) ([]Information, []Vulnerability) {
	var info []Information
	var vulns []Vulnerability

	// ETW trace bilgilerini tetikleyebilecek istekler
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

		// ETW leak pattern'ları
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
					"ETW trace bilgileri sızdırılıyor",
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL + trigger
				vuln.Method = "GET"
				vuln.Evidence = pattern
				vuln.Remediation = "Debug ve trace özelliklerini production'da devre dışı bırakın"
				vulns = append(vulns, vuln)
				break
			}
		}
	}

	return info, vulns
}

// extractIISVersion server header'ından IIS versiyonunu çıkarır
func (f *FingerprintModule) extractIISVersion(serverHeader string) string {
	re := regexp.MustCompile(`IIS/(\d+\.\d+)`)
	matches := re.FindStringSubmatch(serverHeader)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// isVulnerableVersion IIS versiyonunun zafiyet içerip içermediğini kontrol eder
func (f *FingerprintModule) isVulnerableVersion(version string) bool {
	vulnerableVersions := []string{"6.0", "7.0", "7.5", "8.0"}
	for _, vulnVersion := range vulnerableVersions {
		if version == vulnVersion {
			return true
		}
	}
	return false
}

// isVerboseServerHeader server header'ının fazla bilgi içerip içermediğini kontrol eder
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
