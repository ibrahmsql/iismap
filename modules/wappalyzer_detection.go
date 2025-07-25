package modules

import (
	"fmt"
	"strings"

	"github.com/ibrahmsql/issmap/internal/config"
	"github.com/ibrahmsql/issmap/pkg/http"
	"github.com/ibrahmsql/issmap/pkg/logger"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// WappalyzerDetectionModule Wappalyzer ile teknoloji tespit modülü
type WappalyzerDetectionModule struct {
	*BaseModule
	config           *config.Config
	logger           *logger.Logger
	wappalyzerClient *wappalyzer.Wappalyze
}

// NewWappalyzerDetectionModule yeni Wappalyzer detection modülü oluşturur
func NewWappalyzerDetectionModule(cfg *config.Config, log *logger.Logger) Module {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Error("Wappalyzer client oluşturulamadı: %v", err)
		return nil
	}

	return &WappalyzerDetectionModule{
		BaseModule:       NewBaseModule("wappalyzer_detection", "Wappalyzer Technology Detection & Windows/IIS Validation"),
		config:           cfg,
		logger:           log,
		wappalyzerClient: wappalyzerClient,
	}
}

// Run Wappalyzer detection modülünü çalıştırır
func (w *WappalyzerDetectionModule) Run(client *http.Client) (*ModuleResult, error) {
	w.Start()
	defer w.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := w.config.GetBaseURL()

	// Ana sayfayı al
	w.logger.Debug("Wappalyzer ile teknoloji tespiti yapılıyor...")
	resp, err := client.Get(baseURL)
	if err != nil {
		return w.CreateResult("ERROR", vulnerabilities, info, err), nil
	}
	w.IncrementRequests()

	// Wappalyzer fingerprinting
	fingerprints := w.wappalyzerClient.Fingerprint(resp.Headers, []byte(resp.Body))

	// Tespit edilen teknolojileri logla
	w.logger.Debug("Tespit edilen teknolojiler: %v", fingerprints)

	// Teknoloji bilgilerini info olarak ekle
	for tech := range fingerprints {
		info = append(info, CreateInformation("detected_technology", "Detected Technology",
			"Wappalyzer ile tespit edilen teknoloji", tech))
	}

	// Windows/IIS kontrolü
	isWindows := w.isWindowsServer(fingerprints)
	isIIS := w.isIISServer(fingerprints)

	if isWindows {
		info = append(info, CreateInformation("os_detection", "Operating System",
			"Tespit edilen işletim sistemi", "Windows"))
		w.logger.Success("✅ Windows Server tespit edildi (Wappalyzer)")
	}

	if isIIS {
		info = append(info, CreateInformation("web_server", "Web Server",
			"Tespit edilen web sunucusu", "Microsoft IIS"))
		w.logger.Success("✅ Microsoft IIS tespit edildi (Wappalyzer)")

		// IIS versiyon tespiti
		iisVersion := w.getIISVersion(fingerprints)
		if iisVersion != "" {
			info = append(info, CreateInformation("iis_version", "IIS Version",
				"Tespit edilen IIS versiyonu", iisVersion))
		}
	}

	// ASP.NET tespiti
	if w.isASPNET(fingerprints) {
		info = append(info, CreateInformation("framework", "Web Framework",
			"Tespit edilen web framework", "ASP.NET"))
		w.logger.Success("✅ ASP.NET tespit edildi (Wappalyzer)")

		// ASP.NET versiyon tespiti
		aspnetVersion := w.getASPNETVersion(fingerprints)
		if aspnetVersion != "" {
			info = append(info, CreateInformation("aspnet_version", "ASP.NET Version",
				"Tespit edilen ASP.NET versiyonu", aspnetVersion))
		}
	}

	// Windows Server kontrolü - eğer Windows değilse zafiyet olarak işaretle
	if !isWindows && !isIIS {
		vuln := CreateVulnerability(
			"WAPP-DETECT-001",
			"Non-Windows/IIS Server Detected",
			"Hedef sistem Windows Server/IIS değil. Bu araç sadece IIS sunucuları için tasarlanmıştır.",
			"INFO",
			0.0,
		)
		vuln.URL = baseURL
		vuln.Evidence = fmt.Sprintf("Tespit edilen teknolojiler: %v", w.getTechnologyList(fingerprints))
		vuln.Remediation = "IIS taraması için Windows Server ve Microsoft IIS gereklidir"
		vulnerabilities = append(vulnerabilities, vuln)

		w.logger.Error("❌ Windows Server/IIS tespit edilmedi (Wappalyzer)")
	}

	// Ek güvenlik kontrolleri
	securityVulns := w.checkSecurityTechnologies(fingerprints, baseURL)
	vulnerabilities = append(vulnerabilities, securityVulns...)

	return w.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// isWindowsServer Windows Server olup olmadığını kontrol eder
func (w *WappalyzerDetectionModule) isWindowsServer(fingerprints map[string]struct{}) bool {
	windowsIndicators := []string{
		"Windows Server",
		"Microsoft IIS",
		"IIS",
		"ASP.NET",
		"Microsoft ASP.NET",
	}

	for _, indicator := range windowsIndicators {
		if _, exists := fingerprints[indicator]; exists {
			return true
		}
	}

	return false
}

// isIISServer IIS sunucu olup olmadığını kontrol eder
func (w *WappalyzerDetectionModule) isIISServer(fingerprints map[string]struct{}) bool {
	iisIndicators := []string{
		"Microsoft IIS",
		"IIS",
	}

	for _, indicator := range iisIndicators {
		if _, exists := fingerprints[indicator]; exists {
			return true
		}
	}

	return false
}

// isASPNET ASP.NET olup olmadığını kontrol eder
func (w *WappalyzerDetectionModule) isASPNET(fingerprints map[string]struct{}) bool {
	aspnetIndicators := []string{
		"ASP.NET",
		"Microsoft ASP.NET",
		".NET Framework",
		".NET Core",
	}

	for _, indicator := range aspnetIndicators {
		if _, exists := fingerprints[indicator]; exists {
			return true
		}
	}

	return false
}

// getIISVersion IIS versiyonunu tespit eder
func (w *WappalyzerDetectionModule) getIISVersion(fingerprints map[string]struct{}) string {
	// Wappalyzer'dan versiyon bilgisi almaya çalış
	for tech := range fingerprints {
		if strings.Contains(tech, "IIS") {
			// IIS version pattern'ları
			if strings.Contains(tech, "10.0") {
				return "10.0"
			} else if strings.Contains(tech, "8.5") {
				return "8.5"
			} else if strings.Contains(tech, "8.0") {
				return "8.0"
			} else if strings.Contains(tech, "7.5") {
				return "7.5"
			} else if strings.Contains(tech, "7.0") {
				return "7.0"
			} else if strings.Contains(tech, "6.0") {
				return "6.0"
			}
		}
	}

	return ""
}

// getASPNETVersion ASP.NET versiyonunu tespit eder
func (w *WappalyzerDetectionModule) getASPNETVersion(fingerprints map[string]struct{}) string {
	for tech := range fingerprints {
		if strings.Contains(tech, "ASP.NET") || strings.Contains(tech, ".NET") {
			// ASP.NET version pattern'ları
			if strings.Contains(tech, "Core") {
				return "ASP.NET Core"
			} else if strings.Contains(tech, "4.8") {
				return "4.8"
			} else if strings.Contains(tech, "4.7") {
				return "4.7"
			} else if strings.Contains(tech, "4.6") {
				return "4.6"
			} else if strings.Contains(tech, "4.5") {
				return "4.5"
			} else if strings.Contains(tech, "4.0") {
				return "4.0"
			} else if strings.Contains(tech, "3.5") {
				return "3.5"
			} else if strings.Contains(tech, "2.0") {
				return "2.0"
			}
		}
	}

	return ""
}

// getTechnologyList teknoloji listesini string olarak döndürür
func (w *WappalyzerDetectionModule) getTechnologyList(fingerprints map[string]struct{}) string {
	var technologies []string
	for tech := range fingerprints {
		technologies = append(technologies, tech)
	}
	return strings.Join(technologies, ", ")
}

// checkSecurityTechnologies güvenlik teknolojilerini kontrol eder
func (w *WappalyzerDetectionModule) checkSecurityTechnologies(fingerprints map[string]struct{}, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Güvenlik teknolojileri
	securityTechs := map[string]string{
		"Cloudflare":     "CDN/WAF",
		"AWS CloudFront": "CDN",
		"Akamai":         "CDN/Security",
		"Incapsula":      "WAF",
		"Sucuri":         "WAF",
		"ModSecurity":    "WAF",
	}

	foundSecurity := false
	for tech := range fingerprints {
		if description, exists := securityTechs[tech]; exists {
			foundSecurity = true
			w.logger.Info("🛡️  Güvenlik teknolojisi tespit edildi: %s (%s)", tech, description)
		}
	}

	// Güvenlik teknolojisi yoksa uyarı
	if !foundSecurity {
		vuln := CreateVulnerability(
			"WAPP-DETECT-002",
			"No Security Technologies Detected",
			"Herhangi bir güvenlik teknolojisi (WAF, CDN) tespit edilmedi",
			"LOW",
			3.1,
		)
		vuln.URL = baseURL
		vuln.Evidence = "WAF, CDN veya güvenlik teknolojisi bulunamadı"
		vuln.Remediation = "WAF (Web Application Firewall) veya CDN kullanmayı düşünün"
		vulns = append(vulns, vuln)
	}

	// Eski teknolojiler kontrolü
	oldTechs := []string{
		"jQuery 1.",
		"Bootstrap 2.",
		"AngularJS 1.",
		"PHP 5.",
		"Apache 2.2",
	}

	for tech := range fingerprints {
		for _, oldTech := range oldTechs {
			if strings.Contains(tech, oldTech) {
				vuln := CreateVulnerability(
					"WAPP-DETECT-003",
					"Outdated Technology Detected",
					fmt.Sprintf("Eski teknoloji tespit edildi: %s", tech),
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL
				vuln.Evidence = fmt.Sprintf("Eski teknoloji: %s", tech)
				vuln.Remediation = "Teknolojileri güncel versiyonlara yükseltin"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}
