package modules

import (
	"fmt"
	"strings"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// WappalyzerDetectionModule technology detection module using Wappalyzer
type WappalyzerDetectionModule struct {
	*BaseModule
	config           *config.Config
	logger           *logger.Logger
	wappalyzerClient *wappalyzer.Wappalyze
}

// NewWappalyzerDetectionModule creates a new Wappalyzer detection module
func NewWappalyzerDetectionModule(cfg *config.Config, log *logger.Logger) Module {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Error("Failed to create Wappalyzer client: %v", err)
		return nil
	}

	return &WappalyzerDetectionModule{
		BaseModule:       NewBaseModule("wappalyzer_detection", "Wappalyzer Technology Detection & Windows/IIS Validation"),
		config:           cfg,
		logger:           log,
		wappalyzerClient: wappalyzerClient,
	}
}

// Run executes the Wappalyzer detection module
func (w *WappalyzerDetectionModule) Run(client *http.Client) (*ModuleResult, error) {
	w.Start()
	defer w.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := w.config.GetBaseURL()

	// Get the main page
	w.logger.Debug("Performing technology detection with Wappalyzer...")
	resp, err := client.Get(baseURL)
	if err != nil {
		return w.CreateResult("ERROR", vulnerabilities, info, err), nil
	}
	w.IncrementRequests()

	// Wappalyzer fingerprinting
	fingerprints := w.wappalyzerClient.Fingerprint(resp.Headers, []byte(resp.Body))

	// Log detected technologies
	w.logger.Debug("Detected technologies: %v", fingerprints)

	// Add technology information as info
	for tech := range fingerprints {
		info = append(info, CreateInformation("detected_technology", "Detected Technology",
			"Technology detected by Wappalyzer", tech))
	}

	// Windows/IIS detection
	isWindows := w.isWindowsServer(fingerprints)
	isIIS := w.isIISServer(fingerprints)

	if isWindows {
		info = append(info, CreateInformation("os_detection", "Operating System",
			"Detected operating system", "Windows"))
		w.logger.Success("✅ Windows Server detected (Wappalyzer)")
	}

	if isIIS {
		info = append(info, CreateInformation("web_server", "Web Server",
			"Detected web server", "Microsoft IIS"))
		w.logger.Success("✅ Microsoft IIS detected (Wappalyzer)")

		// IIS version detection
		iisVersion := w.getIISVersion(fingerprints)
		if iisVersion != "" {
			info = append(info, CreateInformation("iis_version", "IIS Version",
				"Detected IIS version", iisVersion))
		}
	}

	// ASP.NET detection
	if w.isASPNET(fingerprints) {
		info = append(info, CreateInformation("framework", "Web Framework",
			"Detected web framework", "ASP.NET"))
		w.logger.Success("✅ ASP.NET detected (Wappalyzer)")

		// ASP.NET version detection
		aspnetVersion := w.getASPNETVersion(fingerprints)
		if aspnetVersion != "" {
			info = append(info, CreateInformation("aspnet_version", "ASP.NET Version",
				"Detected ASP.NET version", aspnetVersion))
		}
	}

	// Windows Server check - mark as vulnerability if not Windows
	if !isWindows && !isIIS {
		vuln := CreateVulnerability(
			"WAPP-DETECT-001",
			"Non-Windows/IIS Server Detected",
			"Target system is not Windows Server/IIS. This tool is designed specifically for IIS servers.",
			"INFO",
			0.0,
		)
		vuln.URL = baseURL
		vuln.Evidence = fmt.Sprintf("Detected technologies: %v", w.getTechnologyList(fingerprints))
		vuln.Remediation = "Windows Server and Microsoft IIS are required for IIS scanning"
		vulnerabilities = append(vulnerabilities, vuln)

		w.logger.Error("❌ Windows Server/IIS not detected (Wappalyzer)")
	}

	// Additional security checks
	securityVulns := w.checkSecurityTechnologies(fingerprints, baseURL)
	vulnerabilities = append(vulnerabilities, securityVulns...)

	return w.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// isWindowsServer checks if the server is Windows Server
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

// isIISServer checks if the server is IIS
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

// isASPNET checks if the server is running ASP.NET
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

// getIISVersion detects the IIS version
func (w *WappalyzerDetectionModule) getIISVersion(fingerprints map[string]struct{}) string {
	// Try to get version information from Wappalyzer
	for tech := range fingerprints {
		if strings.Contains(tech, "IIS") {
			// IIS version patterns
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

// getASPNETVersion detects the ASP.NET version
func (w *WappalyzerDetectionModule) getASPNETVersion(fingerprints map[string]struct{}) string {
	for tech := range fingerprints {
		if strings.Contains(tech, "ASP.NET") || strings.Contains(tech, ".NET") {
			// ASP.NET version patterns
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

// getTechnologyList returns the technology list as a string
func (w *WappalyzerDetectionModule) getTechnologyList(fingerprints map[string]struct{}) string {
	var technologies []string
	for tech := range fingerprints {
		technologies = append(technologies, tech)
	}
	return strings.Join(technologies, ", ")
}

// checkSecurityTechnologies checks for security technologies
func (w *WappalyzerDetectionModule) checkSecurityTechnologies(fingerprints map[string]struct{}, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Security technologies
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
			w.logger.Info("🛡️  Security technology detected: %s (%s)", tech, description)
		}
	}

	// Warning if no security technology found
	if !foundSecurity {
		vuln := CreateVulnerability(
			"WAPP-DETECT-002",
			"No Security Technologies Detected",
			"No security technologies (WAF, CDN) were detected",
			"LOW",
			3.1,
		)
		vuln.URL = baseURL
		vuln.Evidence = "No WAF, CDN or security technology found"
		vuln.Remediation = "Consider using WAF (Web Application Firewall) or CDN"
		vulns = append(vulns, vuln)
	}

	// Check for outdated technologies
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
					fmt.Sprintf("Outdated technology detected: %s", tech),
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL
				vuln.Evidence = fmt.Sprintf("Outdated technology: %s", tech)
				vuln.Remediation = "Upgrade technologies to current versions"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}
