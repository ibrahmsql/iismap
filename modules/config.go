package modules

import (
	"fmt"
	"strings"

	"github.com/ibrahmsql/issmap/internal/config"
	"github.com/ibrahmsql/issmap/pkg/http"
	"github.com/ibrahmsql/issmap/pkg/logger"
)

// ConfigModule IIS Configuration Vulnerabilities modülü
type ConfigModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewConfigModule yeni config modülü oluşturur
func NewConfigModule(cfg *config.Config, log *logger.Logger) Module {
	return &ConfigModule{
		BaseModule: NewBaseModule("config", "IIS Configuration Vulnerabilities Scanner"),
		config:     cfg,
		logger:     log,
	}
}

// Run config modülünü çalıştırır
func (c *ConfigModule) Run(client *http.Client) (*ModuleResult, error) {
	c.Start()
	defer c.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := c.config.GetBaseURL()

	// 1. web.config exposure kontrolü
	c.logger.Debug("web.config exposure kontrol ediliyor...")
	webConfigVulns := c.checkWebConfigExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, webConfigVulns...)

	// 2. machine.config leak tespiti
	c.logger.Debug("machine.config leak tespiti yapılıyor...")
	machineConfigVulns := c.checkMachineConfigLeak(client, baseURL)
	vulnerabilities = append(vulnerabilities, machineConfigVulns...)

	// 3. Global.asa/Global.asax exposure
	c.logger.Debug("Global.asa/Global.asax exposure kontrol ediliyor...")
	globalVulns := c.checkGlobalFileExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, globalVulns...)

	// 4. Bin directory enumeration
	c.logger.Debug("Bin directory enumeration yapılıyor...")
	binVulns := c.checkBinDirectoryAccess(client, baseURL)
	vulnerabilities = append(vulnerabilities, binVulns...)

	// 5. App_Data directory access kontrolü
	c.logger.Debug("App_Data directory access kontrol ediliyor...")
	appDataVulns := c.checkAppDataAccess(client, baseURL)
	vulnerabilities = append(vulnerabilities, appDataVulns...)

	// 6. Temporary ASP.NET files exposure
	c.logger.Debug("Temporary ASP.NET files exposure kontrol ediliyor...")
	tempVulns := c.checkTempFilesExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, tempVulns...)

	// 7. Backup files tespiti
	c.logger.Debug("Backup files tespiti yapılıyor...")
	backupVulns := c.checkBackupFiles(client, baseURL)
	vulnerabilities = append(vulnerabilities, backupVulns...)

	return c.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// checkWebConfigExposure web.config dosyası exposure'ını kontrol eder
func (c *ConfigModule) checkWebConfigExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// web.config dosyası path'leri
	configPaths := []string{
		"/web.config",
		"/Web.config",
		"/WEB.CONFIG",
		"/web.config.bak",
		"/web.config.old",
		"/web.config.backup",
		"/web.config~",
		"/web.config.txt",
		"/web.config.orig",
		"/web.config.sample",
		"/web.config.default",
		"/app/web.config",
		"/admin/web.config",
		"/test/web.config",
		"/backup/web.config",
	}

	for _, path := range configPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		c.IncrementRequests()

		if resp.StatusCode == 200 {
			// web.config içeriği kontrolü
			if c.isWebConfigContent(resp.Body) {
				severity := "HIGH"
				cvss := 7.5

				// Hassas bilgi kontrolü
				if c.containsSensitiveInfo(resp.Body) {
					severity = "CRITICAL"
					cvss = 9.1
				}

				vuln := CreateVulnerability(
					"IIS-CONFIG-001",
					"web.config File Exposure",
					fmt.Sprintf("web.config dosyası erişilebilir durumda: %s", path),
					severity,
					cvss,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = c.extractSensitiveConfigInfo(resp.Body)
				vuln.Remediation = "web.config dosyasına erişimi engelleyin ve hassas bilgileri şifreleyin"
				vuln.CWE = "CWE-200"
				vuln.OWASP = "A06:2021 – Vulnerable and Outdated Components"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// checkMachineConfigLeak machine.config leak'ini kontrol eder
func (c *ConfigModule) checkMachineConfigLeak(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// machine.config leak path'leri
	leakPaths := []string{
		"/machine.config",
		"/Machine.config",
		"/MACHINE.CONFIG",
		"/%WINDIR%/Microsoft.NET/Framework/v4.0.30319/Config/machine.config",
		"/%WINDIR%/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config",
		"/Windows/Microsoft.NET/Framework/v4.0.30319/Config/machine.config",
		"/Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config",
	}

	for _, path := range leakPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		c.IncrementRequests()

		if resp.StatusCode == 200 && strings.Contains(resp.Body, "<configuration>") {
			vuln := CreateVulnerability(
				"IIS-CONFIG-002",
				"machine.config File Leak",
				fmt.Sprintf("machine.config dosyası sızdırılıyor: %s", path),
				"CRITICAL",
				9.8,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "machine.config içeriği erişilebilir"
			vuln.Remediation = "machine.config dosyasına erişimi tamamen engelleyin"
			vuln.CWE = "CWE-200"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkGlobalFileExposure Global.asa/Global.asax exposure'ını kontrol eder
func (c *ConfigModule) checkGlobalFileExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Global dosya path'leri
	globalPaths := []string{
		"/Global.asa",
		"/Global.asax",
		"/global.asa",
		"/global.asax",
		"/GLOBAL.ASA",
		"/GLOBAL.ASAX",
		"/Global.asa.bak",
		"/Global.asax.bak",
		"/Global.asa.old",
		"/Global.asax.old",
		"/app/Global.asax",
		"/admin/Global.asax",
	}

	for _, path := range globalPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		c.IncrementRequests()

		if resp.StatusCode == 200 {
			// Global dosya içeriği kontrolü
			if c.isGlobalFileContent(resp.Body) {
				vuln := CreateVulnerability(
					"IIS-CONFIG-003",
					"Global Application File Exposure",
					fmt.Sprintf("Global uygulama dosyası erişilebilir: %s", path),
					"MEDIUM",
					6.5,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = "Global dosya içeriği görüntülenebilir"
				vuln.Remediation = "Global dosyalarına doğrudan erişimi engelleyin"
				vuln.CWE = "CWE-200"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// checkBinDirectoryAccess bin directory erişimini kontrol eder
func (c *ConfigModule) checkBinDirectoryAccess(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Bin directory path'leri
	binPaths := []string{
		"/bin/",
		"/Bin/",
		"/BIN/",
		"/app/bin/",
		"/admin/bin/",
		"/bin/debug/",
		"/bin/release/",
	}

	for _, path := range binPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		c.IncrementRequests()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			// Directory listing kontrolü
			if c.isDirectoryListing(resp.Body) {
				vuln := CreateVulnerability(
					"IIS-CONFIG-004",
					"Bin Directory Listing Enabled",
					fmt.Sprintf("Bin directory listing aktif: %s", path),
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = "Directory listing görüntülenebilir"
				vuln.Remediation = "Bin directory'ye erişimi engelleyin ve directory listing'i devre dışı bırakın"
				vuln.CWE = "CWE-200"
				vulns = append(vulns, vuln)
			}
		}

		// DLL dosyalarına doğrudan erişim testi
		dllFiles := []string{"System.Web.dll", "System.dll", "mscorlib.dll"}
		for _, dll := range dllFiles {
			dllResp, err := client.Get(baseURL + path + dll)
			if err != nil {
				continue
			}
			c.IncrementRequests()

			if dllResp.StatusCode == 200 {
				vuln := CreateVulnerability(
					"IIS-CONFIG-005",
					"DLL File Direct Access",
					fmt.Sprintf("DLL dosyasına doğrudan erişim mümkün: %s%s", path, dll),
					"HIGH",
					7.5,
				)
				vuln.URL = baseURL + path + dll
				vuln.Method = "GET"
				vuln.Evidence = "DLL dosyası indirilebilir"
				vuln.Remediation = "DLL dosyalarına doğrudan erişimi engelleyin"
				vuln.CWE = "CWE-200"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// checkAppDataAccess App_Data directory erişimini kontrol eder
func (c *ConfigModule) checkAppDataAccess(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// App_Data path'leri
	appDataPaths := []string{
		"/App_Data/",
		"/app_data/",
		"/APP_DATA/",
		"/App_Data/database.mdb",
		"/App_Data/database.sdf",
		"/App_Data/logs/",
		"/App_Data/temp/",
		"/App_Data/cache/",
	}

	for _, path := range appDataPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		c.IncrementRequests()

		if resp.StatusCode == 200 {
			vuln := CreateVulnerability(
				"IIS-CONFIG-006",
				"App_Data Directory Access",
				fmt.Sprintf("App_Data directory'ye erişim mümkün: %s", path),
				"HIGH",
				7.5,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "App_Data içeriği erişilebilir"
			vuln.Remediation = "App_Data directory'ye erişimi tamamen engelleyin"
			vuln.CWE = "CWE-200"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkTempFilesExposure temporary ASP.NET files exposure'ını kontrol eder
func (c *ConfigModule) checkTempFilesExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Temporary files path'leri
	tempPaths := []string{
		"/Temporary ASP.NET Files/",
		"/Windows/Microsoft.NET/Framework/v4.0.30319/Temporary ASP.NET Files/",
		"/Windows/Microsoft.NET/Framework64/v4.0.30319/Temporary ASP.NET Files/",
		"/temp/",
		"/tmp/",
		"/cache/",
		"/_temp/",
		"/_cache/",
	}

	for _, path := range tempPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		c.IncrementRequests()

		if resp.StatusCode == 200 && c.isDirectoryListing(resp.Body) {
			vuln := CreateVulnerability(
				"IIS-CONFIG-007",
				"Temporary Files Directory Exposure",
				fmt.Sprintf("Temporary files directory erişilebilir: %s", path),
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "Temporary files directory listing görüntülenebilir"
			vuln.Remediation = "Temporary files directory'ye erişimi engelleyin"
			vuln.CWE = "CWE-200"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkBackupFiles backup dosyalarını kontrol eder
func (c *ConfigModule) checkBackupFiles(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Backup file pattern'ları
	backupPatterns := []string{
		"/backup/",
		"/backups/",
		"/bak/",
		"/old/",
		"/orig/",
		"/copy/",
		"/web.config.bak",
		"/default.aspx.bak",
		"/index.aspx.old",
		"/login.aspx.orig",
		"/admin.aspx.backup",
		"/database.bak",
		"/site.zip",
		"/backup.zip",
		"/www.zip",
		"/web.rar",
	}

	for _, pattern := range backupPatterns {
		resp, err := client.Get(baseURL + pattern)
		if err != nil {
			continue
		}
		c.IncrementRequests()

		if resp.StatusCode == 200 {
			vuln := CreateVulnerability(
				"IIS-CONFIG-008",
				"Backup File Exposure",
				fmt.Sprintf("Backup dosyası erişilebilir: %s", pattern),
				"MEDIUM",
				6.5,
			)
			vuln.URL = baseURL + pattern
			vuln.Method = "GET"
			vuln.Evidence = "Backup dosyası indirilebilir"
			vuln.Remediation = "Backup dosyalarını web root dışına taşıyın"
			vuln.CWE = "CWE-200"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// Helper functions

func (c *ConfigModule) isWebConfigContent(body string) bool {
	indicators := []string{
		"<configuration>",
		"<system.web>",
		"<appSettings>",
		"<connectionStrings>",
		"<system.webServer>",
	}

	for _, indicator := range indicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	return false
}

func (c *ConfigModule) containsSensitiveInfo(body string) bool {
	sensitivePatterns := []string{
		"connectionString",
		"password",
		"pwd",
		"secret",
		"key",
		"token",
		"api",
		"database",
		"server=",
		"uid=",
		"user id=",
	}

	lowerBody := strings.ToLower(body)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}
	return false
}

func (c *ConfigModule) extractSensitiveConfigInfo(body string) string {
	// Hassas bilgilerin bir kısmını evidence olarak döndür
	if len(body) > 500 {
		return body[:500] + "..."
	}
	return body
}

func (c *ConfigModule) isGlobalFileContent(body string) bool {
	indicators := []string{
		"Application_Start",
		"Application_End",
		"Session_Start",
		"Session_End",
		"<script runat=\"server\">",
		"<%@ Application",
	}

	for _, indicator := range indicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	return false
}

func (c *ConfigModule) isDirectoryListing(body string) bool {
	indicators := []string{
		"Directory Listing",
		"Index of /",
		"<title>Directory Listing",
		"Parent Directory",
		"[DIR]",
		"<pre>",
	}

	for _, indicator := range indicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	return false
}
