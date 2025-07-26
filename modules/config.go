package modules
import (
	"fmt"
	"strings"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// ConfigModule IIS Configuration Vulnerabilities module
type ConfigModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewConfigModule creates new config module
func NewConfigModule(cfg *config.Config, log *logger.Logger) Module {
	return &ConfigModule{
		BaseModule: NewBaseModule("config", "IIS Configuration Vulnerabilities Scanner"),
		config:     cfg,
		logger:     log,
	}
}

// Run executes config module
func (c *ConfigModule) Run(client *http.Client) (*ModuleResult, error) {
	c.Start()
	defer c.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := c.config.GetBaseURL()

	// 1. web.config exposure check
	c.logger.Debug("Checking web.config exposure...")
	webConfigVulns := c.checkWebConfigExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, webConfigVulns...)

	// 2. machine.config leak detection
	c.logger.Debug("Detecting machine.config leak...")
	machineConfigVulns := c.checkMachineConfigLeak(client, baseURL)
	vulnerabilities = append(vulnerabilities, machineConfigVulns...)

	// 3. Global.asa/Global.asax exposure
	c.logger.Debug("Checking Global.asa/Global.asax exposure...")
	globalVulns := c.checkGlobalFileExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, globalVulns...)

	// 4. Bin directory enumeration
	c.logger.Debug("Performing bin directory enumeration...")
	binVulns := c.checkBinDirectoryAccess(client, baseURL)
	vulnerabilities = append(vulnerabilities, binVulns...)

	// 5. App_Data directory access check
	c.logger.Debug("Checking App_Data directory access...")
	appDataVulns := c.checkAppDataAccess(client, baseURL)
	vulnerabilities = append(vulnerabilities, appDataVulns...)

	// 6. Temporary ASP.NET files exposure
	c.logger.Debug("Checking temporary ASP.NET files exposure...")
	tempVulns := c.checkTempFilesExposure(client, baseURL)
	vulnerabilities = append(vulnerabilities, tempVulns...)

	// 7. Backup files detection
	c.logger.Debug("Detecting backup files...")
	backupVulns := c.checkBackupFiles(client, baseURL)
	vulnerabilities = append(vulnerabilities, backupVulns...)

	return c.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// checkWebConfigExposure checks web.config file exposure
func (c *ConfigModule) checkWebConfigExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// web.config file paths
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
			// web.config content check
			if c.isWebConfigContent(resp.Body) {
				severity := "HIGH"
				cvss := 7.5

				// Sensitive information check
				if c.containsSensitiveInfo(resp.Body) {
					severity = "CRITICAL"
					cvss = 9.1
				}

				vuln := CreateVulnerability(
					"IIS-CONFIG-001",
					"web.config File Exposure",
					fmt.Sprintf("web.config file is accessible: %s", path),
					severity,
					cvss,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = c.extractSensitiveConfigInfo(resp.Body)
				vuln.Remediation = "Block access to web.config file and encrypt sensitive information"
				vuln.CWE = "CWE-200"
				vuln.OWASP = "A06:2021 – Vulnerable and Outdated Components"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// checkMachineConfigLeak checks machine.config leak
func (c *ConfigModule) checkMachineConfigLeak(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// machine.config leak paths
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
				fmt.Sprintf("machine.config file is leaking: %s", path),
				"CRITICAL",
				9.8,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "machine.config content is accessible"
			vuln.Remediation = "Completely block access to machine.config file"
			vuln.CWE = "CWE-200"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkGlobalFileExposure checks Global.asa/Global.asax exposure
func (c *ConfigModule) checkGlobalFileExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Global file paths
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
			// Global file content check
			if c.isGlobalFileContent(resp.Body) {
				vuln := CreateVulnerability(
					"IIS-CONFIG-003",
					"Global Application File Exposure",
					fmt.Sprintf("Global application file is accessible: %s", path),
					"MEDIUM",
					6.5,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = "Global file content is viewable"
				vuln.Remediation = "Block direct access to Global files"
				vuln.CWE = "CWE-200"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// checkBinDirectoryAccess checks bin directory access
func (c *ConfigModule) checkBinDirectoryAccess(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Bin directory paths
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
			// Directory listing check
			if c.isDirectoryListing(resp.Body) {
				vuln := CreateVulnerability(
					"IIS-CONFIG-004",
					"Bin Directory Listing Enabled",
					fmt.Sprintf("Bin directory listing is active: %s", path),
					"MEDIUM",
					5.3,
				)
				vuln.URL = baseURL + path
				vuln.Method = "GET"
				vuln.Evidence = "Directory listing is viewable"
				vuln.Remediation = "Block access to Bin directory and disable directory listing"
				vuln.CWE = "CWE-200"
				vulns = append(vulns, vuln)
			}
		}

		// Direct access test to DLL files
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
					fmt.Sprintf("Direct access to DLL file is possible: %s%s", path, dll),
					"HIGH",
					7.5,
				)
				vuln.URL = baseURL + path + dll
				vuln.Method = "GET"
				vuln.Evidence = "DLL file is downloadable"
				vuln.Remediation = "Block direct access to DLL files"
				vuln.CWE = "CWE-200"
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// checkAppDataAccess checks App_Data directory access
func (c *ConfigModule) checkAppDataAccess(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// App_Data paths
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
				fmt.Sprintf("App_Data directory access is possible: %s", path),
				"HIGH",
				7.5,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "App_Data content is accessible"
			vuln.Remediation = "Completely block access to App_Data directory"
			vuln.CWE = "CWE-200"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkTempFilesExposure checks temporary ASP.NET files exposure
func (c *ConfigModule) checkTempFilesExposure(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Temporary files paths
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
				fmt.Sprintf("Temporary files directory is accessible: %s", path),
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + path
			vuln.Method = "GET"
			vuln.Evidence = "Temporary files directory listing is viewable"
			vuln.Remediation = "Block access to temporary files directory"
			vuln.CWE = "CWE-200"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// checkBackupFiles checks backup files
func (c *ConfigModule) checkBackupFiles(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Backup file patterns
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
				fmt.Sprintf("Backup file is accessible: %s", pattern),
				"MEDIUM",
				6.5,
			)
			vuln.URL = baseURL + pattern
			vuln.Method = "GET"
			vuln.Evidence = "Backup file is downloadable"
			vuln.Remediation = "Move backup files outside web root"
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
	// Return part of sensitive information as evidence
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
