package modules

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// WindowsDetectionModule Windows Server detection module
type WindowsDetectionModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewWindowsDetectionModule creates new Windows detection module
func NewWindowsDetectionModule(cfg *config.Config, log *logger.Logger) Module {
	return &WindowsDetectionModule{
		BaseModule: NewBaseModule("windows_detection", "Windows Server Detection & Validation"),
		config:     cfg,
		logger:     log,
	}
}

// Run executes Windows detection module
func (w *WindowsDetectionModule) Run(client *http.Client) (*ModuleResult, error) {
	w.Start()
	defer w.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := w.config.GetBaseURL()

	// 1. Server Header Check
	w.logger.Debug("Performing Windows detection via server header...")
	serverInfo := w.detectWindowsFromHeaders(client, baseURL)
	info = append(info, serverInfo...)

	// 2. IIS Specific Response Patterns
	w.logger.Debug("Checking IIS response patterns...")
	iisInfo := w.detectIISPatterns(client, baseURL)
	info = append(info, iisInfo...)

	// 3. Windows-specific File/Directory Patterns
	w.logger.Debug("Checking Windows-specific paths...")
	pathInfo := w.detectWindowsPaths(client, baseURL)
	info = append(info, pathInfo...)

	// 4. ASP.NET Detection
	w.logger.Debug("Performing ASP.NET detection...")
	aspnetInfo := w.detectASPNET(client, baseURL)
	info = append(info, aspnetInfo...)

	// 5. Windows Server Version Detection
	w.logger.Debug("Detecting Windows Server version...")
	versionInfo := w.detectWindowsVersion(client, baseURL)
	info = append(info, versionInfo...)

	// 6. Network Level Detection
	w.logger.Debug("Performing network-level Windows detection...")
	networkInfo := w.detectWindowsFromNetwork()
	info = append(info, networkInfo...)

	// Windows Server check
	isWindows := w.isWindowsServer(info)
	if !isWindows {
		vuln := CreateVulnerability(
			"WIN-DETECT-001",
			"Non-Windows Server Detected",
			"Target system is not Windows Server. IIS only runs on Windows Server.",
			"INFO",
			0.0,
		)
		vuln.URL = baseURL
		vuln.Evidence = "Windows Server not detected"
		vuln.Remediation = "Windows Server is required for IIS scanning"
		vulnerabilities = append(vulnerabilities, vuln)

		info = append(info, CreateInformation("os_detection", "Operating System",
			"Detected operating system", "Non-Windows"))
	} else {
		info = append(info, CreateInformation("os_detection", "Operating System",
			"Detected operating system", "Windows Server"))

		w.logger.Success("Windows Server detected, IIS scanning can continue")
	}

	return w.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// detectWindowsFromHeaders detects Windows from server headers
func (w *WindowsDetectionModule) detectWindowsFromHeaders(client *http.Client, baseURL string) []Information {
	var info []Information

	resp, err := client.Head(baseURL)
	if err != nil {
		return info
	}
	w.IncrementRequests()

	// Server header check
	serverHeader := resp.GetHeader("Server")
	if serverHeader != "" {
		info = append(info, CreateInformation("server_header", "Server Header",
			"HTTP Server header information", serverHeader))

		// Windows/IIS indicators
		windowsIndicators := []string{
			"Microsoft-IIS",
			"Microsoft-HTTPAPI",
			"ASP.NET",
			"Windows",
		}

		for _, indicator := range windowsIndicators {
			if strings.Contains(serverHeader, indicator) {
				info = append(info, CreateInformation("windows_indicator", "Windows Indicator",
					fmt.Sprintf("Windows indicator detected: %s", indicator), indicator))
			}
		}
	}

	// X-Powered-By header
	poweredBy := resp.GetHeader("X-Powered-By")
	if poweredBy != "" && strings.Contains(poweredBy, "ASP.NET") {
		info = append(info, CreateInformation("aspnet_header", "ASP.NET Detection",
			"ASP.NET detected in X-Powered-By header", poweredBy))
	}

	// X-AspNet-Version header
	aspNetVersion := resp.GetHeader("X-AspNet-Version")
	if aspNetVersion != "" {
		info = append(info, CreateInformation("aspnet_version", "ASP.NET Version",
			"ASP.NET version information", aspNetVersion))
	}

	return info
}

// detectIISPatterns detects IIS-specific patterns
func (w *WindowsDetectionModule) detectIISPatterns(client *http.Client, baseURL string) []Information {
	var info []Information

	// 404 error page test
	resp, err := client.Get(baseURL + "/nonexistent-test-page-" + fmt.Sprintf("%d", time.Now().Unix()))
	if err == nil && resp.StatusCode == 404 {
		w.IncrementRequests()

		// IIS error page patterns
		iisPatterns := map[string]string{
			"IIS 6.0":  `HTTP Error 404 - File or directory not found`,
			"IIS 7.0+": `HTTP Error 404.0 - Not Found`,
			"IIS":      `Internet Information Services`,
		}

		for version, pattern := range iisPatterns {
			if strings.Contains(resp.Body, pattern) {
				info = append(info, CreateInformation("iis_pattern", "IIS Pattern Detection",
					fmt.Sprintf("IIS pattern detected: %s", version), pattern))
			}
		}

		// Windows-specific error patterns
		windowsErrorPatterns := []string{
			"Microsoft-IIS",
			"Internet Information Services",
			"Windows NT",
			"Microsoft Corporation",
		}

		for _, pattern := range windowsErrorPatterns {
			if strings.Contains(resp.Body, pattern) {
				info = append(info, CreateInformation("windows_error_pattern", "Windows Error Pattern",
					"Windows error pattern detected", pattern))
			}
		}
	}

	return info
}

// detectWindowsPaths checks Windows-specific paths
func (w *WindowsDetectionModule) detectWindowsPaths(client *http.Client, baseURL string) []Information {
	var info []Information

	// Windows-specific paths
	windowsPaths := []string{
		"/iisstart.htm",
		"/iisstart.png",
		"/welcome.png",
		"/iis-85.png",
		"/iis-8.png",
		"/iis-7.png",
		"/aspnet_client/",
		"/App_Data/",
		"/bin/",
		"/_vti_bin/",
		"/_vti_pvt/",
	}

	for _, path := range windowsPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		w.IncrementRequests()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			info = append(info, CreateInformation("windows_path", "Windows-specific Path",
				fmt.Sprintf("Windows-specific path accessible: %s", path),
				fmt.Sprintf("Status: %d", resp.StatusCode)))
		}
	}

	return info
}

// detectASPNET performs ASP.NET detection
func (w *WindowsDetectionModule) detectASPNET(client *http.Client, baseURL string) []Information {
	var info []Information

	// ASP.NET specific extensions
	aspnetExtensions := []string{".aspx", ".asmx", ".ashx", ".axd"}

	for _, ext := range aspnetExtensions {
		testURL := baseURL + "/test" + ext
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		w.IncrementRequests()

		// Responses other than 404 may indicate ASP.NET presence
		if resp.StatusCode != 404 {
			info = append(info, CreateInformation("aspnet_extension", "ASP.NET Extension",
				fmt.Sprintf("ASP.NET extension response: %s", ext),
				fmt.Sprintf("Status: %d", resp.StatusCode)))
		}
	}

	// ViewState check
	resp, err := client.Get(baseURL)
	if err == nil && resp.StatusCode == 200 {
		w.IncrementRequests()

		if strings.Contains(resp.Body, "__VIEWSTATE") {
			info = append(info, CreateInformation("viewstate", "ASP.NET ViewState",
				"ASP.NET ViewState detected", "__VIEWSTATE found"))
		}

		if strings.Contains(resp.Body, "__EVENTVALIDATION") {
			info = append(info, CreateInformation("eventvalidation", "ASP.NET EventValidation",
				"ASP.NET EventValidation detected", "__EVENTVALIDATION found"))
		}
	}

	return info
}

// detectWindowsVersion detects Windows Server version
func (w *WindowsDetectionModule) detectWindowsVersion(client *http.Client, baseURL string) []Information {
	var info []Information

	// IIS version to Windows Server mapping
	iisVersionMap := map[string]string{
		"6.0":  "Windows Server 2003",
		"7.0":  "Windows Server 2008",
		"7.5":  "Windows Server 2008 R2",
		"8.0":  "Windows Server 2012",
		"8.5":  "Windows Server 2012 R2",
		"10.0": "Windows Server 2016/2019/2022",
	}

	// Extract IIS version from server header
	resp, err := client.Head(baseURL)
	if err == nil {
		w.IncrementRequests()

		serverHeader := resp.GetHeader("Server")
		for iisVersion, windowsVersion := range iisVersionMap {
			if strings.Contains(serverHeader, "IIS/"+iisVersion) {
				info = append(info, CreateInformation("windows_version", "Windows Server Version",
					"Detected Windows Server version", windowsVersion))
				info = append(info, CreateInformation("iis_version", "IIS Version",
					"Detected IIS version", iisVersion))
				break
			}
		}
	}

	return info
}

// detectWindowsFromNetwork performs network-level Windows detection
func (w *WindowsDetectionModule) detectWindowsFromNetwork() []Information {
	var info []Information

	host := w.config.ParsedURL.Host

	// Port scanning (common Windows ports)
	windowsPorts := []int{135, 139, 445, 1433, 3389, 5985, 5986}

	for _, port := range windowsPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
		if err == nil {
			conn.Close()
			info = append(info, CreateInformation("windows_port", "Windows Service Port",
				fmt.Sprintf("Windows service port open: %d", port),
				w.getPortDescription(port)))
		}
	}

	return info
}

// getPortDescription returns port description
func (w *WindowsDetectionModule) getPortDescription(port int) string {
	descriptions := map[int]string{
		135:  "RPC Endpoint Mapper",
		139:  "NetBIOS Session Service",
		445:  "SMB/CIFS",
		1433: "SQL Server",
		3389: "Remote Desktop Protocol (RDP)",
		5985: "WinRM HTTP",
		5986: "WinRM HTTPS",
	}

	if desc, exists := descriptions[port]; exists {
		return desc
	}
	return "Unknown Windows Service"
}

// isWindowsServer checks if it's Windows Server based on information
func (w *WindowsDetectionModule) isWindowsServer(info []Information) bool {
	windowsIndicators := 0

	for _, infoItem := range info {
		switch infoItem.Type {
		case "windows_indicator", "aspnet_header", "aspnet_version", "iis_pattern",
			"windows_error_pattern", "windows_path", "aspnet_extension", "viewstate",
			"eventvalidation", "windows_version", "iis_version", "windows_port":
			windowsIndicators++
		case "server_header":
			if strings.Contains(strings.ToLower(infoItem.Value), "iis") ||
				strings.Contains(strings.ToLower(infoItem.Value), "microsoft") ||
				strings.Contains(strings.ToLower(infoItem.Value), "asp.net") {
				windowsIndicators++
			}
		}
	}

	// Accept as Windows Server if at least 2 Windows indicators are present
	return windowsIndicators >= 2
}
