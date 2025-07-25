package modules

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/internal/config"
	"github.com/ibrahmsql/issmap/pkg/http"
	"github.com/ibrahmsql/issmap/pkg/logger"
)

// WindowsDetectionModule Windows Server tespit modülü
type WindowsDetectionModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewWindowsDetectionModule yeni Windows detection modülü oluşturur
func NewWindowsDetectionModule(cfg *config.Config, log *logger.Logger) Module {
	return &WindowsDetectionModule{
		BaseModule: NewBaseModule("windows_detection", "Windows Server Detection & Validation"),
		config:     cfg,
		logger:     log,
	}
}

// Run Windows detection modülünü çalıştırır
func (w *WindowsDetectionModule) Run(client *http.Client) (*ModuleResult, error) {
	w.Start()
	defer w.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := w.config.GetBaseURL()

	// 1. Server Header Kontrolü
	w.logger.Debug("Server header ile Windows tespiti yapılıyor...")
	serverInfo := w.detectWindowsFromHeaders(client, baseURL)
	info = append(info, serverInfo...)

	// 2. IIS Specific Response Pattern'ları
	w.logger.Debug("IIS response pattern'ları kontrol ediliyor...")
	iisInfo := w.detectIISPatterns(client, baseURL)
	info = append(info, iisInfo...)

	// 3. Windows-specific File/Directory Patterns
	w.logger.Debug("Windows-specific path'ler kontrol ediliyor...")
	pathInfo := w.detectWindowsPaths(client, baseURL)
	info = append(info, pathInfo...)

	// 4. ASP.NET Detection
	w.logger.Debug("ASP.NET tespiti yapılıyor...")
	aspnetInfo := w.detectASPNET(client, baseURL)
	info = append(info, aspnetInfo...)

	// 5. Windows Server Version Detection
	w.logger.Debug("Windows Server versiyonu tespit ediliyor...")
	versionInfo := w.detectWindowsVersion(client, baseURL)
	info = append(info, versionInfo...)

	// 6. Network Level Detection
	w.logger.Debug("Network seviyesinde Windows tespiti yapılıyor...")
	networkInfo := w.detectWindowsFromNetwork()
	info = append(info, networkInfo...)

	// Windows Server kontrolü
	isWindows := w.isWindowsServer(info)
	if !isWindows {
		vuln := CreateVulnerability(
			"WIN-DETECT-001",
			"Non-Windows Server Detected",
			"Hedef sistem Windows Server değil. IIS sadece Windows Server üzerinde çalışır.",
			"INFO",
			0.0,
		)
		vuln.URL = baseURL
		vuln.Evidence = "Windows Server tespit edilmedi"
		vuln.Remediation = "IIS taraması için Windows Server gereklidir"
		vulnerabilities = append(vulnerabilities, vuln)

		info = append(info, CreateInformation("os_detection", "Operating System",
			"Tespit edilen işletim sistemi", "Non-Windows"))
	} else {
		info = append(info, CreateInformation("os_detection", "Operating System",
			"Tespit edilen işletim sistemi", "Windows Server"))

		w.logger.Success("Windows Server tespit edildi, IIS taraması devam edebilir")
	}

	return w.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// detectWindowsFromHeaders server header'larından Windows tespiti
func (w *WindowsDetectionModule) detectWindowsFromHeaders(client *http.Client, baseURL string) []Information {
	var info []Information

	resp, err := client.Head(baseURL)
	if err != nil {
		return info
	}
	w.IncrementRequests()

	// Server header kontrolü
	serverHeader := resp.GetHeader("Server")
	if serverHeader != "" {
		info = append(info, CreateInformation("server_header", "Server Header",
			"HTTP Server header bilgisi", serverHeader))

		// Windows/IIS göstergeleri
		windowsIndicators := []string{
			"Microsoft-IIS",
			"Microsoft-HTTPAPI",
			"ASP.NET",
			"Windows",
		}

		for _, indicator := range windowsIndicators {
			if strings.Contains(serverHeader, indicator) {
				info = append(info, CreateInformation("windows_indicator", "Windows Indicator",
					fmt.Sprintf("Windows göstergesi tespit edildi: %s", indicator), indicator))
			}
		}
	}

	// X-Powered-By header
	poweredBy := resp.GetHeader("X-Powered-By")
	if poweredBy != "" && strings.Contains(poweredBy, "ASP.NET") {
		info = append(info, CreateInformation("aspnet_header", "ASP.NET Detection",
			"X-Powered-By header'ında ASP.NET tespit edildi", poweredBy))
	}

	// X-AspNet-Version header
	aspNetVersion := resp.GetHeader("X-AspNet-Version")
	if aspNetVersion != "" {
		info = append(info, CreateInformation("aspnet_version", "ASP.NET Version",
			"ASP.NET versiyon bilgisi", aspNetVersion))
	}

	return info
}

// detectIISPatterns IIS-specific pattern'ları tespit eder
func (w *WindowsDetectionModule) detectIISPatterns(client *http.Client, baseURL string) []Information {
	var info []Information

	// 404 error page testi
	resp, err := client.Get(baseURL + "/nonexistent-test-page-" + fmt.Sprintf("%d", time.Now().Unix()))
	if err == nil && resp.StatusCode == 404 {
		w.IncrementRequests()

		// IIS error page pattern'ları
		iisPatterns := map[string]string{
			"IIS 6.0":  `HTTP Error 404 - File or directory not found`,
			"IIS 7.0+": `HTTP Error 404.0 - Not Found`,
			"IIS":      `Internet Information Services`,
		}

		for version, pattern := range iisPatterns {
			if strings.Contains(resp.Body, pattern) {
				info = append(info, CreateInformation("iis_pattern", "IIS Pattern Detection",
					fmt.Sprintf("IIS pattern tespit edildi: %s", version), pattern))
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
					"Windows error pattern tespit edildi", pattern))
			}
		}
	}

	return info
}

// detectWindowsPaths Windows-specific path'leri kontrol eder
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
				fmt.Sprintf("Windows-specific path erişilebilir: %s", path),
				fmt.Sprintf("Status: %d", resp.StatusCode)))
		}
	}

	return info
}

// detectASPNET ASP.NET tespiti yapar
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

		// 404 dışındaki yanıtlar ASP.NET varlığını gösterebilir
		if resp.StatusCode != 404 {
			info = append(info, CreateInformation("aspnet_extension", "ASP.NET Extension",
				fmt.Sprintf("ASP.NET extension response: %s", ext),
				fmt.Sprintf("Status: %d", resp.StatusCode)))
		}
	}

	// ViewState kontrolü
	resp, err := client.Get(baseURL)
	if err == nil && resp.StatusCode == 200 {
		w.IncrementRequests()

		if strings.Contains(resp.Body, "__VIEWSTATE") {
			info = append(info, CreateInformation("viewstate", "ASP.NET ViewState",
				"ASP.NET ViewState tespit edildi", "__VIEWSTATE found"))
		}

		if strings.Contains(resp.Body, "__EVENTVALIDATION") {
			info = append(info, CreateInformation("eventvalidation", "ASP.NET EventValidation",
				"ASP.NET EventValidation tespit edildi", "__EVENTVALIDATION found"))
		}
	}

	return info
}

// detectWindowsVersion Windows Server versiyonunu tespit eder
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

	// Server header'dan IIS versiyonu çıkar
	resp, err := client.Head(baseURL)
	if err == nil {
		w.IncrementRequests()

		serverHeader := resp.GetHeader("Server")
		for iisVersion, windowsVersion := range iisVersionMap {
			if strings.Contains(serverHeader, "IIS/"+iisVersion) {
				info = append(info, CreateInformation("windows_version", "Windows Server Version",
					"Tespit edilen Windows Server versiyonu", windowsVersion))
				info = append(info, CreateInformation("iis_version", "IIS Version",
					"Tespit edilen IIS versiyonu", iisVersion))
				break
			}
		}
	}

	return info
}

// detectWindowsFromNetwork network seviyesinde Windows tespiti
func (w *WindowsDetectionModule) detectWindowsFromNetwork() []Information {
	var info []Information

	host := w.config.ParsedURL.Host

	// Port tarama (yaygın Windows portları)
	windowsPorts := []int{135, 139, 445, 1433, 3389, 5985, 5986}

	for _, port := range windowsPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
		if err == nil {
			conn.Close()
			info = append(info, CreateInformation("windows_port", "Windows Service Port",
				fmt.Sprintf("Windows service portu açık: %d", port),
				w.getPortDescription(port)))
		}
	}

	return info
}

// getPortDescription port açıklamasını döndürür
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

// isWindowsServer bilgilere göre Windows Server olup olmadığını kontrol eder
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

	// En az 2 Windows göstergesi varsa Windows Server kabul et
	return windowsIndicators >= 2
}
