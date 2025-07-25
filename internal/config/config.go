package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Config ana konfigürasyon yapısı
type Config struct {
	// Hedef bilgileri
	Target    string
	ParsedURL *url.URL

	// Modül seçenekleri
	Modules       []string
	Comprehensive bool
	Fast          bool

	// Tarama seçenekleri
	Stealth bool
	Delay   time.Duration
	Threads int
	Timeout time.Duration

	// Çıktı seçenekleri
	Output string
	Format string

	// Network seçenekleri
	Proxy     string
	UserAgent string
	Cookies   map[string]string
	Headers   map[string]string

	// Debug seçenekleri
	Verbose bool
	Debug   bool
}

// LoadFromFlags cobra command'dan konfigürasyonu yükler
func LoadFromFlags(cmd *cobra.Command) (*Config, error) {
	cfg := &Config{}

	var err error

	// Temel parametreler
	cfg.Target, _ = cmd.Flags().GetString("target")
	modules, _ := cmd.Flags().GetString("modules")
	cfg.Modules = parseModules(modules)
	cfg.Comprehensive, _ = cmd.Flags().GetBool("comprehensive")
	cfg.Fast, _ = cmd.Flags().GetBool("fast")

	// Tarama seçenekleri
	cfg.Stealth, _ = cmd.Flags().GetBool("stealth")
	delay, _ := cmd.Flags().GetFloat64("delay")
	cfg.Delay = time.Duration(delay * float64(time.Second))
	cfg.Threads, _ = cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetInt("timeout")
	cfg.Timeout = time.Duration(timeout) * time.Second

	// Çıktı seçenekleri
	cfg.Output, _ = cmd.Flags().GetString("output")
	cfg.Format, _ = cmd.Flags().GetString("format")

	// Network seçenekleri
	cfg.Proxy, _ = cmd.Flags().GetString("proxy")
	cfg.UserAgent, _ = cmd.Flags().GetString("user-agent")
	if cfg.UserAgent == "" {
		cfg.UserAgent = getDefaultUserAgent()
	}

	cookies, _ := cmd.Flags().GetString("cookies")
	cfg.Cookies = parseCookies(cookies)

	headers, _ := cmd.Flags().GetString("headers")
	cfg.Headers = parseHeaders(headers)

	// Debug seçenekleri
	cfg.Verbose, _ = cmd.Flags().GetBool("verbose")
	cfg.Debug, _ = cmd.Flags().GetBool("debug")

	// URL'yi parse et
	cfg.ParsedURL, err = url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("geçersiz URL: %v", err)
	}

	// Varsayılan değerleri ayarla
	cfg.setDefaults()

	return cfg, nil
}

// ValidateTarget hedef URL'yi doğrular
func (c *Config) ValidateTarget() error {
	if c.ParsedURL.Scheme == "" || c.ParsedURL.Host == "" {
		return fmt.Errorf("geçersiz URL formatı")
	}

	if c.ParsedURL.Scheme != "http" && c.ParsedURL.Scheme != "https" {
		return fmt.Errorf("sadece HTTP/HTTPS protokolleri desteklenir")
	}

	return nil
}

// GetBaseURL base URL'yi döndürür
func (c *Config) GetBaseURL() string {
	return fmt.Sprintf("%s://%s", c.ParsedURL.Scheme, c.ParsedURL.Host)
}

// parseModules modül listesini parse eder
func parseModules(modules string) []string {
	if modules == "" {
		return getDefaultModules()
	}

	var result []string
	for _, module := range strings.Split(modules, ",") {
		result = append(result, strings.TrimSpace(module))
	}

	return result
}

// getDefaultModules varsayılan modül listesi
func getDefaultModules() []string {
	return []string{
		"wappalyzer_detection",
		"fingerprint",
		"advanced_shortscan",
		"config",
		"aspnet",
		"http_methods",
		"ssl_tls",
	}
}

// getAllModules tüm mevcut modüller
func getAllModules() []string {
	return []string{
		"wappalyzer_detection",
		"windows_detection",
		"fingerprint",
		"tilde",
		"enhanced_tilde",
		"advanced_shortscan",
		"config",
		"aspnet",
		"http_methods",
		"ssl_tls",
		"path_traversal",
		"handlers",
		"auth_bypass",
		"buffer_overflow",
		"webdav",
		"information_disclosure",
		"file_upload",
		"sql_injection",
		"xss",
		"csrf",
	}
}

// getDefaultUserAgent varsayılan User-Agent
func getDefaultUserAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

// parseCookies cookie string'ini parse eder
func parseCookies(cookieStr string) map[string]string {
	cookies := make(map[string]string)

	if cookieStr == "" {
		return cookies
	}

	for _, cookie := range strings.Split(cookieStr, ";") {
		parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
		if len(parts) == 2 {
			cookies[parts[0]] = parts[1]
		}
	}

	return cookies
}

// parseHeaders header string'ini parse eder
func parseHeaders(headerStr string) map[string]string {
	headers := make(map[string]string)

	if headerStr == "" {
		return headers
	}

	for _, header := range strings.Split(headerStr, ",") {
		parts := strings.SplitN(strings.TrimSpace(header), ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return headers
}

// setDefaults varsayılan değerleri ayarlar
func (c *Config) setDefaults() {
	// Fast modda daha hızlı tarama
	if c.Fast {
		c.Delay = 0 // Hiç delay yok
		if c.Threads < 50 {
			c.Threads = 50
		}
		if c.Timeout > 3*time.Second {
			c.Timeout = 3 * time.Second
		}
	}

	// Stealth modda daha yavaş tarama
	if c.Stealth {
		if c.Delay < time.Second {
			c.Delay = time.Second
		}
		if c.Threads > 5 {
			c.Threads = 5
		}
	}

	// Comprehensive modda tüm modüller
	if c.Comprehensive {
		c.Modules = getAllModules()
	}

	// Windows detection modülünü her zaman ekle (eğer yoksa)
	c.ensureWindowsDetection()

	// Output dosyası belirtilmemişse varsayılan
	if c.Output == "" {
		c.Output = fmt.Sprintf("iis_scan_report_%d.%s",
			time.Now().Unix(), c.Format)
	}
}

// ensureWindowsDetection Windows detection modülünün listede olduğundan emin olur
func (c *Config) ensureWindowsDetection() {
	hasWindowsDetection := false
	for _, module := range c.Modules {
		if module == "wappalyzer_detection" || module == "windows_detection" {
			hasWindowsDetection = true
			break
		}
	}

	if !hasWindowsDetection {
		// Wappalyzer detection'ı listenin başına ekle
		newModules := []string{"wappalyzer_detection"}
		newModules = append(newModules, c.Modules...)
		c.Modules = newModules
	}
}
