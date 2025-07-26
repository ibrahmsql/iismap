package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Config main configuration structure
type Config struct {
	// Hedef bilgileri
	Target    string
	ParsedURL *url.URL

	// Module options
	Modules       []string
	Wordlist      string
	Comprehensive bool
	Fast          bool

	// Scan options
	Stealth bool
	Delay   time.Duration
	Threads int
	Timeout time.Duration

	// Output options
	Output string
	Format string

	// Network options
	Proxy     string
	UserAgent string
	Cookies   map[string]string
	Headers   map[string]string

	// Debug options
	Verbose bool
	Debug   bool
}

// LoadFromFlags loads configuration from cobra command
func LoadFromFlags(cmd *cobra.Command) (*Config, error) {
	cfg := &Config{}

	var err error

	// Temel parametreler
	cfg.Target, _ = cmd.Flags().GetString("target")
	modules, _ := cmd.Flags().GetString("modules")
	cfg.Modules = parseModules(modules)
	cfg.Comprehensive, _ = cmd.Flags().GetBool("comprehensive")
	cfg.Fast, _ = cmd.Flags().GetBool("fast")

	// Scanning options
	cfg.Stealth, _ = cmd.Flags().GetBool("stealth")
	delay, _ := cmd.Flags().GetFloat64("delay")
	cfg.Delay = time.Duration(delay * float64(time.Second))
	cfg.Threads, _ = cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetInt("timeout")
	cfg.Timeout = time.Duration(timeout) * time.Second

	// Output options
	cfg.Output, _ = cmd.Flags().GetString("output")
	cfg.Format, _ = cmd.Flags().GetString("format")

	// Network options
	cfg.Proxy, _ = cmd.Flags().GetString("proxy")
	cfg.UserAgent, _ = cmd.Flags().GetString("user-agent")
	if cfg.UserAgent == "" {
		cfg.UserAgent = getDefaultUserAgent()
	}

	cookies, _ := cmd.Flags().GetString("cookies")
	cfg.Cookies = parseCookies(cookies)

	headers, _ := cmd.Flags().GetString("headers")
	cfg.Headers = parseHeaders(headers)

	// Debug options
	cfg.Verbose, _ = cmd.Flags().GetBool("verbose")
	cfg.Debug, _ = cmd.Flags().GetBool("debug")

	// URL'yi parse et
	cfg.ParsedURL, err = url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	// Set default values
	cfg.setDefaults()

	return cfg, nil
}

// ValidateTarget validates target URL
func (c *Config) ValidateTarget() error {
	if c.ParsedURL.Scheme == "" || c.ParsedURL.Host == "" {
		return fmt.Errorf("invalid URL format")
	}

	if c.ParsedURL.Scheme != "http" && c.ParsedURL.Scheme != "https" {
		return fmt.Errorf("only HTTP/HTTPS protocols are supported")
	}

	return nil
}

// GetBaseURL returns base URL
func (c *Config) GetBaseURL() string {
	return fmt.Sprintf("%s://%s", c.ParsedURL.Scheme, c.ParsedURL.Host)
}

// parseModules parses module list
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

// getDefaultModules returns default module list
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

// getAllModules returns all available modules
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

// setDefaults sets default values
func (c *Config) setDefaults() {
	// Faster scanning in fast mode
	if c.Fast {
		c.Delay = 0 // No delay
		if c.Threads < 50 {
			c.Threads = 50
		}
		if c.Timeout > 3*time.Second {
			c.Timeout = 3 * time.Second
		}
	}

	// Slower scanning in stealth mode
	if c.Stealth {
		if c.Delay < time.Second {
			c.Delay = time.Second
		}
		if c.Threads > 5 {
			c.Threads = 5
		}
	}

	// All modules in comprehensive mode
	if c.Comprehensive {
		c.Modules = getAllModules()
	}

	// Always add Windows detection module (if not present)
	c.ensureWindowsDetection()

	// Default if output file is not specified
	if c.Output == "" {
		c.Output = fmt.Sprintf("iis_scan_report_%d.%s",
			time.Now().Unix(), c.Format)
	}
}

// ensureWindowsDetection ensures Windows detection module is in the list
func (c *Config) ensureWindowsDetection() {
	hasWindowsDetection := false
	for _, module := range c.Modules {
		if module == "wappalyzer_detection" || module == "windows_detection" {
			hasWindowsDetection = true
			break
		}
	}

	if !hasWindowsDetection {
		// Add Wappalyzer detection to the beginning of the list
		newModules := []string{"wappalyzer_detection"}
		newModules = append(newModules, c.Modules...)
		c.Modules = newModules
	}
}
