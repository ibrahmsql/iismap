package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/modules"
	"github.com/ibrahmsql/iismap/pkg/http"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// Scanner main scanning engine
type Scanner struct {
	config     *config.Config
	logger     *logger.Logger
	httpClient *http.Client
	modules    []modules.Module
}

// Results scan results
type Results map[string]*modules.ModuleResult

// New creates a new scanner
func New(cfg *config.Config, log *logger.Logger) *Scanner {
	return &Scanner{
		config:     cfg,
		logger:     log,
		httpClient: http.NewClient(cfg),
		modules:    loadModules(cfg, log),
	}
}

// Scan starts the scanning process
func (s *Scanner) Scan() (Results, error) {
	s.logger.Info("Starting scan...")

	results := make(Results)

	// First run Windows detection module
	windowsModule := s.findWindowsDetectionModule()
	if windowsModule != nil {
		s.logger.Info("🔍 Checking Windows Server...")
		windowsResult, err := windowsModule.Run(s.httpClient)
		if err != nil {
			return nil, fmt.Errorf("Windows detection error: %v", err)
		}

		results[windowsModule.Name()] = windowsResult

		// Windows Server check
		if !s.isWindowsServer(windowsResult) {
			s.logger.Error("❌ TARGET SYSTEM IS NOT DETECTED AS WINDOWS SERVER!")
			s.logger.Error("❌ IIS normally runs only on Windows Server.")
			s.logger.Error("❌ Scan terminated. Use --force flag to bypass this check.")
			return results, fmt.Errorf("target system is not Windows Server")
		} else {
			s.logger.Success("✅ Windows Server detected - IIS scan continuing")
		}
	} else {
		s.logger.Warning("⚠️  Windows detection module not found - continuing scan")
	}

	// Run other modules (except Windows detection)
	otherModules := s.getOtherModules()
	if len(otherModules) == 0 {
		s.logger.Info("No modules to run except Windows detection")
		return results, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Semaphore ile thread sayısını sınırla
	semaphore := make(chan struct{}, s.config.Threads)

	for _, module := range otherModules {
		wg.Add(1)
		go func(mod modules.Module) {
			defer wg.Done()

			// Semaphore al
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Apply delay (no delay in fast mode)
			if !s.config.Fast {
				if s.config.Stealth && s.config.Delay > 0 {
					time.Sleep(s.config.Delay)
				} else if s.config.Delay > 0 {
					time.Sleep(s.config.Delay / 5) // Very short delay in normal mode
				}
			}

			s.logger.Info("Running module: %s", mod.Name())

			// Run module
			result, err := mod.Run(s.httpClient)
			if err != nil {
				s.logger.Error("Module error [%s]: %v", mod.Name(), err)
				result = &modules.ModuleResult{
					ModuleName:      mod.Name(),
					Status:          "ERROR",
					Error:           err.Error(),
					Vulnerabilities: []modules.Vulnerability{},
				}
			}

			// Save results
			mu.Lock()
			results[mod.Name()] = result
			mu.Unlock()

			// Log vulnerability count
			vulnCount := len(result.Vulnerabilities)
			if vulnCount > 0 {
				s.logger.Warning("Module [%s]: %d vulnerabilities detected", mod.Name(), vulnCount)

				// Log each vulnerability
				for _, vuln := range result.Vulnerabilities {
					s.logger.Vulnerability(vuln.Severity, vuln.Title)
				}
			} else {
				s.logger.Success("Module [%s]: No vulnerabilities detected", mod.Name())
			}
		}(module)
	}

	// Wait for all modules to complete
	wg.Wait()

	s.logger.Info("Scan completed")
	return results, nil
}

// loadModules loads modules according to configuration
func loadModules(cfg *config.Config, log *logger.Logger) []modules.Module {
	var loadedModules []modules.Module

	// Available modules
	availableModules := map[string]func(*config.Config, *logger.Logger) modules.Module{
		"wappalyzer_detection":   modules.NewWappalyzerDetectionModule,
		"windows_detection":      modules.NewWindowsDetectionModule,
		"fingerprint":            modules.NewFingerprintModule,
		"tilde":                  modules.NewTildeModule,
		"config":                 modules.NewConfigModule,
		"aspnet":                 modules.NewASPNETModule,
		"http_methods":           modules.NewHTTPMethodsModule,
		"ssl_tls":                modules.NewSSLTLSModule,
		"handlers":               modules.NewHandlersModule,
		"buffer_overflow":        modules.NewBufferOverflowModule,
		"filehunter":             modules.NewFileHunterModule,
	}

	// Load selected modules
	for _, moduleName := range cfg.Modules {
		if moduleFactory, exists := availableModules[moduleName]; exists {
			module := moduleFactory(cfg, log)
			loadedModules = append(loadedModules, module)
			log.Debug("Module loaded: %s", moduleName)
		} else {
			log.Warning("Unknown module: %s", moduleName)
		}
	}

	if len(loadedModules) == 0 {
		log.Warning("No modules loaded, using default modules")
		// Load default modules
		defaultModules := []string{"fingerprint", "tilde", "config"}
		for _, moduleName := range defaultModules {
			if moduleFactory, exists := availableModules[moduleName]; exists {
				module := moduleFactory(cfg, log)
				loadedModules = append(loadedModules, module)
			}
		}
	}

	log.Info("%d modules loaded", len(loadedModules))
	return loadedModules
}

// findWindowsDetectionModule finds Windows detection module
func (s *Scanner) findWindowsDetectionModule() modules.Module {
	// First look for Wappalyzer detection
	for _, module := range s.modules {
		if module.Name() == "wappalyzer_detection" {
			return module
		}
	}

	// Then look for Windows detection
	for _, module := range s.modules {
		if module.Name() == "windows_detection" {
			return module
		}
	}
	return nil
}

// getOtherModules returns modules other than Windows detection
func (s *Scanner) getOtherModules() []modules.Module {
	var otherModules []modules.Module
	for _, module := range s.modules {
		if module.Name() != "windows_detection" && module.Name() != "wappalyzer_detection" {
			otherModules = append(otherModules, module)
		}
	}
	return otherModules
}

// isWindowsServer checks if the target is Windows Server based on detection results
func (s *Scanner) isWindowsServer(result *modules.ModuleResult) bool {
	// For Wappalyzer detection
	if result.ModuleName == "wappalyzer_detection" {
		// Vulnerability check - if Non-Windows/IIS Server detected, it's not Windows
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "WAPP-DETECT-001" && strings.Contains(vuln.Title, "Non-Windows/IIS Server Detected") {
				return false
			}
		}

		// Info check - was Windows or IIS detected?
		for _, info := range result.Info {
			if info.Type == "os_detection" && info.Value == "Windows" {
				return true
			}
			if info.Type == "web_server" && strings.Contains(info.Value, "IIS") {
				return true
			}
			if info.Type == "detected_technology" && (strings.Contains(info.Value, "IIS") ||
				strings.Contains(info.Value, "ASP.NET") || strings.Contains(info.Value, "Microsoft")) {
				return true
			}
		}

		return false
	}

	// For old Windows detection
	// Vulnerability check - if Non-Windows Server detected, it's not Windows
	for _, vuln := range result.Vulnerabilities {
		if vuln.ID == "WIN-DETECT-001" && vuln.Title == "Non-Windows Server Detected" {
			return false
		}
	}

	// Info check - was Windows Server detected?
	windowsIndicators := 0
	for _, info := range result.Info {
		switch info.Type {
		case "windows_indicator", "aspnet_header", "aspnet_version", "iis_pattern",
			"windows_error_pattern", "windows_path", "aspnet_extension", "viewstate",
			"eventvalidation", "windows_version", "iis_version", "windows_port":
			windowsIndicators++
		case "server_header":
			if contains(info.Value, "iis") || contains(info.Value, "microsoft") || contains(info.Value, "asp.net") {
				windowsIndicators++
			}
		case "os_detection":
			if info.Value == "Windows Server" {
				return true
			}
		}
	}

	// Accept as Windows Server if at least 2 Windows indicators
	return windowsIndicators >= 2
}

// contains searches for substring in string (case insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findInString(s, substr)))
}

// findInString searches for substring in string
func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
