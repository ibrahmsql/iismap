package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ibrahmsql/issmap/internal/config"
	"github.com/ibrahmsql/issmap/modules"
	"github.com/ibrahmsql/issmap/pkg/http"
	"github.com/ibrahmsql/issmap/pkg/logger"
)

// Scanner ana tarama motoru
type Scanner struct {
	config     *config.Config
	logger     *logger.Logger
	httpClient *http.Client
	modules    []modules.Module
}

// Results tarama sonuçları
type Results map[string]*modules.ModuleResult

// New yeni scanner oluşturur
func New(cfg *config.Config, log *logger.Logger) *Scanner {
	return &Scanner{
		config:     cfg,
		logger:     log,
		httpClient: http.NewClient(cfg),
		modules:    loadModules(cfg, log),
	}
}

// Scan taramayı başlatır
func (s *Scanner) Scan() (Results, error) {
	s.logger.Info("Tarama başlatılıyor...")

	results := make(Results)

	// Önce Windows detection modülünü çalıştır
	windowsModule := s.findWindowsDetectionModule()
	if windowsModule != nil {
		s.logger.Info("🔍 Windows Server kontrolü yapılıyor...")
		windowsResult, err := windowsModule.Run(s.httpClient)
		if err != nil {
			return nil, fmt.Errorf("Windows detection hatası: %v", err)
		}

		results[windowsModule.Name()] = windowsResult

		// Windows Server kontrolü
		if !s.isWindowsServer(windowsResult) {
			s.logger.Error("❌ HEDEF SİSTEM WINDOWS SERVER DEĞİL!")
			s.logger.Error("❌ IIS sadece Windows Server üzerinde çalışır.")
			s.logger.Error("❌ Tarama durduruluyor...")

			// Non-Windows için özel hata döndür
			return results, fmt.Errorf("hedef sistem Windows Server değil - IIS taraması yapılamaz")
		}

		s.logger.Success("✅ Windows Server tespit edildi - IIS taraması devam ediyor")
	} else {
		s.logger.Warning("⚠️  Windows detection modülü bulunamadı - tarama devam ediyor")
	}

	// Diğer modülleri çalıştır (Windows detection hariç)
	otherModules := s.getOtherModules()
	if len(otherModules) == 0 {
		s.logger.Info("Windows detection dışında çalıştırılacak modül yok")
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

			// Delay uygula (fast modda hiç delay yok)
			if !s.config.Fast {
				if s.config.Stealth && s.config.Delay > 0 {
					time.Sleep(s.config.Delay)
				} else if s.config.Delay > 0 {
					time.Sleep(s.config.Delay / 5) // Normal modda çok kısa delay
				}
			}

			s.logger.Info("Modül çalıştırılıyor: %s", mod.Name())

			// Modülü çalıştır
			result, err := mod.Run(s.httpClient)
			if err != nil {
				s.logger.Error("Modül hatası [%s]: %v", mod.Name(), err)
				result = &modules.ModuleResult{
					ModuleName:      mod.Name(),
					Status:          "ERROR",
					Error:           err.Error(),
					Vulnerabilities: []modules.Vulnerability{},
				}
			}

			// Sonuçları kaydet
			mu.Lock()
			results[mod.Name()] = result
			mu.Unlock()

			// Zafiyet sayısını logla
			vulnCount := len(result.Vulnerabilities)
			if vulnCount > 0 {
				s.logger.Warning("Modül [%s]: %d zafiyet tespit edildi", mod.Name(), vulnCount)

				// Her zafiyeti logla
				for _, vuln := range result.Vulnerabilities {
					s.logger.Vulnerability(vuln.Severity, vuln.Title)
				}
			} else {
				s.logger.Success("Modül [%s]: Zafiyet tespit edilmedi", mod.Name())
			}
		}(module)
	}

	// Tüm modüllerin tamamlanmasını bekle
	wg.Wait()

	s.logger.Info("Tarama tamamlandı")
	return results, nil
}

// loadModules konfigürasyona göre modülleri yükler
func loadModules(cfg *config.Config, log *logger.Logger) []modules.Module {
	var loadedModules []modules.Module

	// Mevcut modüller
	availableModules := map[string]func(*config.Config, *logger.Logger) modules.Module{
		"wappalyzer_detection":   modules.NewWappalyzerDetectionModule,
		"windows_detection":      modules.NewWindowsDetectionModule,
		"fingerprint":            modules.NewFingerprintModule,
		"tilde":                  modules.NewTildeModule,
		"enhanced_tilde":         modules.NewEnhancedTildeModule,
		"advanced_shortscan":     modules.NewAdvancedShortscanModule,
		"config":                 modules.NewConfigModule,
		"aspnet":                 modules.NewASPNETModule,
		"http_methods":           modules.NewHTTPMethodsModule,
		"ssl_tls":                modules.NewSSLTLSModule,
		"path_traversal":         modules.NewPathTraversalModule,
		"handlers":               modules.NewHandlersModule,
		"auth_bypass":            modules.NewAuthBypassModule,
		"buffer_overflow":        modules.NewBufferOverflowModule,
		"webdav":                 modules.NewWebDAVModule,
		"information_disclosure": modules.NewInformationDisclosureModule,
		"file_upload":            modules.NewFileUploadModule,
		"sql_injection":          modules.NewSQLInjectionModule,
		"xss":                    modules.NewXSSModule,
		"csrf":                   modules.NewCSRFModule,
	}

	// Seçilen modülleri yükle
	for _, moduleName := range cfg.Modules {
		if moduleFactory, exists := availableModules[moduleName]; exists {
			module := moduleFactory(cfg, log)
			loadedModules = append(loadedModules, module)
			log.Debug("Modül yüklendi: %s", moduleName)
		} else {
			log.Warning("Bilinmeyen modül: %s", moduleName)
		}
	}

	if len(loadedModules) == 0 {
		log.Warning("Hiç modül yüklenmedi, varsayılan modüller kullanılacak")
		// Varsayılan modülleri yükle
		defaultModules := []string{"fingerprint", "tilde", "config"}
		for _, moduleName := range defaultModules {
			if moduleFactory, exists := availableModules[moduleName]; exists {
				module := moduleFactory(cfg, log)
				loadedModules = append(loadedModules, module)
			}
		}
	}

	log.Info("%d modül yüklendi", len(loadedModules))
	return loadedModules
}

// findWindowsDetectionModule Windows detection modülünü bulur
func (s *Scanner) findWindowsDetectionModule() modules.Module {
	// Önce Wappalyzer detection'ı ara
	for _, module := range s.modules {
		if module.Name() == "wappalyzer_detection" {
			return module
		}
	}

	// Yoksa eski Windows detection'ı ara
	for _, module := range s.modules {
		if module.Name() == "windows_detection" {
			return module
		}
	}
	return nil
}

// getOtherModules Windows detection dışındaki modülleri döndürür
func (s *Scanner) getOtherModules() []modules.Module {
	var otherModules []modules.Module
	for _, module := range s.modules {
		if module.Name() != "windows_detection" && module.Name() != "wappalyzer_detection" {
			otherModules = append(otherModules, module)
		}
	}
	return otherModules
}

// isWindowsServer Windows detection sonucuna göre Windows Server olup olmadığını kontrol eder
func (s *Scanner) isWindowsServer(result *modules.ModuleResult) bool {
	// Wappalyzer detection için
	if result.ModuleName == "wappalyzer_detection" {
		// Zafiyet kontrolü - Non-Windows/IIS Server detected varsa Windows değil
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "WAPP-DETECT-001" && strings.Contains(vuln.Title, "Non-Windows/IIS Server Detected") {
				return false
			}
		}

		// Info kontrolü - Windows veya IIS tespit edildi mi?
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

	// Eski Windows detection için
	// Zafiyet kontrolü - Non-Windows Server detected varsa Windows değil
	for _, vuln := range result.Vulnerabilities {
		if vuln.ID == "WIN-DETECT-001" && vuln.Title == "Non-Windows Server Detected" {
			return false
		}
	}

	// Info kontrolü - Windows Server tespit edildi mi?
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

	// En az 2 Windows göstergesi varsa Windows Server kabul et
	return windowsIndicators >= 2
}

// contains string içinde substring arar (case insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findInString(s, substr)))
}

// findInString string içinde substring arar
func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
