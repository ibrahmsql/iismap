package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/internal/config"
	"github.com/ibrahmsql/issmap/internal/reporter"
	"github.com/ibrahmsql/issmap/internal/scanner"
	"github.com/ibrahmsql/issmap/pkg/logger"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	banner  = `
██╗██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ███╗███╗   ██╗███████╗██████╗ 
██║██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗ ████║████╗  ██║██╔════╝██╔══██╗
██║██║███████╗    ███████╗██║     ███████║██╔████╔██║██╔██╗ ██║█████╗  ██████╔╝
██║██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╔╝██║██║╚██╗██║██╔══╝  ██╔══██╗
██║██║███████║    ███████║╚██████╗██║  ██║██║ ╚═╝ ██║██║ ╚████║███████╗██║  ██║
╚═╝╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

IIS Security Scanner Framework v%s
Comprehensive IIS Vulnerability Assessment Tool
Use responsibly and only on authorized targets
`
)

func printBanner() {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	cyan.Printf(banner, version)
	yellow.Println("IIS Security Scanner Framework v" + version)
	green.Println("Comprehensive IIS Vulnerability Assessment Tool")
	red.Println("Use responsibly and only on authorized targets")
	fmt.Println()
}

var rootCmd = &cobra.Command{
	Use:   "issmap",
	Short: "IIS Security Scanner Framework",
	Long:  "Kapsamlı IIS güvenlik tarama ve zafiyet tespit framework'ü",
	Run:   runScanner,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringP("target", "t", "", "Hedef URL (örn: https://example.com)")
	rootCmd.PersistentFlags().StringP("modules", "m", "", "Çalıştırılacak modüller (virgülle ayrılmış)")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Çıktı dosyası")
	rootCmd.PersistentFlags().String("format", "json", "Çıktı formatı (json, html, xml)")

	// Tarama seçenekleri
	rootCmd.PersistentFlags().Bool("comprehensive", false, "Kapsamlı tarama modu")
	rootCmd.PersistentFlags().Bool("stealth", false, "Stealth tarama modu")
	rootCmd.PersistentFlags().Bool("fast", false, "Hızlı tarama modu")
	rootCmd.PersistentFlags().Float64("delay", 0.1, "İstekler arası gecikme (saniye)")
	rootCmd.PersistentFlags().Int("threads", 20, "Thread sayısı")
	rootCmd.PersistentFlags().Int("timeout", 10, "İstek timeout süresi")

	// Proxy ve authentication
	rootCmd.PersistentFlags().String("proxy", "", "Proxy URL")
	rootCmd.PersistentFlags().String("user-agent", "", "Özel User-Agent")
	rootCmd.PersistentFlags().String("cookies", "", "Çerezler")
	rootCmd.PersistentFlags().String("headers", "", "Özel HTTP başlıkları")

	// Verbose ve debug
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Detaylı çıktı")
	rootCmd.PersistentFlags().Bool("debug", false, "Debug modu")

	// Required flags
	rootCmd.MarkPersistentFlagRequired("target")
}

func runScanner(cmd *cobra.Command, args []string) {
	printBanner()

	// Konfigürasyonu yükle
	cfg, err := config.LoadFromFlags(cmd)
	if err != nil {
		color.Red("[!] Konfigürasyon hatası: %v", err)
		os.Exit(1)
	}

	// Logger'ı başlat
	log := logger.New(cfg.Verbose, cfg.Debug)

	// Hedef URL'yi doğrula
	if err := cfg.ValidateTarget(); err != nil {
		color.Red("[!] Geçersiz hedef URL: %v", err)
		os.Exit(1)
	}

	color.Green("[+] Hedef: %s", cfg.Target)
	color.Green("[+] Tarama başlatılıyor...")

	// Scanner'ı başlat
	s := scanner.New(cfg, log)

	startTime := time.Now()
	results, err := s.Scan()
	if err != nil {
		// Windows Server değilse özel mesaj
		if strings.Contains(err.Error(), "Windows Server değil") {
			color.Red("\n[!] TARAMA DURDURULDU!")
			color.Red("[!] %v", err)
			color.Yellow("[i] Bu araç sadece Windows Server üzerinde çalışan IIS sunucuları için tasarlanmıştır.")
			color.Yellow("[i] Lütfen Windows Server çalıştıran bir hedef seçin.")
			os.Exit(2) // Özel exit code
		}
		color.Red("[!] Tarama hatası: %v", err)
		os.Exit(1)
	}
	duration := time.Since(startTime)

	// Raporu oluştur
	r := reporter.New(cfg, log)
	reportPath, err := r.GenerateReport(results, duration)
	if err != nil {
		color.Red("[!] Rapor oluşturma hatası: %v", err)
		os.Exit(1)
	}

	// Sonuçları göster
	fmt.Println()
	color.Green("[+] Tarama tamamlandı!")
	color.Green("[+] Süre: %.2f saniye", duration.Seconds())
	color.Green("[+] Rapor: %s", reportPath)

	// Özet bilgileri
	totalVulns := 0
	for _, moduleResults := range results {
		totalVulns += len(moduleResults.Vulnerabilities)
	}

	if totalVulns > 0 {
		color.Red("[!] %d zafiyet tespit edildi!", totalVulns)
	} else {
		color.Green("[+] Zafiyet tespit edilmedi.")
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("[!] Hata: %v", err)
		os.Exit(1)
	}
}
