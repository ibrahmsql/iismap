package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/internal/reporter"
	"github.com/ibrahmsql/iismap/internal/scanner"
	"github.com/ibrahmsql/iismap/pkg/logger"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	banners = []string{
		`
██╗██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ███╗███╗   ██╗███████╗██████╗ 
██║██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗ ████║████╗  ██║██╔════╝██╔══██╗
██║██║███████╗    ███████╗██║     ███████║██╔████╔██║██╔██╗ ██║█████╗  ██████╔╝
██║██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╔╝██║██║╚██╗██║██╔══╝  ██╔══██╗
██║██║███████║    ███████║╚██████╗██║  ██║██║ ╚═╝ ██║██║ ╚████║███████╗██║  ██║
╚═╝╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝`,
		`
 ██▓ ██▓  ██████  ███▄ ▄███▓ ▄▄▄       ██▓███  
▓██▒▓██▒▒██    ▒ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒
▒██▒▒██▒░ ▓██▄   ▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒
░██░░██░  ▒   ██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
░██░░██░▒██████▒▒▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░
░▓  ░▓  ▒ ▒▓▒ ▒ ░░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░
 ▒ ░ ▒ ░░ ░▒  ░ ░░  ░      ░  ▒   ▒▒ ░░▒ ░     
 ▒ ░ ▒ ░░  ░  ░  ░      ░     ░   ▒   ░░       
 ░   ░        ░         ░         ░  ░         `,
		`
▀█▀ ▀█▀ █▀▀ █▄█▄█ █▀▀█ █▀▀█ 
 ▀█▀  ▀█▀ ▀▀█ █ █ █ █▄▄█ █▄▄█ 
 ▀▀▀  ▀▀▀ ▀▀▀ ▀ ▀ ▀ ▀  ▀ ▀    `,
		`
██╗██╗███████╗███╗   ███╗ █████╗ ██████╗ 
██║██║██╔════╝████╗ ████║██╔══██╗██╔══██╗
██║██║███████╗██╔████╔██║███████║██████╔╝
██║██║╚════██║██║╚██╔╝██║██╔══██║██╔═══╝ 
██║██║███████║██║ ╚═╝ ██║██║  ██║██║     
╚═╝╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     `,
		`
 ▄█  ▄█  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄       ▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░▌▐░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌     ▐░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░▌░▐░▌ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌░▌   ▐░▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
▐░▌▐░▌  ▐░▌          ▐░▌          ▐░▌▐░▌ ▐░▌▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
▐░▌░▌   ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌ ▐░▐░▌ ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌
▐░▌▐░▌  ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░▌ ▐░▌ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌   ▀   ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌  ▐░▌▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          
▐░▌   ▐░▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          
 ▀     ▀ ▀            ▀            ▀         ▀  ▀         ▀  ▀           `,
	}

	consoleBanner = `
 ██▓ ██▓  ██████  ███▄ ▄███▓ ▄▄▄       ██▓███  
▓██▒▓██▒▒██    ▒ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒
▒██▒▒██▒░ ▓██▄   ▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒
░██░░██░  ▒   ██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
░██░░██░▒██████▒▒▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░
░▓  ░▓  ▒ ▒▓▒ ▒ ░░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░
 ▒ ░ ▒ ░░ ░▒  ░ ░░  ░      ░  ▒   ▒▒ ░░▒ ░     
 ▒ ░ ▒ ░░  ░  ░  ░      ░     ░   ▒   ░░       
 ░   ░        ░         ░         ░  ░         `
)

func printBanner() {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	// Random banner selection
	rand.Seed(time.Now().UnixNano())
	selectedBanner := banners[rand.Intn(len(banners))]

	cyan.Println(selectedBanner)
	yellow.Println("IIS Security Scanner Framework v" + version)
	green.Println("Comprehensive IIS Vulnerability Assessment Tool")
	red.Println("Use responsibly and only on authorized targets")
	fmt.Println()
}

var rootCmd = &cobra.Command{
	Use:   "iismap",
	Short: "IIS Security Scanner Framework",
	Long:  "Comprehensive IIS security scanning and vulnerability detection framework",
	Run:   runScanner,
}

var interactiveCmd = &cobra.Command{
	Use:   "console",
	Short: "Start interactive console mode",
	Long:  "Start an interactive console similar to MSFConsole for IIS scanning",
	Run:   runInteractiveMode,
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show available modules and options",
	Long:  "Display available modules, targets, and scanning options",
	Run:   showOptions,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringP("target", "t", "", "Target URL (e.g., https://example.com)")
	rootCmd.PersistentFlags().StringP("modules", "m", "", "Modules to run (comma-separated)")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output file")
	rootCmd.PersistentFlags().String("format", "json", "Output format (json, html, xml)")

	// Scanning options
	rootCmd.PersistentFlags().Bool("comprehensive", false, "Comprehensive scanning mode")
	rootCmd.PersistentFlags().Bool("stealth", false, "Stealth scanning mode")
	rootCmd.PersistentFlags().Bool("fast", false, "Fast scanning mode")
	rootCmd.PersistentFlags().Float64("delay", 0.1, "Delay between requests (seconds)")
	rootCmd.PersistentFlags().Int("threads", 20, "Number of threads")
	rootCmd.PersistentFlags().Int("timeout", 10, "Request timeout duration")

	// Proxy and authentication
	rootCmd.PersistentFlags().String("proxy", "", "Proxy URL")
	rootCmd.PersistentFlags().String("user-agent", "", "Custom User-Agent")
	rootCmd.PersistentFlags().String("cookies", "", "Cookies")
	rootCmd.PersistentFlags().String("headers", "", "Custom HTTP headers")

	// Verbose and debug
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().Bool("debug", false, "Debug mode")

	// Add subcommands
	rootCmd.AddCommand(interactiveCmd)
	rootCmd.AddCommand(showCmd)

	// Required flags for main command only
	if len(os.Args) > 1 && os.Args[1] != "console" && os.Args[1] != "show" {
		rootCmd.MarkPersistentFlagRequired("target")
	}
}

func runScanner(cmd *cobra.Command, args []string) {
	printBanner()

	// Load configuration
	cfg, err := config.LoadFromFlags(cmd)
	if err != nil {
		color.Red("[!] Configuration error: %v", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.Verbose, cfg.Debug)

	// Validate target URL
	if err := cfg.ValidateTarget(); err != nil {
		color.Red("[!] Invalid target URL: %v", err)
		os.Exit(1)
	}

	color.Green("[+] Target: %s", cfg.Target)
	color.Green("[+] Starting scan...")

	// Start the scanner
	s := scanner.New(cfg, log)

	startTime := time.Now()
	results, err := s.Scan()
	if err != nil {
		// Special message if not Windows Server
		if strings.Contains(err.Error(), "Windows Server") {
			color.Red("\n[!] SCAN STOPPED!")
			color.Red("[!] Target system is not Windows Server")
			color.Yellow("[i] This tool is designed for IIS servers running on Windows Server.")
			color.Yellow("[i] Please select a target running Windows Server.")
			os.Exit(2) // Special exit code
		}
		color.Red("[!] Scan error: %v", err)
		os.Exit(1)
	}
	duration := time.Since(startTime)

	// Generate the report
	r := reporter.New(cfg, log)
	reportPath, err := r.GenerateReport(results, duration)
	if err != nil {
		color.Red("[!] Report generation error: %v", err)
		os.Exit(1)
	}

	// Show results
	fmt.Println()
	color.Green("[+] Scan completed!")
	color.Green("[+] Duration: %.2f seconds", duration.Seconds())
	color.Green("[+] Report: %s", reportPath)

	// Summary information
	totalVulns := 0
	for _, moduleResults := range results {
		totalVulns += len(moduleResults.Vulnerabilities)
	}

	if totalVulns > 0 {
		color.Red("[!] %d vulnerabilities detected!", totalVulns)
	} else {
		color.Green("[+] No vulnerabilities detected.")
	}
}

func runInteractiveMode(cmd *cobra.Command, args []string) {
	cyan := color.New(color.FgCyan)
	cyan.Println(consoleBanner)
	color.Green("[+] Starting IISMap Interactive Console")
	color.Yellow("[i] Type 'help' for available commands")
	color.Yellow("[i] Type 'exit' to quit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		color.Cyan("iismap > ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := parts[0]

		switch command {
		case "help":
			showHelp()
		case "show":
			if len(parts) > 1 {
				handleShow(parts[1])
			} else {
				color.Red("[!] Usage: show [modules|options]")
			}
		case "set":
			if len(parts) >= 3 {
				handleSet(parts[1], strings.Join(parts[2:], " "))
			} else {
				color.Red("[!] Usage: set <option> <value>")
			}
		case "scan":
			handleScan()
		case "exit", "quit":
			color.Green("[+] Goodbye!")
			return
		case "clear":
			fmt.Print("\033[2J\033[H")
		default:
			color.Red("[!] Unknown command: %s", command)
			color.Yellow("[i] Type 'help' for available commands")
		}
	}
}

func showOptions(cmd *cobra.Command, args []string) {
	color.Green("[+] Available Modules:")
	modules := []string{
		"wappalyzer_detection", "windows_detection", "fingerprint",
		"tilde", "config", "aspnet", "http_methods",
		"ssl_tls", "handlers", "buffer_overflow", "filehunter",
	}

	for _, module := range modules {
		color.Cyan("  - %s", module)
	}

	color.Green("\n[+] Scanning Options:")
	color.Cyan("  --comprehensive    Comprehensive scanning mode")
	color.Cyan("  --stealth          Stealth scanning mode")
	color.Cyan("  --fast             Fast scanning mode")
	color.Cyan("  --threads <num>    Number of threads (default: 20)")
	color.Cyan("  --timeout <sec>    Request timeout (default: 10)")
	color.Cyan("  --delay <sec>      Delay between requests (default: 0.1)")
}

var currentTarget string
var currentModules string
var currentWordlist string
var currentOptions = make(map[string]string)

func showHelp() {
	color.Green("[+] Available Commands:")
	color.Cyan("  help                 Show this help message")
	color.Cyan("  show modules         Show available modules")
	color.Cyan("  show options         Show current options")
	color.Cyan("  set target <url>     Set target URL")
	color.Cyan("  set modules <list>   Set modules to run (comma-separated or 'all')")
	color.Cyan("  set wordlist <path>  Set custom wordlist file path")
	color.Cyan("  set threads <num>    Set number of threads")
	color.Cyan("  set timeout <sec>    Set request timeout")
	color.Cyan("  set delay <sec>      Set delay between requests")
	color.Cyan("  scan                 Start scanning with current settings")
	color.Cyan("  clear                Clear screen")
	color.Cyan("  exit/quit            Exit console")
}

func handleShow(option string) {
	switch option {
	case "modules":
		modules := []string{
			"wappalyzer_detection", "windows_detection", "fingerprint",
			"tilde", "config", "aspnet", "http_methods",
			"ssl_tls", "handlers", "buffer_overflow", "filehunter",
		}
		color.Green("[+] Available Modules:")
		for _, module := range modules {
			color.Cyan("  - %s", module)
		}
	case "options":
		color.Green("[+] Current Options:")
		color.Cyan("  Target: %s", getOption("target", "not set"))
		color.Cyan("  Modules: %s", getOption("modules", "default"))
		color.Cyan("  Wordlist: %s", getOption("wordlist", "default"))
		color.Cyan("  Threads: %s", getOption("threads", "20"))
		color.Cyan("  Timeout: %s", getOption("timeout", "10"))
		color.Cyan("  Delay: %s", getOption("delay", "0.1"))
	default:
		color.Red("[!] Unknown option: %s", option)
		color.Yellow("[i] Available: modules, options")
	}
}

func handleSet(option, value string) {
	switch option {
	case "target":
		currentTarget = value
		currentOptions["target"] = value
		color.Green("[+] Target set to: %s", value)
	case "modules":
		if value == "all" {
			allModules := []string{
				"wappalyzer_detection", "windows_detection", "fingerprint",
				"tilde", "config", "aspnet", "http_methods",
				"ssl_tls", "handlers", "buffer_overflow", "filehunter",
			}
			value = strings.Join(allModules, ",")
		}
		currentModules = value
		currentOptions["modules"] = value
		color.Green("[+] Modules set to: %s", value)
	case "wordlist":
		currentWordlist = value
		currentOptions["wordlist"] = value
		color.Green("[+] Wordlist set to: %s", value)
	case "threads", "timeout", "delay":
		currentOptions[option] = value
		color.Green("[+] %s set to: %s", option, value)
	default:
		color.Red("[!] Unknown option: %s", option)
		color.Yellow("[i] Available: target, modules, wordlist, threads, timeout, delay")
	}
}

func getOption(key, defaultValue string) string {
	if value, exists := currentOptions[key]; exists {
		return value
	}
	return defaultValue
}

func handleScan() {
	if currentTarget == "" {
		color.Red("[!] Target not set. Use 'set target <url>' first")
		return
	}

	color.Green("[+] Starting scan with current settings...")
	color.Cyan("[+] Target: %s", currentTarget)
	if currentModules != "" {
		color.Cyan("[+] Modules: %s", currentModules)
	}

	// Add protocol if missing
	target := currentTarget
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// Create a temporary config for scanning
	cfg := &config.Config{
		Target:   target,
		Modules:  strings.Split(getOption("modules", "wappalyzer_detection,fingerprint,tilde,config"), ","),
		Wordlist: getOption("wordlist", ""),
		Verbose:  true,
		Debug:    false,
	}

	// Parse URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		color.Red("[!] Invalid URL: %v", err)
		return
	}
	cfg.ParsedURL = parsedURL

	// Parse numeric options
	if threads := getOption("threads", "20"); threads != "20" {
		fmt.Sscanf(threads, "%d", &cfg.Threads)
	} else {
		cfg.Threads = 20
	}

	if timeout := getOption("timeout", "10"); timeout != "10" {
		fmt.Sscanf(timeout, "%d", &cfg.Timeout)
	} else {
		cfg.Timeout = 10
	}

	if delay := getOption("delay", "0.1"); delay != "0.1" {
		var delayFloat float64
		fmt.Sscanf(delay, "%f", &delayFloat)
		cfg.Delay = time.Duration(delayFloat * float64(time.Second))
	} else {
		cfg.Delay = 100 * time.Millisecond
	}

	// Validate target
	if err := cfg.ValidateTarget(); err != nil {
		color.Red("[!] Invalid target URL: %v", err)
		return
	}

	// Initialize logger
	log := logger.New(cfg.Verbose, cfg.Debug)

	// Start scanner
	s := scanner.New(cfg, log)

	startTime := time.Now()
	results, err := s.Scan()
	if err != nil {
		color.Red("[!] Scan error: %v", err)
		return
	}
	duration := time.Since(startTime)

	// Generate report
	r := reporter.New(cfg, log)
	reportPath, err := r.GenerateReport(results, duration)
	if err != nil {
		color.Red("[!] Report generation error: %v", err)
		return
	}

	// Show results
	color.Green("[+] Scan completed!")
	color.Green("[+] Duration: %.2f seconds", duration.Seconds())
	color.Green("[+] Report: %s", reportPath)

	// Summary
	totalVulns := 0
	for _, moduleResults := range results {
		totalVulns += len(moduleResults.Vulnerabilities)
	}

	if totalVulns > 0 {
		color.Red("[!] %d vulnerabilities detected!", totalVulns)
	} else {
		color.Green("[+] No vulnerabilities detected.")
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("[!] Error: %v", err)
		os.Exit(1)
	}
}
