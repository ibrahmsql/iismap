package logger

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
)

// Logger yapısı
type Logger struct {
	verbose bool
	debug   bool
	logger  *log.Logger
}

// New yeni logger oluşturur
func New(verbose, debug bool) *Logger {
	return &Logger{
		verbose: verbose,
		debug:   debug,
		logger:  log.New(os.Stdout, "", 0),
	}
}

// Info bilgi mesajı
func (l *Logger) Info(format string, args ...interface{}) {
	if l.verbose {
		timestamp := time.Now().Format("15:04:05")
		color.Blue("[%s] [INFO] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Success başarı mesajı
func (l *Logger) Success(format string, args ...interface{}) {
	if l.verbose {
		timestamp := time.Now().Format("15:04:05")
		color.Green("[%s] [SUCCESS] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Warning uyarı mesajı
func (l *Logger) Warning(format string, args ...interface{}) {
	if l.verbose {
		timestamp := time.Now().Format("15:04:05")
		color.Yellow("[%s] [WARNING] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Error hata mesajı
func (l *Logger) Error(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	color.Red("[%s] [ERROR] %s", timestamp, fmt.Sprintf(format, args...))
}

// Debug debug mesajı
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		timestamp := time.Now().Format("15:04:05")
		color.Cyan("[%s] [DEBUG] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Vulnerability zafiyet mesajı
func (l *Logger) Vulnerability(severity, title string) {
	var colorFunc func(string, ...interface{})

	switch severity {
	case "CRITICAL":
		colorFunc = color.Red
	case "HIGH":
		colorFunc = color.Magenta
	case "MEDIUM":
		colorFunc = color.Yellow
	case "LOW":
		colorFunc = color.Blue
	default:
		colorFunc = color.White
	}

	timestamp := time.Now().Format("15:04:05")
	colorFunc("[%s] [VULN] [%s] %s", timestamp, severity, title)
}

// Progress ilerleme mesajı
func (l *Logger) Progress(current, total int, module string) {
	if l.verbose {
		percentage := float64(current) / float64(total) * 100
		color.Cyan("[PROGRESS] %s: %d/%d (%.1f%%)", module, current, total, percentage)
	}
}
