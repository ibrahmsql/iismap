package logger

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
)

// Logger structure
type Logger struct {
	verbose bool
	debug   bool
	logger  *log.Logger
}

// New creates a new logger
func New(verbose, debug bool) *Logger {
	return &Logger{
		verbose: verbose,
		debug:   debug,
		logger:  log.New(os.Stdout, "", 0),
	}
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.verbose {
		timestamp := time.Now().Format("15:04:05")
		color.Blue("[%s] [INFO] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Success logs a success message
func (l *Logger) Success(format string, args ...interface{}) {
	if l.verbose {
		timestamp := time.Now().Format("15:04:05")
		color.Green("[%s] [SUCCESS] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	if l.verbose {
		timestamp := time.Now().Format("15:04:05")
		color.Yellow("[%s] [WARNING] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05")
	color.Red("[%s] [ERROR] %s", timestamp, fmt.Sprintf(format, args...))
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		timestamp := time.Now().Format("15:04:05")
		color.Cyan("[%s] [DEBUG] %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Vulnerability logs a vulnerability message
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

// Progress logs a progress message
func (l *Logger) Progress(current, total int, module string) {
	if l.verbose {
		percentage := float64(current) / float64(total) * 100
		color.Cyan("[PROGRESS] %s: %d/%d (%.1f%%)", module, current, total, percentage)
	}
}
