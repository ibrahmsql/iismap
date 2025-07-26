package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/ibrahmsql/iismap/internal/config"
	"github.com/ibrahmsql/iismap/internal/scanner"
	"github.com/ibrahmsql/iismap/pkg/logger"
)

// Reporter report generator
type Reporter struct {
	config *config.Config
	logger *logger.Logger
}

// Report report structure
type Report struct {
	Metadata    ReportMetadata  `json:"metadata"`
	Target      TargetInfo      `json:"target"`
	Summary     ScanSummary     `json:"summary"`
	Results     scanner.Results `json:"results"`
	GeneratedAt time.Time       `json:"generated_at"`
}

// ReportMetadata report metadata
type ReportMetadata struct {
	Tool        string `json:"tool"`
	Version     string `json:"version"`
	Author      string `json:"author"`
	Description string `json:"description"`
}

// TargetInfo target information
type TargetInfo struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Port   string `json:"port"`
}

// ScanSummary scan summary
type ScanSummary struct {
	Duration      time.Duration `json:"duration"`
	ModulesRun    int           `json:"modules_run"`
	TotalRequests int           `json:"total_requests"`
	VulnCount     VulnSummary   `json:"vulnerability_count"`
	InfoCount     int           `json:"info_count"`
}

// VulnSummary vulnerability summary
type VulnSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// New creates new reporter
func New(cfg *config.Config, log *logger.Logger) *Reporter {
	return &Reporter{
		config: cfg,
		logger: log,
	}
}

// GenerateReport generates report
func (r *Reporter) GenerateReport(results scanner.Results, duration time.Duration) (string, error) {
	// Build report structure
	report := r.buildReport(results, duration)

	// Generate report based on format
	switch r.config.Format {
	case "json":
		return r.generateJSONReport(report)
	case "html":
		return r.generateHTMLReport(report)
	case "xml":
		return r.generateXMLReport(report)
	default:
		return r.generateJSONReport(report)
	}
}

// buildReport builds report structure
func (r *Reporter) buildReport(results scanner.Results, duration time.Duration) *Report {
	// Target information
	target := TargetInfo{
		URL:    r.config.Target,
		Host:   r.config.ParsedURL.Host,
		Scheme: r.config.ParsedURL.Scheme,
		Port:   r.config.ParsedURL.Port(),
	}

	// Calculate summary information
	summary := r.calculateSummary(results, duration)

	return &Report{
		Metadata: ReportMetadata{
			Tool:        "IIS Security Scanner",
			Version:     "1.0.0",
			Author:      "IIS Scanner Framework",
			Description: "Comprehensive IIS Security Assessment Report",
		},
		Target:      target,
		Summary:     summary,
		Results:     results,
		GeneratedAt: time.Now(),
	}
}

// calculateSummary calculates summary information
func (r *Reporter) calculateSummary(results scanner.Results, duration time.Duration) ScanSummary {
	var totalRequests int
	var infoCount int
	vulnCount := VulnSummary{}

	for _, moduleResult := range results {
		totalRequests += moduleResult.RequestCount
		infoCount += len(moduleResult.Info)

		for _, vuln := range moduleResult.Vulnerabilities {
			vulnCount.Total++
			switch vuln.Severity {
			case "CRITICAL":
				vulnCount.Critical++
			case "HIGH":
				vulnCount.High++
			case "MEDIUM":
				vulnCount.Medium++
			case "LOW":
				vulnCount.Low++
			}
		}
	}

	return ScanSummary{
		Duration:      duration,
		ModulesRun:    len(results),
		TotalRequests: totalRequests,
		VulnCount:     vulnCount,
		InfoCount:     infoCount,
	}
}

// generateJSONReport creates JSON report
func (r *Reporter) generateJSONReport(report *Report) (string, error) {
	// Create JSON file
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON marshaling error: %v", err)
	}

	// Write to file
	filename := r.getOutputFilename("json")
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return "", fmt.Errorf("file write error: %v", err)
	}

	r.logger.Success("JSON report created: %s", filename)
	return filename, nil
}

// generateHTMLReport creates HTML report
func (r *Reporter) generateHTMLReport(report *Report) (string, error) {
	// HTML template
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>IIS Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .vulnerability { margin: 10px 0; padding: 10px; border-left: 4px solid; }
        .critical { border-color: #e74c3c; background: #fdf2f2; }
        .high { border-color: #e67e22; background: #fef9f3; }
        .medium { border-color: #f39c12; background: #fefbf3; }
        .low { border-color: #3498db; background: #f3f9ff; }
        .module { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>IIS Security Scan Report</h1>
        <p>Target: {{.Target.URL}}</p>
        <p>Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <table>
            <tr><td>Duration</td><td>{{.Summary.Duration}}</td></tr>
            <tr><td>Modules Run</td><td>{{.Summary.ModulesRun}}</td></tr>
            <tr><td>Total Requests</td><td>{{.Summary.TotalRequests}}</td></tr>
            <tr><td>Total Vulnerabilities</td><td>{{.Summary.VulnCount.Total}}</td></tr>
            <tr><td>Critical</td><td>{{.Summary.VulnCount.Critical}}</td></tr>
            <tr><td>High</td><td>{{.Summary.VulnCount.High}}</td></tr>
            <tr><td>Medium</td><td>{{.Summary.VulnCount.Medium}}</td></tr>
            <tr><td>Low</td><td>{{.Summary.VulnCount.Low}}</td></tr>
        </table>
    </div>
    
    {{range $moduleName, $moduleResult := .Results}}
    <div class="module">
        <h3>{{$moduleName}} Module</h3>
        <p>Status: {{$moduleResult.Status}} | Duration: {{$moduleResult.Duration}} | Requests: {{$moduleResult.RequestCount}}</p>
        
        {{if $moduleResult.Vulnerabilities}}
        <h4>Vulnerabilities ({{len $moduleResult.Vulnerabilities}})</h4>
        {{range $moduleResult.Vulnerabilities}}
        <div class="vulnerability {{.Severity | lower}}">
            <h5>{{.Title}} ({{.Severity}})</h5>
            <p><strong>Description:</strong> {{.Description}}</p>
            <p><strong>URL:</strong> {{.URL}}</p>
            {{if .Evidence}}<p><strong>Evidence:</strong> {{.Evidence}}</p>{{end}}
            {{if .Remediation}}<p><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
        </div>
        {{end}}
        {{end}}
        
        {{if $moduleResult.Info}}
        <h4>Information ({{len $moduleResult.Info}})</h4>
        <ul>
        {{range $moduleResult.Info}}
        <li><strong>{{.Title}}:</strong> {{.Value}}</li>
        {{end}}
        </ul>
        {{end}}
    </div>
    {{end}}
</body>
</html>`

	// Parse template
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": func(s string) string {
			return fmt.Sprintf("%s", s)
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("template parsing error: %v", err)
	}

	// Create HTML file
	filename := r.getOutputFilename("html")
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("file creation error: %v", err)
	}
	defer file.Close()

	// Execute template
	err = tmpl.Execute(file, report)
	if err != nil {
		return "", fmt.Errorf("template execution error: %v", err)
	}

	r.logger.Success("HTML report created: %s", filename)
	return filename, nil
}

// generateXMLReport creates XML report
func (r *Reporter) generateXMLReport(report *Report) (string, error) {
	// Simple XML implementation
	filename := r.getOutputFilename("xml")

	// Convert JSON to XML (simple implementation)
	jsonData, _ := json.MarshalIndent(report, "", "  ")

	xmlContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<iis_scan_report>
<json_data><![CDATA[%s]]></json_data>
</iis_scan_report>`, string(jsonData))

	err := os.WriteFile(filename, []byte(xmlContent), 0644)
	if err != nil {
		return "", fmt.Errorf("XML file write error: %v", err)
	}

	r.logger.Success("XML report created: %s", filename)
	return filename, nil
}

// getOutputFilename generates output filename
func (r *Reporter) getOutputFilename(extension string) string {
	if r.config.Output != "" {
		// Change extension
		dir := filepath.Dir(r.config.Output)
		base := filepath.Base(r.config.Output)
		name := base[:len(base)-len(filepath.Ext(base))]
		return filepath.Join(dir, name+"."+extension)
	}

	// Default filename
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("iis_scan_report_%s.%s", timestamp, extension)
}
