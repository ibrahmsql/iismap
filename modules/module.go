package modules

import (
	"time"

	"github.com/ibrahmsql/iismap/pkg/http"
)

// Module interface for all scanning modules
type Module interface {
	Name() string
	Description() string
	Run(client *http.Client) (*ModuleResult, error)
}

// ModuleResult module result structure
type ModuleResult struct {
	ModuleName      string          `json:"module_name"`
	Status          string          `json:"status"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	RequestCount    int             `json:"request_count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Info            []Information   `json:"info"`
	Error           string          `json:"error,omitempty"`
}

// Vulnerability vulnerability structure
type Vulnerability struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	CVSS        float64           `json:"cvss"`
	CWE         string            `json:"cwe"`
	OWASP       string            `json:"owasp"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Payload     string            `json:"payload"`
	Response    string            `json:"response"`
	Evidence    string            `json:"evidence"`
	References  []string          `json:"references"`
	Remediation string            `json:"remediation"`
	Metadata    map[string]string `json:"metadata"`
}

// Information information structure
type Information struct {
	Type        string            `json:"type"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Value       string            `json:"value"`
	URL         string            `json:"url"`
	Metadata    map[string]string `json:"metadata"`
}

// BaseModule base module structure
type BaseModule struct {
	name        string
	description string
	startTime   time.Time
	endTime     time.Time
	requests    int
}

// NewBaseModule creates a new base module
func NewBaseModule(name, description string) *BaseModule {
	return &BaseModule{
		name:        name,
		description: description,
	}
}

// Name returns the module name
func (b *BaseModule) Name() string {
	return b.name
}

// Description returns the module description
func (b *BaseModule) Description() string {
	return b.description
}

// Start marks the module start
func (b *BaseModule) Start() {
	b.startTime = time.Now()
	b.requests = 0
}

// End marks the module end
func (b *BaseModule) End() {
	b.endTime = time.Now()
}

// IncrementRequests increments the request count
func (b *BaseModule) IncrementRequests() {
	b.requests++
}

// CreateResult creates a result structure
func (b *BaseModule) CreateResult(status string, vulnerabilities []Vulnerability, info []Information, err error) *ModuleResult {
	result := &ModuleResult{
		ModuleName:      b.name,
		Status:          status,
		StartTime:       b.startTime,
		EndTime:         b.endTime,
		Duration:        b.endTime.Sub(b.startTime),
		RequestCount:    b.requests,
		Vulnerabilities: vulnerabilities,
		Info:            info,
	}

	if err != nil {
		result.Error = err.Error()
	}

	return result
}

// CreateVulnerability creates a vulnerability
func CreateVulnerability(id, title, description, severity string, cvss float64) Vulnerability {
	return Vulnerability{
		ID:          id,
		Title:       title,
		Description: description,
		Severity:    severity,
		CVSS:        cvss,
		References:  []string{},
		Metadata:    make(map[string]string),
	}
}

// CreateInformation creates an information
func CreateInformation(infoType, title, description, value string) Information {
	return Information{
		Type:        infoType,
		Title:       title,
		Description: description,
		Value:       value,
		Metadata:    make(map[string]string),
	}
}
