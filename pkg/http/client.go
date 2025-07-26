package http

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ibrahmsql/iismap/internal/config"
)

// Client HTTP client structure
type Client struct {
	client  *http.Client
	config  *config.Config
	headers map[string]string
}

// Response HTTP response structure
type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       string
	Length     int
	Duration   time.Duration
}

// NewClient creates new HTTP client
func NewClient(cfg *config.Config) *Client {
	// Transport configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip SSL verification
		},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     10 * time.Second,
		DisableKeepAlives:   false, // Keep keep-alive active
		DisableCompression:  false, // Keep compression active
	}

	// Proxy settings
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	// HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Default headers
	headers := map[string]string{
		"User-Agent": cfg.UserAgent,
		"Accept":     "*/*",
		"Connection": "close",
	}

	// Add custom headers
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	return &Client{
		client:  client,
		config:  cfg,
		headers: headers,
	}
}

// Get sends GET request
func (c *Client) Get(targetURL string) (*Response, error) {
	return c.Request("GET", targetURL, "")
}

// Post sends POST request
func (c *Client) Post(targetURL, body string) (*Response, error) {
	return c.Request("POST", targetURL, body)
}

// Head sends HEAD request
func (c *Client) Head(targetURL string) (*Response, error) {
	return c.Request("HEAD", targetURL, "")
}

// Options sends OPTIONS request
func (c *Client) Options(targetURL string) (*Response, error) {
	return c.Request("OPTIONS", targetURL, "")
}

// Request sends custom HTTP request
func (c *Client) Request(method, targetURL, body string) (*Response, error) {
	start := time.Now()

	// Create request
	req, err := http.NewRequest(method, targetURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request creation error: %v", err)
	}

	// Add headers
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	// Add cookies
	for k, v := range c.config.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	// Set Content-Type
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request sending error: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	bodyBytes := make([]byte, 1024*1024) // 1MB limit
	n, _ := resp.Body.Read(bodyBytes)
	responseBody := string(bodyBytes[:n])

	duration := time.Since(start)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       responseBody,
		Length:     len(responseBody),
		Duration:   duration,
	}, nil
}

// GetHeader gets response header
func (r *Response) GetHeader(name string) string {
	values := r.Headers[name]
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// HasHeader checks header existence
func (r *Response) HasHeader(name string) bool {
	_, exists := r.Headers[name]
	return exists
}

// ContainsBody searches string in body
func (r *Response) ContainsBody(text string) bool {
	return strings.Contains(strings.ToLower(r.Body), strings.ToLower(text))
}

// IsSuccess checks successful response
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsRedirect checks redirect response
func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

// IsClientError checks client error
func (r *Response) IsClientError() bool {
	return r.StatusCode >= 400 && r.StatusCode < 500
}

// IsServerError checks server error
func (r *Response) IsServerError() bool {
	return r.StatusCode >= 500
}
