package http

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ibrahmsql/issmap/internal/config"
)

// Client HTTP istemci yapısı
type Client struct {
	client  *http.Client
	config  *config.Config
	headers map[string]string
}

// Response HTTP yanıt yapısı
type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       string
	Length     int
	Duration   time.Duration
}

// NewClient yeni HTTP istemci oluşturur
func NewClient(cfg *config.Config) *Client {
	// Transport konfigürasyonu
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // SSL doğrulamasını atla
		},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     10 * time.Second,
		DisableKeepAlives:   false, // Keep-alive'ı aktif tut
		DisableCompression:  false, // Compression'ı aktif tut
	}

	// Proxy ayarları
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	// HTTP istemci
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Redirect'leri takip etme
		},
	}

	// Varsayılan header'lar
	headers := map[string]string{
		"User-Agent": cfg.UserAgent,
		"Accept":     "*/*",
		"Connection": "close",
	}

	// Özel header'ları ekle
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	return &Client{
		client:  client,
		config:  cfg,
		headers: headers,
	}
}

// Get GET isteği gönderir
func (c *Client) Get(targetURL string) (*Response, error) {
	return c.Request("GET", targetURL, "")
}

// Post POST isteği gönderir
func (c *Client) Post(targetURL, body string) (*Response, error) {
	return c.Request("POST", targetURL, body)
}

// Head HEAD isteği gönderir
func (c *Client) Head(targetURL string) (*Response, error) {
	return c.Request("HEAD", targetURL, "")
}

// Options OPTIONS isteği gönderir
func (c *Client) Options(targetURL string) (*Response, error) {
	return c.Request("OPTIONS", targetURL, "")
}

// Request özel HTTP isteği gönderir
func (c *Client) Request(method, targetURL, body string) (*Response, error) {
	start := time.Now()

	// İstek oluştur
	req, err := http.NewRequest(method, targetURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("istek oluşturma hatası: %v", err)
	}

	// Header'ları ekle
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	// Cookie'leri ekle
	for k, v := range c.config.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	// Content-Type ayarla
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// İsteği gönder
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("istek gönderme hatası: %v", err)
	}
	defer resp.Body.Close()

	// Yanıtı oku
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

// GetHeader yanıt header'ını alır
func (r *Response) GetHeader(name string) string {
	values := r.Headers[name]
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// HasHeader header'ın varlığını kontrol eder
func (r *Response) HasHeader(name string) bool {
	_, exists := r.Headers[name]
	return exists
}

// ContainsBody body'de string arar
func (r *Response) ContainsBody(text string) bool {
	return strings.Contains(strings.ToLower(r.Body), strings.ToLower(text))
}

// IsSuccess başarılı yanıt kontrolü
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsRedirect redirect yanıt kontrolü
func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

// IsClientError client error kontrolü
func (r *Response) IsClientError() bool {
	return r.StatusCode >= 400 && r.StatusCode < 500
}

// IsServerError server error kontrolü
func (r *Response) IsServerError() bool {
	return r.StatusCode >= 500
}
