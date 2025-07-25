# IIS Security Scanner Framework

Kapsamlı IIS (Internet Information Services) güvenlik tarama ve zafiyet tespit framework'ü. Go dilinde yazılmış, yüksek performanslı ve modüler yapıda.

## 🚀 Özellikler

### Core Modules
- **IIS Fingerprinting & Version Detection**: Server header analizi, ETW leak tespiti, version-specific pattern analizi
- **Tilde Character Vulnerability**: Short filename enumeration (8.3 format), directory bruteforce, encoding bypass
- **Configuration Vulnerabilities**: web.config/machine.config exposure, Global.asa/asax leak, bin directory enumeration
- **Path Traversal Attacks**: Double encoding, Unicode bypass, canonical path bypass, ADS exploitation
- **ASP.NET Specific**: ViewState MAC validation, padding oracle, trace.axd exposure, Elmah leak
- **HTTP Handler Vulnerabilities**: .NET Remoting, WCF service enumeration, ASMX discovery, SharePoint detection
- **Authentication Bypass**: NTLM bypass, Kerberos delegation, Windows Integrated Auth flaws
- **Buffer Overflow & DoS**: Long URL attacks, header overflow, chunked encoding, request smuggling
- **WebDAV Vulnerabilities**: PROPFIND abuse, LOCK/UNLOCK exploitation, file upload via WebDAV
- **SSL/TLS Specific**: SNI bypass, renegotiation attacks, certificate validation bypass

### Advanced Features
- **Evasion Techniques**: Multiple encoding methods, case variation, HTTP parameter pollution, verb tampering
- **Automated Exploitation**: Metasploit integration, payload generation, reverse shell creation
- **Comprehensive Reporting**: OWASP Top 10 mapping, CWE classification, CVSS scoring, HTML/JSON/XML output
- **Stealth & Performance**: Intelligent request throttling, distributed scanning, proxy chain support
- **Concurrent Scanning**: Goroutine-based parallel processing, configurable thread limits

## 📦 Kurulum

### Gereksinimler
- Go 1.21 veya üzeri
- Git

### Kurulum Adımları

```bash
# Repository'yi klonla
git clone https://github.com/ibrahmsql/iismap.git
cd issmap

# Dependencies'leri yükle
go mod tidy

# Binary'yi derle
go build -o issmap .

# Veya Makefile kullan
make build
```

## 🔧 Kullanım

### Temel Kullanım

```bash
# Temel tarama
./issmap --target https://target.com

# Kapsamlı tarama (tüm modüller)
./issmap --target https://target.com --comprehensive

# Belirli modülleri çalıştır
./issmap --target https://target.com --modules fingerprint,tilde,config

# Verbose output ile
./issmap --target https://target.com --verbose

# Debug modu
./issmap --target https://target.com --debug
```

### Gelişmiş Seçenekler

```bash
# Stealth mode (yavaş tarama)
./issmap --target https://target.com --stealth --delay 2

# Özel thread sayısı
./issmap --target https://target.com --threads 20

# Proxy kullanımı
./issmap --target https://target.com --proxy http://proxy:8080

# Özel User-Agent
./issmap --target https://target.com --user-agent "Custom Scanner 1.0"

# Özel header'lar
./issmap --target https://target.com --headers "Authorization: Bearer token123"

# Cookie'ler
./issmap --target https://target.com --cookies "session=abc123; auth=xyz789"

# Farklı output formatları
./issmap --target https://target.com --format html --output report.html
./issmap --target https://target.com --format json --output report.json
./issmap --target https://target.com --format xml --output report.xml
```

### Mevcut Modüller

| Modül | Açıklama | Durum |
|-------|----------|-------|
| `fingerprint` | IIS version detection & fingerprinting | ✅ Aktif |
| `tilde` | Tilde (~) character vulnerability | ✅ Aktif |
| `config` | Configuration file exposure | ✅ Aktif |
| `path_traversal` | Path traversal attacks | 🚧 Geliştiriliyor |
| `aspnet` | ASP.NET specific vulnerabilities | 🚧 Geliştiriliyor |
| `handlers` | HTTP handler vulnerabilities | 🚧 Geliştiriliyor |
| `auth_bypass` | Authentication bypass | 🚧 Geliştiriliyor |
| `buffer_overflow` | Buffer overflow & DoS | 🚧 Geliştiriliyor |
| `webdav` | WebDAV vulnerabilities | 🚧 Geliştiriliyor |
| `ssl_tls` | SSL/TLS specific issues | 🚧 Geliştiriliyor |

## 📊 Rapor Örnekleri

### JSON Output
```json
{
  "metadata": {
    "tool": "IIS Security Scanner",
    "version": "1.0.0"
  },
  "target": {
    "url": "https://example.com",
    "host": "example.com"
  },
  "summary": {
    "duration": "15.2s",
    "modules_run": 10,
    "vulnerability_count": {
      "total": 5,
      "critical": 1,
      "high": 2,
      "medium": 2,
      "low": 0
    }
  }
}
```

### HTML Raporu
Framework otomatik olarak profesyonel HTML raporları oluşturur:
- Executive summary
- Vulnerability details with CVSS scores
- Remediation recommendations
- Technical evidence

## 🛡️ Güvenlik Uyarıları

⚠️ **UYARI**: Bu araç sadece yetkili penetrasyon testleri ve güvenlik değerlendirmeleri için tasarlanmıştır.

- Sadece sahip olduğunuz veya test etme yetkisine sahip olduğunuz sistemlerde kullanın
- Üçüncü taraf sistemlerde kullanmadan önce yazılı izin alın
- Rate limiting ve stealth modunu kullanarak hedef sistemlere zarar vermekten kaçının
- Yasal sorumluluk tamamen kullanıcıya aittir

## 🔧 Geliştirme

### Yeni Modül Ekleme

```go
// modules/custom_module.go
package modules

import (
    "issmap/internal/config"
    "issmap/pkg/http"
    "issmap/pkg/logger"
)

type CustomModule struct {
    *BaseModule
    config *config.Config
    logger *logger.Logger
}

func NewCustomModule(cfg *config.Config, log *logger.Logger) Module {
    return &CustomModule{
        BaseModule: NewBaseModule("custom", "Custom Vulnerability Scanner"),
        config:     cfg,
        logger:     log,
    }
}

func (c *CustomModule) Run(client *http.Client) (*ModuleResult, error) {
    c.Start()
    defer c.End()
    
    // Tarama logic'i burada
    
    return c.CreateResult("COMPLETED", vulnerabilities, info, nil), nil
}
```

### Build & Test

```bash
# Test çalıştır
make test

# Linting
make lint

# Binary oluştur
make build

# Cross-platform build
make build-all
```

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 🤝 Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📞 İletişim

- GitHub Issues: Bug raporları ve feature istekleri için
- Email: security@example.com

---

**Disclaimer**: Bu araç eğitim ve yasal penetrasyon testi amaçları için geliştirilmiştir. Kötüye kullanımdan doğacak sorumluluk kullanıcıya aittir.