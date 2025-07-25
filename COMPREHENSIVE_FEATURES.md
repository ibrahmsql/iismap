# IIS Security Scanner - Comprehensive Feature Documentation

## 🎯 Enhanced Framework Overview

Bu Go tabanlı IIS Security Scanner, Microsoft IIS web sunucuları için kapsamlı güvenlik değerlendirmesi yapan profesyonel bir araçtır. Framework, modüler yapısı sayesinde genişletilebilir ve her modül belirli güvenlik kontrollerini gerçekleştirir.

## 🚀 Yeni Eklenen Özellikler

### ✅ Windows Server Detection Module
**Amaç**: IIS sadece Windows Server üzerinde çalıştığı için hedef sistemin Windows Server olup olmadığını tespit eder.

**Kontroller**:
- **Server Header Analysis**: HTTP header'larından Windows/IIS göstergelerini tespit
- **IIS Response Patterns**: Error page pattern'larından IIS versiyonu tespiti
- **Windows-specific Paths**: Windows'a özgü dosya/dizin path'lerini kontrol
- **ASP.NET Detection**: ViewState, EventValidation gibi ASP.NET göstergelerini arar
- **Network Level Detection**: Windows service portlarını (135, 139, 445, 3389, vb.) tarar
- **Version Mapping**: IIS versiyonundan Windows Server versiyonunu tespit

**Tespit Edilen Zafiyetler**:
- Non-Windows Server detection (INFO level)
- Windows version information disclosure

### ✅ ASP.NET Security Module
**Amaç**: ASP.NET uygulamalarına özgü güvenlik zafiyetlerini tespit eder.

**Kontroller**:
- **ViewState Security**: MAC validation, encryption, manipulation testleri
- **Event Validation**: CSRF koruması kontrolü
- **Trace.axd Exposure**: Debug trace sayfası erişim kontrolü
- **Elmah.axd Exposure**: Error logging sayfası erişim kontrolü
- **Error Information Disclosure**: Detaylı hata mesajları kontrolü
- **Session Management**: Cookie güvenlik flag'leri (HttpOnly, Secure)
- **Padding Oracle Attacks**: ViewState padding oracle zafiyeti testi
- **Version Disclosure**: ASP.NET versiyon bilgisi sızıntısı

**Tespit Edilen Zafiyetler**:
- ViewState MAC validation disabled (HIGH)
- ViewState not encrypted (MEDIUM)
- Event validation disabled (MEDIUM)
- ASP.NET trace information disclosure (HIGH)
- ELMAH error log exposure (HIGH)
- Detailed error information disclosure (MEDIUM)
- Session cookie security issues (MEDIUM)
- Padding oracle vulnerability (HIGH)
- ASP.NET version disclosure (LOW)

### ✅ HTTP Methods Security Module
**Amaç**: HTTP metodlarının güvenlik açısından değerlendirilmesi.

**Kontroller**:
- **HTTP Methods Enumeration**: Desteklenen HTTP metodlarını tespit
- **Dangerous Methods**: PUT, DELETE, TRACE, CONNECT metodları
- **WebDAV Methods**: PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK
- **Method Override**: X-HTTP-Method-Override header testleri
- **TRACE XST**: Cross-Site Tracing saldırısı testi
- **File Upload/Delete**: PUT/DELETE ile dosya işlemleri

**Tespit Edilen Zafiyetler**:
- Dangerous HTTP methods enabled (CRITICAL/HIGH)
- HTTP PUT method file upload (CRITICAL)
- HTTP DELETE method file deletion (HIGH)
- WebDAV methods enabled (MEDIUM)
- PROPFIND directory enumeration (MEDIUM)
- HTTP method override possible (MEDIUM)
- TRACE method XST vulnerability (MEDIUM)

### ✅ SSL/TLS Security Module
**Amaç**: SSL/TLS konfigürasyonunun güvenlik değerlendirmesi.

**Kontroller**:
- **Certificate Analysis**: Sertifika geçerliliği, imza algoritması, anahtar boyutu
- **Protocol Versions**: SSLv3, TLS 1.0/1.1/1.2/1.3 desteği
- **Cipher Suites**: Zayıf şifreleme algoritmaları
- **Security Headers**: HSTS (HTTP Strict Transport Security)
- **Renegotiation**: SSL/TLS renegotiation zafiyetleri
- **SNI Testing**: Server Name Indication bypass
- **Mixed Content**: HTTPS sayfalarında HTTP resource'ları

**Tespit Edilen Zafiyetler**:
- Unencrypted HTTP connection (HIGH)
- Expired/expiring SSL certificates (HIGH/MEDIUM)
- Self-signed certificates (MEDIUM)
- Weak signature algorithms (MEDIUM)
- Weak key sizes (HIGH)
- Insecure SSL/TLS protocols (CRITICAL/HIGH)
- Weak cipher suites (HIGH)
- Missing HSTS header (MEDIUM)
- SSL/TLS renegotiation enabled (MEDIUM)
- SNI bypass possible (LOW)
- Mixed content detected (MEDIUM)

## 📊 Geliştirilmiş Özellikler

### 🔍 Enhanced Fingerprinting
- **ETW Leak Detection**: Event Tracing for Windows bilgi sızıntısı
- **Hidden Module Detection**: Gizli IIS yönetim path'leri
- **ISAPI Extension Enumeration**: Aktif ISAPI extension'ları
- **Version-specific Patterns**: IIS versiyonuna özgü response pattern'ları

### 🛡️ Advanced Configuration Checks
- **Sensitive Data Detection**: web.config'de hassas bilgi kontrolü
- **Backup File Detection**: Yedek dosya ve arşiv tespiti
- **Directory Listing**: Bin, App_Data directory erişimi
- **Temporary Files**: ASP.NET geçici dosya exposure'ı

### 🔐 Comprehensive Tilde Vulnerability
- **Encoding Bypass**: Multiple encoding teknikleri
- **Unicode Normalization**: Unicode karakter bypass
- **Full Name Resolution**: Kısa dosya adlarından tam ad tespiti
- **Directory Enumeration**: 8.3 format dizin adları

## 🎯 Kullanım Senaryoları

### 1. Temel Windows Server Kontrolü
```bash
./iis-scanner --target https://example.com --modules windows_detection
```

### 2. ASP.NET Güvenlik Değerlendirmesi
```bash
./iis-scanner --target https://example.com --modules aspnet --verbose
```

### 3. HTTP Methods Güvenlik Testi
```bash
./iis-scanner --target https://example.com --modules http_methods --aggressive
```

### 4. SSL/TLS Konfigürasyon Kontrolü
```bash
./iis-scanner --target https://example.com --modules ssl_tls --comprehensive
```

### 5. Kapsamlı IIS Güvenlik Taraması
```bash
./iis-scanner --target https://example.com --comprehensive --format html
```

## 📈 Performans ve Güvenilirlik

### Concurrent Processing
- **Goroutine-based**: Paralel modül çalıştırma
- **Configurable Threads**: Ayarlanabilir thread limitleri
- **Request Throttling**: Rate limiting ve stealth mode

### Error Handling
- **Graceful Degradation**: Modül hatalarında devam etme
- **Comprehensive Logging**: Detaylı hata kayıtları
- **Retry Mechanisms**: Başarısız istekler için tekrar deneme

### Security Considerations
- **Non-intrusive**: Sistem zarar vermeyen testler
- **Cleanup Operations**: Test dosyalarını otomatik temizleme
- **Rate Limiting**: Hedef sistemi yormayan tarama

## 🔧 Teknik Detaylar

### Vulnerability Classification
- **CVSS Scoring**: 0.0-10.0 arası risk puanlaması
- **CWE Mapping**: Common Weakness Enumeration kategorileri
- **OWASP Top 10**: OWASP 2021 kategorilerine göre sınıflandırma
- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW, INFO

### Evidence Collection
- **Request/Response Capture**: Tam HTTP istek/yanıt kayıtları
- **Payload Documentation**: Kullanılan test payload'ları
- **Pattern Matching**: Zafiyet tespit pattern'ları
- **Remediation Guidance**: Her zafiyet için düzeltme önerileri

### Report Generation
- **Multiple Formats**: JSON, HTML, XML çıktı formatları
- **Executive Summary**: Yönetici özet raporları
- **Technical Details**: Teknik detay raporları
- **Proof of Concept**: Zafiyet kanıtlama örnekleri

## 🎯 Gelecek Geliştirmeler

### Planned Modules
1. **Path Traversal Advanced**: Double encoding, Unicode bypass
2. **Authentication Bypass**: NTLM, Kerberos, Windows Integrated Auth
3. **Buffer Overflow Testing**: Long URL, header overflow
4. **WebDAV Advanced**: File upload, directory creation
5. **Information Disclosure**: Comprehensive info leak detection

### Integration Features
1. **Metasploit Integration**: Otomatik exploitation
2. **Burp Suite Plugin**: Professional tool entegrasyonu
3. **CI/CD Integration**: Automated security testing
4. **Database Backend**: Vulnerability tracking
5. **API Interface**: RESTful API for automation

## 📋 Desteklenen IIS Versiyonları

| IIS Version | Windows Server | Support Status |
|-------------|----------------|----------------|
| IIS 6.0     | 2003          | ✅ Full Support |
| IIS 7.0     | 2008          | ✅ Full Support |
| IIS 7.5     | 2008 R2       | ✅ Full Support |
| IIS 8.0     | 2012          | ✅ Full Support |
| IIS 8.5     | 2012 R2       | ✅ Full Support |
| IIS 10.0    | 2016/2019/2022| ✅ Full Support |

## 🛡️ Güvenlik Uyarıları

⚠️ **YASAL UYARI**: Bu araç sadece yetkili penetrasyon testleri için tasarlanmıştır.

- ✅ Sahip olduğunuz sistemlerde kullanın
- ✅ Yazılı test yetkisi alın
- ✅ Stealth mode kullanarak sistem yükünü minimize edin
- ❌ Yetkisiz sistemlerde kullanmayın
- ❌ Üretim sistemlerinde agresif mod kullanmayın

## 📞 Destek ve Katkı

- **GitHub Issues**: Bug raporları ve feature istekleri
- **Documentation**: Kapsamlı kullanım kılavuzu
- **Community**: Güvenlik araştırmacıları topluluğu
- **Updates**: Düzenli güvenlik güncellemeleri

Bu framework, IIS güvenlik değerlendirmesi için endüstri standardında bir araç olarak tasarlanmış ve sürekli geliştirilmektedir.