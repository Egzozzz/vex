# VEX - Vulnerability Explorer

⚠️ **YASAL UYARI & ETİK KULLANIM | LEGAL & ETHICAL USE**
Bu araç sadece **izin verilen sistemlerde** test amacıyla kullanılmalıdır.
- Başka insanların sistemlerinde izinsiz test yapmak yasal sorumluluk doğurur!
- Bu aracı kullanırken tüm yerel ve uluslararası yasaları takip etmek sizin sorumluluğunuzdadır.
- Geliştiriciler, bu aracın yanlış kullanımından sorumlu tutulamaz.

## Kısa Açıklama

**VEX**, gelişmiş siber güvenlik zafiyet tarama aracıdır. WAF atlatma, stealth tarama, otomatik payload üretimi ve PoC komutlarıyla donatılmıştır.

## v0.5.0 Yenilikleri

- **Gelişmiş WAF Bypass Motoru**: Cloudflare, Akamai, ModSecurity, AWS WAF, Imperva, Sucuri, Fortinet, Barracuda, Wordfence
- **Stealth Engine**: Proxy desteği, header rotasyonu, rate limiting, JA3 fingerprint evasion
- **Context-Aware XSS**: HTML/body/attribute/JS/URL bağlamı tespiti
- **SSTI Multi-Engine**: Jinja2, Twig, Freemarker, Velocity, ERB, EJS, Handlebars, Pug
- **Cloud Metadata SSRF**: AWS, GCP, Azure metadata endpoint testleri
- **Method Tampering**: IDOR ve BAC için HTTP method bypass
- **JS Endpoint Discovery**: JavaScript dosyalarından API endpoint çıkarma
- **CVSS Skorlama & PoC Üretimi**: Otomatik risk skoru ve PoC komutları
- **Gelişmiş Raporlama**: JSON, Markdown, HTML formatlarında interaktif raporlar
- **Built-in Help Sistemi**: `--help-vulns` ve `--help-tools` komutları

## Kurulum

### Windows (CMD / PowerShell)

#### Yöntem 1: Pip ile Kurulum (Önerilen)
<<<<<<< HEAD
1. Repoyu klonla:
   ```bash
   git clone https://github.com/Egzozzz/vex.git
   cd vex
   ```
2. Projeyi yükle:
   ```bash
   pip install -e .
   ```
3. (Opsiyonel) AI özellikleri için:
   ```bash
   pip install -e ".[ai]"
   ```
4. Artık `vex` komutunu kullanabilirsin!
   ```cmd
   vex -h
   vex -u https://site.com
   ```

#### Yöntem 2: Basit Kullanım
1. Repoyu klonla:
   ```bash
   git clone https://github.com/Egzozzz/vex.git
   cd vex
   ```
2. Gerekli paketleri kur:
   ```bash
   pip install -r requirements.txt
   ```
3. Artık `vex.bat` dosyasını kullanabilirsin!
   ```cmd
   vex.bat -h
   vex.bat -u https://site.com
   ```

```cmd
git clone https://github.com/kullanici-adi/vex.git
cd vex
pip install -e .
vex -h
```

#### Yöntem 2: Otomatik Kurulum
```cmd
install_windows.bat
```
`install_windows.bat` çalıştırın, tüm bağımlılıklar otomatik kurulur.


#### Yöntem 3: vex.bat ile Taşınabilir Kullanım
```cmd
vex.bat -u https://site.com
vex.bat --type sqli xss
```
Hiçbir kurulum gerektirmez. `vex.bat` VEX'i otomatik olarak bulur ve çalıştırır.

#### Yöntem 4: PowerShell ile
```powershell
.\vex.ps1 -u https://site.com
```

### Linux / Kali
```bash
git clone https://github.com/Egzozzz/vex.git
cd vex
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./install.sh
vex -h
...
  HEAD
#### Yöntem 2: Pip ile Manuel Kurulum
```bash
git clone https://github.com/Egzozzz/vex.git
cd vex
pip3 install -e .
# (Opsiyonel) AI özellikleri için:
pip3 install -e ".[ai]"
```

=======
 7e54534 (v0.5.0 - Major Update)
## Kullanım

### Temel Tarama
```bash
vex -u https://site.com
```

### Belirli Zafiyet Türleri
```bash
vex -u https://site.com --type sqli xss rce
```

### WAF Bypass + Stealth
```bash
vex -u https://site.com --waf-bypass --stealth-level 3 --proxy socks5://127.0.0.1:9050
```

### Kimlik Doğrulama ile
```bash
vex -u https://site.com -c "PHPSESSID=abc123" --auth-header "Authorization: Bearer token"
```

### Raporlama
```bash
vex -u https://site.com -o report.html
vex -u https://site.com -o report.json
vex -u https://site.com -o report.md
```

### Gizli Endpoint Keşfi
```bash
vex -u https://site.com --discover-hidden
```

### IDOR Cross-User Test
```bash
vex -u https://site.com --type idor --user-b "SESSION_COOKIE_USER_B"
```

### AI Destekli Tarama
```bash
vex -u https://site.com -m smart --api-key YOUR_OPENAI_KEY
```

### Help Komutları
```bash
vex --help-vulns     # Desteklenen zafiyet türleri hakkında bilgi
vex --help-tools     # Önerilen dış araçlar hakkında bilgi
```

## Parametreler

### Keşif ve Kapsam
| Parametre | Açıklama |
|---|---|
| `-u, --url` | Hedef temel URL |
| `-w, --wordlist` | Dizin/dosya keşfi için wordlist |
| `-x, --exclude` | Belirli yolları dışarıda bırak |
| `--depth` | Crawler derinliği (varsayılan: 3) |
| `--include-subdomains` | Alt alan adlarını dahil et |
| `--discover-hidden` | Gizli endpoint keşfi |
| `--no-stealth` | Stealth modunu kapat |

### AI & Analiz
| Parametre | Açıklama |
|---|---|
| `-m, --mode` | Çalışma modu (fast, smart, fuzz) |
| `--ai-model` | AI model adı |
| `--api-key` | OpenAI API anahtarı |

### Kimlik Doğrulama
| Parametre | Açıklama |
|---|---|
| `-c, --cookie` | Oturum çerezi |
| `--auth-header` | Authorization başlığı |
| `--user-b` | IDOR için ikinci kullanıcı |
| `--csrf-token` | CSRF token |

### Saldırı Vektörleri
| Parametre | Açıklama |
|---|---|
| `--type` | Zafiyet türleri (sqli, xss, rce, ssrf, path, xxe, idor, bac) |
| `--custom-payloads` | Özel payload dosyası |
| `--waf-bypass` | WAF bypass aktifleştir |

### Stealth & Proxy
| Parametre | Açıklama |
|---|---|
| `--proxy` | Proxy adresi (socks5://, http://) |
| `--stealth-level` | 0=pasif, 1=normal, 2=stealth, 3=agresif |
| `--rate-limit` | Dakikadaki maks istek |
| `--delay` | İstekler arası bekleme |

### Çıktı
| Parametre | Açıklama |
|---|---|
| `-o, --output` | Rapor dosyası (.json, .md, .html) |
| `--verbose` | Detaylı çıktı |
| `--json` | JSON formatında çıktı |

## Desteklenen Zafiyet Türleri

| Tür | Teknikler | Dış Araçlar |
|---|---|---|
| **SQLi** | Error-based, Boolean blind, Time-based, Stacked, UNION, WAF bypass | sqlmap |
| **XSS** | Reflected, Context-aware, DOM, Filter bypass, WAF bypass | dalfox, XSStrike, XSSer |
| **RCE** | Command injection, SSTI (11 motor), Commix-style | commix, nuclei |
| **SSRF** | Content match, Response diff, Cloud metadata, Blind, Protocol | SSRFmap, Gopherus |
| **Path Traversal** | File read, Encoding, DotDotPwn, WAF bypass | dotdotpwn, nuclei |
| **XXE** | Entity expansion, OOB, DTD, Protocol | Burp Suite |
| **IDOR** | Sequential ID, UUID, Cross-user, Method tampering | nuclei, Autorize |
| **BAC** | Admin panel, Method bypass, Header bypass, Auth bypass | nuclei |

## Desteklenen WAF'lar

| WAF | Tespit | Bypass Teknikleri |
|---|---|---|
| Cloudflare | Header/Content | IP rotation, Unicode, Encoding |
| Akamai | Header/Content | URL bypass, Encoding |
| ModSecurity | Header/Content | Tamper scripts, Case variation |
| AWS WAF | Header/Content | IP bypass, Header injection |
| F5 BIG-IP | Header/Content | Encoding, Chunked |
| Imperva/Incapsula | Header/Content | IP rotation, Unicode |
| Sucuri | Header/Content | Encoding, Delay |
| Wordfence | Header/Content | Case variation, Encoding |
| Fortinet | Header/Content | Encoding, Delay |
| Barracuda | Header/Content | Encoding, Tamper |

## Raporlama Formatları

### JSON
- CVSS skorları
- PoC komutları
- Özet istatistikleri

### HTML
- İnteraktif arayüz
- Koyu tema
- Renk kodlu ciddiyet seviyeleri
- Kopyalanabilir PoC komutları

### Markdown
- CI/CD entegrasyonu için uygun
- GitHub/GitLab README desteği

## Katkıda Bulunma
Pull request'ler ve issue'ler her zaman kabul edilir!
