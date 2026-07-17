# VEX - Vulnerability Explorer v0.5.0

⚠️ **YASAL UYARI & ETİK KULLANIM**
Bu araç sadece **izin verilen sistemlerde** test amacıyla kullanılmalıdır. Başka insanların sistemlerinde izinsiz test yapmak yasal sorumluluk doğurur. Geliştiriciler, bu aracın yanlış kullanımından sorumlu tutulamaz.

Gelişmiş siber güvenlik zafiyet tarama aracı. WAF atlatma, stealth tarama, otomatik payload üretimi ve PoC komutlarıyla donatılmıştır.

## Yenilikler (v0.5.0)
- Gelişmiş WAF Bypass Motoru: Cloudflare, Akamai, ModSecurity, AWS WAF, Imperva, Sucuri, Fortinet, Barracuda, Wordfence
- Stealth Engine: Proxy desteği, header rotasyonu, rate limiting, JA3 fingerprint evasion
- Context-Aware XSS: HTML/body/attribute/JS/URL bağlamı tespiti
- SSTI Multi-Engine: Jinja2, Twig, Freemarker, Velocity, ERB, EJS, Handlebars, Pug
- Cloud Metadata SSRF: AWS, GCP, Azure metadata endpoint testleri
- Method Tampering: IDOR ve BAC için HTTP method bypass
- JS Endpoint Discovery: JavaScript dosyalarından API endpoint çıkarma
- CVSS Skorlama & PoC Üretimi: Otomatik risk skoru ve PoC komutları
- Gelişmiş Raporlama: JSON, Markdown, HTML formatlarında interaktif raporlar
- Built-in Help Sistemi: `--help-vulns` ve `--help-tools` komutları

---

## Kurulum

### Windows

#### Yöntem 1: Pip ile Kurulum (Önerilen)
```cmd
git clone https://github.com/Egzozzz/vex.git
cd vex
pip install -e .
vex -h
```
AI özellikleri için: `pip install -e ".[ai]"`

#### Yöntem 2: Otomatik Kurulum
```cmd
install_windows.bat
```
Tüm bağımlılıklar otomatik kurulur.

#### Yöntem 3: vex.bat ile Taşınabilir (Kurulum Gerektirmez)
```cmd
vex.bat -u https://site.com
vex.bat --type sqli xss
```

#### Yöntem 4: PowerShell ile
```powershell
.\vex.ps1 -u https://site.com
```

#### Yöntem 5: Basit Kullanım (sadece bağımlılıklar)
```cmd
git clone https://github.com/Egzozzz/vex.git
cd vex
pip install -r requirements.txt
vex.bat -h
```

### Linux / Kali

#### Yöntem 1: Otomatik Kurulum (Önerilen)
```bash
git clone https://github.com/Egzozzz/vex.git
cd vex
python3 -m venv .venv
source .venv/bin/activate
chmod +x install.sh
./install.sh
vex -h
```

#### Yöntem 2: Pip ile Manuel Kurulum
```bash
git clone https://github.com/Egzozzz/vex.git
cd vex
python3 -m venv .venv
source .venv/bin/activate
pip3 install -e .
vex -h
```
AI özellikleri için: `pip3 install -e ".[ai]"`

---

## Kullanım

| Komut | Açıklama |
|---|---|
| `vex -u https://site.com` | Temel tarama |
| `vex -u https://site.com --type sqli xss rce` | Belirli zafiyet türleri |
| `vex -u https://site.com --waf-bypass --stealth-level 3` | WAF Bypass + Stealth |
| `vex -u https://site.com --proxy socks5://127.0.0.1:9050` | Proxy ile |
| `vex -u https://site.com -c "PHPSESSID=abc123"` | Kimlik doğrulama ile |
| `vex -u https://site.com -o report.html` | HTML rapor |
| `vex -u https://site.com --discover-hidden` | Gizli endpoint keşfi |
| `vex -u https://site.com --type idor --user-b "COOKIE_B"` | IDOR Cross-User test |
| `vex -u https://site.com -m smart --api-key YOUR_KEY` | AI destekli tarama |
| `vex --help-vulns` | Zafiyet türleri hakkında bilgi |
| `vex --help-tools` | Önerilen dış araçlar hakkında bilgi |

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
- CVSS skorları, PoC komutları, özet istatistikleri

### HTML
- İnteraktif arayüz, koyu tema, renk kodlu ciddiyet seviyeleri, kopyalanabilir PoC komutları

### Markdown
- CI/CD entegrasyonu için uygun, GitHub/GitLab README desteği

## Katkıda Bulunma
Pull request'ler ve issue'ler her zaman kabul edilir!
