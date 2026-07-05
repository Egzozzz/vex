# VEX - Vulnerability Explorer

⚠️ **YASAL UYARI & ETİK KULLANIM | LEGAL & ETHICAL USE**
Bu araç sadece **izin verilen sistemlerde** test amacıyla kullanılmalıdır. This tool should only be used on systems you own or have explicit permission to test.
- Başka insanların sistemlerinde izinsiz test yapmak yasal sorumluluk doğurur! Unauthorized testing on systems you do not own is illegal and may result in criminal charges.
- Bu aracı kullanırken tüm yerel ve uluslararası yasaları, özellikle de bilgisayar suçları yasalarını takip etmek sizin sorumluluğunuzdadır.
- Geliştiriciler, bu aracın yanlış kullanımından sorumlu tutulamaz.

## Kısa Açıklama | Short Description

**Türkçe**:
VEX, otomatik güvenlik zafiyeti tarama aracıdır. Web uygulamalarında SQL Injection, Cross-Site Scripting (XSS), XML External Entity (XXE), IDOR, RCE, Broken Access Control, Path Traversal ve SSRF gibi potansiyel zafiyetleri tespit eder. Akıllı keşif, dizin brute-force, alt alan adı tarama ve AI destekli payload üretimi gibi özellikler sunar. Tespitler sonrası kullanıcıya manuel doğrulama için öneriler verir.

**English**:
VEX is an automated security vulnerability scanner designed to detect potential flaws in web applications, including SQL Injection, Cross-Site Scripting (XSS), XML External Entity (XXE), IDOR, RCE, Broken Access Control, Path Traversal, and SSRF. It offers smart crawling, directory brute-forcing, subdomain scanning, and AI-assisted payload generation, and provides manual verification recommendations after detection.

## Özellikler

- **Çoklu Zafiyet Tespiti**: SQLi, XSS, XXE, IDOR, RCE, BAC, Path Traversal, SSRF
- **Dizin Bruteforce**: Özel wordlistler ile dizin keşfi
- **Alt Alan Adı Keşfi**: Yaygın alt alan adlarını tarama
- **AI Motoru**: Smart mode ile akıllı payload üretimi (OpenAI uyumlu)
- **Özel Payloadlar**: Kendi payload dosyalarınızı kullanma
- **Gelişmiş Raporlama**: JSON, Markdown, HTML formatlarında raporlar

## Kurulum ve Kullanım

### Windows Kurulumu

#### Yöntem 1: Pip ile Kurulum (Önerilen)
1. Repoyu klonla:
   ```bash
   git clone https://github.com/kullanici-adi/vex.git
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
   git clone https://github.com/kullanici-adi/vex.git
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

### Linux / Kali Linux Kurulumu

#### Yöntem 1: Otomatik Kurulum Scripti (Önerilen)
```bash
git clone https://github.com/kullanici-adi/vex.git
cd vex
python -m venv .venv
source .venv/bin/activate
./install.sh
vex -h
...

#### Yöntem 2: Pip ile Manuel Kurulum
```bash
git clone https://github.com/kullanici-adi/vex.git
cd vex
pip3 install -e .
# (Opsiyonel) AI özellikleri için:
pip3 install -e ".[ai]"
```

## Kullanım

### Temel Kullanım
```bash
# Basit tarama
vex -u https://site.com

# Sadece SQLi tara
vex -u https://site.com --type sqli

# Wordlist ile dizin brute-force
vex -u https://site.com -w /usr/share/wordlists/dirb/common.txt

# Sonuçları kaydet (JSON/MD/HTML)
vex -u https://site.com -o results.html
```

### Yardım
```bash
vex -h
```

### Parametreler

#### Keşif ve Kapsam
- `-u, --url <url>`: Hedef temel URL.
- `-w, --wordlist <dosya>`: Dizin/dosya keşfi için wordlist.
- `-x, --exclude <regex>`: Belirli yol/parametreleri dışarıda bırak.
- `--depth <n>`: Crawler derinliği (varsayılan: 3).
- `--include-subdomains`: Alt alan adlarını dahil et.

#### AI & Analiz Motoru
- `-m, --mode <mod>`: Çalışma modu (fast, smart, fuzz).
- `--ai-model <model_adi>`: AI model adı (örn: gpt-4o, varsayılan: gpt-4o-mini).
- `--api-key <key>`: OpenAI API anahtarı.

#### Kimlik Doğrulama ve IDOR/CSRF Testi
- `-c, --cookie <cerez>`: Oturum çerezi.
- `--auth-header <header>`: Authorization başlığı.
- `--user-b <cookie>`: IDOR için ikinci kullanıcı çerezi.
- `--csrf-token <token>`: CSRF token.

#### Saldırı Vektörleri
- `--type <tur>`: Belirli açık türlerine odaklan (sqli, xss, idor, rce, xxe, ssrf, path, bac).
- `--custom-payloads <dosya>`: Özel payload dosyası.

#### Çıktı ve Raporlama
- `-o, --output <dosya>`: Sonuçları dosyaya kaydet (.json, .md, .html).
- `--verbose`: Detaylı çıktı.
- `--json`: JSON formatında çıktı.

## Örnekler

```bash
# Sadece SQLi ve XSS tara
vex -u https://site.com --type sqli xss

# HTML raporu kaydet
vex -u https://site.com -o report.html

# Cookie ve AI mode ile tarama
vex -u https://site.com -c "PHPSESSID=abc123" -m smart

# Alt alan adlarını dahil et
vex -u https://site.com --include-subdomains
```

## Konfigürasyon

### .env Dosyası
AI motorunu yapılandırmak için `.env.example` dosyasını `.env` olarak kopyalayıp düzenleyebilirsiniz:
```bash
cp .env.example .env
# .env dosyasını düzenle ve API anahtarını ekle
```

## Desteklenen Zafiyet Türleri
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- XML External Entity (XXE)
- Insecure Direct Object Reference (IDOR)
- Remote Code Execution (RCE)
- Broken Access Control (BAC)
- Path Traversal
- Server-Side Request Forgery (SSRF)

## Katkıda Bulunma
Pull request'ler ve issue'ler her zaman kabul edilir!

