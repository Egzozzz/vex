import argparse
import sys
from . import __version__


def parse_args():
    parser = argparse.ArgumentParser(
        prog='vex',
        description='VEX - Vulnerability Explorer: Advanced cybersecurity vulnerability scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vex -u https://site.com                              # Basic scan
  vex -u https://site.com --type sqli xss              # Specific vulns
  vex -u https://site.com -m smart -c "PHPSESSID=abc"  # Auth + AI mode
  vex -u https://site.com --proxy socks5://127.0.0.1:9050  # Via proxy
  vex -u https://site.com --waf-bypass --stealth-level 3    # Max stealth
  vex -u https://site.com -o report.html               # HTML report
  vex -u https://site.com --type sqli --custom-payloads my_payloads.txt

Supported vuln types: sqli, xss, rce, ssrf, path, xxe, idor, bac
        """
    )

    parser.add_argument('-v', '--version', action='version', version=f'VEX {__version__}')

    # Keşif ve Kapsam
    recon_group = parser.add_argument_group('Keşif ve Kapsam (Recon & Scope)')
    recon_group.add_argument('-u', '--url', type=str, help='Hedef temel URL')
    recon_group.add_argument('-w', '--wordlist', type=str, help='Dizin/dosya keşfi için wordlist')
    recon_group.add_argument('-x', '--exclude', type=str, help='Belirli yol/parametreleri dışarıda bırak')
    recon_group.add_argument('--depth', type=int, default=3, help='Crawler derinliği (varsayılan: 3)')
    recon_group.add_argument('--include-subdomains', action='store_true', help='Alt alan adlarını dahil et')
    recon_group.add_argument('--no-stealth', action='store_true', help='Stealth modunu devre dışı bırak')
    recon_group.add_argument('--discover-hidden', action='store_true', help='Gizli endpoint keşfi yap (API, JS, .env)')

    # AI & Analiz
    ai_group = parser.add_argument_group('AI & Analiz Motoru')
    ai_group.add_argument('-m', '--mode', type=str, default='fast', choices=['fast', 'smart', 'fuzz'],
                          help='Çalışma modu (fast, smart, fuzz)')
    ai_group.add_argument('--ai-model', type=str, help='AI model adı (örn: gpt-4o)')
    ai_group.add_argument('--api-key', type=str, help='API anahtarı')

    # Kimlik Doğrulama
    auth_group = parser.add_argument_group('Kimlik Doğrulama ve IDOR/CSRF Testi')
    auth_group.add_argument('-c', '--cookie', type=str, help='Oturum çerezi')
    auth_group.add_argument('--auth-header', type=str, help='Authorization başlığı')
    auth_group.add_argument('--user-b', type=str, help='IDOR için ikinci kullanıcı çerezi')
    auth_group.add_argument('--csrf-token', type=str, help='CSRF token')

    # Saldırı Vektörleri
    payload_group = parser.add_argument_group('Saldırı Vektörleri')
    payload_group.add_argument('--type', nargs='+', type=str,
                               help='Belirli açık türleri (sqli, xss, idor, rce, xxe, ssrf, path, bac)')
    payload_group.add_argument('--custom-payloads', type=str, help='Özel payload dosyası')
    payload_group.add_argument('--waf-bypass', action='store_true', help='WAF bypass modunu aktifleştir')

    # Stealth & Proxy
    stealth_group = parser.add_argument_group('Stealth & Proxy')
    stealth_group.add_argument('--proxy', type=str, help='Proxy adresi (örn: socks5://127.0.0.1:9050)')
    stealth_group.add_argument('--stealth-level', type=int, default=2, choices=[0, 1, 2, 3],
                               help='Stealth seviyesi (0=pasif, 1=normal, 2=stealth, 3=agresif)')
    stealth_group.add_argument('--rate-limit', type=int, help='Dakikadaki maks istek sayısı')
    stealth_group.add_argument('--delay', type=float, help='İstekler arası minimum bekleme (saniye)')

    # Çıktı ve Raporlama
    output_group = parser.add_argument_group('Çıktı ve Raporlama')
    output_group.add_argument('-o', '--output', type=str, help='Sonuçları dosyaya kaydet (.json, .md, .html)')
    output_group.add_argument('--verbose', action='store_true', help='Detaylı çıktı')
    output_group.add_argument('--json', action='store_true', help='JSON formatında çıktı')
    output_group.add_argument('--no-color', action='store_true', help='Renkli çıktıyı devre dışı bırak')

    # Help
    parser.add_argument('--help-vulns', action='store_true', help='Desteklenen zafiyet türleri hakkında bilgi')
    parser.add_argument('--help-tools', action='store_true', help='Önerilen dış araçlar hakkında bilgi')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Özel help komutları
    if getattr(args, 'help_vulns', False):
        print_vuln_help()
        sys.exit(0)

    if getattr(args, 'help_tools', False):
        print_tools_help()
        sys.exit(0)

    return args


def print_vuln_help():
    """Desteklenen zafiyet türleri hakkında detaylı bilgi."""
    help_text = """
╔══════════════════════════════════════════════════════════════════════╗
║                    VEX - Desteklenen Zafiyet Türleri               ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  SQLI (SQL Injection)                                                ║
║  ├─ Error-based: DBMS hata mesajlarından tespit                     ║
║  ├─ Boolean blind: True/false yanıt karşılaştırması                 ║
║  ├─ Time-based: Gecikme sinyalleri tespiti                          ║
║  ├─ Stacked queries: Birden fazla sorgu enjeksiyonu                 ║
║  ├─ UNION: Sütun sayısı tespiti                                     ║
║  └─ WAF bypass: Otomatik encoding ve tamper teknikleri              ║
║                                                                      ║
║  XSS (Cross-Site Scripting)                                          ║
║  ├─ Reflected: Payload yansıma tespiti                              ║
║  ├─ Context-aware: HTML/body/attribute/JS/URL bağlamı              ║
║  ├─ DOM XSS: Kaynak/sink analizi                                   ║
║  ├─ Filter bypass: Null byte, encoding, case variation             ║
║  └─ WAF bypass: Çift encoding, Unicode bypass                      ║
║                                                                      ║
║  RCE (Remote Code Execution)                                         ║
║  ├─ Command injection: Echo marker ile tespit                       ║
║  ├─ SSTI: Çoklu motor testi (Jinja2, Twig, Freemarker, vb.)       ║
║  ├─ Commix-style: Encoding ve IFS bypass                           ║
║  └─ Indicator match: Sistem çıktısı tespiti                         ║
║                                                                      ║
║  SSRF (Server-Side Request Forgery)                                  ║
║  ├─ Content match: Yanıt içeriği analizi                           ║
║  ├─ Response diff: Baseline karşılaştırması                         ║
║  ├─ Cloud metadata: AWS/GCP/Azure metadata endpoint'leri           ║
║  ├─ Blind SSRF: Zamanlama analizi                                   ║
║  └─ Protocol: Gopher, dict, file, LDAP wrapper'ları                ║
║                                                                      ║
║  Path Traversal / LFI                                                ║
║  ├─ File read: /etc/passwd, win.ini, .env göstergeleri             ║
║  ├─ Encoding: Double encoding, null byte, Unicode                   ║
║  ├─ DotDotPwn: Derin traversal payload'ları                        ║
║  └─ WAF bypass: Çift encoding ve alternatif delimiter'lar          ║
║                                                                      ║
║  XXE (XML External Entity)                                           ║
║  ├─ Entity expansion: File read XXE                                 ║
║  ├─ OOB: Out-of-band XXE (blind)                                   ║
║  ├─ DTD invocations: External DTD yükleme                          ║
║  └─ Protocol: file://, php://, expect://, gopher://                 ║
║                                                                      ║
║  IDOR (Insecure Direct Object Reference)                             ║
║  ├─ Sequential ID: Artan/azalan ID testi                           ║
║  ├─ UUID: UUID varyasyonları                                        ║
║  ├─ Cross-user: İki farklı kullanıcı ile test                      ║
║  └─ Method tampering: GET/POST/PUT/DELETE ile test                 ║
║                                                                      ║
║  BAC (Broken Access Control)                                         ║
║  ├─ Admin panel: exposed admin path keşfi                          ║
║  ├─ Method bypass: HTTP method tampering                           ║
║  ├─ Header bypass: X-Forwarded-For ile bypass                      ║
║  └─ Auth bypass: Yetkisiz erişim tespiti                           ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(help_text)


def print_tools_help():
    """Önerilen dış araçlar hakkında bilgi."""
    help_text = """
╔══════════════════════════════════════════════════════════════════════╗
║                    VEX - Önerilen Dış Araçlar                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  SQL Injection Test Araçları:                                        ║
║  ├─ sqlmap: sqlmap -u "URL" -p PARAM --batch --level=3 --risk=2    ║
║  ├─ sqlmap (WAF bypass): --tamper=space2comment,randomcase          ║
║  └─ NoSQLMap: MongoDB/NoSQL injection testleri                     ║
║                                                                      ║
║  XSS Test Araçları:                                                  ║
║  ├─ dalfox: dalfox url "URL" -p PARAM --blind-callback              ║
║  ├─ XSStrike: xsstrike -u "URL" --params                          ║
║  └─ XSSer: xsser -u "URL" --auto                                  ║
║                                                                      ║
║  RCE / Command Injection Test Araçları:                              ║
║  ├─ commix: commix -u "URL" --data="param=*"                       ║
║  └─ nuclei -t rce/ templates -u "URL"                              ║
║                                                                      ║
║  SSRF Test Araçları:                                                 ║
║  ├─ SSRFmap: ssrfmap -r request.txt -p param -m portscan           ║
║  └─ Gopherus: Gopher payload üretimi                                ║
║                                                                      ║
║  Path Traversal Test Araçları:                                       ║
║  ├─ dotdotpwn: dotdotpwn -m http -u "URL" -q                       ║
║  └─ nuclei -t lfi/ templates -u "URL"                              ║
║                                                                      ║
║  XXE Test Araçları:                                                  ║
║  ├─ XXEinjector: XXE enjeksiyon testleri                          ║
║  └─ Burp Suite Repeater: Manuel XXE testleri                       ║
║                                                                      ║
║  IDOR & BAC Test Araçları:                                           ║
║  ├─ nuclei -t idor/ templates -u "URL"                             ║
║  ├─ nuclei -t bac/ templates -u "URL"                              ║
║  └─ Autorize (Burp extension): Authorization bypass testleri       ║
║                                                                      ║
║  WAF Bypass Araçları:                                                ║
║  ├─ wafninja: WAF bypass payload üretimi                           ║
║  ├─ bypass: ModSecurity bypass                                      ║
║  └─ sqlmap --tamper: Built-in WAF bypass                          ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(help_text)
