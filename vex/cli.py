import argparse
import sys
from . import __version__

def parse_args():
    parser = argparse.ArgumentParser(
        prog='vex',
        description='VEX - Vulnerability Explorer: A cybersecurity tool for automated vulnerability scanning'
    )
    
    parser.add_argument('-v', '--version', action='version', version=f'VEX {__version__}')
    
    recon_group = parser.add_argument_group('Keşif ve Kapsam (Recon & Scope)')
    recon_group.add_argument('-u', '--url', type=str, help='Hedef temel URL')
    recon_group.add_argument('-w', '--wordlist', type=str, help='Dizin/dosya keşfi için wordlist')
    recon_group.add_argument('-x', '--exclude', type=str, help='Belirli yol/parametreleri dışarıda bırak')
    recon_group.add_argument('--depth', type=int, default=3, help='Crawler derinliği (varsayılan: 3)')
    recon_group.add_argument('--include-subdomains', action='store_true', help='Alt alan adlarını dahil et')
    
    ai_group = parser.add_argument_group('AI & Analiz Motoru')
    ai_group.add_argument('-m', '--mode', type=str, default='fast', choices=['fast', 'smart', 'fuzz'], help='Çalışma modu (fast, smart, fuzz)')
    ai_group.add_argument('--ai-model', type=str, help='AI model adı (örn: gpt-4o)')
    ai_group.add_argument('--api-key', type=str, help='API anahtarı')
    
    auth_group = parser.add_argument_group('Kimlik Doğrulama ve IDOR/CSRF Testi')
    auth_group.add_argument('-c', '--cookie', type=str, help='Oturum çerezi')
    auth_group.add_argument('--auth-header', type=str, help='Authorization başlığı')
    auth_group.add_argument('--user-b', type=str, help='IDOR için ikinci kullanıcı çerezi')
    auth_group.add_argument('--csrf-token', type=str, help='CSRF token')
    
    payload_group = parser.add_argument_group('Saldırı Vektörleri')
    payload_group.add_argument('--type', nargs='+', type=str, help='Belirli açık türlerine odaklan (sqli, xss, idor, rce, xxe, ssrf, path, bac) - birden fazla yazılabilir')
    payload_group.add_argument('--custom-payloads', type=str, help='Özel payload dosyası')
    
    output_group = parser.add_argument_group('Çıktı ve Raporlama')
    output_group.add_argument('-o', '--output', type=str, help='Sonuçları dosyaya kaydet')
    output_group.add_argument('--verbose', action='store_true', help='Detaylı çıktı')
    output_group.add_argument('--json', action='store_true', help='JSON formatında çıktı')
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    return parser.parse_args()
