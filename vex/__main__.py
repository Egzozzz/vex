from .cli import parse_args
from .crawler import Crawler
from .detectors import (
    SQLIDetector,
    XSSDetector,
    XXEDetector,
    IDORDetector,
    RCEDetector,
    BACDetector,
    PathTraversalDetector,
    SSRFDetector
)
from .core.ai_engine import AIEngine
from .core.report_generator import save_report
from .payloads.loader import load_custom_payloads
import json
from colorama import init, Fore, Style

init(autoreset=True)

def main():
    args = parse_args()
    
    print(f"{Fore.CYAN}{Style.BRIGHT}██╗   ██╗███████╗██╗  ██╗")
    print(f"{Fore.CYAN}{Style.BRIGHT}██║   ██║██╔════╝╚██╗██╔╝")
    print(f"{Fore.CYAN}{Style.BRIGHT}██║   ██║█████╗   ╚███╔╝ ")
    print(f"{Fore.CYAN}{Style.BRIGHT}╚██╗ ██╔╝██╔══╝   ██╔██╗ ")
    print(f"{Fore.CYAN}{Style.BRIGHT} ╚████╔╝ ███████╗██╔╝ ██╗")
    print(f"{Fore.CYAN}{Style.BRIGHT}  ╚═══╝  ╚══════╝╚═╝  ╚═╝")
    print(f"{Fore.WHITE}VEX - Vulnerability Explorer v0.3.0")
    print()
    print(f"{Fore.RED}{Style.BRIGHT}⚠️ UYARI: Sadece izin verilen sistemlerde kullanın!")
    print(f"{Fore.YELLOW}Bu aracı izinsiz sistemlerde kullanmak yasal sorumluluk doğurur!")
    print()
    
    if not args.url:
        print(f"{Fore.RED}Hedef URL gerekli! -u/--url kullanın.")
        return
        
    print(f"{Fore.YELLOW}[*] Tarama başlatılıyor: {args.url}")
    
    ai_engine = AIEngine(model=args.ai_model, api_key=args.api_key)
    if ai_engine.enabled:
        print(f"{Fore.CYAN}[*] AI Engine aktif: {ai_engine.model}")
    else:
        print(f"{Fore.YELLOW}[*] AI Engine pasif (API anahtarı yok)")
    
    custom_payloads = {}
    if args.custom_payloads:
        custom_payloads = load_custom_payloads(args.custom_payloads)
        print(f"{Fore.CYAN}[*] Özel payloadlar yüklendi: {args.custom_payloads}")
    
    crawler = Crawler(args.url, depth=args.depth, exclude=args.exclude, wordlist_path=args.wordlist, include_subdomains=args.include_subdomains)
    
    if args.cookie:
        cookie_dict = {}
        for item in args.cookie.split(';'):
            if '=' in item:
                key, val = item.split('=', 1)
                cookie_dict[key.strip()] = val.strip()
        crawler.session.cookies.update(cookie_dict)
    
    if args.auth_header:
        key, val = args.auth_header.split(':', 1)
        crawler.session.headers.update({key.strip(): val.strip()})
    
    print(f"{Fore.YELLOW}[*] Site crawlanıyor...")
    crawler.crawl()
    
    if args.include_subdomains:
        print(f"{Fore.YELLOW}[*] Alt alan adları keşfediliyor...")
        crawler.discover_subdomains()
        
    if args.wordlist:
        print(f"{Fore.YELLOW}[*] Dizin brute-force yapılıyor...")
        crawler.brute_force_directories()
        
    targets = crawler.get_all_targets()
    
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}=== BULUNAN HEDEFLER ===")
    print(f"{Fore.WHITE}Toplam {len(targets)} hedef bulundu!")
    print()

    if crawler.found_subdomains:
        print(f"{Fore.GREEN}{Style.BRIGHT}Bulunan Alt Alan Adları ({len(crawler.found_subdomains)}):")
        for sub in crawler.found_subdomains:
            color = Fore.GREEN if sub['status_code'] == 200 else (Fore.YELLOW if sub['status_code'] in (301, 302, 307, 308) else Fore.RED)
            print(f"{color}  [{sub['status_code']}] {sub['subdomain']} ({sub['url']})")
        print()

    if crawler.bruteforced_paths:
        print(f"{Fore.GREEN}{Style.BRIGHT}Bulunan Dizinler ({len(crawler.bruteforced_paths)}):")
        for path in crawler.bruteforced_paths:
            color = Fore.GREEN if path['status_code'] == 200 else (Fore.YELLOW if path['status_code'] in (301, 302, 307, 308) else Fore.RED)
            print(f"{color}  [{path['status_code']}] {path['url']}")
        print()

    if crawler.endpoints:
        print(f"{Fore.BLUE}{Style.BRIGHT}GET Endpointleri ({len(crawler.endpoints)}):")
        for ep in crawler.endpoints:
            print(f"{Fore.WHITE}  [+] {ep['url']}")
            print(f"{Fore.WHITE}      Parametreler: {', '.join(ep['params'])}")
        print()

    if crawler.forms:
        print(f"{Fore.BLUE}{Style.BRIGHT}Formlar ({len(crawler.forms)}):")
        for form in crawler.forms:
            print(f"{Fore.WHITE}  [+] {form['method']} {form['url']}")
            print(f"{Fore.WHITE}      Parametreler: {', '.join(form['params'])}")
        print()
    
    print(f"{Fore.CYAN}{Style.BRIGHT}=== TESTLER BAŞLIYOR ===")
    print()
    
    all_results = []
    seen_results = set()
    
    detector_map = {
        'sqli': SQLIDetector,
        'sql': SQLIDetector,
        'xss': XSSDetector,
        'xxe': XXEDetector,
        'idor': IDORDetector,
        'rce': RCEDetector,
        'bac': BACDetector,
        'path': PathTraversalDetector,
        'path_traversal': PathTraversalDetector,
        'ssrf': SSRFDetector
    }
    
    alias_map = {
        'sql': 'sqli',
        'path_traversal': 'path'
    }
    
    # Normalize and deduplicate selected types
    selected_types_raw = args.type if args.type else list(detector_map.keys())
    normalized_types = []
    seen = set()
    for t in selected_types_raw:
        normalized = alias_map.get(t, t)
        if normalized not in seen:
            normalized_types.append(normalized)
            seen.add(normalized)
    selected_types = normalized_types
    
    if 'bac' in selected_types:
        print(f"{Fore.YELLOW}[*] BAC taranıyor...")
        bac_detector = BACDetector(session=crawler.session, ai_engine=ai_engine, mode=args.mode, custom_payloads=custom_payloads)
        bac_results = bac_detector.test(args.url)
        for result in bac_results:
            key = (result['type'], result['url'])
            if key not in seen_results:
                seen_results.add(key)
                all_results.append(result)
        selected_types.remove('bac')

    for idx, target in enumerate(targets, 1):
        print(f"{Fore.YELLOW}[{idx}/{len(targets)}] Hedef: {target['url']}")
        print(f"{Fore.WHITE}  Metot: {target['method']}")
        print(f"{Fore.WHITE}  Parametreler: {', '.join(target['params'])}")
        print()

        for vuln_type in selected_types:
            print(f"{Fore.BLUE}  [-] {vuln_type.upper()} test ediliyor...")

            DetectorClass = detector_map[vuln_type]
            if vuln_type == 'idor':
                detector = DetectorClass(session=crawler.session, user_b_cookie=args.user_b, ai_engine=ai_engine, mode=args.mode, custom_payloads=custom_payloads)
            else:
                detector = DetectorClass(session=crawler.session, ai_engine=ai_engine, mode=args.mode, custom_payloads=custom_payloads)
                
            results = detector.test(target)
            
            unique_results = []
            for result in results:
                key_parts = [result['type'], result['url']]
                if 'param' in result:
                    key_parts.append(result['param'])
                if 'payload' in result:
                    key_parts.append(result['payload'][:50])
                key = tuple(key_parts)
                
                if key not in seen_results:
                    seen_results.add(key)
                    all_results.append(result)
                    unique_results.append(result)
            
            for result in unique_results:
                color = Fore.RED if result['confidence'] == 'high' else Fore.YELLOW
                technique = result.get('technique', 'unknown')
                print(f"{color}    [+] {result['type'].upper()} olası ({technique}) — manuel test önerilir")
        print()
            
    print()
    print(f"{Fore.MAGENTA}{Style.BRIGHT}=== TARAMA SONUÇLARI ===")
    print()
    
    if not all_results:
        print(f"{Fore.GREEN}[+] Hiç zafiyet bulunamadı!")
    else:
        print(f"{Fore.WHITE}Toplam {len(all_results)} zafiyet bulundu:")
        print()
        for result in all_results:
            type_name = result['type'].upper()
            color = Fore.RED if result['confidence'] == 'high' else Fore.YELLOW
            
            print(f"{color}[!] {type_name} olası — manuel doğrulama gerekli")
            print(f"    URL: {result['url']}")
            if 'param' in result:
                print(f"    Parametre: {result['param']}")
            if 'payload' in result:
                payload = result['payload']
                if len(str(payload)) > 120:
                    payload = str(payload)[:120] + '...'
                print(f"    Payload: {payload}")
            if 'technique' in result:
                print(f"    Teknik: {result['technique']}")
            if 'confidence' in result:
                print(f"    Güven: {result['confidence']}")
            if 'manual_test' in result:
                print(f"    {Fore.CYAN}Manuel test: {result['manual_test']}")
            print()
            
    if args.output:
        save_report(all_results, args.output)
        print(f"{Fore.GREEN}[+] Sonuçlar kaydedildi: {args.output}")
        
    if args.json:
        print(json.dumps(all_results, indent=2, ensure_ascii=False))
        
if __name__ == "__main__":
    main()
