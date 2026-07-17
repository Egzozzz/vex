import sys
import io
import time
from .cli import parse_args
from .crawler import Crawler
from .detectors import (
    SQLIDetector, XSSDetector, XXEDetector, IDORDetector,
    RCEDetector, BACDetector, PathTraversalDetector, SSRFDetector
)
from .core.ai_engine import AIEngine
from .core.report_generator import save_report
from .core.stealth import StealthEngine
from .payloads.loader import load_custom_payloads
import json
from colorama import init, Fore, Style

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}██╗   ██╗███████╗██╗  ██╗
{Fore.CYAN}{Style.BRIGHT}██║   ██║██╔════╝╚██╗██╔╝
{Fore.CYAN}{Style.BRIGHT}██║   ██║█████╗   ╚███╔╝ 
{Fore.CYAN}{Style.BRIGHT}╚██╗ ██╔╝██╔══╝   ██╔██╗ 
{Fore.CYAN}{Style.BRIGHT} ╚████╔╝ ███████╗██╔╝ ██╗
{Fore.CYAN}{Style.BRIGHT}  ╚═══╝  ╚══════╝╚═╝  ╚═╝
{Fore.WHITE}VEX - Vulnerability Explorer {Style.DIM}v0.5.0 - {Fore.RED}Endpoint Canavarı
"""

def log_info(msg):
    print(f"  {Fore.CYAN}▸ {Fore.WHITE}{msg}")

def log_ok(msg):
    print(f"  {Fore.GREEN}✔ {Fore.WHITE}{msg}")

def log_warn(msg):
    print(f"  {Fore.YELLOW}⚠ {Fore.WHITE}{msg}")

def log_find(msg, vuln_type='info'):
    colors = {'sqli': Fore.RED, 'xss': Fore.MAGENTA, 'rce': Fore.RED,
              'ssrf': Fore.YELLOW, 'xxe': Fore.BLUE, 'path': Fore.CYAN,
              'idor': Fore.MAGENTA, 'bac': Fore.YELLOW}
    c = colors.get(vuln_type, Fore.WHITE)
    print(f"  {c}◆ {Fore.WHITE}{msg}")

def log_error(msg):
    print(f"  {Fore.RED}✘ {Fore.WHITE}{msg}")

def print_separator(title):
    w = 60
    print()
    print(f"  {Fore.CYAN}{'═' * w}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}  {title}")
    print(f"  {Fore.CYAN}{'═' * w}")
    print()

def print_section(title):
    print(f"  {Fore.CYAN}━━━ {Style.BRIGHT}{title} {Fore.CYAN}{'━' * (50 - len(title))}")
    print()

def test_endpoint_with_timeout(detector, target, vuln_type):
    """Test endpoint and return results, handling timeouts per vuln type."""
    try:
        results = detector.test(target)
        return results
    except Exception as e:
        log_warn(f"{vuln_type.upper()} test failed: {e}")
        return []

def main():
    args = parse_args()
    print(BANNER)

    print(f"  {Fore.RED}{Style.BRIGHT}⚠  YALNIZCA İZİN VERİLEN SİSTEMLERDE KULLANIN!")
    print(f"  {Fore.YELLOW}  İzinsiz test yapmak yasal sorumluluk doğurur!")
    print()

    if not args.url:
        log_error("Hedef URL gerekli! -u/--url kullanın.")
        return

    total_start = time.time()

    # ─── TARGET INFO ──────────────────────────────────────────
    print_separator(f"HEDEF: {args.url}")

    # ─── AI ENGINE ────────────────────────────────────────────
    ai_engine = AIEngine(model=args.ai_model, api_key=args.api_key)
    if ai_engine.enabled:
        log_ok(f"AI Engine aktif: {Fore.CYAN}{ai_engine.model}")
    else:
        log_info("AI Engine pasif (API anahtarı yok)")

    # ─── STEALTH ENGINE ───────────────────────────────────────
    stealth_engine = StealthEngine(
        proxy=getattr(args, 'proxy', None),
        rate_limit=getattr(args, 'rate_limit', None),
        stealth_level=getattr(args, 'stealth_level', 2),
    )
    stealth_info = stealth_engine.get_stealth_info()
    level_names = {0: 'Pasif', 1: 'Normal', 2: 'Stealth', 3: 'Agresif'}
    log_ok(f"Stealth seviyesi: {Fore.CYAN}{stealth_info['level']} ({level_names.get(stealth_info['level'], '?')})")
    if stealth_info['proxy']:
        log_ok(f"Proxy: {Fore.CYAN}{stealth_info['proxy']}")
    if stealth_info['rate_limit']:
        log_ok(f"Rate limit: {Fore.CYAN}{stealth_info['rate_limit']} req/min")

    # ─── CUSTOM PAYLOADS ──────────────────────────────────────
    custom_payloads = {}
    if args.custom_payloads:
        custom_payloads = load_custom_payloads(args.custom_payloads)
        log_ok(f"Özel payloadlar yüklendi: {Fore.CYAN}{args.custom_payloads}")

    # ─── CRAWLER ──────────────────────────────────────────────
    print_section("ENDPOINT KEŞFİ")
    log_info(f"Crawler başlatılıyor (depth={args.depth})...")

    crawler = Crawler(
        args.url,
        depth=args.depth,
        exclude=args.exclude,
        wordlist_path=args.wordlist,
        include_subdomains=args.include_subdomains,
        stealth=not getattr(args, 'no_stealth', False),
        proxy=getattr(args, 'proxy', None),
    )

    if args.cookie:
        for item in args.cookie.split(';'):
            if '=' in item:
                k, v = item.split('=', 1)
                crawler.session.cookies.update({k.strip(): v.strip()})

    if args.auth_header:
        k, v = args.auth_header.split(':', 1)
        crawler.session.headers.update({k.strip(): v.strip()})

    crawler.crawl()
    log_ok(f"Crawl tamamlandı: {Fore.CYAN}{len(crawler.visited)}{Fore.WHITE} sayfa tarandı")

    if crawler.detected_wafs and crawler.detected_wafs != ["unknown"]:
        log_warn(f"WAF tespit edildi: {Fore.MAGENTA}{', '.join(crawler.detected_wafs)}")
        stealth_engine.detected_wafs = crawler.detected_wafs

    # Hidden endpoint discovery
    if getattr(args, 'discover_hidden', False):
        log_info("Gizli endpoint'ler taranıyor...")
        hidden = crawler._discover_hidden_paths()
        if hidden:
            log_ok(f"{len(hidden)} gizli endpoint bulundu:")
            for h in hidden[:15]:
                color = Fore.GREEN if h['status_code'] == 200 else Fore.YELLOW
                print(f"    {color}[{h['status_code']}] {h['url']}")
            if len(hidden) > 15:
                log_info(f"...ve {len(hidden)-15} daha")

    # Subdomain discovery
    if args.include_subdomains:
        print_section("ALT ALAN ADI KEŞFİ")
        log_info(f"500+ alt alan adı taranıyor...")
        crawler.include_subdomains = True
        crawler.discover_subdomains()

    # Directory brute-force
    if args.wordlist:
        print_section("DİZİN BRUTE-FORCE")
        log_info(f"Wordlist: {args.wordlist}")
        crawler.brute_force_directories()

    # ─── RESULTS SUMMARY ──────────────────────────────────────
    targets = crawler.get_all_targets(max_targets=25)
    print_section(f"BULUNAN HEDEFLER")
    log_ok(f"Toplam {len(targets)} hedef (öncelik sırasına göre)")
    print()

    if crawler.found_subdomains:
        active = [s for s in crawler.found_subdomains if s['status_code'] == 200]
        redirect = [s for s in crawler.found_subdomains if s['status_code'] in (301, 302)]
        log_ok(f"Alt alan adları: {Fore.GREEN}{len(active)} aktif {Fore.WHITE}| {Fore.YELLOW}{len(redirect)} yönlendirme {Fore.WHITE}| {len(crawler.found_subdomains)} toplam")
        for s in crawler.found_subdomains[:8]:
            c = Fore.GREEN if s['status_code'] == 200 else Fore.YELLOW if s['status_code'] in (301, 302) else Fore.RED
            print(f"    {c}[{s['status_code']}] {s['subdomain']}")
        if len(crawler.found_subdomains) > 8:
            log_info(f"  ...ve {len(crawler.found_subdomains)-8} daha")
        print()

    if crawler.bruteforced_paths:
        accessible = [p for p in crawler.bruteforced_paths if p['status_code'] == 200]
        log_ok(f"Bulunan dizinler: {Fore.GREEN}{len(accessible)} erişilebilir {Fore.WHITE}| {len(crawler.bruteforced_paths)} toplam")
        for p in crawler.bruteforced_paths[:5]:
            c = Fore.GREEN if p['status_code'] == 200 else Fore.YELLOW
            print(f"    {c}[{p['status_code']}] {p['url']}")
        if len(crawler.bruteforced_paths) > 5:
            log_info(f"  ...ve {len(crawler.bruteforced_paths)-5} daha")
        print()

    if crawler.endpoints:
        print(f"  {Fore.BLUE}◆ GET Endpointleri ({len(crawler.endpoints)}):")
        for ep in crawler.endpoints[:8]:
            print(f"    {Fore.WHITE}{ep['url']}")
            if ep.get('params'):
                print(f"      {Fore.YELLOW}params: {', '.join(ep['params'])}  priority: {ep.get('priority', 0)}")
        print()

    if crawler.js_endpoints:
        print(f"  {Fore.BLUE}◆ JS Endpointleri ({len(crawler.js_endpoints)}):")
        for ep in crawler.js_endpoints[:5]:
            print(f"    {Fore.WHITE}{ep['url']} {Style.DIM}(from: {ep['source']})")

    if crawler.forms:
        print(f"  {Fore.BLUE}◆ Formlar ({len(crawler.forms)}):")
        for fm in crawler.forms[:5]:
            print(f"    {Fore.WHITE}{fm['method']} {fm['url']}")
            print(f"      {Fore.YELLOW}params: {', '.join(fm['params'])}  priority: {fm.get('priority', 0)}")
        print()

    # ─── VULNERABILITY SCANNING ─────────────────────────────
    print_separator("ZAFİYET TARAMASI BAŞLIYOR")

    all_results = []
    seen_results = set()

    detector_map = {
        'sqli': SQLIDetector, 'sql': SQLIDetector, 'xss': XSSDetector,
        'xxe': XXEDetector, 'idor': IDORDetector, 'rce': RCEDetector,
        'bac': BACDetector, 'path': PathTraversalDetector,
        'path_traversal': PathTraversalDetector, 'ssrf': SSRFDetector,
    }
    alias_map = {'sql': 'sqli', 'path_traversal': 'path'}

    selected_types_raw = args.type if args.type else list(detector_map.keys())
    normalized_types, seen = [], set()
    for t in selected_types_raw:
        n = alias_map.get(t, t)
        if n not in seen:
            normalized_types.append(n)
            seen.add(n)
    selected_types = normalized_types

    vuln_labels = {
        'sqli': 'SQL Injection', 'xss': 'Cross-Site Scripting',
        'rce': 'RCE / Command Inj.', 'ssrf': 'Server-Side RF',
        'path': 'Path Traversal', 'xxe': 'XXE Injection',
        'idor': 'Insecure Direct Obj. Ref.', 'bac': 'Broken Access Ctrl',
    }

    # BAC test (specific - tests admin paths globally)
    if 'bac' in selected_types:
        print_section("BAC / ADMIN PANEL TARAMASI")
        log_info("Admin yolları taranıyor...")
        bac_detector = BACDetector(
            session=crawler.session, ai_engine=ai_engine, mode=args.mode,
            custom_payloads=custom_payloads, stealth=not getattr(args, 'no_stealth', False),
        )
        bac_detector._configure_stealth(stealth_engine)
        bac_results = bac_detector.test(args.url)
        for r in bac_results:
            key = (r['type'], r['url'])
            if key not in seen_results:
                seen_results.add(key)
                all_results.append(r)
        selected_types = [t for t in selected_types if t != 'bac']

    # Per-target scanning
    total_tests = len(targets) * len(selected_types)
    test_count = 0
    scan_start = time.time()

    for idx, target in enumerate(targets, 1):
        print_section(f"HEDEF [{idx}/{len(targets)}]: {target['url']}")
        log_info(f"Method: {Fore.CYAN}{target.get('method', 'GET')}")
        log_info(f"Parametreler: {Fore.YELLOW}{', '.join(target.get('params', []))}")
        if 'priority' in target:
            log_info(f"Öncelik: {target['priority']}")

        for vuln_type in selected_types:
            test_count += 1
            label = vuln_labels.get(vuln_type, vuln_type.upper())
            print(f"    {Fore.BLUE}[{test_count}/{total_tests}] {label} taranıyor...")

            DetectorClass = detector_map[vuln_type]
            kwargs = {
                'session': crawler.session, 'ai_engine': ai_engine,
                'mode': args.mode, 'custom_payloads': custom_payloads,
                'stealth': not getattr(args, 'no_stealth', False),
            }
            if vuln_type == 'idor':
                kwargs['user_b_cookie'] = args.user_b

            detector = DetectorClass(**kwargs)
            detector._configure_stealth(stealth_engine)
            results = test_endpoint_with_timeout(detector, target, vuln_type)

            for r in results:
                key = tuple([r['type'], r['url']] +
                            ([r['param']] if 'param' in r else []) +
                            ([str(r['payload'])[:50]] if 'payload' in r else []))
                if key not in seen_results:
                    seen_results.add(key)
                    all_results.append(r)
                    confidence = r.get('confidence', 'low')
                    technique = r.get('technique', 'unknown')
                    param = r.get('param', '?')
                    icon = '●' if confidence == 'high' else '○' if confidence == 'medium' else '◌'
                    color = Fore.RED if confidence == 'high' else Fore.YELLOW if confidence == 'medium' else Fore.CYAN
                    print(f"      {color}{icon} {label} tespit edildi!")
                    print(f"        {Fore.WHITE}param: {param} | technique: {technique} | confidence: {confidence}")

    # ─── FINAL REPORT ─────────────────────────────────────────
    scan_elapsed = time.time() - scan_start
    total_elapsed = time.time() - total_start
    print_separator("TARAMA SONUÇLARI")

    highs = len([r for r in all_results if r.get('confidence') == 'high'])
    mediums = len([r for r in all_results if r.get('confidence') == 'medium'])
    lows = len([r for r in all_results if r.get('confidence') == 'low'])

    print(f"  {Fore.WHITE}Toplam: {Fore.CYAN}{len(all_results)} zafiyet {Fore.WHITE}| "
          f"{Fore.RED}{highs} yüksek {Fore.WHITE}| "
          f"{Fore.YELLOW}{mediums} orta {Fore.WHITE}| "
          f"{Fore.CYAN}{lows} düşük")
    print(f"  {Fore.WHITE}Süre: {Fore.CYAN}{total_elapsed:.0f}s {Fore.WHITE}| "
          f"Tarama: {scan_elapsed:.0f}s {Fore.WHITE}| "
          f"Endpoint: {len(targets)}")
    print()

    if not all_results:
        log_ok("Hiç zafiyet bulunamadı! Site güvenli görünüyor.")
    else:
        # Group by type
        by_type = {}
        for r in all_results:
            t = r['type']
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(r)

        for vuln_type, findings in sorted(by_type.items()):
            label = vuln_labels.get(vuln_type, vuln_type.upper())
            high_count = len([f for f in findings if f.get('confidence') == 'high'])
            print(f"  {Fore.RED if high_count else Fore.YELLOW}◆ {label}: {len(findings)} bulgu ({high_count} yüksek güven)")
            for f in findings[:3]:
                c = Fore.RED if f.get('confidence') == 'high' else Fore.YELLOW
                print(f"    {c}▪ {f['url']}")
                print(f"      {Fore.WHITE}param: {f.get('param', '?')} | technique: {f.get('technique', '?')}")
                if 'manual_test' in f:
                    print(f"      {Fore.CYAN}→ {f['manual_test'][:100]}...")
            if len(findings) > 3:
                print(f"      {Fore.WHITE}...ve {len(findings)-3} daha")
            print()

    # ─── OUTPUT ───────────────────────────────────────────────
    if args.output:
        save_report(all_results, args.output)
        log_ok(f"Rapor kaydedildi: {Fore.CYAN}{args.output}")

    if args.json:
        print(json.dumps(all_results, indent=2, ensure_ascii=False))

    # ─── SUMMARY ──────────────────────────────────────────────
    print_separator("İSTATİSTİKLER")
    print(f"  {Fore.WHITE}• Crawled pages:  {Fore.CYAN}{len(crawler.visited)}")
    print(f"  {Fore.WHITE}• Endpoints:      {Fore.CYAN}{len(crawler.endpoints)}")
    print(f"  {Fore.WHITE}• Forms:           {Fore.CYAN}{len(crawler.forms)}")
    print(f"  {Fore.WHITE}• JS endpoints:   {Fore.CYAN}{len(crawler.js_endpoints)}")
    if crawler.found_subdomains:
        print(f"  {Fore.WHITE}• Subdomains:     {Fore.CYAN}{len(crawler.found_subdomains)}")
    if crawler.bruteforced_paths:
        print(f"  {Fore.WHITE}• Directories:    {Fore.CYAN}{len(crawler.bruteforced_paths)}")
    print(f"  {Fore.WHITE}• WAF detected:   {Fore.MAGENTA}{', '.join(crawler.detected_wafs) if crawler.detected_wafs else 'None'}")
    print(f"  {Fore.WHITE}• Total time:     {Fore.CYAN}{total_elapsed:.1f}s")
    print()

    if all_results:
        print(f"  {Fore.GREEN}{Style.BRIGHT}╔══════════════════════════════════════════════════════╗")
        print(f"  {Fore.GREEN}{Style.BRIGHT}║  TARAMA TAMAMLANDI - {len(all_results)} ZAFİYET BULUNDU            ║")
        print(f"  {Fore.GREEN}{Style.BRIGHT}╚══════════════════════════════════════════════════════╝")
        print()
        print(f"  {Fore.YELLOW}Önerilen manuel doğrulama araçları:")
        print(f"  {Fore.CYAN}  sqlmap    → SQL Injection testleri")
        print(f"  {Fore.CYAN}  dalfox    → XSS testleri")
        print(f"  {Fore.CYAN}  commix    → Command injection testleri")
        print(f"  {Fore.CYAN}  SSRFmap   → SSRF testleri")
        print(f"  {Fore.CYAN}  dotdotpwn → Path traversal testleri")
        print(f"  {Fore.CYAN}  nuclei    → Genel zafiyet taraması")
        print()

if __name__ == "__main__":
    main()
