import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
from .payloads.subdomains import COMMON_SUBDOMAINS


class Crawler:
    def __init__(self, base_url, depth=3, exclude=None, wordlist_path=None, include_subdomains=False):
        self.base_url = base_url
        self.depth = depth
        self.exclude = exclude
        self.visited = set()
        self.endpoints = []
        self.forms = []
        self.bruteforced_paths = []
        self.found_subdomains = []
        self.wordlist_path = wordlist_path
        self.include_subdomains = include_subdomains
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    def is_valid_url(self, url):
        parsed = urlparse(url)
        base_parsed = urlparse(self.base_url)
        if parsed.netloc != base_parsed.netloc:
            return False
        if self.exclude and re.search(self.exclude, url):
            return False
        if parsed.path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf')):
            return False
        return True
        
    def extract_params(self, url):
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
        
    def crawl(self, url=None, current_depth=0):
        if current_depth > self.depth:
            return
        if url is None:
            url = self.base_url
        if url in self.visited:
            return
            
        self.visited.add(url)
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
        except Exception:
            return
            
        parsed_url = urlparse(url)
        params = self.extract_params(url)
        if params:
            self.endpoints.append({
                'url': url,
                'params': params,
                'method': 'GET',
                'query_params': parse_qs(parsed_url.query)
            })
            
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception:
            soup = None
            
        if soup:
            for form in soup.find_all('form'):
                action = form.get('action', '')
                full_action = urljoin(url, action)
                if not self.is_valid_url(full_action):
                    continue
                    
                method = form.get('method', 'GET').upper()
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        inputs.append(name)
                        
                self.forms.append({
                    'url': full_action,
                    'method': method,
                    'params': inputs
                })
                
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                if self.is_valid_url(next_url) and next_url not in self.visited:
                    self.crawl(next_url, current_depth + 1)
                
    def brute_force_directories(self):
        if not self.wordlist_path:
            return
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {self.wordlist_path}")
            return
        except Exception as e:
            print(f"[!] Error reading wordlist: {e}")
            return

        parsed_base = urlparse(self.base_url)
        base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"

        for path in wordlist:
            if not path.startswith('/'):
                path = '/' + path
            test_url = urljoin(base_url, path)
            if test_url in self.visited:
                continue
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=True)
                if response.status_code in (200, 301, 302, 307, 308, 403):
                    self.bruteforced_paths.append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'path': path
                    })
                    if response.status_code == 200:
                        self.crawl(test_url)
            except Exception:
                continue

    def discover_subdomains(self):
        if not self.include_subdomains:
            return
        parsed_base = urlparse(self.base_url)
        domain_parts = parsed_base.netloc.split('.')
        if len(domain_parts) < 2:
            return
        base_domain = '.'.join(domain_parts[-2:])
        
        for subdomain in COMMON_SUBDOMAINS:
            test_subdomain = f"{subdomain}.{base_domain}"
            test_url = f"{parsed_base.scheme}://{test_subdomain}"
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=True)
                self.found_subdomains.append({
                    'subdomain': test_subdomain,
                    'url': test_url,
                    'status_code': response.status_code
                })
                if response.status_code == 200:
                    self.crawl(test_url)
            except Exception:
                continue

    def get_all_targets(self):
        return self.endpoints + self.forms
