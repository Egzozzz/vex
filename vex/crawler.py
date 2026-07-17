"""
VEX Advanced Crawler — Precision endpoint discovery engine.
Features: JS parsing, API extraction, GraphQL introspection, hidden path discovery, WAF-aware.
"""

import requests
import time
import random
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
from .payloads.subdomains import COMMON_SUBDOMAINS,  ADDITIONAL_SUBDOMAINS
from .payloads.waf import get_random_headers, detect_waf


class Crawler:
    def __init__(self, base_url, depth=3, exclude=None, wordlist_path=None,
                 include_subdomains=False, stealth=True, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.depth = depth
        self.exclude = exclude
        self.visited = set()
        self.endpoints = []
        self.forms = []
        self.bruteforced_paths = []
        self.found_subdomains = []
        self.discovered_apis = []
        self.js_endpoints = []
        self.hidden_paths = []
        self.wordlist_path = wordlist_path
        self.include_subdomains = include_subdomains
        self.stealth = stealth
        self.proxy = proxy
        self.detected_wafs = []
        self.session = requests.Session()
        self._init_session()
        self.parsed_base = urlparse(self.base_url)
        self.base_domain = self.parsed_base.netloc

    def _init_session(self):
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
        if self.stealth:
            self.session.headers.update(get_random_headers())
        else:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
            })

    def _stealth_wait(self):
        if self.stealth:
            time.sleep(random.uniform(0.1, 1.0))

    def _fetch(self, url, timeout=10):
        """Safe fetch with error handling."""
        try:
            self._stealth_wait()
            resp = self.session.get(url, timeout=timeout, allow_redirects=True)
            if not self.detected_wafs:
                self.detected_wafs = detect_waf(resp.headers, resp.status_code, resp.text)
            return resp
        except Exception:
            return None

    def _calculate_priority(self, params):
        priority = 0
        high_priority_params = [
            'id', 'uid', 'user_id', 'user', 'q', 'query', 'search', 's',
            'order', 'sort', 'page', 'limit', 'offset', 'start', 'end',
            'from', 'to', 'date', 'time', 'datetime', 'timestamp',
            'email', 'username', 'name', 'password', 'pass',
            'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
            'redirect', 'next', 'return', 'callback', 'file', 'document',
            'path', 'folder', 'root', 'feed', 'host', 'site',
            'action', 'cmd', 'command', 'execute', 'run', 'exec',
            'data', 'xml', 'json', 'payload', 'input', 'text', 'content',
            'token', 'api_key', 'key', 'secret', 'auth', 'session',
            'upload', 'download', 'export', 'import', 'ref', 'debug',
            'admin', 'config', 'setting', 'mode', 'method', 'format',
        ]
        for param in params:
            param_lower = param.lower()
            if any(hint in param_lower for hint in high_priority_params):
                priority += 2
            if len(param) <= 5:
                priority += 1
        return priority

    def is_valid_url(self, url):
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        if parsed.netloc != self.base_domain:
            return False
        if self.exclude and re.search(self.exclude, url):
            return False
        if parsed.path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
                                  '.ico', '.svg', '.pdf', '.woff', '.woff2', '.ttf',
                                  '.eot', '.mp4', '.mp3', '.zip', '.tar', '.gz')):
            return False
        return True

    def extract_params(self, url):
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def _normalize_path(self, url):
        """Normalize URLs to group similar patterns."""
        parsed = urlparse(url)
        path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        if params:
            norm = {}
            for k, v in params.items():
                val = v[0] if v else ''
                if val.isdigit():
                    norm[k] = '{NUM}'
                elif re.match(r'^[0-9a-f]{8,36}$', val, re.I):
                    norm[k] = '{HASH}'
                elif re.match(r'^[a-z0-9_-]{20,}$', val, re.I):
                    norm[k] = '{TOKEN}'
                elif '%' in val or '/' in val or len(val) > 30:
                    norm[k] = '{VAL}'
                else:
                    norm[k] = val
            return f"{path}?{urlencode(norm)}"
        return path

    def _extract_js_endpoints(self, text, source_url):
        """Extract API endpoints from JavaScript code."""
        patterns = [
            # Standard API patterns
            r'["\']/(?:api|v[0-9]+|rest|graphql|endpoint)/[^"\'\s]*["\']',
            # HTTP requests
            r'(?:fetch|axios|ajax|getJSON|postJSON|put|del|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            # XMLHttpRequest
            r'XMLHttpRequest.*?["\']([^"\']+)["\']',
            r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']',
            # WebSocket
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            # Service Worker
            r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
            # Import
            r'import\s*\(\s*["\']([^"\']+)["\']',
            # Require
            r'require\s*\(\s*["\']([^"\']+)["\']',
            # URL patterns in config
            r'["\'](?:api[_-]?url|base[_-]?url|endpoint|service[_-]?url)["\']\s*[:=]\s*["\']([^"\']+)["\']',
            # Hidden endpoints in comments
            r'//\s*(?:TODO|FIXME|HACK|XXX|NOTE)\s*:\s*([^"\'\n]+)',
            r'/\*\s*(?:TODO|FIXME|HACK|XXX|NOTE)\s*:\s*([^*]+)\*/',
        ]
        found = set()
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.I):
                url_str = match.group(1) if match.lastindex else match.group(0)
                url_str = url_str.strip('"\' ')
                if url_str.startswith('/'):
                    url_str = urljoin(source_url, url_str)
                if url_str.startswith(('http://', 'https://')) and self.is_valid_url(url_str):
                    found.add(url_str)
                elif not url_str.startswith(('http://', 'https://', 'data:', 'blob:')):
                    full_url = urljoin(source_url, url_str)
                    if self.is_valid_url(full_url):
                        found.add(full_url)
        return list(found)

    def _discover_hidden_paths(self):
        """Discover hidden endpoints and sensitive files."""
        hidden_paths = [
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/api/health',
            '/api/users', '/api/admin', '/api/config', '/api/status',
            '/rest', '/rest/v1', '/rest/v2',
            # GraphQL
            '/graphql', '/graphiql', '/graphql/console', '/gql',
            # Swagger / OpenAPI
            '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json',
            '/swagger.yaml', '/api-docs', '/api-docs.json', '/openapi.json',
            '/v2/api-docs', '/v3/api-docs',
            # Spring Actuator
            '/actuator', '/actuator/env', '/actuator/health', '/actuator/info',
            '/actuator/metrics', '/actuator/beans', '/actuator/mappings',
            '/actuator/configprops', '/actuator/threaddump', '/actuator/heapdump',
            # Debug
            '/debug', '/trace', '/metrics', '/prometheus', '/health',
            '/info', '/env', '/config', '/settings', '/status',
            # Source code / Config
            '/.git/config', '/.git/HEAD', '/.env', '/.env.local', '/.env.prod',
            '/.gitignore', '/.htaccess', '/.htpasswd',
            '/wp-config.php', '/wp-config.bak', '/config.php', '/config.json',
            '/appsettings.json', '/web.config', '/application.yml',
            '/application.properties', '/database.yml',
            # Admin
            '/admin', '/administrator', '/admin.php', '/panel', '/dashboard',
            '/manage', '/management', '/backend', '/cpanel', '/console',
            # Backups
            '/backup', '/backup.sql', '/dump', '/export', '/db_backup',
            # Security
            '/robots.txt', '/sitemap.xml', '/security.txt', '/.well-known/',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            # Common CMS
            '/wp-json/', '/wp-json/wp/v2/users',
            '/wp-admin/admin-ajax.php', '/wp-content/debug.log',
            # Other
            '/phpinfo.php', '/info.php', '/test.php', '/shell.php',
            '/cgi-bin/', '/cgi-bin/status', '/cgi-bin/test.cgi',
            '/server-status', '/server-info',
        ]
        discovered = []
        base = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}"

        for path in hidden_paths:
            test_url = urljoin(base, path)
            if test_url in self.visited:
                continue
            resp = self._fetch(test_url, timeout=5)
            if resp and resp.status_code in (200, 301, 302, 307, 308, 401, 403):
                discovered.append({'url': test_url, 'status_code': resp.status_code, 'path': path})
                if resp.status_code == 200:
                    self.visited.add(test_url)
                    js_urls = self._extract_js_endpoints(resp.text, test_url)
                    for js_url in js_urls:
                        if js_url not in [e['url'] for e in self.js_endpoints]:
                            self.js_endpoints.append({
                                'url': js_url,
                                'source': test_url,
                                'params': self.extract_params(js_url),
                            })
        return discovered

    def _is_dynamic_param(self, url):
        """Check if URL has dynamic parameters."""
        parsed = urlparse(url)
        return bool(parse_qs(parsed.query))

    def crawl(self, url=None, current_depth=0):
        if current_depth > self.depth:
            return
        if url is None:
            url = self.base_url
        if url in self.visited:
            return

        self.visited.add(url)
        resp = self._fetch(url)
        if not resp:
            return

        # Extract params from current URL
        params = self.extract_params(url)
        if params:
            priority = self._calculate_priority(params)
            self.endpoints.append({
                'url': url,
                'params': params,
                'method': 'GET',
                'query_params': parse_qs(urlparse(url).query),
                'priority': priority,
            })

        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
        except Exception:
            soup = None

        if soup is None:
            return

        # --- FORMS ---
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
            if inputs:
                priority = self._calculate_priority(inputs)
                # Normalize form URLs too
                existing = None
                for f in self.forms:
                    if self._normalize_path(f['url']) == self._normalize_path(full_action):
                        existing = f
                        break
                if existing:
                    existing['params'] = list(set(existing['params'] + inputs))
                    existing['priority'] = max(existing['priority'], priority)
                else:
                    self.forms.append({
                        'url': full_action, 'method': method,
                        'params': inputs, 'priority': priority,
                    })

        # --- SCRIPTS (JS endpoint extraction) ---
        for script in soup.find_all('script', src=True):
            script_url = urljoin(url, script['src'])
            if not self.is_valid_url(script_url):
                continue
            js_resp = self._fetch(script_url, timeout=5)
            if js_resp and js_resp.status_code == 200:
                js_urls = self._extract_js_endpoints(js_resp.text, script_url)
                for js_url in js_urls:
                    if js_url not in [e['url'] for e in self.js_endpoints]:
                        self.js_endpoints.append({
                            'url': js_url,
                            'source': script_url,
                            'params': self.extract_params(js_url),
                        })

        # Inline scripts
        for script in soup.find_all('script'):
            if script.string:
                js_urls = self._extract_js_endpoints(script.string, url)
                for js_url in js_urls:
                    if js_url not in [e['url'] for e in self.js_endpoints]:
                        self.js_endpoints.append({
                            'url': js_url,
                            'source': f'{url} (inline)',
                            'params': self.extract_params(js_url),
                        })

        # --- DATA ATTRIBUTES ---
        for tag in soup.find_all(attrs={'data-api': True}):
            api_url = urljoin(url, tag['data-api'])
            if self.is_valid_url(api_url):
                params = self.extract_params(api_url)
                priority = self._calculate_priority(params)
                self.endpoints.append({
                    'url': api_url, 'params': params, 'method': 'GET',
                    'query_params': parse_qs(urlparse(api_url).query),
                    'priority': priority,
                })

        for tag in soup.find_all(attrs={'data-endpoint': True}):
            ep_url = urljoin(url, tag['data-endpoint'])
            if self.is_valid_url(ep_url):
                params = self.extract_params(ep_url)
                priority = self._calculate_priority(params)
                self.endpoints.append({
                    'url': ep_url, 'params': params, 'method': 'GET',
                    'query_params': parse_qs(urlparse(ep_url).query),
                    'priority': priority,
                })

        # --- LINKS ---
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
            print(f"  [!] Wordlist not found: {self.wordlist_path}")
            return
        except Exception as e:
            print(f"  [!] Error reading wordlist: {e}")
            return

        base = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}"
        total = len(wordlist)
        for i, path in enumerate(wordlist):
            if not path.startswith('/'):
                path = '/' + path
            test_url = urljoin(base, path)
            if test_url in self.visited:
                continue
            resp = self._fetch(test_url, timeout=5)
            if resp and resp.status_code in (200, 301, 302, 307, 308, 403):
                self.bruteforced_paths.append({
                    'url': test_url, 'status_code': resp.status_code, 'path': path,
                })
                if resp.status_code == 200 and test_url not in self.visited:
                    self.crawl(test_url)
            if i % 100 == 0:
                print(f"  [~] Brute-force: {i}/{total} ({len(self.bruteforced_paths)} found)")

    def discover_subdomains(self):
        if not self.include_subdomains:
            return
        domain_parts = self.base_domain.split('.')
        if len(domain_parts) < 2:
            return
        root_domain = '.'.join(domain_parts[-2:])

        all_subdomains = list(COMMON_SUBDOMAINS) + list(ADDITIONAL_SUBDOMAINS)
        scheme = self.parsed_base.scheme
        total = len(all_subdomains)

        for i, sub in enumerate(all_subdomains):
            test_sub = f"{sub}.{root_domain}"
            test_url = f"{scheme}://{test_sub}"
            resp = self._fetch(test_url, timeout=5)
            if resp:
                self.found_subdomains.append({
                    'subdomain': test_sub, 'url': test_url,
                    'status_code': resp.status_code, 'length': len(resp.text or ''),
                })
                if resp.status_code == 200:
                    self.crawl(test_url)
            if i % 50 == 0:
                print(f"  [~] Subdomain scan: {i}/{total} ({len(self.found_subdomains)} found)")

    def get_all_targets(self, max_targets=15):
        self._normalize_targets()
        all_targets = self.endpoints + self.forms + self.js_endpoints
        all_targets.sort(key=lambda t: t.get('priority', 0), reverse=True)
        if max_targets and len(all_targets) > max_targets:
            all_targets = all_targets[:max_targets]
        return all_targets

    def _normalize_targets(self):
        """Group similar targets to avoid testing duplicates."""
        seen = {}
        for ep in self.endpoints:
            key = self._normalize_path(ep['url'])
            if key in seen:
                seen[key]['params'] = list(set(seen[key]['params'] + ep['params']))
                seen[key]['priority'] = max(seen[key]['priority'], ep.get('priority', 0))
            else:
                seen[key] = dict(ep)
        self.endpoints = list(seen.values())

        seen_form = {}
        for fm in self.forms:
            key = self._normalize_path(fm['url'])
            if key in seen_form:
                seen_form[key]['params'] = list(set(seen_form[key]['params'] + fm['params']))
                seen_form[key]['priority'] = max(seen_form[key]['priority'], fm.get('priority', 0))
            else:
                seen_form[key] = dict(fm)
        self.forms = list(seen_form.values())
