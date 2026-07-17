from urllib.parse import urljoin

from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import BAC_KEYWORDS, BAC_PATHS


class BACDetector(BaseDetector):
    """Nuclei-inspired Broken Access Control / exposed admin panel tespiti — method fuzzing."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None, stealth=True):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads, stealth)
        self.admin_paths = BAC_PATHS

    def _test_method_bypass(self, url):
        """HTTP method bypass ile BAC testi."""
        results = []
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

        for method in methods:
            try:
                if method == 'HEAD':
                    resp = self.session.head(url, timeout=self.timeout, allow_redirects=True)
                else:
                    resp = self.session.request(method, url, timeout=self.timeout, allow_redirects=True)

                if resp.status_code == 200 and len(resp.text) > 200:
                    keyword = self.analyzer.match_any(resp.text, BAC_KEYWORDS)
                    if keyword:
                        results.append({
                            'method': method,
                            'status': resp.status_code,
                            'keyword': keyword,
                        })
            except Exception:
                continue
        return results

    def _test_header_bypass(self, url):
        """Header-based auth bypass testi."""
        results = []
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1, 10.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-Forwarded-Host': 'localhost'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin
        ]

        for headers in bypass_headers:
            try:
                resp = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200:
                    keyword = self.analyzer.match_any(resp.text, BAC_KEYWORDS)
                    if keyword:
                        results.append({
                            'headers': headers,
                            'status': resp.status_code,
                            'keyword': keyword,
                        })
            except Exception:
                continue
        return results

    def test(self, base_url):
        results = []
        if not base_url:
            return results

        for path in self.admin_paths:
            try:
                test_url = urljoin(base_url, path)
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)

                if resp.status_code not in (200, 301, 302, 307, 308, 401, 403):
                    continue

                keyword = self.analyzer.match_any(resp.text, BAC_KEYWORDS)
                is_login_redirect = resp.status_code in (301, 302) and 'login' in resp.headers.get('Location', '').lower()

                if keyword and resp.status_code == 200:
                    # Method tampering testi
                    method_results = self._test_method_bypass(test_url)
                    accessible_methods = [r['method'] for r in method_results if r['status'] == 200]

                    results.append(self._make_result(
                        'bac', test_url, 'path', path, 'high', 'exposed-admin',
                        hint=f'Admin panel göstergesi ({keyword}) — yetkisiz erişimi farklı oturumlarla ve HTTP metotlarıyla doğrulayın',
                        keyword=keyword,
                        accessible_methods=accessible_methods,
                    ))

                    # Header bypass testi
                    header_results = self._test_header_bypass(test_url)
                    if header_results:
                        for hr in header_results:
                            results.append(self._make_result(
                                'bac', test_url, 'path', path, 'high', 'header-bypass',
                                hint=f'Header bypass ile erişim sağlandı ({hr["keyword"]}) — {list(hr["headers"].keys())[0]} header\'ı ile bypass',
                                keyword=hr['keyword'],
                                bypass_headers=hr['headers'],
                            ))

                elif resp.status_code == 200 and len(resp.text) > 200 and not keyword:
                    if self.analyzer.match_regex(resp.text, [r'admin', r'dashboard', r'panel', r'management']):
                        results.append(self._make_result(
                            'bac', test_url, 'path', path, 'medium', 'accessible-path',
                            hint='Erişilebilir admin/hassas yol — yetki kontrolünü manuel test edin',
                        ))
                elif is_login_redirect:
                    results.append(self._make_result(
                        'bac', test_url, 'path', path, 'low', 'login-redirect',
                        hint='Login\'e yönlendiren admin yolu — auth bypass manuel test edin',
                    ))

            except Exception:
                continue

        return results
