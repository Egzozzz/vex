from urllib.parse import urljoin

from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import BAC_KEYWORDS, BAC_PATHS


class BACDetector(BaseDetector):
    """Nuclei-inspired Broken Access Control / exposed admin panel tespiti."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads)
        self.admin_paths = BAC_PATHS

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
                    results.append(self._make_result(
                        'bac', test_url, 'path', path, 'high', 'exposed-admin',
                        hint=f'Admin panel göstergesi ({keyword}) — yetkisiz erişimi farklı oturumlarla doğrulayın',
                        keyword=keyword,
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
