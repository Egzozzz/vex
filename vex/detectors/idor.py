import re

import requests

from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import IDOR_PARAM_HINTS, IDOR_PATTERNS, idor_test_values


class IDORDetector(BaseDetector):
    """Nuclei-inspired IDOR tespiti — sequential ID mutation."""

    def __init__(self, session=None, user_b_cookie=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads)
        self.user_b_cookie = user_b_cookie

    def _parse_cookie(self, cookie_str):
        cookies = {}
        for item in cookie_str.split(';'):
            if '=' in item:
                key, val = item.split('=', 1)
                cookies[key.strip()] = val.strip()
        return cookies

    def _param_relevant(self, param):
        param_lower = param.lower()
        return any(h in param_lower for h in IDOR_PARAM_HINTS) or param_lower in IDOR_PARAM_HINTS

    def test(self, endpoint):
        results = []
        if not endpoint or not endpoint.get('params'):
            return results

        if endpoint.get('method', 'GET') != 'GET':
            return results

        for param in endpoint['params']:
            try:
                from urllib.parse import parse_qs, urlencode, urlparse

                parsed = urlparse(endpoint['url'])
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                if 'query_params' in endpoint:
                    test_params = {k: (v[0] if isinstance(v, list) and v else v)
                                   for k, v in endpoint['query_params'].items()}
                else:
                    test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

                if param not in test_params:
                    continue

                original_val = str(test_params[param])
                matched = any(re.match(p, original_val) for p in IDOR_PATTERNS)
                if not matched and not self._param_relevant(param):
                    continue

                new_vals = idor_test_values(original_val)
                if not new_vals:
                    continue

                orig_url = f"{base_url}?{urlencode(test_params)}"
                orig_resp = self.session.get(orig_url, timeout=self.timeout, allow_redirects=True)
                orig_hash = self.analyzer.body_hash(orig_resp.text)

                for new_val in new_vals:
                    test_params[param] = new_val
                    test_url = f"{base_url}?{urlencode(test_params)}"

                    resp_a = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)

                    if resp_a.status_code != 200 or len(resp_a.text) < 50:
                        continue

                    resp_hash = self.analyzer.body_hash(resp_a.text)
                    if resp_hash == orig_hash:
                        continue

                    confidence = 'low'
                    technique = 'id-mutation'

                    if self.user_b_cookie:
                        session_b = requests.Session()
                        session_b.cookies.update(self._parse_cookie(self.user_b_cookie))
                        resp_b = session_b.get(test_url, timeout=self.timeout, allow_redirects=True)
                        if resp_b.status_code == 200 and len(resp_b.text) > 50:
                            confidence = 'medium'
                            technique = 'cross-user-access'
                    elif self._param_relevant(param):
                        confidence = 'medium'

                    results.append(self._make_result(
                        'idor', test_url, param, f'{original_val} -> {new_val}',
                        confidence, technique,
                        hint='Farklı ID ile farklı içerik döndü — farklı kullanıcı oturumlarıyla nuclei idor template\'leri ile doğrulayın',
                        original=original_val,
                        modified=new_val,
                    ))
                    break

            except Exception:
                continue

        return results
