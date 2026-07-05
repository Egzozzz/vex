from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import RCE_INDICATORS, RCE_PAYLOADS


class RCEDetector(BaseDetector):
    """Nuclei-inspired command injection / SSTI tespiti — güvenli echo marker."""

    def __init__(self, session=None, timeout=10, ai_engine=None, mode='fast', custom_payloads=None):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads)
        self.payloads = RCE_PAYLOADS

    def test(self, endpoint):
        results = []
        if not endpoint or not endpoint.get('params'):
            return results

        method = endpoint.get('method', 'GET')
        baseline_body = ''

        try:
            if method == 'GET':
                baseline_resp, _, _ = self._baseline_get(endpoint)
                baseline_body = baseline_resp.text
        except Exception:
            pass

        for param, method in self._iterate_params(endpoint):
            for payload in self.payloads:
                try:
                    if method == 'GET':
                        resp, _, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, _ = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

                    if 'VEXRCEMARKER' in resp.text:
                        results.append(self._make_result(
                            'rce', url, param, payload, 'high', 'command-output',
                            hint='Komut çıktısı yansıdı — kontrollü ortamda manuel doğrulayın',
                        ))
                        break

                    indicator = self.analyzer.match_any(resp.text, [i for i in RCE_INDICATORS if i != 'VEXRCEMARKER'])
                    if indicator and not self.analyzer.match_any(baseline_body, [indicator]):
                        results.append(self._make_result(
                            'rce', url, param, payload, 'medium', 'indicator-match',
                            hint=f'Sistem göstergesi ({indicator}) bulundu — nuclei rce template\'leri ile doğrulayın',
                            indicator=indicator,
                        ))
                        break

                    if '{{7*7}}' in payload or '${7*7}' in payload:
                        if '49' in resp.text and '49' not in baseline_body:
                            results.append(self._make_result(
                                'rce', url, param, payload, 'medium', 'ssti-hint',
                                hint='SSTI sinyali (7*7=49) — template injection manuel test edin',
                            ))
                            break

                except Exception:
                    continue

        return results
