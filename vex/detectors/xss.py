import hashlib

from ..core.base_detector import BaseDetector
from ..payloads.xss import DOM_SINKS, DOM_SOURCES, gen_xss_payloads


class XSSDetector(BaseDetector):
    """Dalfox + XSStrike inspired XSS tespiti — marker yansıması."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads)

    def _marker_for(self, param):
        return hashlib.md5(param.encode()).hexdigest()[:8]

    def test(self, endpoint):
        results = []
        if not endpoint or not endpoint.get('params'):
            return results

        method = endpoint.get('method', 'GET')

        for param, method in self._iterate_params(endpoint):
            marker = self._marker_for(param)
            payloads = list(gen_xss_payloads(marker))[:120]

            for payload in payloads:
                try:
                    if method == 'GET':
                        resp, _, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, _ = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

                    if self.analyzer.reflected_marker(resp.text, payload):
                        results.append(self._make_result(
                            'xss', url, param, payload, 'high', 'reflected-exact',
                            hint=f'Payload yansıdı. dalfox url "{url}" -p {param} ile doğrulayın',
                        ))
                        break

                    if self.analyzer.reflected_marker(resp.text, marker):
                        results.append(self._make_result(
                            'xss', url, param, payload, 'high', 'reflected-marker',
                            hint=f'Marker ({marker}) yansıdı — XSS olası. dalfox/XSStrike ile doğrulayın',
                        ))
                        break

                    if self.analyzer.reflected_partial(resp.text, payload):
                        results.append(self._make_result(
                            'xss', url, param, payload, 'medium', 'partial-reflection',
                            hint='Kısmi yansıma — filtre bypass denemeleri için XSStrike kullanın',
                        ))
                        break

                except Exception:
                    continue

            # DOM XSS hint (Dalfox static analysis)
            try:
                if method == 'GET':
                    resp, _, url = self._request_get(endpoint, param, 'test')
                else:
                    resp, _ = self._request_post(endpoint, param, 'test')
                    url = endpoint['url']

                body = resp.text
                has_sink = self.analyzer.match_any(body, DOM_SINKS, case_insensitive=False)
                has_source = self.analyzer.match_any(body, DOM_SOURCES, case_insensitive=False)
                if has_sink and has_source:
                    results.append(self._make_result(
                        'xss', url, param, 'DOM analysis', 'low', 'dom-hint',
                        hint=f'DOM kaynak ({has_source}) + sink ({has_sink}) bulundu — DOM XSS manuel test edin',
                    ))
            except Exception:
                pass

        return results
