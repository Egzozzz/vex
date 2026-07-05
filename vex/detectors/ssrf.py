from ..core.base_detector import BaseDetector
from ..payloads.ssrf import SSRF_INDICATORS, SSRF_PARAM_HINTS, gen_ssrf_payloads


class SSRFDetector(BaseDetector):
    """SSRFmap-inspired SSRF tespiti — bypass + cloud metadata."""

    def __init__(self, session=None, timeout=10, ai_engine=None, mode='fast', custom_payloads=None):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads)
        self.payloads = list(gen_ssrf_payloads())

    def _param_priority(self, param):
        param_lower = param.lower()
        for hint in SSRF_PARAM_HINTS:
            if hint in param_lower:
                return 0
        return 1

    def test(self, endpoint):
        results = []
        if not endpoint or not endpoint.get('params'):
            return results

        method = endpoint.get('method', 'GET')
        baseline_body = ''
        baseline_len = 0

        try:
            if method == 'GET':
                baseline_resp, _, _ = self._baseline_get(endpoint)
                baseline_body = baseline_resp.text
                baseline_len = len(baseline_body)
        except Exception:
            pass

        sorted_params = sorted(endpoint['params'], key=self._param_priority)
        max_payloads = 80 if self._param_priority(sorted_params[0]) == 0 else 40

        for param in sorted_params:
            tested = 0
            for payload in self.payloads:
                if tested >= max_payloads:
                    break
                tested += 1
                try:
                    if method == 'GET':
                        resp, elapsed, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, elapsed = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

                    indicator = self.analyzer.match_any(resp.text, SSRF_INDICATORS)
                    content_changed = self.analyzer.significant_diff(baseline_body, resp.text)
                    slow_response = elapsed > 4

                    if indicator and not self.analyzer.match_any(baseline_body, [indicator]):
                        results.append(self._make_result(
                            'ssrf', url, param, payload, 'high', 'content-match',
                            hint=f'İçerik göstergesi: {indicator}. SSRFmap ile manuel doğrulayın',
                            indicator=indicator,
                        ))
                        break

                    if content_changed and resp.status_code in (200, 301, 302, 307, 308):
                        results.append(self._make_result(
                            'ssrf', url, param, payload, 'medium', 'response-diff',
                            hint='Yanıt içeriği değişti — sunucu dış kaynağa istek atmış olabilir. SSRFmap ile test edin',
                        ))
                        break

                    if slow_response and resp.status_code not in (404, 400, 403):
                        results.append(self._make_result(
                            'ssrf', url, param, payload, 'low', 'timing-hint',
                            hint=f'Yavaş yanıt ({elapsed:.1f}s) — blind SSRF olabilir, manuel test edin',
                        ))
                        break

                except Exception:
                    continue

        return results
