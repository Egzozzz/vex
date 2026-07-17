from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import PATH_INDICATORS, gen_path_traversal_payloads


class PathTraversalDetector(BaseDetector):
    """Nuclei + DotDotPwn inspired path traversal / LFI tespiti — WAF-aware, encoding."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None, stealth=True):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads, stealth)
        all_payloads = list(gen_path_traversal_payloads())
        if self.mode == 'fast':
            self.payloads = all_payloads[:15]
        elif self.mode == 'fuzz':
            self.payloads = all_payloads[:200]
        else:
            self.payloads = all_payloads[:60]

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
            tested = 0
            max_pt_payloads = 30 if self.mode == 'fast' else (200 if self.mode == 'fuzz' else 100)
            for payload in self.payloads:
                if tested >= max_pt_payloads:
                    break
                tested += 1
                try:
                    if method == 'GET':
                        resp, _, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, _ = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

                    if self._is_waf_blocking(resp):
                        for bp_resp, bp_elapsed, bp_url, bp_payload in self._request_with_bypass(
                            endpoint, param, payload, 'path'
                        ):
                            if not self._is_waf_blocking(bp_resp):
                                indicator = self.analyzer.match_any(bp_resp.text, PATH_INDICATORS)
                                if indicator and not self.analyzer.match_any(baseline_body, [indicator]):
                                    results.append(self._make_result(
                                        'path_traversal', bp_url, param, bp_payload, 'high', 'waf-bypass-file-read',
                                        hint=f'WAF bypass ile dosya içeriği göstergesi ({indicator}) — dotdotpwn ile doğrulayın',
                                        indicator=indicator,
                                    ))
                                    break
                        continue

                    indicator = self.analyzer.match_any(resp.text, PATH_INDICATORS)
                    if indicator and not self.analyzer.match_any(baseline_body, [indicator]):
                        results.append(self._make_result(
                            'path_traversal', url, param, payload, 'high', 'file-read',
                            hint=f'Dosya içeriği göstergesi ({indicator}) — nuclei lfi template\'leri ile doğrulayın',
                            indicator=indicator,
                        ))
                        break

                except Exception:
                    continue

        return results
