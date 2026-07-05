from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import PATH_INDICATORS, gen_path_traversal_payloads


class PathTraversalDetector(BaseDetector):
    """Nuclei-inspired path traversal / LFI tespiti."""

    def __init__(self, session=None, timeout=8, ai_engine=None, mode='fast', custom_payloads=None):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads)
        self.payloads = list(gen_path_traversal_payloads())

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
            for payload in self.payloads:
                if tested >= 100:
                    break
                tested += 1
                try:
                    if method == 'GET':
                        resp, _, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, _ = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

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
