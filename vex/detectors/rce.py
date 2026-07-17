from ..core.base_detector import BaseDetector
from ..payloads.nuclei_patterns import RCE_INDICATORS, RCE_PAYLOADS


class RCEDetector(BaseDetector):
    """Commix + Nuclei inspired command injection / SSTI tespiti — WAF-aware, encoding."""

    def __init__(self, session=None, timeout=10, ai_engine=None, mode='fast', custom_payloads=None, stealth=True):
        super().__init__(session, timeout, ai_engine, mode, custom_payloads, stealth)
        if self.mode == 'fast':
            self.payloads = RCE_PAYLOADS[:10]
        elif self.mode == 'fuzz':
            self.payloads = RCE_PAYLOADS[:200]
        else:
            self.payloads = RCE_PAYLOADS[:50]

    def _test_ssti_engines(self, endpoint, param):
        """Çoklu SSTI motoru testi."""
        ssti_markers = {
            'jinja2': ('{{7*7}}', '49'),
            'twig': ('{{7*7}}', '49'),
            'freemarker': ('${7*7}', '49'),
            'velocity': ('${7*7}', '49'),
            'erb': ('<%= 7*7 %>', '49'),
            'ejs': ('<%= 7*7 %>', '49'),
            'mako': ('${7*7}', '49'),
            'handlebars': ('{{7*7}}', '49'),
            'pug': ('#{7*7}', '49'),
            'nunjucks': ('{{7*7}}', '49'),
            'razor': ('@(7*7)', '49'),
        }
        results = []
        for engine, (payload, expected) in ssti_markers.items():
            try:
                if endpoint.get('method', 'GET') == 'GET':
                    resp, _, url = self._request_get(endpoint, param, payload)
                else:
                    resp, _ = self._request_post(endpoint, param, payload)
                    url = endpoint['url']

                if self._is_waf_blocking(resp):
                    continue

                if expected in resp.text and expected not in (resp.text[:100] if resp.text else ''):
                    results.append(self._make_result(
                        'rce', url, param, payload, 'medium', f'ssti-{engine}',
                        hint=f'SSTI sinyali ({engine}: {expected}) — {engine} template injection manuel test edin',
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

        try:
            if method == 'GET':
                baseline_resp, _, _ = self._baseline_get(endpoint)
                baseline_body = baseline_resp.text
        except Exception:
            pass

        for param, method in self._iterate_params(endpoint):
            found = False

            # Phase 1: Echo marker testleri
            for payload in self.payloads:
                if found:
                    break
                try:
                    if method == 'GET':
                        resp, _, url = self._request_get(endpoint, param, payload)
                    else:
                        resp, _ = self._request_post(endpoint, param, payload)
                        url = endpoint['url']

                    if self._is_waf_blocking(resp):
                        for bp_resp, bp_elapsed, bp_url, bp_payload in self._request_with_bypass(
                            endpoint, param, payload, 'rce'
                        ):
                            if not self._is_waf_blocking(bp_resp) and 'VEXRCEMARKER' in bp_resp.text:
                                results.append(self._make_result(
                                    'rce', bp_url, param, bp_payload, 'high', 'waf-bypass-command-output',
                                    hint='WAF bypass ile komut çıktısı yansıdı — kontrollü ortamda Commix ile doğrulayın',
                                ))
                                found = True
                                break
                        continue

                    if 'VEXRCEMARKER' in resp.text:
                        results.append(self._make_result(
                            'rce', url, param, payload, 'high', 'command-output',
                            hint='Komut çıktısı yansıdı — Commix ile test edin: commix -u "{url}" --data="{param}=*"'.format(url=url, param=param),
                        ))
                        found = True
                        break

                    # SSTI kontrolü
                    if '{{' in payload or '${' in payload or '#{' in payload or '@(' in payload:
                        if '49' in resp.text and '49' not in baseline_body:
                            results.append(self._make_result(
                                'rce', url, param, payload, 'medium', 'ssti-hint',
                                hint='SSTI sinyali (7*7=49) — template injection manuel test edin',
                            ))
                            found = True
                            break

                    # Indicator match
                    indicator = self.analyzer.match_any(resp.text, [i for i in RCE_INDICATORS if i != 'VEXRCEMARKER'])
                    if indicator and not self.analyzer.match_any(baseline_body, [indicator]):
                        results.append(self._make_result(
                            'rce', url, param, payload, 'medium', 'indicator-match',
                            hint=f'Sistem göstergesi ({indicator}) bulundu — nuclei rce template\'leri ile doğrulayın',
                            indicator=indicator,
                        ))
                        found = True
                        break

                except Exception:
                    continue

            # Phase 2: SSTI multi-engine test
            if not found:
                ssti_results = self._test_ssti_engines(endpoint, param)
                results.extend(ssti_results)

        return results
